#!/usr/bin/env python3
"""
DokkOS  —  interactive local recon console.

A Flask app serving a touch HUD that:
  * discovers live hosts with `nmap -sn` and lists them,
  * lets you select a host and run whitelisted nmap scans with live output,
  * launches interactive security tools (airgeddon, wifite, bettercap) in a
    real terminal window, because those are ncurses TUIs that can't be driven
    from a streamed <pre>.

SECURITY MODEL (unchanged from v1):
  * The browser sends *ids* (scan profile id, tool id) — never command strings.
  * The only free text is the target/subnet, validated as IP/CIDR/hostname
    before it ever reaches a subprocess.
  * subprocess always runs with an argument LIST and shell=False. No shell.
  * Bound to 127.0.0.1 only.

  Only scan / audit networks you own or are explicitly authorised to test.
  Wireless auditing tools are illegal to use against networks you don't own.

Run (root needed for OS-detection scans and the wireless tools):
  pip install flask
  sudo -E python3 app.py        # -E preserves DISPLAY so terminals can open
  open http://127.0.0.1:5000
"""

import argparse
import glob
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET

try:
    from flask import Flask, Response, jsonify, request, stream_with_context
except ModuleNotFoundError:
    sys.stderr.write(
        "\nDokkOS needs Flask — the one third-party Python dependency.\n"
        "Install it, then re-run:\n"
        "  sudo apt install python3-flask          # Debian / Kali (recommended)\n"
        "  pip install flask --break-system-packages\n"
        "  # or in a venv:  python3 -m venv venv && . venv/bin/activate && pip install flask\n\n")
    raise SystemExit(1)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Whitelisted nmap scan profiles. id -> fixed argument list. Target appended.
# ---------------------------------------------------------------------------
SCAN_PROFILES = {
    "quick":    {"label": "Quick Scan",
                 "args": ["-v", "-F", "-T4"], "root": False},
    "services": {"label": "Services + Ports",
                 "args": ["-v", "-sV", "-O", "--osscan-guess", "-T4"], "root": True},
    "full":     {"label": "All Ports",
                 "args": ["-v", "-sV", "-O", "--osscan-guess", "-p-", "-T4",
                          "--host-timeout", "25m"], "root": True},
    "os":       {"label": "OS + Services",
                 "args": ["-v", "-sV", "-O", "--osscan-guess", "-T4"], "root": True},
    "vuln":     {"label": "Vulnerabilities",
                 "args": ["-v", "-sV", "-O", "--osscan-guess",
                          "--script", "vuln,vulners", "-T4",
                          "--host-timeout", "6m", "--script-timeout", "90s"], "root": True},
    "deep":     {"label": "Full Recon",
                 "args": ["-v", "-sV", "-O", "--osscan-guess",
                          "--script", "vuln,vulners", "-T4",
                          "--host-timeout", "6m", "--script-timeout", "90s"], "root": True},
}
DEFAULT_PROFILE = "deep"

# Service-aware NSE script sets for the per-port "dig deeper" action. The browser
# sends a service *name*; we look it up here (fixed map) so no arbitrary scripts
# can be injected. Unknown services fall back to the generic set.
SERVICE_SCRIPTS = {
    "http":          "http-title,http-headers,http-methods,http-enum,vulners",
    "https":         "http-title,http-headers,ssl-enum-ciphers,ssl-cert,vulners",
    "ssl":           "ssl-enum-ciphers,ssl-cert,vulners",
    "ssh":           "ssh2-enum-algos,ssh-auth-methods,vulners",
    "ftp":           "ftp-anon,ftp-syst,vulners",
    "smb":           "smb-os-discovery,smb-security-mode,smb-protocols,smb-vuln-*",
    "microsoft-ds":  "smb-os-discovery,smb-security-mode,smb-protocols,smb-vuln-*",
    "netbios-ssn":   "smb-os-discovery,smb-protocols,smb-vuln-*",
    "mysql":         "mysql-info,mysql-empty-password,vulners",
    "ms-sql-s":      "ms-sql-info,ms-sql-ntlm-info",
    "rdp":           "rdp-ntlm-info,rdp-enum-encryption",
    "ms-wbt-server": "rdp-ntlm-info,rdp-enum-encryption",
    "dns":           "dns-nsid,dns-recursion",
    "domain":        "dns-nsid,dns-recursion",
    "smtp":          "smtp-commands,smtp-open-relay,vulners",
    "snmp":          "snmp-info,snmp-sysdescr",
    "telnet":        "telnet-encryption,vulners",
    "vnc":           "vnc-info,vnc-title",
    "redis":         "redis-info",
    "mongodb":       "mongodb-info",
}
DEFAULT_PORT_SCRIPTS = "default,vuln,vulners"

# ---------------------------------------------------------------------------
# Dependencies. Maps a command -> how to install it. Used by --install / --check
# so a fresh box can be set up in one go (needs root for apt).
# ---------------------------------------------------------------------------
DEPENDENCIES = {
    "nmap":         ("apt", "nmap"),
    "bluetoothctl": ("apt", "bluez"),
    "sdptool":      ("apt", "bluez"),
    "l2ping":       ("apt", "bluez"),
    "iw":           ("apt", "iw"),
    "airodump-ng":  ("apt", "aircrack-ng"),
    "tshark":       ("apt", "tshark"),
    "avahi-browse": ("apt", "avahi-utils"),
    "openssl":      ("apt", "openssl"),
    "macchanger":   ("apt", "macchanger"),
    "airgeddon":    ("apt", "airgeddon"),
    "wifite":       ("apt", "wifite"),
    "bettercap":    ("apt", "bettercap"),
    "bluing":       ("pip", "bluing"),
    "msfconsole":   ("apt", "metasploit-framework"),
    "sqlmap":       ("apt", "sqlmap"),
    "nikto":        ("apt", "nikto"),
    "hydra":        ("apt", "hydra"),
}


def check_dependencies():
    """Return (present, missing_apt_pkgs, missing_pip_pkgs)."""
    present, apt_pkgs, pip_pkgs = [], [], []
    for tool, (kind, pkg) in DEPENDENCIES.items():
        if shutil.which(tool):
            present.append(tool)
        elif kind == "apt":
            if pkg not in apt_pkgs:
                apt_pkgs.append(pkg)
        else:
            if pkg not in pip_pkgs:
                pip_pkgs.append(pkg)
    return present, apt_pkgs, pip_pkgs


def install_dependencies():
    """Install missing apt + pip packages. Requires root for apt."""
    _, apt_pkgs, pip_pkgs = check_dependencies()
    if not apt_pkgs and not pip_pkgs:
        print("[install] all dependencies already present.")
        return
    if apt_pkgs:
        if os.geteuid() != 0:
            print("[install] apt packages need root — re-run with sudo:", " ".join(apt_pkgs))
        else:
            print("[install] apt-get install:", " ".join(apt_pkgs))
            subprocess.run(["apt-get", "update"], check=False)
            subprocess.run(["apt-get", "install", "-y"] + apt_pkgs, check=False)
    if pip_pkgs:
        print("[install] pip install:", " ".join(pip_pkgs))
        subprocess.run(["pip", "install", "--break-system-packages"] + pip_pkgs, check=False)


def stealth_prefix(data):
    """nmap flags to randomise our own MAC when the Stealth toggle is on."""
    return ["--spoof-mac", "0"] if (data or {}).get("stealth") else []


# Tools the built-in recon/detection features actually call. The rest are
# optional TUIs launched from the toolbar — nice to have, not required.
CORE_TOOLS = {"nmap", "bluetoothctl", "sdptool", "l2ping", "iw",
              "airodump-ng", "tshark", "avahi-browse", "openssl"}


def report_dependencies():
    """Print a per-package present/missing report on every startup.

    Returns the list of missing *core* packages so the caller can warn loudly.
    """
    seen, core_rows, opt_rows, missing_core = set(), [], [], []
    for tool, (kind, pkg) in DEPENDENCIES.items():
        if pkg in seen:
            continue
        seen.add(pkg)
        ok = shutil.which(tool) is not None
        mark = "OK " if ok else "-- "
        hint = "" if ok else f"   ->  {kind} install {pkg}"
        row = f"   [{mark}] {pkg}{hint}"
        if tool in CORE_TOOLS:
            core_rows.append(row)
            if not ok:
                missing_core.append(pkg)
        else:
            opt_rows.append(row)
    print("[deps] core tools (needed for the built-in recon & detection):")
    for r in core_rows:
        print(r)
    print("[deps] optional launchers (only used if you open them from the toolbar):")
    for r in opt_rows:
        print(r)
    if missing_core:
        print("[deps] ! missing core tools:", " ".join(missing_core))
        print("[deps]   features that use them will report the gap when invoked.")
        print("[deps]   install everything:  sudo python3 app.py --install")
    else:
        print("[deps] all core tools present.")
    return missing_core


# ---------------------------------------------------------------------------
# Whitelisted interactive tools. Launched in a real terminal window.
# These are TUIs (menus / live capture), so they get their own terminal,
# not the in-browser output pane.
# ---------------------------------------------------------------------------
TOOLS = {
    "airgeddon":  {"label": "airgeddon",  "cmd": ["airgeddon"]},
    "wifite":     {"label": "wifite",     "cmd": ["wifite"]},
    "bettercap":  {"label": "bettercap",  "cmd": ["bettercap"]},
    "bluing":     {"label": "bluing",     "cmd": ["bluing"]},
    "metasploit": {"label": "metasploit", "cmd": ["msfconsole"]},
    "sqlmap":     {"label": "sqlmap",     "cmd": ["sqlmap", "--wizard"]},
    "nikto":      {"label": "nikto",      "cmd": ["nikto"]},
    "hydra":      {"label": "hydra",      "cmd": ["hydra"]},
}
# Map launch ids whose binary differs from the id (for the install check).
TOOL_BIN = {"metasploit": "msfconsole"}

# Whitelisted Bluetooth scan profiles. Each maps id -> fixed command prefix; the
# validated MAC is appended. These cover classic + BLE enumeration with BlueZ.
# "vuln" uses bluing (a dedicated BT recon/vuln tool) if installed.
BT_PROFILES = {
    "info":     {"label": "Info",     "cmd": ["bluetoothctl", "info"], "root": False},
    "services": {"label": "Services", "cmd": ["sdptool", "browse"],    "root": True},
    "ping":     {"label": "L2 Ping",  "cmd": ["l2ping", "-c", "5"],    "root": True},
    "vuln":     {"label": "Vuln",     "cmd": ["bluing", "br", "--sdp"],"root": True},
}

# Terminal emulators tried in order. Edit if yours isn't here.
TERMINAL_CANDIDATES = [
    ["x-terminal-emulator", "-e"],
    ["xterm", "-e"],
    ["qterminal", "-e"],
    ["konsole", "-e"],
    ["xfce4-terminal", "-x"],
]

HARD_TIMEOUT_SECONDS = 30 * 60
DISCOVERY_TIMEOUT_SECONDS = 180

# Passive deauth/disassoc-flood detection (listen only, never transmit).
# 802.11 mgmt subtypes: deauth = 12 (0x0c), disassoc = 10 (0x0a).
DEAUTH_FILTER = "wlan.fc.type_subtype==12 || wlan.fc.type_subtype==10"
DEAUTH_FIELDS = ["-T", "fields", "-E", "separator=,",
                 "-e", "frame.time_epoch", "-e", "wlan.fc.type_subtype",
                 "-e", "wlan.sa", "-e", "wlan.da", "-e", "wlan.bssid",
                 "-e", "wlan.fixed.reason_code"]
DEAUTH_SCAN_SECONDS = 10      # one-shot sample length
DEAUTH_FLOOD_TOTAL = 40       # one-shot: >= this many frames in the window => flood
DEAUTH_RATE_ALERT = 10        # live: >= this many frames in a 1s bucket => alert

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(raw):
    """Return cleaned target (IP / CIDR / hostname) or None."""
    if raw is None:
        return None
    t = raw.strip()
    if not t or len(t) > 255:
        return None
    try:
        ipaddress.ip_network(t, strict=False)
        return t
    except ValueError:
        pass
    return t if _HOSTNAME_RE.match(t) else None


_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def validate_mac(raw):
    """Return an uppercase MAC/BT address, or None."""
    if raw is None:
        return None
    m = raw.strip().upper()
    return m if _MAC_RE.match(m) else None


def parse_bt_devices(text):
    """Parse `bluetoothctl devices` output: lines like 'Device AA:.. Name'."""
    devs = []
    for line in (text or "").splitlines():
        mobj = re.search(r"Device\s+([0-9A-Fa-f:]{17})\s*(.*)", line)
        if mobj:
            devs.append({"mac": mobj.group(1).upper(), "name": mobj.group(2).strip() or None})
    return devs


def parse_bt_info(text):
    """Parse `bluetoothctl info MAC` into BLE recon fields."""
    info = {"type": None, "rssi": None, "name": None,
            "connected": None, "uuids": [], "manufacturer": None}
    for line in (text or "").splitlines():
        s = line.strip()
        mh = re.match(r"Device\s+[0-9A-Fa-f:]{17}\s+\((public|random)\)", s)
        if mh:
            info["type"] = mh.group(1)
            continue
        if s.startswith("Name:"):
            info["name"] = s.split(":", 1)[1].strip()
        elif s.startswith("RSSI:"):
            info["rssi"] = s.split(":", 1)[1].strip()
        elif s.startswith("Connected:"):
            info["connected"] = s.split(":", 1)[1].strip()
        elif s.startswith("UUID:"):
            mu = re.search(r"UUID:\s*(.+?)\s*\(", s)
            if mu:
                info["uuids"].append(mu.group(1).strip())
        elif s.startswith("ManufacturerData Key:"):
            info["manufacturer"] = s.split(":", 1)[1].strip()
    return info


def validate_port(raw):
    """Return an int port 1-65535, or None."""
    try:
        p = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def detect_monitor_iface():
    """Return the first wireless interface in monitor mode, or None."""
    try:
        out = subprocess.run(["iw", "dev"], stdout=subprocess.PIPE, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            iface = line.split(None, 1)[1]
        elif line.startswith("type ") and "monitor" in line and iface:
            return iface
    return None


def parse_airodump_csv(text):
    """Parse airodump-ng CSV into access points and associated clients."""
    aps, clients = [], []
    section = 0
    mac_re = re.compile(r"^[0-9A-Fa-f:]{17}$")
    for line in (text or "").splitlines():
        st = line.strip()
        if st.startswith("BSSID,"):
            section = 1
            continue
        if st.startswith("Station MAC,"):
            section = 2
            continue
        if not st:
            continue
        cols = [c.strip() for c in line.split(",")]
        if section == 1 and len(cols) >= 14 and mac_re.match(cols[0]):
            aps.append({
                "bssid": cols[0], "channel": cols[3],
                "enc": (cols[5] + " " + cols[6]).strip(),
                "power": cols[8], "beacons": cols[9], "data": cols[10],
                "essid": cols[13] or "<hidden>",
            })
        elif section == 2 and len(cols) >= 6 and mac_re.match(cols[0]):
            clients.append({
                "station": cols[0], "power": cols[3],
                "packets": cols[4], "bssid": cols[5],
            })
    return {"aps": aps, "clients": clients}


def find_terminal():
    for cand in TERMINAL_CANDIDATES:
        if shutil.which(cand[0]):
            return cand
    return None


# Networks the discovery sweep is allowed to scan. Set at startup from CLI args
# (or auto-detected). The browser can only pick from this list — it can't inject
# an arbitrary range.
SCAN_TARGETS = []

# Monitor-mode interface for Wi-Fi recon (set via --wlan-mon, or auto-detected).
WIFI_MON = None

# ---------------------------------------------------------------------------
# Passive-detection state, persisted as JSON next to this file.
#   devices : known network hosts   { mac: {first_seen,last_seen,ip,vendor,name} }
#   aps     : known Wi-Fi APs        { bssid: {essid,channel,first_seen,last_seen} }
# Used to flag *new* devices, *rogue/evil-twin* APs, and BLE advertisement floods.
# All read-only recon — nothing here transmits.
# ---------------------------------------------------------------------------
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dokkos_state.json")
STATE = {"devices": {}, "aps": {}, "events": [], "sessions": {}, "settings": {}}
STATE_LOCK = threading.Lock()
MAX_EVENTS = 300


def load_state():
    global STATE
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            STATE = {"devices": data.get("devices", {}), "aps": data.get("aps", {}),
                     "events": data.get("events", []), "sessions": data.get("sessions", {}),
                     "settings": data.get("settings", {})}
    except (OSError, ValueError):
        STATE = {"devices": {}, "aps": {}, "events": [], "sessions": {}, "settings": {}}


def save_state():
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(STATE, fh, indent=2)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass


def _now():
    return int(time.time())


def notify(message):
    """Best-effort push to a configured webhook (ntfy / Slack / Discord / generic)."""
    url = (STATE.get("settings", {}) or {}).get("webhook")
    if not url:
        return

    def _send():
        try:
            if "ntfy" in url:
                data = message.encode("utf-8")
                headers = {"Title": "DokkOS", "Content-Type": "text/plain"}
            else:
                data = json.dumps({"text": message, "content": message}).encode("utf-8")
                headers = {"Content-Type": "application/json"}
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            urllib.request.urlopen(req, timeout=6).read()
        except (OSError, ValueError):
            pass

    threading.Thread(target=_send, daemon=True).start()


_recent_log = {}


def log_event(kind, detail, level="info", persist=True, dedup_key=None, dedup_window=60):
    """Append a detection/recon event to the persistent timeline (with optional dedup)."""
    if dedup_key:
        now = time.time()
        if now - _recent_log.get(dedup_key, 0) < dedup_window:
            return None
        _recent_log[dedup_key] = now
    ev = {"ts": _now(), "kind": kind, "detail": detail, "level": level}
    with STATE_LOCK:
        STATE["events"].append(ev)
        if len(STATE["events"]) > MAX_EVENTS:
            STATE["events"] = STATE["events"][-MAX_EVENTS:]
        if persist:
            save_state()
    notify(f"[{level.upper()}] {kind}: {detail}")
    return ev




def annotate_new_devices(hosts):
    """Mark each host new/known vs the persisted store; refresh last_seen for known ones."""
    now = _now()
    with STATE_LOCK:
        dev = STATE["devices"]
        changed = False
        for h in hosts:
            mac = h.get("mac")
            if not mac:
                h["new"] = False          # no MAC -> can't track (e.g. unprivileged scan)
                h["unknown_mac"] = True
                continue
            rec = dev.get(mac)
            if rec:
                h["new"] = False
                h["first_seen"] = rec.get("first_seen")
                rec["last_seen"] = now
                rec["ip"] = h.get("ip") or rec.get("ip")
                changed = True
            else:
                h["new"] = True            # seen, but not yet acknowledged as known
        if changed:
            save_state()
    return hosts


def ack_devices(devices):
    """Add devices (list of {mac,ip,vendor,name}) to the known store."""
    now = _now()
    added = 0
    with STATE_LOCK:
        dev = STATE["devices"]
        for d in devices:
            mac = (d or {}).get("mac")
            if not mac or mac in dev:
                continue
            dev[mac] = {"first_seen": now, "last_seen": now,
                        "ip": d.get("ip"), "vendor": d.get("vendor"), "name": d.get("name")}
            added += 1
        if added:
            save_state()
    return added


def annotate_aps(aps):
    """Flag APs that are unknown, or whose SSID is broadcast by more than one BSSID
    (possible evil twin), and the channel mismatches a known baseline."""
    # intra-scan: SSID -> set of BSSIDs seen right now
    by_ssid = {}
    for ap in aps:
        by_ssid.setdefault(ap.get("essid", ""), set()).add(ap.get("bssid"))
    with STATE_LOCK:
        known = STATE["aps"]
        for ap in aps:
            bssid = ap.get("bssid")
            essid = ap.get("essid", "")
            rec = known.get(bssid)
            ap["known"] = rec is not None
            twin = essid not in ("", "<hidden>") and len(by_ssid.get(essid, set())) > 1
            # SSID we have a baseline for, but this exact BSSID isn't in it -> impostor
            baseline_bssids = {b for b, r in known.items() if r.get("essid") == essid}
            impostor = bool(baseline_bssids) and bssid not in baseline_bssids
            ap["suspicious"] = bool(twin or impostor)
            ap["reason"] = ("duplicate SSID / different BSSID" if twin
                            else ("SSID matches a known AP but BSSID is new" if impostor else ""))
            if ap["suspicious"]:
                log_event("rogue-ap", f"{essid or '<hidden>'} via {bssid} — {ap['reason']}",
                          "alert", dedup_key=f"rogueap:{bssid}", dedup_window=300)
            if rec and rec.get("channel") not in (None, "", ap.get("channel")):
                ap["channel_changed"] = True
    return aps


def ack_aps(aps):
    """Baseline the given APs (list of {bssid,essid,channel}) as trusted."""
    now = _now()
    added = 0
    with STATE_LOCK:
        known = STATE["aps"]
        for ap in aps:
            bssid = (ap or {}).get("bssid")
            if not bssid or bssid in known:
                continue
            known[bssid] = {"essid": ap.get("essid"), "channel": ap.get("channel"),
                            "first_seen": now, "last_seen": now}
            added += 1
        if added:
            save_state()
    return added


load_state()


def detect_local_networks():
    """Return CIDRs for every globally-scoped IPv4 the host is attached to."""
    nets = []
    try:
        out = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            stdout=subprocess.PIPE, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return nets
    for line in out.splitlines():
        mobj = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if not mobj:
            continue
        try:
            cidr = str(ipaddress.ip_network(mobj.group(1), strict=False))
        except ValueError:
            continue
        if cidr not in nets:
            nets.append(cidr)
    return nets


def get_scan_targets():
    """Configured targets, or a lazy auto-detect fallback if launched without."""
    if SCAN_TARGETS:
        return SCAN_TARGETS
    return detect_local_networks() or ["192.168.1.0/24"]


def parse_discovery(xml_text):
    """Parse `nmap -sn -oX -` output into a list of host dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = name = None
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            name = hn.get("name")
        if ip:
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "name": name})
    return hosts


def run_capture(cmd, timeout):
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout,
    )
    return proc.stdout, proc.stderr, proc.returncode


def _is_real_finding(txt):
    """True unless the NSE output is just a script-execution error (not a real vuln)."""
    t = (txt or "").strip()
    if "VULNERABLE" in t:
        return True
    low = t.lower()
    if t.startswith("ERROR:") or "script execution failed" in low \
       or "could not" in low or "couldn't" in low:
        return False
    return True


def parse_scan_xml(path):
    """Parse an nmap XML result into hosts with ports, services, OS, vulns."""
    out = {"hosts": []}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError, OSError):
        return out
    for h in root.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        info = {"ip": None, "name": None, "vendor": None,
                "os": None, "os_detail": None, "os_guesses": [],
                "ports": [], "vulns": []}
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                info["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                info["vendor"] = addr.get("vendor")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            info["name"] = hn.get("name")
        osnode = h.find("os")
        if osnode is not None:
            matches = osnode.findall("osmatch")
            if matches:
                best = matches[0]
                info["os"] = f'{best.get("name")} ({best.get("accuracy")}%)'
                cls = best.find("osclass")
                if cls is None:
                    cls = osnode.find("osclass")
                if cls is not None:
                    bits = []
                    for attr, lbl in (("type", "type"), ("vendor", "vendor"),
                                      ("osfamily", "family"), ("osgen", "gen")):
                        if cls.get(attr):
                            bits.append(f"{lbl} {cls.get(attr)}")
                    info["os_detail"] = " · ".join(bits) or None
                try:
                    top_acc = int(best.get("accuracy", "0"))
                except ValueError:
                    top_acc = 0
                if len(matches) > 1 and top_acc < 97:
                    info["os_guesses"] = [
                        f'{mm.get("name")} ({mm.get("accuracy")}%)'
                        for mm in matches[1:4]
                    ]
        for p in h.findall("ports/port"):
            pst = p.find("state")
            if pst is None or pst.get("state") != "open":
                continue
            svc = p.find("service")
            product = ""
            if svc is not None:
                product = " ".join(filter(None, [svc.get("product"),
                                                 svc.get("version")])).strip()
            info["ports"].append({
                "port": p.get("portid"), "proto": p.get("protocol"),
                "service": (svc.get("name") if svc is not None else ""),
                "product": product,
            })
            for sc in p.findall("script"):
                sid, txt = sc.get("id", ""), (sc.get("output") or "")
                if ("vuln" in sid or "VULNERABLE" in txt) and _is_real_finding(txt):
                    info["vulns"].append((f'{p.get("portid")}/{sid}', txt.strip()))
        for sc in h.findall("hostscript/script"):
            sid, txt = sc.get("id", ""), (sc.get("output") or "")
            if ("vuln" in sid or "VULNERABLE" in txt) and _is_real_finding(txt):
                info["vulns"].append((sid, txt.strip()))
        out["hosts"].append(info)
    return out


def format_summary(path):
    data = parse_scan_xml(path)
    if not data["hosts"]:
        return "\n[no summary — host appears down or scan was interrupted]\n"
    lines = ["", "=" * 50, "SUMMARY", "=" * 50]
    for h in data["hosts"]:
        dev = h["ip"] or "?"
        if h["name"]:
            dev += f"  {h['name']}"
        if h["vendor"]:
            dev += f"  ({h['vendor']})"
        lines.append(f"DEVICE   {dev}")
        if h["os"]:
            lines.append(f"OS       {h['os']}")
            if h.get("os_detail"):
                lines.append(f"         {h['os_detail']}")
            for g in h.get("os_guesses", []):
                lines.append(f"  guess: {g}")
        else:
            lines.append("OS       undetermined "
                         "(needs root + an open & a closed port; try OS Detect)")
        lines.append(f"OPEN PORTS ({len(h['ports'])})")
        if h["ports"]:
            for p in h["ports"]:
                svc = p["service"] or "?"
                prod = f"  {p['product']}" if p["product"] else ""
                lines.append(f"  {p['port'] + '/' + p['proto']:<10} {svc:<14}{prod}")
        else:
            lines.append("  (none open)")
        lines.append(f"VULNERABILITIES ({len(h['vulns'])})")
        if h["vulns"]:
            for vid, vtxt in h["vulns"]:
                lines.append(f"  [{vid}]")
                for vl in vtxt.splitlines()[:8]:
                    if vl.strip():
                        lines.append("    " + vl.strip())
        else:
            lines.append("  (none reported by NSE vuln scripts)")

        # CVE enrichment: pull every CVE id out of the vuln/vulners output,
        # keep the highest CVSS score seen for each, and list them sorted.
        cves = {}
        cve_line = re.compile(r"(CVE-\d{4}-\d{3,7})(?:\s+(\d{1,2}\.\d))?")
        for _, vtxt in h["vulns"]:
            for cm in cve_line.finditer(vtxt):
                cid, score = cm.group(1), cm.group(2)
                prev = cves.get(cid)
                if score and (prev is None or float(score) > float(prev)):
                    cves[cid] = score
                elif cid not in cves:
                    cves[cid] = prev
        if cves:
            ordered = sorted(cves.items(), key=lambda kv: float(kv[1]) if kv[1] else -1, reverse=True)
            lines.append(f"CVES ({len(ordered)})")
            for cid, score in ordered[:20]:
                lines.append(f"  {cid}" + (f"   CVSS {score}" if score else ""))
            if len(ordered) > 20:
                lines.append(f"  … and {len(ordered) - 20} more")
        lines.append("")
    return "\n".join(lines) + "\n"


def stream_scan(args, target):
    """Run an nmap scan: stream live verbose output, then a parsed summary."""
    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="dokkos_")
    os.close(fd)
    base = ["nmap"] + args + ["--stats-every", "6s", "-oX", xml_path, target]
    # stdbuf forces line-buffered output so the stream updates live instead of
    # arriving in one block when nmap finishes. --stats-every adds a heartbeat.
    cmd = (["stdbuf", "-oL", "-eL"] + base) if shutil.which("stdbuf") else base
    proc = None
    try:
        yield f"$ {' '.join(cmd)}\n\n"
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
        timer.start()
        try:
            for line in iter(proc.stdout.readline, ""):
                yield line
            proc.wait()
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
        yield f"\n[exit code {proc.returncode}]\n"
        yield format_summary(xml_path)
    finally:
        # Runs on normal completion AND on client disconnect (GeneratorExit):
        # never leave the scan process or its temp file behind.
        if proc is not None and proc.poll() is None:
            proc.kill()
        try:
            os.remove(xml_path)
        except OSError:
            pass


def stream_proc(cmd):
    """Stream any command's combined output line-by-line (no summary)."""
    line_buffered = (["stdbuf", "-oL", "-eL"] + cmd) if shutil.which("stdbuf") else cmd
    yield f"$ {' '.join(cmd)}\n\n"
    proc = subprocess.Popen(
        line_buffered, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
    timer.start()
    try:
        for line in iter(proc.stdout.readline, ""):
            yield line
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
    yield f"\n[exit code {proc.returncode}]\n"


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.route("/api/config")
def api_config():
    return jsonify(targets=get_scan_targets(), wlan_mon=WIFI_MON or detect_monitor_iface())


@app.route("/api/discover", methods=["POST"])
def api_discover():
    if shutil.which("nmap") is None:
        return jsonify(error="nmap is not installed"), 500
    targets = get_scan_targets()
    scope = (request.get_json(silent=True) or {}).get("scope", "all")
    if scope == "all":
        chosen = targets
    elif scope in targets:
        chosen = [scope]
    else:
        return jsonify(error="scope not in the configured target list"), 400
    try:
        out, _, _ = run_capture(
            ["nmap", "-sn"] + stealth_prefix(request.get_json(silent=True))
            + ["-oX", "-"] + chosen,
            DISCOVERY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return jsonify(error="discovery timed out"), 504
    hosts = parse_discovery(out)
    hosts = annotate_new_devices(hosts)
    new_count = sum(1 for h in hosts if h.get("new"))
    return jsonify(hosts=hosts, count=len(hosts), new_count=new_count,
                   scope=scope, scanned=chosen)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan")
    target = validate_target(data.get("target"))
    if scan_id not in SCAN_PROFILES:
        return Response("[error] unknown scan profile\n", mimetype="text/plain", status=400)
    if target is None:
        return Response("[error] no valid target selected\n", mimetype="text/plain", status=400)
    if shutil.which("nmap") is None:
        return Response("[error] nmap is not installed\n", mimetype="text/plain", status=500)
    cmd_args = stealth_prefix(data) + SCAN_PROFILES[scan_id]["args"]
    return Response(stream_with_context(stream_scan(cmd_args, target)), mimetype="text/plain")


@app.route("/api/settings", methods=["POST"])
def api_settings():
    global WIFI_MON
    data = request.get_json(silent=True) or {}
    if "wlan_mon" in data:
        v = (data.get("wlan_mon") or "").strip()
        if v == "":
            WIFI_MON = None
        elif re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", v):
            WIFI_MON = v
        else:
            return jsonify(error="invalid interface name"), 400
    if "webhook" in data:
        wh = (data.get("webhook") or "").strip()
        if wh and not re.match(r"^https?://", wh):
            return jsonify(error="webhook must be an http(s) URL"), 400
        with STATE_LOCK:
            STATE["settings"]["webhook"] = wh or None
            save_state()
    if "monitor_interval" in data:
        try:
            iv = max(30, min(3600, int(data.get("monitor_interval"))))
            with STATE_LOCK:
                STATE["settings"]["monitor_interval"] = iv
                save_state()
        except (TypeError, ValueError):
            return jsonify(error="bad interval"), 400
    return jsonify(ok=True, wlan_mon=WIFI_MON,
                   webhook=STATE["settings"].get("webhook"),
                   monitor_interval=STATE["settings"].get("monitor_interval", 120))


@app.route("/api/bt_discover", methods=["POST"])
def api_bt_discover():
    if shutil.which("bluetoothctl") is None:
        return jsonify(error="bluetoothctl (BlueZ) is not installed"), 500
    try:
        # timed scan, then dump what was discovered
        subprocess.run(["bluetoothctl", "--timeout", "12", "scan", "on"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=25)
        out, _, _ = run_capture(["bluetoothctl", "devices"], 10)
    except subprocess.TimeoutExpired:
        return jsonify(error="bluetooth scan timed out"), 504
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"bluetooth scan failed: {e}"), 500
    devices = parse_bt_devices(out)
    # BLE recon enrichment: pull address type, RSSI, service UUIDs and the
    # manufacturer/company id for each device (best-effort, capped, read-only).
    for dev in devices[:15]:
        try:
            info_out, _, _ = run_capture(["bluetoothctl", "info", dev["mac"]], 6)
            info = parse_bt_info(info_out)
            dev["type"] = info["type"]
            dev["rssi"] = info["rssi"]
            dev["services"] = len(info["uuids"])
            dev["uuids"] = info["uuids"][:6]
            dev["manufacturer"] = info["manufacturer"]
        except (OSError, subprocess.SubprocessError):
            pass
    return jsonify(devices=devices, count=len(devices))


@app.route("/api/bt_discover_stream", methods=["POST"])
def api_bt_discover_stream():
    if shutil.which("bluetoothctl") is None:
        return Response("[error] bluetoothctl (BlueZ) is not installed\n",
                        mimetype="text/plain", status=500)

    def gen():
        yield "$ bluetoothctl --timeout 12 scan on\n"
        yield "  controller in discovery, enumerating classic + BLE…\n\n"
        try:
            subprocess.run(["bluetoothctl", "--timeout", "12", "scan", "on"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=25)
            devs_out, _, _ = run_capture(["bluetoothctl", "devices"], 10)
        except subprocess.TimeoutExpired:
            yield "[error] bluetooth scan timed out\n"
            return
        except (OSError, subprocess.SubprocessError) as e:
            yield f"[error] bluetooth scan failed: {e}\n"
            return
        devices = parse_bt_devices(devs_out)
        yield f"discovered {len(devices)} device(s); pulling BLE recon…\n\n"
        for dev in devices[:15]:
            yield f"• {dev.get('name') or dev['mac']}\n"
            try:
                info_out, _, _ = run_capture(["bluetoothctl", "info", dev["mac"]], 6)
                info = parse_bt_info(info_out)
                dev["type"] = info["type"]
                dev["rssi"] = info["rssi"]
                dev["services"] = len(info["uuids"])
                dev["uuids"] = info["uuids"][:6]
                dev["manufacturer"] = info["manufacturer"]
                yield f"    addr   {dev['mac']}{('  ['+info['type']+']') if info['type'] else ''}\n"
                if info["rssi"]:
                    yield f"    rssi   {info['rssi']} dBm\n"
                yield (f"    svcs   {len(info['uuids'])}"
                       f"{('  ('+', '.join(info['uuids'][:4])+')') if info['uuids'] else ''}\n")
                if info["manufacturer"]:
                    yield f"    mfr    {info['manufacturer']}\n"
            except (OSError, subprocess.SubprocessError):
                yield f"    addr   {dev['mac']}  (info unavailable)\n"
            yield "\n"
        yield f"found {len(devices)} bluetooth device(s).\n"
        yield "@@DEVICES@@" + json.dumps(devices) + "\n"

    return Response(stream_with_context(gen()), mimetype="text/plain")


@app.route("/api/bt_scan", methods=["POST"])
def api_bt_scan():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan")
    mac = validate_mac(data.get("target"))
    if scan_id not in BT_PROFILES:
        return Response("[error] unknown bluetooth profile\n", mimetype="text/plain", status=400)
    if mac is None:
        return Response("[error] invalid bluetooth address (need AA:BB:CC:DD:EE:FF)\n",
                        mimetype="text/plain", status=400)
    prof = BT_PROFILES[scan_id]
    if shutil.which(prof["cmd"][0]) is None:
        return Response(
            f"[error] {prof['cmd'][0]} is not installed — needed for the {prof['label']} "
            f"profile.\n  classic/BLE tools live in the bluez package; "
            f"'bluing' (for Vuln) is a separate install.\n",
            mimetype="text/plain", status=500)
    cmd = prof["cmd"] + [mac]
    return Response(stream_with_context(stream_proc(cmd)), mimetype="text/plain")


@app.route("/api/port_scan", methods=["POST"])
def api_port_scan():
    data = request.get_json(silent=True) or {}
    target = validate_target(data.get("target"))
    port = validate_port(data.get("port"))
    if target is None:
        return Response("[error] no valid target\n", mimetype="text/plain", status=400)
    if port is None:
        return Response("[error] invalid port\n", mimetype="text/plain", status=400)
    if shutil.which("nmap") is None:
        return Response("[error] nmap is not installed\n", mimetype="text/plain", status=500)
    # Service-aware: the browser sends the detected service name; we map it to a
    # fixed NSE script set (no arbitrary scripts can be passed). Unknown -> generic.
    service = (data.get("service") or "").strip().lower()
    scripts = SERVICE_SCRIPTS.get(service, DEFAULT_PORT_SCRIPTS)
    args = stealth_prefix(data) + ["-v", "-sV", "-p", str(port), "--script", scripts, "-T4"]
    return Response(stream_with_context(stream_scan(args, target)), mimetype="text/plain")


@app.route("/api/wifi_scan", methods=["POST"])
def api_wifi_scan():
    if shutil.which("airodump-ng") is None:
        return jsonify(error="airodump-ng (aircrack-ng) is not installed"), 500
    iface = WIFI_MON or detect_monitor_iface()
    if not iface:
        return jsonify(error="no monitor interface — run 'sudo airmon-ng start wlan0' "
                             "then relaunch with --wlan-mon wlan0mon"), 400
    tmpdir = tempfile.mkdtemp(prefix="dokkos_wifi_")
    prefix = os.path.join(tmpdir, "cap")
    try:
        try:
            subprocess.run(
                ["timeout", "14", "airodump-ng", "--output-format", "csv",
                 "--write-interval", "1", "--write", prefix, iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25,
            )
        except subprocess.TimeoutExpired:
            pass
        except (OSError, subprocess.SubprocessError) as e:
            return jsonify(error=f"airodump failed: {e}"), 500
        csvs = sorted(glob.glob(prefix + "*.csv"))
        text = ""
        if csvs:
            try:
                with open(csvs[-1], encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    parsed = parse_airodump_csv(text)
    parsed["aps"] = annotate_aps(parsed["aps"])
    suspicious = sum(1 for a in parsed["aps"] if a.get("suspicious"))
    return jsonify(iface=iface, count=len(parsed["aps"]),
                   suspicious=suspicious, **parsed)


@app.route("/api/devices/ack", methods=["POST"])
def api_devices_ack():
    devices = (request.get_json(silent=True) or {}).get("devices") or []
    if not isinstance(devices, list):
        return jsonify(error="bad payload"), 400
    added = ack_devices(devices)
    return jsonify(ok=True, added=added, known=len(STATE["devices"]))


@app.route("/api/aps/ack", methods=["POST"])
def api_aps_ack():
    aps = (request.get_json(silent=True) or {}).get("aps") or []
    if not isinstance(aps, list):
        return jsonify(error="bad payload"), 400
    added = ack_aps(aps)
    return jsonify(ok=True, added=added, known=len(STATE["aps"]))


@app.route("/api/state/reset", methods=["POST"])
def api_state_reset():
    what = (request.get_json(silent=True) or {}).get("what", "all")
    with STATE_LOCK:
        if what in ("all", "devices"):
            STATE["devices"] = {}
        if what in ("all", "aps"):
            STATE["aps"] = {}
        save_state()
    return jsonify(ok=True, devices=len(STATE["devices"]), aps=len(STATE["aps"]))


def _deauth_iface_or_error():
    if shutil.which("tshark") is None:
        return None, (jsonify(error="tshark (wireshark-cli) is not installed"), 500)
    iface = WIFI_MON or detect_monitor_iface()
    if not iface:
        return None, (jsonify(error="no monitor interface — run 'sudo airmon-ng start wlan0' "
                              "then relaunch with --wlan-mon wlan0mon"), 400)
    return iface, None


def _top(d, n=3):
    return sorted(d.items(), key=lambda kv: -kv[1])[:n]


@app.route("/api/deauth_scan", methods=["POST"])
def api_deauth_scan():
    """One-shot: sample ~10s of 802.11 mgmt frames and report any deauth flood."""
    iface, err = _deauth_iface_or_error()
    if err:
        return err
    dur = DEAUTH_SCAN_SECONDS
    cmd = (["tshark", "-i", iface, "-a", f"duration:{dur}", "-n", "-l",
            "-Y", DEAUTH_FILTER] + DEAUTH_FIELDS)
    try:
        out, _, _ = run_capture(cmd, dur + 20)
    except subprocess.TimeoutExpired:
        return jsonify(error="capture timed out"), 504
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"tshark failed: {e}"), 500
    deauth = disassoc = 0
    srcs, bssids, reasons = {}, {}, {}
    for line in out.splitlines():
        c = line.split(",")
        if len(c) < 2:
            continue
        st = c[1].strip()
        if st == "12":
            deauth += 1
        elif st == "10":
            disassoc += 1
        else:
            continue
        sa = (c[2] if len(c) > 2 else "").strip()
        bssid = (c[4] if len(c) > 4 else "").strip()
        rc = (c[5] if len(c) > 5 else "").strip()
        if sa:
            srcs[sa] = srcs.get(sa, 0) + 1
        if bssid:
            bssids[bssid] = bssids.get(bssid, 0) + 1
        if rc:
            reasons[rc] = reasons.get(rc, 0) + 1
    total = deauth + disassoc
    if total >= DEAUTH_FLOOD_TOTAL:
        top = _top(srcs, 1)
        src = top[0][0] if top else "?"
        log_event("deauth-flood", f"{total} frames in {dur}s (src {src})", "alert",
                  dedup_key="deauth", dedup_window=30)
    return jsonify(iface=iface, seconds=dur, deauth=deauth, disassoc=disassoc,
                   total=total, rate=round(total / dur, 1),
                   flood=total >= DEAUTH_FLOOD_TOTAL,
                   top_sources=_top(srcs), top_bssids=_top(bssids), reasons=_top(reasons))


@app.route("/api/deauth_monitor", methods=["POST"])
def api_deauth_monitor():
    """Live: stream a per-second deauth/disassoc rate and flag floods until stopped."""
    iface, err = _deauth_iface_or_error()
    if err:
        return err
    cmd = ["tshark", "-i", iface, "-n", "-l", "-Y", DEAUTH_FILTER] + DEAUTH_FIELDS

    def gen():
        yield f"$ tshark -i {iface}   (passive deauth / disassoc watch)\n"
        yield "  listening for 802.11 management floods — tap Abort to stop.\n\n"
        lb = (["stdbuf", "-oL", "-eL"] + cmd) if shutil.which("stdbuf") else cmd
        try:
            proc = subprocess.Popen(lb, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except (OSError, subprocess.SubprocessError) as e:
            yield f"[error] tshark failed: {e}\n"
            return
        timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
        timer.start()
        bucket = int(time.time())
        cnt = total = da = di = 0
        last_src = ""
        alerted = False
        try:
            for line in iter(proc.stdout.readline, ""):
                c = line.split(",")
                if len(c) < 2:
                    continue
                st = c[1].strip()
                if st not in ("12", "10"):
                    continue
                now = int(time.time())
                if now != bucket:
                    if cnt:
                        stamp = time.strftime("%H:%M:%S", time.localtime(bucket))
                        yield f"  {stamp}   {cnt} frame/s" + (f"   src {last_src}" if last_src else "") + "\n"
                    bucket, cnt, alerted = now, 0, False
                cnt += 1
                total += 1
                if st == "12":
                    da += 1
                else:
                    di += 1
                last_src = (c[2] if len(c) > 2 else "").strip()
                if cnt >= DEAUTH_RATE_ALERT and not alerted:
                    alerted = True
                    src = f" — src {last_src}" if last_src else ""
                    yield f"@@ALERT@@deauth flood: {cnt}+ frames/sec{src}\n"
                    log_event("deauth-flood", f"{cnt}+ frames/sec{src}", "alert",
                              dedup_key="deauth", dedup_window=30)
            proc.wait()
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
        yield f"\n[stopped] {total} mgmt frames ({da} deauth, {di} disassoc)\n"

    return Response(stream_with_context(gen()), mimetype="text/plain")


# ---------------------------------------------------------------------------
# Extra recon: HTTP banners, mDNS/SSDP, BLE GATT, probe-request listen, RSSI hunt
# ---------------------------------------------------------------------------
def _grab_banner(host, port, tls, timeout=4):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "DokkOS-recon", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(20000).decode("utf-8", "replace")
        conn.close()
        title = None
        mt = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if mt:
            title = re.sub(r"\s+", " ", mt.group(1)).strip()[:140]
        return {"port": port, "scheme": "https" if tls else "http", "status": resp.status,
                "server": resp.getheader("Server"), "title": title,
                "location": resp.getheader("Location")}
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None


@app.route("/api/http_banner", methods=["POST"])
def api_http_banner():
    data = request.get_json(silent=True) or {}
    target = validate_target(data.get("target"))
    if target is None or "/" in target:
        return jsonify(error="need a single host (IP or hostname)"), 400
    results = []
    ports = data.get("ports")
    if isinstance(ports, list) and ports:
        for p in ports:
            if isinstance(p, dict):
                pn = validate_port(p.get("port"))
                svc = (p.get("service") or "").lower()
                tls = "https" in svc or "ssl" in svc or pn in (443, 8443)
            else:
                pn = validate_port(p)
                tls = pn in (443, 8443)
            if not pn:
                continue
            r = _grab_banner(target, pn, tls)
            if r is None and not tls:          # maybe it's actually TLS
                r = _grab_banner(target, pn, True)
            if r:
                results.append(r)
    else:
        for pn in (80, 8080, 8000, 8888):
            r = _grab_banner(target, pn, False)
            if r:
                results.append(r)
        for pn in (443, 8443):
            r = _grab_banner(target, pn, True)
            if r:
                results.append(r)
    return jsonify(target=target, count=len(results), services=results)


def _mdns_browse(timeout=5):
    if shutil.which("avahi-browse") is None:
        return []
    try:
        out, _, _ = run_capture(["avahi-browse", "-a", "-t", "-r", "-p", "-l"], timeout)
    except (OSError, subprocess.SubprocessError):
        return []
    svcs = []
    for line in out.splitlines():
        if not line.startswith("="):
            continue
        f = line.split(";")
        if len(f) < 9:
            continue
        svcs.append({"name": f[3], "type": f[4], "host": f[6],
                     "address": f[7], "port": f[8]})
    return svcs


def _ssdp_search(timeout=3):
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    devices = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            hdr = {}
            for ln in data.decode("utf-8", "replace").split("\r\n"):
                if ":" in ln:
                    k, _, v = ln.partition(":")
                    hdr[k.strip().upper()] = v.strip()
            d = devices.setdefault(addr[0], {"address": addr[0],
                                             "server": hdr.get("SERVER"),
                                             "location": hdr.get("LOCATION"), "st": set()})
            if hdr.get("ST"):
                d["st"].add(hdr["ST"])
        s.close()
    except OSError:
        pass
    return [{"address": ip, "server": d["server"], "location": d["location"],
             "st": sorted(d["st"])[:6]} for ip, d in devices.items()]


@app.route("/api/mdns", methods=["POST"])
def api_mdns():
    target = (request.get_json(silent=True) or {}).get("target")
    if target is not None:
        target = validate_target(target)
    mdns = _mdns_browse()
    ssdp = _ssdp_search()
    if target:
        mdns = [m for m in mdns if m.get("address") == target]
        ssdp = [s for s in ssdp if s.get("address") == target]
    return jsonify(mdns=mdns, ssdp=ssdp, mdns_count=len(mdns), ssdp_count=len(ssdp))


@app.route("/api/ble_gatt", methods=["POST"])
def api_ble_gatt():
    """Read-only GATT enumeration of one BLE device via bluetoothctl."""
    mac = validate_mac((request.get_json(silent=True) or {}).get("target"))
    if mac is None:
        return jsonify(error="invalid bluetooth address"), 400
    if shutil.which("bluetoothctl") is None:
        return jsonify(error="bluetoothctl (bluez) is not installed"), 500
    try:
        proc = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        proc.stdin.write(f"connect {mac}\n")
        proc.stdin.flush()
        time.sleep(6)                       # allow connect + service resolution
        proc.stdin.write(f"gatt.list-attributes {mac}\n")
        proc.stdin.flush()
        time.sleep(3)
        proc.stdin.write(f"disconnect {mac}\n")
        proc.stdin.flush()
        time.sleep(1)
        proc.stdin.write("quit\n")
        proc.stdin.flush()
        out, _ = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"bluetoothctl failed: {e}"), 500
    connected = "Connection successful" in out or "Connected: yes" in out
    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    attrs, kind = [], None
    lines = out.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        low = s.lower()
        if "primary service" in low or "secondary service" in low:
            kind = "service"
        elif low.startswith("characteristic"):
            kind = "characteristic"
        elif low.startswith("descriptor"):
            kind = "descriptor"
        elif uuid_re.match(s) and kind:
            name = lines[i + 1].strip() if i + 1 < len(lines) else ""
            if uuid_re.match(name) or name.startswith("/org/bluez"):
                name = ""
            attrs.append({"kind": kind, "uuid": s.lower(), "name": name})
    return jsonify(target=mac, connected=connected, count=len(attrs), attributes=attrs)


@app.route("/api/probe_listen", methods=["POST"])
def api_probe_listen():
    """Stream probe-request SSIDs nearby devices are searching for (passive)."""
    iface, err = _deauth_iface_or_error()
    if err:
        return err
    cmd = (["tshark", "-i", iface, "-n", "-l", "-Y", "wlan.fc.type_subtype==4",
            "-T", "fields", "-E", "separator=,", "-e", "wlan.sa", "-e", "wlan.ssid"])

    def gen():
        yield f"$ tshark -i {iface}   (passive probe-request listen)\n"
        yield "  SSIDs nearby devices are looking for — tap Abort to stop.\n\n"
        lb = (["stdbuf", "-oL", "-eL"] + cmd) if shutil.which("stdbuf") else cmd
        try:
            proc = subprocess.Popen(lb, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except (OSError, subprocess.SubprocessError) as e:
            yield f"[error] tshark failed: {e}\n"
            return
        timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
        timer.start()
        seen = set()
        try:
            for line in iter(proc.stdout.readline, ""):
                sa, _, ssid = line.strip().partition(",")
                ssid = ssid.strip()
                if not ssid:                 # broadcast/wildcard probe
                    continue
                key = (sa, ssid)
                if key in seen:
                    continue
                seen.add(key)
                yield f"  {sa}  →  \"{ssid}\"\n"
            proc.wait()
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
        yield f"\n[stopped] {len(seen)} device/SSID pair(s) observed\n"

    return Response(stream_with_context(gen()), mimetype="text/plain")


@app.route("/api/hunt", methods=["POST"])
def api_hunt():
    """Stream live RSSI for one target so it can be physically located."""
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    if kind == "bt":
        mac = validate_mac(data.get("target"))
        if mac is None:
            return jsonify(error="invalid bluetooth address"), 400
        if shutil.which("bluetoothctl") is None:
            return Response("[error] bluetoothctl not installed\n", mimetype="text/plain", status=500)

        def gen_bt():
            yield f"$ bluetoothctl scan on   (RSSI hunt: {mac})\n  walk toward the strongest signal — tap Abort to stop.\n\n"
            try:
                proc = subprocess.Popen(["bluetoothctl"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, bufsize=1)
                proc.stdin.write("scan on\n")
                proc.stdin.flush()
            except (OSError, subprocess.SubprocessError) as e:
                yield f"[error] {e}\n"
                return
            timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
            timer.start()
            target = mac.lower()
            try:
                for line in iter(proc.stdout.readline, ""):
                    low = line.lower()
                    if target in low and "rssi" in low:
                        mt = re.search(r"rssi:?\s*(-?\d+)", low)
                        if mt:
                            yield f"@@RSSI@@{mt.group(1)}\n"
            finally:
                timer.cancel()
                try:
                    proc.stdin.write("scan off\nquit\n")
                    proc.stdin.flush()
                except (OSError, ValueError):
                    pass
                if proc.poll() is None:
                    proc.kill()
            yield "\n[stopped]\n"

        return Response(stream_with_context(gen_bt()), mimetype="text/plain")

    # Wi-Fi RSSI hunt (AP beacon or station frames)
    iface, err = _deauth_iface_or_error()
    if err:
        return err
    mac = validate_mac(data.get("target"))
    if mac is None:
        return Response("[error] invalid BSSID/station MAC\n", mimetype="text/plain", status=400)
    sta = data.get("station") is True
    flt = (f"wlan.sa=={mac}" if sta else f"wlan.bssid=={mac} && wlan.fc.type_subtype==8")
    cmd = ["tshark", "-i", iface, "-n", "-l", "-Y", flt,
           "-T", "fields", "-e", "radiotap.dbm_antsignal"]

    def gen_wifi():
        yield f"$ tshark -i {iface}   (RSSI hunt: {mac})\n  walk toward the strongest signal — tap Abort to stop.\n\n"
        lb = (["stdbuf", "-oL", "-eL"] + cmd) if shutil.which("stdbuf") else cmd
        try:
            proc = subprocess.Popen(lb, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except (OSError, subprocess.SubprocessError) as e:
            yield f"[error] {e}\n"
            return
        timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
        timer.start()
        try:
            for line in iter(proc.stdout.readline, ""):
                v = line.strip().split(",")[0].strip()
                mt = re.search(r"-?\d+", v)
                if mt:
                    yield f"@@RSSI@@{mt.group(0)}\n"
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
        yield "\n[stopped]\n"

    return Response(stream_with_context(gen_wifi()), mimetype="text/plain")


def _lan_iface():
    try:
        out, _, _ = run_capture(["ip", "route"], 5)
        m = re.search(r"default via \S+ dev (\S+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def _gateway_ip():
    try:
        out, _, _ = run_capture(["ip", "route"], 5)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


@app.route("/api/arp_scan", methods=["POST"])
def api_arp_scan():
    """Passively watch ARP replies and flag one IP claimed by multiple MACs (spoofing)."""
    if shutil.which("tshark") is None:
        return jsonify(error="tshark is not installed"), 500
    iface = _lan_iface()
    if not iface:
        return jsonify(error="no active LAN interface found"), 400
    cmd = ["tshark", "-i", iface, "-a", "duration:8", "-n", "-l",
           "-Y", "arp.opcode==2", "-T", "fields", "-E", "separator=,",
           "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac"]
    try:
        out, _, _ = run_capture(cmd, 25)
    except subprocess.TimeoutExpired:
        return jsonify(error="capture timed out"), 504
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"tshark failed: {e}"), 500
    ip2mac = {}
    for line in out.splitlines():
        ip, _, mac = line.strip().partition(",")
        if ip and mac:
            ip2mac.setdefault(ip, set()).add(mac.lower())
    conflicts = [{"ip": ip, "macs": sorted(macs)} for ip, macs in ip2mac.items() if len(macs) > 1]
    gw = _gateway_ip()
    gw_macs = sorted(ip2mac.get(gw, []))
    spoof = bool(conflicts)
    if spoof:
        worst = conflicts[0]
        log_event("arp-spoof", f"{worst['ip']} claimed by {len(worst['macs'])} MACs", "alert",
                  dedup_key="arpspoof", dedup_window=120)
    return jsonify(iface=iface, gateway=gw, gateway_macs=gw_macs,
                   conflicts=conflicts, spoof=spoof, seen=len(ip2mac))


@app.route("/api/dhcp_scan", methods=["POST"])
def api_dhcp_scan():
    """Discover DHCP servers (broadcast) and flag any that aren't the gateway."""
    if shutil.which("nmap") is None:
        return jsonify(error="nmap is not installed"), 500
    try:
        out, _, _ = run_capture(["nmap", "--script", "broadcast-dhcp-discover"], 45)
    except subprocess.TimeoutExpired:
        return jsonify(error="dhcp discovery timed out"), 504
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"nmap failed: {e}"), 500
    servers = sorted(set(re.findall(r"Server Identifier:\s*(\d+\.\d+\.\d+\.\d+)", out)))
    gw = _gateway_ip()
    rogue = [s for s in servers if s != gw]
    if rogue:
        log_event("rogue-dhcp", f"unexpected DHCP server(s): {', '.join(rogue)}", "alert",
                  dedup_key="roguedhcp", dedup_window=600)
    return jsonify(gateway=gw, servers=servers, rogue=rogue, count=len(servers))


def _tls_cert(host, port, timeout=8):
    if shutil.which("openssl") is None:
        return None
    try:
        p = subprocess.run(["openssl", "s_client", "-connect", f"{host}:{port}",
                            "-servername", host],
                           input="", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    mt = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", p.stdout, re.S)
    if not mt:
        return None
    pem = mt.group(0)
    try:
        x = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer",
                            "-startdate", "-enddate", "-ext", "subjectAltName"],
                           input=pem, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    o = x.stdout

    def g(pat):
        mm = re.search(pat, o)
        return mm.group(1).strip() if mm else None

    subject, issuer = g(r"subject=(.*)"), g(r"issuer=(.*)")
    notafter = g(r"notAfter=(.*)")
    san_m = re.search(r"Subject Alternative Name:\s*\n?\s*(.+)", o)
    expired = None
    if notafter:
        try:
            import datetime
            dt = datetime.datetime.strptime(notafter, "%b %d %H:%M:%S %Y %Z")
            expired = dt < datetime.datetime.utcnow()
        except ValueError:
            pass
    return {"port": port, "subject": subject, "issuer": issuer,
            "not_before": g(r"notBefore=(.*)"), "not_after": notafter,
            "san": san_m.group(1).strip()[:200] if san_m else None,
            "self_signed": bool(subject and subject == issuer), "expired": expired}


@app.route("/api/tls_cert", methods=["POST"])
def api_tls_cert():
    data = request.get_json(silent=True) or {}
    target = validate_target(data.get("target"))
    if target is None or "/" in target:
        return jsonify(error="need a single host"), 400
    ports = data.get("ports") or [443, 8443]
    certs = []
    for p in ports:
        pn = validate_port(p if not isinstance(p, dict) else p.get("port"))
        if not pn:
            continue
        c = _tls_cert(target, pn)
        if c:
            certs.append(c)
    return jsonify(target=target, count=len(certs), certs=certs)


@app.route("/api/pcap", methods=["POST"])
def api_pcap():
    """Capture N seconds to a pcap the user can open in Wireshark."""
    if shutil.which("tshark") is None:
        return jsonify(error="tshark is not installed"), 500
    data = request.get_json(silent=True) or {}
    try:
        secs = max(3, min(60, int(data.get("seconds", 10))))
    except (TypeError, ValueError):
        secs = 10
    iface = WIFI_MON or detect_monitor_iface() or _lan_iface()
    if not iface:
        return jsonify(error="no capture interface available"), 400
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="dokkos_")
    os.close(fd)
    try:
        subprocess.run(["tshark", "-i", iface, "-a", f"duration:{secs}", "-w", path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=secs + 20)
        with open(path, "rb") as fh:
            blob = fh.read()
    except subprocess.TimeoutExpired:
        return jsonify(error="capture timed out"), 504
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"capture failed: {e}"), 500
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return Response(blob, mimetype="application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition": "attachment; filename=dokkos_capture.pcap"})


def _intify(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


@app.route("/api/events", methods=["GET"])
def api_events():
    with STATE_LOCK:
        evs = list(STATE["events"])
    return jsonify(events=list(reversed(evs)), count=len(evs))


@app.route("/api/events/clear", methods=["POST"])
def api_events_clear():
    with STATE_LOCK:
        STATE["events"] = []
        save_state()
    return jsonify(ok=True)


@app.route("/api/session/save", methods=["POST"])
def api_session_save():
    sess = (request.get_json(silent=True) or {}).get("session") or {}
    if not isinstance(sess, dict):
        return jsonify(error="bad session"), 400
    with STATE_LOCK:
        STATE["sessions"]["snapshot"] = sess
        STATE["sessions"]["saved_ts"] = _now()
        save_state()
    return jsonify(ok=True, hosts=len(sess), saved_ts=STATE["sessions"]["saved_ts"])


@app.route("/api/session/diff", methods=["POST"])
def api_session_diff():
    sess = (request.get_json(silent=True) or {}).get("session") or {}
    snap = STATE["sessions"].get("snapshot", {})
    diffs = []
    for addr, rec in sess.items():
        old = snap.get(addr)
        now_ports = set(rec.get("ports") or [])
        if not old:
            diffs.append({"addr": addr, "status": "new-host",
                          "added_ports": sorted(now_ports), "removed_ports": [],
                          "cve_delta": _intify(rec.get("cves"))})
            continue
        old_ports = set(old.get("ports") or [])
        added, removed = sorted(now_ports - old_ports), sorted(old_ports - now_ports)
        cve_delta = _intify(rec.get("cves")) - _intify(old.get("cves"))
        if added or removed or cve_delta:
            diffs.append({"addr": addr, "status": "changed",
                          "added_ports": added, "removed_ports": removed, "cve_delta": cve_delta})
    return jsonify(has_snapshot=bool(snap), saved_ts=STATE["sessions"].get("saved_ts"),
                   changed=len(diffs), diffs=diffs)


# ---- unattended background monitor ----
MONITOR = {"stop": None, "thread": None, "running": False, "last": None}


def _monitor_once():
    targets = get_scan_targets()
    if shutil.which("nmap") and targets:
        try:
            out, _, _ = run_capture(["nmap", "-sn", "-oX", "-"] + targets, DISCOVERY_TIMEOUT_SECONDS)
            for h in parse_discovery(out):
                mac = h.get("mac")
                if mac and mac not in STATE["devices"]:
                    log_event("new-device", f"{h.get('ip')} ({h.get('vendor') or mac})", "warn",
                              dedup_key=f"newdev:{mac}", dedup_window=3600)
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which("tshark"):
        iface = WIFI_MON or detect_monitor_iface()
        if iface:
            try:
                out, _, _ = run_capture(
                    ["tshark", "-i", iface, "-a", "duration:6", "-n", "-l",
                     "-Y", DEAUTH_FILTER, "-T", "fields", "-e", "wlan.fc.type_subtype"], 30)
                n = sum(1 for ln in out.splitlines() if ln.strip() in ("12", "10"))
                if n >= DEAUTH_FLOOD_TOTAL // 2:
                    log_event("deauth-flood", f"{n} frames in 6s (background watch)", "alert",
                              dedup_key="deauth", dedup_window=120)
            except (OSError, subprocess.SubprocessError):
                pass
    MONITOR["last"] = _now()


def _monitor_loop(stop_event):
    while not stop_event.is_set():
        try:
            _monitor_once()
        except Exception:
            pass
        stop_event.wait(STATE["settings"].get("monitor_interval", 120))


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    if MONITOR["running"]:
        return jsonify(ok=True, running=True, already=True)
    stop = threading.Event()
    th = threading.Thread(target=_monitor_loop, args=(stop,), daemon=True)
    MONITOR.update(stop=stop, thread=th, running=True)
    th.start()
    log_event("monitor", "unattended watch started", "info", persist=False)
    return jsonify(ok=True, running=True,
                   interval=STATE["settings"].get("monitor_interval", 120),
                   webhook=bool(STATE["settings"].get("webhook")))


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    if MONITOR["stop"]:
        MONITOR["stop"].set()
    MONITOR["running"] = False
    return jsonify(ok=True, running=False)


@app.route("/api/monitor/status", methods=["GET"])
def api_monitor_status():
    return jsonify(running=MONITOR["running"], last=MONITOR["last"],
                   interval=STATE["settings"].get("monitor_interval", 120),
                   webhook=bool(STATE["settings"].get("webhook")))


@app.route("/api/dns_sniff", methods=["POST"])
def api_dns_sniff():
    """Passively stream DNS queries (who is resolving what) on the LAN interface."""
    if shutil.which("tshark") is None:
        return Response("[error] tshark not installed\n", mimetype="text/plain", status=500)
    iface = _lan_iface()
    if not iface:
        return Response("[error] no active LAN interface\n", mimetype="text/plain", status=400)
    cmd = ["tshark", "-i", iface, "-n", "-l", "-Y", "dns.flags.response==0",
           "-T", "fields", "-E", "separator=,", "-e", "ip.src", "-e", "dns.qry.name"]

    def gen():
        yield f"$ tshark -i {iface}   (passive DNS — who's resolving what)\n  tap Abort to stop.\n\n"
        lb = (["stdbuf", "-oL", "-eL"] + cmd) if shutil.which("stdbuf") else cmd
        try:
            proc = subprocess.Popen(lb, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except (OSError, subprocess.SubprocessError) as e:
            yield f"[error] tshark failed: {e}\n"
            return
        timer = threading.Timer(HARD_TIMEOUT_SECONDS, proc.kill)
        timer.start()
        seen = set()
        try:
            for line in iter(proc.stdout.readline, ""):
                src, _, name = line.strip().partition(",")
                name = name.strip().rstrip(".")
                if not name:
                    continue
                key = (src, name)
                if key in seen:
                    continue
                seen.add(key)
                yield f"  {src:<15}  →  {name}\n"
            proc.wait()
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
        yield f"\n[stopped] {len(seen)} unique query/host pair(s)\n"

    return Response(stream_with_context(gen()), mimetype="text/plain")


@app.route("/api/talkers", methods=["POST"])
def api_talkers():
    """Capture N seconds, then return top talkers, protocol mix, and topology edges."""
    if shutil.which("tshark") is None:
        return jsonify(error="tshark is not installed"), 500
    data = request.get_json(silent=True) or {}
    try:
        secs = max(5, min(30, int(data.get("seconds", 12))))
    except (TypeError, ValueError):
        secs = 12
    iface = _lan_iface() or WIFI_MON or detect_monitor_iface()
    if not iface:
        return jsonify(error="no capture interface available"), 400
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="dokkos_talk_")
    os.close(fd)
    try:
        subprocess.run(["tshark", "-i", iface, "-a", f"duration:{secs}", "-w", path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=secs + 20)
        out, _, _ = run_capture(
            ["tshark", "-r", path, "-n", "-T", "fields", "-E", "separator=|",
             "-e", "ip.src", "-e", "ip.dst", "-e", "frame.len", "-e", "frame.protocols"], 60)
    except subprocess.TimeoutExpired:
        return jsonify(error="capture/analysis timed out"), 504
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"capture failed: {e}"), 500
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    pairs, protos, nodes = {}, {}, {}
    for line in out.splitlines():
        f = line.split("|")
        if len(f) < 4:
            continue
        src, dst, length, protocols = f[0].strip(), f[1].strip(), f[2].strip(), f[3].strip()
        try:
            ln = int(length)
        except ValueError:
            ln = 0
        if src and dst:
            key = tuple(sorted((src, dst)))
            e = pairs.setdefault(key, {"a": key[0], "b": key[1], "bytes": 0, "frames": 0})
            e["bytes"] += ln
            e["frames"] += 1
            for ip in (src, dst):
                nodes[ip] = nodes.get(ip, 0) + ln
        leaf = protocols.split(":")[-1] if protocols else "other"
        p = protos.setdefault(leaf, {"name": leaf, "frames": 0, "bytes": 0})
        p["frames"] += 1
        p["bytes"] += ln
    talkers = sorted(pairs.values(), key=lambda x: x["bytes"], reverse=True)[:40]
    proto_list = sorted(protos.values(), key=lambda x: x["bytes"], reverse=True)[:14]
    node_list = sorted(({"ip": ip, "bytes": b} for ip, b in nodes.items()),
                       key=lambda x: x["bytes"], reverse=True)[:30]
    return jsonify(seconds=secs, iface=iface, gateway=_gateway_ip(), local=_lan_ip(),
                   talkers=talkers, protocols=proto_list, nodes=node_list,
                   total_bytes=sum(e["bytes"] for e in pairs.values()))


def _lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


# ---- PWA: manifest, service worker, app icon ----
@app.route("/manifest.webmanifest")
def pwa_manifest():
    man = {"name": "DokkOS", "short_name": "DokkOS", "start_url": "/",
           "display": "standalone", "orientation": "any",
           "background_color": "#06070b", "theme_color": "#06070b",
           "description": "Local recon & passive-detection console",
           "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml",
                      "purpose": "any maskable"}]}
    return Response(json.dumps(man), mimetype="application/manifest+json")


@app.route("/sw.js")
def pwa_sw():
    sw = """
const C='dokkos-v1';
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.add('/')));self.skipWaiting();});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.map(x=>x!==C&&caches.delete(x)))));self.clients.claim();});
self.addEventListener('fetch',e=>{
  const r=e.request; if(r.method!=='GET') return;
  const u=new URL(r.url); if(u.pathname.startsWith('/api/')) return;
  if(r.mode==='navigate'){
    e.respondWith(fetch(r).then(res=>{const cl=res.clone();caches.open(C).then(c=>c.put('/',cl));return res;}).catch(()=>caches.match('/')));
    return;
  }
  e.respondWith(caches.match(r).then(c=>c||fetch(r)));
});
"""
    return Response(sw, mimetype="application/javascript")


@app.route("/icon.svg")
def pwa_icon():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
<rect width="512" height="512" rx="96" fill="#06070b"/>
<path d="M256 84l150 60v92c0 108-66 170-150 208-84-38-150-100-150-208v-92z"
 fill="none" stroke="#e24555" stroke-width="14"/>
<path d="M168 220c28-16 56-16 84 0M260 220c28-16 56-16 84 0" fill="none"
 stroke="#5ff0d8" stroke-width="16" stroke-linecap="round"/>
<path d="M256 268v52M214 338c26 18 58 18 84 0" fill="none" stroke="#e24555"
 stroke-width="14" stroke-linecap="round"/>
<circle cx="256" cy="150" r="10" fill="#5ff0d8"/>
</svg>"""
    return Response(svg, mimetype="image/svg+xml")


@app.route("/api/launch", methods=["POST"])
def api_launch():
    tool_id = (request.get_json(silent=True) or {}).get("tool")
    if tool_id not in TOOLS:
        return jsonify(error="unknown tool"), 400
    tool = TOOLS[tool_id]
    if shutil.which(tool["cmd"][0]) is None:
        return jsonify(error=f"{tool['label']} is not installed"), 404
    term = find_terminal()
    if term is None:
        return jsonify(error="no terminal emulator found — edit TERMINAL_CANDIDATES"), 500
    if not os.environ.get("DISPLAY"):
        return jsonify(error="no DISPLAY — run the app from a desktop session (sudo -E)"), 500

    # term + the tool, wrapped so the window stays open after the tool exits.
    inner = " ".join(tool["cmd"]) + '; echo; read -n1 -r -p "[finished] press any key to close…"'
    cmd = term + ["bash", "-lc", inner]
    try:
        subprocess.Popen(cmd, env=os.environ.copy())
    except Exception as e:  # noqa: BLE001
        return jsonify(error=f"launch failed: {e}"), 500
    return jsonify(ok=True, launched=tool["label"])


def _wifi_base_iface():
    """First managed wireless interface (for switching into monitor mode)."""
    if shutil.which("iw"):
        try:
            out, _, _ = run_capture(["iw", "dev"], 5)
            m = re.search(r"Interface (\w+)", out)
            if m:
                return m.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
    return None


@app.route("/api/monitor_mode", methods=["POST"])
def api_monitor_mode():
    """Toggle Wi-Fi monitor mode via airmon-ng (passive listening; needs root)."""
    global WIFI_MON
    if shutil.which("airmon-ng") is None:
        return jsonify(error="airmon-ng (aircrack-ng) is not installed"), 500
    data = request.get_json(silent=True) or {}
    enable = bool(data.get("enable"))
    iface = data.get("iface")
    if iface is not None and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", iface or ""):
        return jsonify(error="invalid interface name"), 400
    if enable:
        base = iface or _wifi_base_iface()
        if not base:
            return jsonify(error="no wireless interface found — plug in a supported adapter"), 400
        try:
            run_capture(["airmon-ng", "check", "kill"], 25)   # stop NM/wpa_supplicant that block monitor mode
            out, _, _ = run_capture(["airmon-ng", "start", base], 40)
        except subprocess.TimeoutExpired:
            return jsonify(error="airmon-ng timed out"), 504
        except (OSError, subprocess.SubprocessError) as e:
            return jsonify(error=f"airmon-ng failed: {e}"), 500
        mon = detect_monitor_iface()
        if not mon:
            m = re.search(r"monitor mode.*?(?:enabled|vif enabled).*?\b(\w+mon\w*|\w+)\)?\s*$",
                          out, re.I | re.M)
            mon = m.group(1) if m else None
        if not mon:
            return jsonify(error="couldn't confirm monitor mode — check the adapter/chipset",
                           raw=out[-400:]), 500
        WIFI_MON = mon
        return jsonify(ok=True, enabled=True, monitor=mon)
    # disable
    target = iface or WIFI_MON or detect_monitor_iface()
    if not target:
        WIFI_MON = None
        return jsonify(ok=True, enabled=False, monitor=None)
    try:
        run_capture(["airmon-ng", "stop", target], 40)
    except (OSError, subprocess.SubprocessError) as e:
        return jsonify(error=f"airmon-ng stop failed: {e}"), 500
    WIFI_MON = None
    return jsonify(ok=True, enabled=False, monitor=None)


@app.route("/api/monitor_mode/status", methods=["GET"])
def api_monitor_mode_status():
    mon = WIFI_MON or detect_monitor_iface()
    return jsonify(enabled=bool(mon), monitor=mon)


@app.route("/")
def index():
    return PAGE


# ---------------------------------------------------------------------------
# Frontend — interactive HUD, inlined.
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>DokkOS</title>
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#06070b">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="DokkOS">
<link rel="apple-touch-icon" href="/icon.svg">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230b0d13'/%3E%3Cpath d='M9 12 L11 5 L14 12' fill='none' stroke='%23ff4533' stroke-width='2' stroke-linejoin='round'/%3E%3Cpath d='M23 12 L21 5 L18 12' fill='none' stroke='%23ff4533' stroke-width='2' stroke-linejoin='round'/%3E%3Cpath d='M7 12 Q16 10 25 12 L23 21 Q16 27 9 21 Z' fill='none' stroke='%23ff4533' stroke-width='2' stroke-linejoin='round'/%3E%3Cpath d='M11 16 l3 1 -3 1.5 Z' fill='%23ff4533'/%3E%3Cpath d='M21 16 l-3 1 3 1.5 Z' fill='%23ff4533'/%3E%3Cpath d='M13 21 q3 1.5 6 0' fill='none' stroke='%23ff4533' stroke-width='1.4'/%3E%3C/svg%3E">
<style>
  :root{--scr:#0b0d13;--scr2:#11141d;--pnl:#161a25;--ln:#262c3b;
    --em:#ff4533;--emd:#8f261d;--gh:#5ff0d8;--sm:#8a91a3;--bn:#e8eaf0}
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{background:#05060a;color:var(--bn);font-family:"JetBrains Mono","DejaVu Sans Mono",ui-monospace,monospace;overflow:hidden}
  .scr{position:fixed;inset:0;background:var(--scr);display:grid;grid-template-rows:auto 1fr auto}
  .scr::before{content:"";position:absolute;inset:0;background-image:linear-gradient(45deg,#ffffff08 25%,transparent 25%,transparent 75%,#ffffff08 75%);background-size:24px 24px;opacity:.22;pointer-events:none}

  /* ---- v4: ambient tablet frame ---- */
  .scr::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:60;
    box-shadow:inset 0 0 0 1px #5ff0d81a, inset 0 0 90px #00000090;
    background:
      linear-gradient(#5ff0d80f,#5ff0d80f) 0 0/22px 2px repeat-x,
      radial-gradient(120% 60% at 50% -10%, #e2455312, transparent 60%);
    animation:framebreathe 6s ease-in-out infinite}
  @keyframes framebreathe{50%{box-shadow:inset 0 0 0 1px #5ff0d833, inset 0 0 90px #00000090}}
  .corner{position:fixed;width:26px;height:26px;z-index:61;pointer-events:none;border:2px solid var(--em);opacity:.55}
  .corner.tl{top:6px;left:6px;border-right:0;border-bottom:0}
  .corner.tr{top:6px;right:6px;border-left:0;border-bottom:0}
  .corner.bl{bottom:6px;left:6px;border-right:0;border-top:0}
  .corner.br{bottom:6px;right:6px;border-left:0;border-top:0}
  .ambient{position:fixed;z-index:61;pointer-events:none;font-size:9px;letter-spacing:.16em;color:#5ff0d866;text-transform:uppercase}
  .ambient.tel-l{left:12px;bottom:10px;text-align:left}
  .ambient.tel-r{right:12px;bottom:10px;text-align:right}
  .ambient b{color:var(--gh)}
  .scanbeam{position:fixed;left:0;right:0;height:2px;z-index:59;pointer-events:none;
    background:linear-gradient(90deg,transparent,#5ff0d855,transparent);animation:beam 7s linear infinite;opacity:.5}
  @keyframes beam{0%{top:-2%}100%{top:102%}}

  /* ---- v4: boot sequence ---- */
  #boot{position:fixed;inset:0;z-index:9999;background:radial-gradient(circle at 50% 42%,#0a0e15,#05060a 70%);
    display:flex;flex-direction:column;align-items:center;justify-content:center;gap:20px;
    transition:opacity .6s ease, visibility .6s;padding:24px}
  #boot.gone{opacity:0;visibility:hidden}
  #boot::before{content:"";position:absolute;inset:0;background:repeating-linear-gradient(0deg,#0000,#0000 3px,#ffffff06 3px,#ffffff06 4px);pointer-events:none;animation:bootscan 8s linear infinite}
  @keyframes bootscan{to{background-position:0 200px}}
  .boot-glyph{width:132px;height:132px;filter:drop-shadow(0 0 16px #e2455566)}
  .boot-glyph path,.boot-glyph line{stroke-dasharray:240;stroke-dashoffset:240;animation:draw 1.2s ease forwards}
  .boot-glyph .g2{animation-delay:.25s}.boot-glyph .g3{animation-delay:.5s}
  .boot-glyph .tl2{stroke:var(--gh);animation-delay:.7s;filter:drop-shadow(0 0 6px #5ff0d8)}
  @keyframes draw{to{stroke-dashoffset:0}}
  .boot-title{font-size:34px;letter-spacing:.5em;color:var(--bn);text-indent:.5em;
    text-shadow:0 0 18px #e2455577;opacity:0;animation:fadeup .5s .9s forwards}
  .boot-sub{font-size:11px;letter-spacing:.34em;color:var(--em);opacity:0;animation:fadeup .5s 1.1s forwards;margin-top:-12px}
  @keyframes fadeup{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  .boot-log{width:min(440px,86vw);height:150px;overflow:hidden;font-size:12px;line-height:1.7;color:var(--sm);white-space:pre-wrap}
  .boot-log .ok{color:var(--gh)} .boot-log .em{color:var(--em)} .boot-log .dim{color:#5c6472}
  .boot-bar{width:min(440px,86vw);height:3px;background:#0d0f16;border:1px solid var(--ln);border-radius:3px;overflow:hidden}
  .boot-bar span{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--emd),var(--em),var(--gh));box-shadow:0 0 10px #e2455588;transition:width .2s}
  .boot-enter{font-size:12px;letter-spacing:.28em;color:var(--gh);opacity:0;transition:opacity .4s;text-shadow:0 0 10px #5ff0d866;cursor:pointer;min-height:20px}
  .boot-enter.show{opacity:1;animation:blink 1.1s step-start infinite}
  @keyframes blink{50%{opacity:.35}}

  /* ---- v4: micro-interactions ---- */
  .op,.tool,.scanbtn,.um,.mode,.save,.gear,.hdr-btn,.dossierbtn,.stealth{transition:transform .09s ease, box-shadow .16s ease, background .16s, color .16s, border-color .16s}
  .op:active,.tool:active,.scanbtn:active,.save:active,.gear:active,.hdr-btn:active,.dossierbtn:active,.stealth:active,.um:active,.mode:active{transform:translateY(1px) scale(.985)}
  .op:hover:not(:disabled){border-color:var(--em);box-shadow:-2px 0 0 var(--em) inset}
  .hostitem{transition:transform .1s ease, background .16s, border-color .16s}
  .hostitem:active{transform:scale(.99)}

  /* ---- v4: command palette ---- */
  #cmdk{position:fixed;inset:0;z-index:220;display:none;align-items:flex-start;justify-content:center;
    background:#05060acc;backdrop-filter:blur(3px);padding-top:14vh}
  #cmdk.show{display:flex}
  .cmdk-box{width:min(520px,94vw);background:var(--scr2);border:1px solid var(--em);border-radius:12px;
    box-shadow:0 0 40px #e2455533, 0 20px 60px #000;overflow:hidden}
  .cmdk-in{width:100%;background:transparent;border:0;border-bottom:1px solid var(--ln);color:var(--bn);
    font-family:inherit;font-size:16px;padding:16px 18px;outline:none;letter-spacing:.04em}
  .cmdk-list{max-height:52vh;overflow:auto}
  .cmdk-row{display:flex;align-items:center;gap:12px;padding:12px 18px;cursor:pointer;border-left:2px solid transparent}
  .cmdk-row .ci{color:var(--sm);display:flex} .cmdk-row .ct{flex:1;font-size:14px;color:var(--bn)}
  .cmdk-row .ck{font-size:10px;letter-spacing:.12em;color:#5c6472;text-transform:uppercase}
  .cmdk-row.sel{background:#ff45331a;border-left-color:var(--em)}
  .cmdk-row.sel .ct{color:var(--em)}
  .cmdk-empty{padding:22px 18px;color:var(--sm);font-size:13px;text-align:center}
  @media (prefers-reduced-motion: reduce){
    .scr::after,.scanbeam,#boot::before,.boot-glyph path,.boot-glyph line,.boot-title,.boot-sub,.boot-enter.show{animation:none}
    .boot-glyph path,.boot-glyph line{stroke-dashoffset:0}
    .boot-title,.boot-sub{opacity:1}
  }

  .top{display:flex;align-items:center;gap:12px;padding:9px 14px;border-bottom:1px solid var(--ln);position:relative;z-index:2}
  .stat{font-size:14px;color:var(--sm);letter-spacing:.1em;white-space:nowrap}
  .stat b{color:var(--em)}
  .stealth{font-family:inherit;font-size:12px;letter-spacing:.14em;color:var(--sm);background:var(--scr2);border:1px solid var(--ln);border-radius:7px;padding:11px 16px;min-height:46px;margin-left:auto;cursor:pointer;white-space:nowrap}
  .uimode{display:flex;border:1px solid var(--ln);border-radius:9px;overflow:hidden}
  .um{font-family:inherit;font-size:14px;font-weight:700;letter-spacing:.22em;color:var(--sm);background:var(--scr2);border:none;padding:11px 22px;min-height:46px;cursor:pointer}
  .um.on{background:#ff45331a;color:var(--em)}
  .stealth.on{color:var(--gh);border-color:var(--gh);background:#5ff0d814}
  .tabs{display:flex;gap:5px;flex:1;justify-content:center;flex-wrap:wrap}
  .spacer{flex:1}
  .tab{font-size:14px;color:var(--sm);padding:11px 16px;min-height:44px;display:flex;align-items:center;border:1px solid transparent;border-radius:6px;cursor:pointer;white-space:nowrap}
  .tab:hover{color:var(--bn)}
  .tab.on{color:var(--bn);background:#ff45331a;border-color:var(--emd)}
  .mark{font-weight:700;letter-spacing:.16em;display:flex;align-items:center;gap:7px}
  .maskico{flex-shrink:0}
  .mark span{color:var(--em)}
  .mark small{font-size:8px;letter-spacing:.34em;color:var(--sm);margin-left:4px;align-self:flex-end;margin-bottom:2px}
  .prog{position:absolute;left:0;bottom:-1px;height:2px;width:0;background:var(--em);transition:width .3s}
  .prog.run{animation:prog 2.4s linear infinite}
  @keyframes prog{0%{width:6%}50%{width:72%}100%{width:96%}}

  main{display:grid;grid-template-columns:308px 1fr 152px;min-height:0;position:relative;z-index:2}
  .col{min-height:0;min-width:0;overflow:auto}
  .col,.out,#hosts{scrollbar-width:thin;scrollbar-color:var(--emd) transparent}
  .col::-webkit-scrollbar,.out::-webkit-scrollbar,#hosts::-webkit-scrollbar{width:8px;height:8px}
  .col::-webkit-scrollbar-track,.out::-webkit-scrollbar-track,#hosts::-webkit-scrollbar-track{background:#0d0f16}
  .col::-webkit-scrollbar-thumb,.out::-webkit-scrollbar-thumb,#hosts::-webkit-scrollbar-thumb{background:linear-gradient(var(--emd),var(--em));border-radius:8px;border:2px solid #0d0f16}
  .col::-webkit-scrollbar-thumb:hover,.out::-webkit-scrollbar-thumb:hover,#hosts::-webkit-scrollbar-thumb:hover{background:var(--em)}
  .list{border-right:1px solid var(--ln);padding:14px 13px;display:flex;flex-direction:column;gap:9px;position:relative;z-index:7}
  .lbl{font-size:12px;letter-spacing:.2em;color:var(--sm);margin:2px 0 4px;display:flex;justify-content:space-between;align-items:center}
  .scanbtn{font-size:14px;letter-spacing:.1em;color:var(--em);border:1px solid var(--emd);background:#ff45331a;border-radius:7px;padding:11px 16px;min-height:44px;cursor:pointer}
  .scanbtn.alt{color:var(--gh);border-color:#2b6f63;background:#5ff0d814;padding:11px 12px}
  .dossierbtn{margin-left:auto;align-self:center;font-family:inherit;font-size:11px;letter-spacing:.14em;color:var(--gh);background:#5ff0d814;border:1px solid #2b6f63;border-radius:6px;padding:7px 12px;min-height:36px;cursor:pointer}
  .dossierbtn:hover{background:#5ff0d822;box-shadow:0 0 10px #5ff0d833}
  .modetabs{display:flex;gap:6px}
  .mtab{font-family:inherit;font-size:16px;letter-spacing:.14em;font-weight:600;color:var(--sm);
    background:transparent;border:1px solid var(--ln);border-radius:8px;padding:10px 20px;min-height:48px;
    cursor:pointer;position:relative;text-transform:uppercase}
  .mtab:hover{border-color:var(--emd);color:var(--bn)}
  .mtab.on{color:#fff;border-color:var(--em);background:#ff45331f;box-shadow:0 0 16px #e2455533,0 2px 0 var(--em) inset}
  .mtab.on::after{content:"";position:absolute;left:12px;right:12px;bottom:-1px;height:2px;background:var(--em);box-shadow:0 0 8px var(--em)}
  .scope{width:100%;margin:0 0 4px;background:var(--scr2);color:var(--bn);border:1px solid var(--ln);border-radius:6px;padding:15px 12px;min-height:50px;font-family:inherit;font-size:15px;letter-spacing:.04em;outline:none}
  .scope:focus{border-color:var(--em)}
  .host{display:flex;align-items:center;gap:12px;background:var(--scr2);border:1px solid var(--ln);border-radius:9px;padding:17px 14px;min-height:70px;font-size:16px;color:var(--sm);cursor:pointer;text-align:left;width:100%}
  .host:hover{border-color:var(--emd)}
  .host.on{background:#ff45331f;border-color:var(--em);color:var(--bn);box-shadow:-3px 0 0 var(--em) inset}
  .host i,.host .ico{font-size:17px;flex-shrink:0;color:var(--gh)}
  .host.on i,.host.on .ico{color:var(--em)}
  .host.act{border-left:3px solid var(--gh)}
  .host.picked{border-color:var(--gh);box-shadow:-3px 0 0 var(--gh) inset}
  .hbody{flex:1;display:flex;align-items:center;gap:12px;min-width:0;background:transparent;border:0;color:inherit;font:inherit;text-align:left;cursor:pointer;padding:0}
  .pick{flex:0 0 26px;width:26px;height:26px;border-radius:6px;border:2px solid var(--ln);background:#0d0f16;
    display:grid;place-items:center;color:transparent;font-size:15px;cursor:pointer;transition:all .12s}
  .pick:hover{border-color:var(--gh)}
  .pick.on{border-color:var(--gh);background:#5ff0d81f;color:var(--gh);box-shadow:0 0 10px #5ff0d844}
  .callbar{display:none;align-items:center;gap:10px;margin:0 0 8px;padding:12px 14px;border-radius:9px;
    background:#e2455318;border:1px solid var(--em);box-shadow:0 0 18px #e2455533}
  .callbar.show{display:flex}
  .callbar b{color:var(--em);font-size:15px;letter-spacing:.1em}
  .callbar .cbtn{margin-left:auto;font-family:inherit;font-size:14px;letter-spacing:.12em;font-weight:600;
    color:#fff;background:var(--em);border:0;border-radius:7px;padding:11px 18px;min-height:46px;cursor:pointer;text-transform:uppercase}
  .callbar .cclr{font-family:inherit;font-size:13px;color:var(--sm);background:transparent;border:1px solid var(--ln);border-radius:7px;padding:11px 14px;min-height:46px;cursor:pointer}
  .wifinote{font-size:11px;line-height:1.55;color:var(--sm);background:var(--scr2);border:1px solid var(--ln);border-left:3px solid var(--gh);border-radius:6px;padding:8px 9px;margin:0 0 6px}
  .wifinote b{color:var(--gh);letter-spacing:.1em;text-transform:uppercase;font-size:10px}
  .wifinote code{color:var(--bn);background:#0d0f16;border:1px solid var(--ln);padding:1px 4px;border-radius:3px;font-size:10.5px;word-break:break-all}
  .wifinote .cmd2{margin-top:5px}
  .ports{display:flex;flex-wrap:wrap;gap:7px;align-items:center;padding:9px 14px;border-bottom:1px solid var(--ln);background:#0d0f16}
  .portlbl{font-size:12px;letter-spacing:.12em;color:var(--sm)}
  .port{font-family:inherit;font-size:14px;color:var(--bn);background:var(--scr2);border:1px solid var(--emd);border-radius:6px;padding:12px 15px;min-height:46px;cursor:pointer}
  .port:hover{background:#ff45331f}
  .host .hn{display:block;line-height:1.25;font-size:16px;letter-spacing:.02em}
  .host .hv{display:block;font-size:12.5px;color:var(--sm);margin-top:2px}
  .empty{font-size:13px;color:var(--sm);padding:10px 6px;line-height:1.6}

  /* passive-detection alert banner */
  .alertbar{font-size:12px;line-height:1.5;color:var(--bn);background:#2a0f0e;border:1px solid var(--em);
    border-left:3px solid var(--em);border-radius:6px;padding:9px 11px;margin:0 0 7px;
    display:flex;align-items:center;gap:8px;flex-wrap:wrap;animation:alertin .4s ease-out, alertglow 2s ease-in-out infinite}
  .alertbar::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--em);box-shadow:0 0 8px var(--em);flex-shrink:0;animation:alertdot 1s ease-in-out infinite}
  .alertbar.warn{background:#2a1c08;border-color:#f5a524;border-left-color:#f5a524}
  .alertbar.warn::before{background:#f5a524;box-shadow:0 0 8px #f5a524}
  .albtn{font-family:inherit;font-size:11px;letter-spacing:.1em;color:var(--bn);background:#ff45331f;border:1px solid var(--em);
    border-radius:5px;padding:6px 10px;min-height:30px;cursor:pointer;margin-left:auto}
  .albtn:hover{background:#ff45332e}
  @keyframes alertin{0%{opacity:0;transform:translateY(-6px)}100%{opacity:1;transform:translateY(0)}}
  @keyframes alertglow{50%{box-shadow:0 0 14px #ff45333a}}
  @keyframes alertdot{50%{opacity:.3}}
  .newbadge{display:inline-block;font-size:9px;font-weight:700;letter-spacing:.12em;color:#06231f;background:var(--gh);
    border-radius:3px;padding:1px 4px;margin-left:7px;vertical-align:middle;animation:badgepop .4s ease-out}
  .warnbadge{display:inline-block;margin-left:7px;color:var(--em);vertical-align:middle;font-weight:700;animation:warnpulse 1.1s ease-in-out infinite}
  @keyframes badgepop{0%{opacity:0;transform:scale(.6)}100%{opacity:1;transform:scale(1)}}
  @keyframes warnpulse{50%{opacity:.4;text-shadow:0 0 8px var(--em)}}

  /* host-list entrance stagger */
  .host{animation:hostin .32s ease-out both}
  #hosts .host:nth-child(1){animation-delay:.0s}#hosts .host:nth-child(2){animation-delay:.03s}
  #hosts .host:nth-child(3){animation-delay:.06s}#hosts .host:nth-child(4){animation-delay:.09s}
  #hosts .host:nth-child(5){animation-delay:.12s}#hosts .host:nth-child(6){animation-delay:.15s}
  #hosts .host:nth-child(7){animation-delay:.18s}#hosts .host:nth-child(8){animation-delay:.21s}
  #hosts .host:nth-child(n+9){animation-delay:.24s}
  @keyframes hostin{0%{opacity:0;transform:translateX(-8px)}100%{opacity:1;transform:translateX(0)}}
  .host{position:relative;overflow:hidden}
  .host::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--em);transform:translateX(-3px);transition:transform .15s}
  .host:hover::before,.host.on::before{transform:translateX(0)}

  /* rail op hover sweep */
  .op{position:relative;overflow:hidden;transition:background .15s}
  .op::after{content:"";position:absolute;left:0;right:0;bottom:0;height:2px;background:var(--em);transform:scaleX(0);transform-origin:left;transition:transform .2s}
  .op:hover::after,.op.on::after{transform:scaleX(1)}
  .op .ico{transition:transform .15s}
  .op:hover .ico{transform:scale(1.12)}

  /* map node ping (vuln nodes pulse) */
  .mapsvg .mnode.vuln circle{animation:nodeping 1.6s ease-out infinite}
  @keyframes nodeping{0%{filter:drop-shadow(0 0 0 var(--em))}40%{filter:drop-shadow(0 0 7px var(--em))}100%{filter:drop-shadow(0 0 0 var(--em))}}
  .mapsvg .mnode.center circle{animation:corepulse 3s ease-in-out infinite}
  @keyframes corepulse{50%{filter:drop-shadow(0 0 8px var(--gh))}}

  @media (prefers-reduced-motion: reduce){
    .alertbar,.alertbar::before,.newbadge,.warnbadge,.host,.mapsvg .mnode.vuln circle,.mapsvg .mnode.center circle{animation:none!important}
  }

  .center{display:flex;flex-direction:column;min-height:0;min-width:0;position:relative;z-index:1}

  /* ---- v4.2: dossier + CALL card (resting state for a selected target) ---- */
  .dcard{position:absolute;inset:0;z-index:5;display:none;padding:20px;overflow:auto;background:var(--scr)}
  .dcard.show{display:block;animation:dcin .28s ease-out both}
  @keyframes dcin{from{opacity:0;transform:translateY(8px) scale(.99)}to{opacity:1;transform:none}}
  .dcard-in{position:relative;max-width:620px;margin:0 auto;background:linear-gradient(180deg,#12141d,#0d0f16);
    border:1px solid var(--ln);border-left:3px solid var(--em);border-radius:12px;padding:22px 22px 20px;
    box-shadow:0 0 40px #00000066, 0 0 0 1px #ff45330f}
  .dc-scan{position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,transparent,#e2455566,transparent);animation:beam 5s linear infinite;opacity:.5;border-radius:12px 12px 0 0}
  .dc-head{display:flex;align-items:center;gap:18px;margin-bottom:18px}
  .dc-portrait{flex:0 0 74px;width:74px;height:74px;display:grid;place-items:center;color:var(--em);
    background:#0d0f16;border:1px solid var(--emd);border-radius:12px;box-shadow:0 0 18px #e2455533}
  .dc-portrait.new{border-color:var(--gh);color:var(--gh);box-shadow:0 0 18px #5ff0d833}
  .dc-id{flex:1;min-width:0}
  .dc-name{font-size:26px;letter-spacing:.05em;color:#fff;line-height:1.05;overflow-wrap:anywhere}
  .dc-sub{font-size:13px;color:var(--sm);margin-top:4px;letter-spacing:.03em}
  .dc-origin{font-size:14px;color:var(--bn);margin-top:8px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
  .dc-origin small{color:var(--sm);letter-spacing:.14em;font-size:10px;display:block;margin-bottom:1px}
  .dc-flag{flex:0 0 auto;align-self:flex-start;font-size:11px;letter-spacing:.14em;color:var(--em);border:1px solid var(--em);border-radius:6px;padding:4px 9px;background:#ff45331a}
  .dc-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px;margin-bottom:18px}
  .dc-tile{background:#0d0f16;border:1px solid var(--ln);border-radius:9px;padding:12px 13px;display:flex;flex-direction:column;gap:5px}
  .dc-tile.wide{grid-column:1 / -1}
  .dc-tile b{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--sm);font-weight:600}
  .dc-tile span{font-size:14px;color:var(--bn);overflow-wrap:anywhere}
  .dc-n{font-size:26px!important;font-weight:700;color:var(--bn);line-height:1;font-variant-numeric:tabular-nums}
  .dc-n.hot{color:var(--em)} .dc-n.dc-hi{color:var(--em)} .dc-n.dc-mid{color:#f0b14a} .dc-n.dc-lo{color:var(--gh)}
  .dc-empty{background:#0d0f16;border:1px dashed var(--ln);border-radius:9px;padding:18px;color:var(--sm);font-size:13px;line-height:1.6;margin-bottom:18px}
  .dc-ports{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}
  .dc-port{font-family:inherit;font-size:15px;color:var(--bn);background:var(--scr2);border:1px solid var(--emd);border-radius:8px;padding:10px 14px;min-height:46px;cursor:pointer;display:flex;align-items:center;gap:6px}
  .dc-port small{color:var(--gh);font-size:12px}
  .dc-port:hover{background:#ff45331f;border-color:var(--em)} .dc-port:active{transform:translateY(1px)}
  .dc-empty b{color:var(--em)}
  .dc-actions{display:flex;gap:10px;align-items:center}
  .dc-call{flex:1;display:flex;align-items:center;justify-content:center;gap:9px;font-family:inherit;font-size:17px;
    letter-spacing:.14em;font-weight:700;color:#fff;background:var(--em);border:0;border-radius:9px;padding:16px;min-height:58px;
    cursor:pointer;text-transform:uppercase;box-shadow:0 0 22px #e2455544}
  .dc-call:hover{box-shadow:0 0 30px #e2455577} .dc-call:active{transform:translateY(1px)}
  .dc-cancel{font-family:inherit;font-size:14px;letter-spacing:.12em;color:var(--sm);background:transparent;border:1px solid var(--ln);border-radius:9px;padding:16px 18px;min-height:58px;cursor:pointer;text-transform:uppercase}
  .dc-cancel:hover{border-color:var(--sm);color:var(--bn)}
  .dc-more{font-family:inherit;font-size:13px;letter-spacing:.1em;color:var(--gh);background:#5ff0d814;border:1px solid #2b6f63;border-radius:9px;padding:16px 16px;min-height:58px;cursor:pointer}
  @media (max-width:520px){ .dc-grid{grid-template-columns:1fr 1fr} .dc-name{font-size:22px} }
  .tcard{display:flex;align-items:center;gap:13px;padding:14px 16px;border-bottom:1px solid var(--ln);background:#ff45330a}
  .tcard-portrait{width:50px;height:50px;border:1px solid var(--ln);background:#0d0f16;display:flex;align-items:center;justify-content:center;color:#3a4150;flex-shrink:0;position:relative}
  .tcard.active .tcard-portrait{border-color:var(--emd)}
  .tcard-portrait::after{content:"";position:absolute;left:5px;right:5px;bottom:4px;height:3px;background:repeating-linear-gradient(90deg,var(--emd) 0 5px,transparent 5px 9px);opacity:0}
  .tcard.active .tcard-portrait::after{opacity:1}
  .tcard-name{font-size:24px;font-weight:700;letter-spacing:.05em;line-height:1.05}
  .tcard-sub{font-size:13px;color:var(--sm);margin-top:2px}
  .tcard-addr{margin-left:auto;text-align:right}
  .tcard-addr small{display:block;font-size:11px;letter-spacing:.18em;color:var(--em)}
  .tcard-addr span{font-size:17px;color:var(--bn)}
  .tcard-status{display:flex;align-items:center;gap:8px;font-size:13px;letter-spacing:.1em;color:var(--sm);padding-left:13px;border-left:1px solid var(--ln);min-width:118px}
  .tcard-dot{width:8px;height:8px;border-radius:50%;background:var(--sm);flex-shrink:0}
  .tcard.calling .tcard-status{color:var(--em)}
  .tcard.calling .tcard-dot{background:var(--em);animation:tpulse 1s infinite}
  @keyframes tpulse{50%{opacity:.25}}
  pre.out{flex:1;margin:0;overflow:auto;padding:15px 18px;font-size:14px;line-height:1.65;color:#c7ccd8;white-space:pre-wrap;word-break:break-word}
  pre.out .cmd{color:var(--gh)}
  pre.out .hint{color:var(--sm)}
  .cursor{display:inline-block;width:.55ch;height:1.05em;vertical-align:-2px;background:var(--em);animation:blink 1s steps(1) infinite}
  @keyframes blink{50%{opacity:0}}

  .rail{border-left:1px solid var(--ln);display:flex;flex-direction:column;overflow:auto;position:relative;z-index:7;padding:10px 8px;gap:8px}
  .op{flex:0 0 auto;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;background:var(--scr2);border:1px solid var(--ln);border-radius:11px;font-family:inherit;color:var(--bn);font-size:13px;letter-spacing:.06em;padding:12px 4px;text-align:center;cursor:pointer}
  .op:hover:not(:disabled){color:#fff;background:#ff45331a;border-color:var(--em);box-shadow:0 0 14px #e2455522}
  .op.on{background:#ff45331f;border-color:var(--em);box-shadow:0 0 14px #e2455533}
  .op{min-height:78px;line-height:1.15}
  .op i,.op .ico{font-size:26px}
  .rail .op .ico,.rail .op i{color:var(--gh)}
  .rail .op:hover .ico,.rail .op:hover i,.rail .op.on .ico,.rail .op.on i{color:var(--em)}
  .op:disabled{opacity:.35;cursor:not-allowed}

  .bot{display:flex;align-items:center;gap:10px;padding:9px 14px;border-top:1px solid var(--ln);position:relative;z-index:2}
  .tools{display:flex;gap:7px;overflow-x:auto;flex:1;scrollbar-width:none}
  .tools::-webkit-scrollbar{display:none}
  .tool{font-size:13px;letter-spacing:.08em;color:var(--bn);background:var(--scr2);border:1px solid var(--ln);border-radius:6px;padding:13px 16px;min-height:52px;cursor:pointer;display:flex;align-items:center;gap:8px}
  .tool:hover{border-color:var(--em)}
  .tool i,.tool .ico{color:var(--em);font-size:16px}
  .callbtn{margin-left:auto;display:flex;align-items:center;gap:9px;background:#ff45331f;border:1px solid var(--em);color:var(--bn);padding:10px 26px;border-radius:30px;font-size:15px;letter-spacing:.14em;cursor:pointer}
  .callbtn:hover{background:#ff45332e}
  .callbtn.run{animation:pulse 1.2s infinite}
  .callbtn i,.callbtn .ico{color:var(--em);font-size:18px}
  .callbtn:disabled{opacity:.4;cursor:not-allowed;animation:none}
  @keyframes pulse{50%{background:#ff45330d;border-color:var(--emd)}}

  .toast{position:fixed;left:50%;bottom:70px;transform:translateX(-50%);background:var(--pnl);border:1px solid var(--emd);color:var(--bn);font-size:14px;letter-spacing:.05em;padding:9px 16px;border-radius:8px;z-index:20;opacity:0;transition:opacity .2s;pointer-events:none}
  .toast.show{opacity:1}

  .gear{display:flex;align-items:center;justify-content:center;width:46px;height:46px;flex-shrink:0;
    background:var(--scr2);border:1px solid var(--ln);border-radius:8px;color:var(--sm);cursor:pointer}
  .gear:hover{border-color:var(--em);color:var(--em)}
  .gear .ico{width:20px;height:20px}
  .modal{position:fixed;inset:0;z-index:30;display:none;align-items:center;justify-content:center;background:#000a;backdrop-filter:blur(2px)}
  .modal.show{display:flex}
  .sheet{width:min(440px,92vw);background:var(--pnl);border:1px solid var(--emd);border-radius:14px;padding:20px 22px;box-shadow:0 0 60px #ff45332e}
  .sheet-head{display:flex;justify-content:space-between;align-items:center;font-size:14px;font-weight:700;letter-spacing:.3em;color:var(--em);margin-bottom:16px}
  .sheet .x{background:none;border:none;color:var(--sm);font-size:18px;cursor:pointer}
  .srow{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:11px 0;font-size:14px;color:var(--bn)}
  .srow select,.srow input{font-family:inherit;font-size:14px;background:var(--scr2);color:var(--bn);border:1px solid var(--ln);border-radius:7px;padding:11px 12px;min-height:46px;min-width:170px;outline:none}
  .srow select:focus,.srow input:focus{border-color:var(--em)}
  .srow-note{font-size:11px;line-height:1.5;color:var(--sm);margin:12px 0 4px}
  .save{width:100%;margin-top:8px;font-family:inherit;font-size:15px;font-weight:700;letter-spacing:.24em;
    background:#ff45331f;border:1px solid var(--em);color:var(--bn);border-radius:9px;padding:14px;min-height:50px;cursor:pointer}
  .save:hover{background:#ff45332e}
  .save.alt{background:#0e211e;border-color:#5ff0d85a;color:var(--bn)}
  .save.alt:hover{background:#11302a}
  .save:disabled{opacity:.4;cursor:not-allowed}

  .hdr-btn{margin-left:auto;display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;
    background:var(--scr2);border:1px solid var(--ln);border-radius:7px;color:var(--gh);cursor:pointer;flex-shrink:0}
  .hdr-btn:hover{border-color:var(--gh)}
  .hdr-btn .ico{width:18px;height:18px}
  .vdot,.sdot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-left:7px;vertical-align:middle}
  .vdot{background:var(--em);box-shadow:0 0 7px var(--em)}
  .sdot{background:var(--gh);box-shadow:0 0 6px #5ff0d8aa}

  .mapsheet{width:min(680px,96vw)}
  .mapwrap{width:100%;aspect-ratio:1/1;max-height:62vh;margin:4px auto 0;display:flex;align-items:center;justify-content:center}
  .mapsvg{width:100%;height:100%;overflow:visible}
  .mapsvg .mfield{fill:#0a1a18;stroke:none;opacity:.5}
  .mapsvg .mring{fill:none;stroke:#5ff0d827;stroke-width:1}
  .mapsvg .mcross{stroke:#5ff0d818;stroke-width:1}
  .mapsvg .mspoke{stroke:#5ff0d825;stroke-width:1}
  .mapsvg .msweep{transform-origin:300px 300px;animation:mapsweep 5s linear infinite}
  .mapsvg .msweep path{fill:#5ff0d80f;stroke:none}
  @keyframes mapsweep{to{transform:rotate(360deg)}}
  .mapsvg .mnode{cursor:pointer}
  .mapsvg .mnode circle{fill:#0c1d1b;stroke:var(--sm);stroke-width:2;transition:.12s}
  .mapsvg .mnode .ico,.mapsvg .mnode svg{color:var(--sm)}
  .mapsvg .mnode.idle circle{stroke:#7f8c91}
  .mapsvg .mnode.scanned circle{stroke:var(--gh)} .mapsvg .mnode.scanned svg{color:var(--gh)}
  .mapsvg .mnode.vuln circle{stroke:var(--em);fill:#23100f} .mapsvg .mnode.vuln svg{color:var(--em)}
  .mapsvg .mnode.sel circle{stroke-width:3;filter:drop-shadow(0 0 6px currentColor)}
  .mapsvg .mnode.center circle{fill:#101f1d;stroke:var(--gh);stroke-width:2.5}
  .mapsvg .mnode.center svg{color:var(--gh)}
  .mapsvg .mnode:hover circle{fill:#13302b}
  .mapsvg .mlabel{fill:var(--bn);font-size:13px;font-family:inherit;text-anchor:middle;letter-spacing:.04em}
  .maprow{display:flex;justify-content:space-between;align-items:center;margin-top:10px;font-size:11px;color:var(--sm)}
  .maplegend{display:flex;gap:14px}
  .maplegend .lg{display:inline-flex;align-items:center;gap:6px;letter-spacing:.08em}
  .maplegend .lg::before{content:"";width:9px;height:9px;border-radius:50%;border:2px solid currentColor}
  .maplegend .idle{color:#7f8c91}
  .maplegend .scanned{color:var(--gh)}
  .maplegend .vuln{color:var(--em)}
  .mapmeta{letter-spacing:.08em}

  /* RSSI hunt meter */
  .huntsheet{width:min(420px,92vw);text-align:center}
  .hunt-target{font-size:14px;color:var(--bn);letter-spacing:.04em;margin:2px 0 16px;overflow-wrap:anywhere}
  .hunt-meter{height:34px;border:1px solid var(--ln);border-radius:8px;background:#0d0f16;overflow:hidden;position:relative}
  .hunt-fill{height:100%;width:0%;border-radius:7px 0 0 7px;transition:width .35s ease, background .35s;
    background:linear-gradient(90deg,#2b6f63,#5ff0d8)}
  .hunt-fill.cold{background:linear-gradient(90deg,#1f3b6e,#3f7fd8)}
  .hunt-fill.mid{background:linear-gradient(90deg,#2b6f63,#5ff0d8)}
  .hunt-fill.hot{background:linear-gradient(90deg,#b3301f,#ff4533);box-shadow:0 0 20px #ff45337a;animation:huntpulse .6s ease-in-out infinite}
  @keyframes huntpulse{50%{box-shadow:0 0 30px #ff4533c0}}
  .hunt-val{font-size:34px;font-weight:700;color:var(--bn);letter-spacing:.04em;margin:16px 0 4px;font-variant-numeric:tabular-nums}
  .hunt-label{font-size:14px;letter-spacing:.18em;color:var(--em);text-transform:uppercase;min-height:18px}
  @media (prefers-reduced-motion: reduce){ .hunt-fill.hot{animation:none} }

  /* report split rows */
  .rprow{display:flex;gap:8px}
  .save.half{flex:1;margin:0}

  /* monitor button pulsing when active */
  #monitorbtn.on{color:var(--em);border-color:var(--em);box-shadow:0 0 12px #e2455533;animation:monpulse 1.8s ease-in-out infinite}
  @keyframes monpulse{50%{box-shadow:0 0 18px #e24555aa}}

  /* detection timeline */
  .tlsheet{width:min(560px,94vw);max-height:84vh}
  .tl-body-wrap{max-height:60vh;overflow:auto;margin:4px 0 12px;padding-right:2px}
  .tl-row{display:flex;gap:12px;padding:11px 4px;border-bottom:1px solid var(--ln);position:relative}
  .tl-row:last-child{border-bottom:0}
  .tl-node{flex:0 0 30px;height:30px;border-radius:50%;display:grid;place-items:center;
    border:1px solid var(--ln);color:var(--sm);background:#0d0f16}
  .tl-row.warn .tl-node{color:#f0b14a;border-color:#6a4f18;box-shadow:0 0 10px #f0b14a33}
  .tl-row.alert .tl-node{color:var(--em);border-color:#6a1f24;box-shadow:0 0 12px #e2455544}
  .tl-body{flex:1;min-width:0}
  .tl-kind{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--bn)}
  .tl-row.alert .tl-kind{color:var(--em)} .tl-row.warn .tl-kind{color:#f0b14a}
  .tl-detail{font-size:13px;color:var(--sm);margin-top:2px;overflow-wrap:anywhere}
  .tl-time{font-size:11px;color:#5c6472;margin-top:3px;font-variant-numeric:tabular-nums}
  .tl-empty{color:var(--sm);text-align:center;padding:34px 10px;font-size:13px}

  /* host dossier drawer */
  .dsrsheet{width:min(480px,94vw)}
  .dsr-head{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:14px}
  .dsr-name{font-size:16px;letter-spacing:.05em;color:var(--bn);overflow-wrap:anywhere}
  .dsr-addr{font-size:12px;color:var(--sm);margin-top:3px}
  .dsr-score{flex:0 0 auto;width:72px;height:72px;border-radius:50%;display:grid;place-items:center;
    border:2px solid var(--ln);position:relative}
  .dsr-score.lo{border-color:#2b6f63;box-shadow:0 0 14px #5ff0d833}
  .dsr-score.mid{border-color:#c8902a;box-shadow:0 0 14px #f0b14a44}
  .dsr-score.hi{border-color:var(--em);box-shadow:0 0 18px #e2455566;animation:monpulse 1.8s ease-in-out infinite}
  .dsr-num{font-size:26px;font-weight:700;color:var(--bn);line-height:1;font-variant-numeric:tabular-nums}
  .dsr-lbl{font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:var(--sm);margin-top:2px}
  .dsr-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .dsr-tile{background:#0d0f16;border:1px solid var(--ln);border-radius:8px;padding:10px 12px;font-size:14px;color:var(--bn);display:flex;flex-direction:column;gap:3px}
  .dsr-tile.wide{grid-column:1 / -1}
  .dsr-tile.flag{border-color:#6a1f24;color:var(--em)}
  .dsr-tile b{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--sm);font-weight:600}
  .dsr-tile.flag b{color:var(--em)}
  .dsr-tile span{font-size:11px;color:var(--sm);overflow-wrap:anywhere}
  @media (prefers-reduced-motion: reduce){ #monitorbtn.on,.dsr-score.hi{animation:none} }

  /* traffic topology — R6 radar graph */
  .toposheet{width:min(560px,94vw);max-height:88vh;overflow:auto}
  .topo-wrap{position:relative;background:radial-gradient(circle at 50% 48%, #0c1119 0%, #06070b 70%);
    border:1px solid var(--ln);border-radius:10px;margin:4px 0 8px;min-height:240px;display:grid;place-items:center;overflow:hidden}
  .topo-wrap::before{content:"";position:absolute;inset:0;background:
    repeating-radial-gradient(circle at 50% 48%, transparent 0 38px, #5ff0d810 38px 39px);pointer-events:none}
  .topo-svg{width:100%;height:300px;display:block}
  .topo-edge{filter:drop-shadow(0 0 2px #5ff0d855);stroke-dasharray:5 6;animation:topoflow 1.1s linear infinite}
  @keyframes topoflow{to{stroke-dashoffset:-22}}
  .topo-node circle{filter:drop-shadow(0 0 5px #00000080)}
  .topo-node.gw circle{filter:drop-shadow(0 0 10px #e2455588);animation:monpulse 1.8s ease-in-out infinite}
  .topo-lbl{fill:var(--sm);font-size:9px;font-family:inherit;letter-spacing:.04em}
  .topo-lbl.gw{fill:var(--em)} .topo-lbl.me{fill:var(--gh)}
  .topo-load{color:var(--sm);font-size:13px;display:flex;align-items:center;gap:10px}
  .topo-spin{width:14px;height:14px;border:2px solid var(--ln);border-top-color:var(--gh);border-radius:50%;animation:spin .8s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .topo-cols{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:6px}
  .topo-h{font-size:10px;letter-spacing:.16em;color:var(--em);margin-bottom:6px}
  .tk-row{display:flex;justify-content:space-between;gap:8px;padding:5px 0;border-bottom:1px solid var(--ln);font-size:11px}
  .tk-pair{color:var(--bn);overflow-wrap:anywhere} .tk-pair i{color:var(--gh);font-style:normal}
  .tk-b{color:var(--gh);font-variant-numeric:tabular-nums;flex:0 0 auto}
  .pb-row{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:11px}
  .pb-name{flex:0 0 56px;color:var(--bn);text-transform:uppercase;letter-spacing:.06em;overflow:hidden;text-overflow:ellipsis}
  .pb-bar{flex:1;height:8px;background:#0d0f16;border:1px solid var(--ln);border-radius:5px;overflow:hidden}
  .pb-bar span{display:block;height:100%;background:linear-gradient(90deg,#2b6f63,#5ff0d8);box-shadow:0 0 8px #5ff0d855}
  .pb-v{flex:0 0 auto;color:var(--sm);font-variant-numeric:tabular-nums}
  @media (prefers-reduced-motion: reduce){ .topo-edge,.topo-node.gw circle,.topo-spin{animation:none} }
  @media (max-width:520px){ .topo-cols{grid-template-columns:1fr} }

  /* ---- v4: responsive / touch ---- */
  @media (max-width:960px){
    main{grid-template-columns:270px 1fr 128px}
    .mtab{font-size:14px;letter-spacing:.1em;padding:10px 14px}
    .stat{display:none}
  }
  @media (max-width:720px){
    .top{flex-wrap:wrap;gap:8px}
    .modetabs{order:1;width:100%}
    .mtab{flex:1;padding:12px 6px;min-height:52px}
    .mark{order:2} .uimode{order:2} .prog{order:3;width:100%}
    main{grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr) auto}
    .list{max-height:40vh;border-right:0;border-bottom:1px solid var(--ln)}
    .rail{flex-direction:row;overflow-x:auto;border-left:0;border-top:1px solid var(--ln)}
    .rail .op{min-width:92px;border-bottom:0;border-right:1px solid var(--ln)}
    .host{min-height:64px}
  }

  /* R6-style call takeover */
  .callscreen{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;z-index:6;overflow:hidden;pointer-events:none;
    background:radial-gradient(circle at 50% 40%, #20100f 0%, var(--scr) 70%)}
  .callscreen.show{display:flex}
  .cs-frame{pointer-events:none}
  .cs-grid{position:absolute;inset:0;pointer-events:none;opacity:.5;
    background-image:linear-gradient(#ff45331a 1px,transparent 1px),linear-gradient(90deg,#ff45331a 1px,transparent 1px);
    background-size:34px 34px;mask:radial-gradient(circle at 50% 42%,#000 0%,transparent 72%);-webkit-mask:radial-gradient(circle at 50% 42%,#000 0%,transparent 72%)}
  .cs-scanline{position:absolute;left:0;right:0;height:120px;pointer-events:none;opacity:0;
    background:linear-gradient(#ff45330a,#ff453326,#ff45330a)}
  .callscreen[data-state="scanning"] .cs-scanline{opacity:1;animation:csscan 2.6s linear infinite}
  @keyframes csscan{0%{transform:translateY(-130px)}100%{transform:translateY(105vh)}}
  .cs-frame{position:relative;display:flex;flex-direction:column;align-items:center;gap:13px;padding:44px 64px}
  .cs-bracket{position:absolute;width:30px;height:30px;border:2px solid var(--em)}
  .cs-bracket.tl{top:0;left:0;border-right:none;border-bottom:none}
  .cs-bracket.tr{top:0;right:0;border-left:none;border-bottom:none}
  .cs-bracket.bl{bottom:0;left:0;border-right:none;border-top:none}
  .cs-bracket.br{bottom:0;right:0;border-left:none;border-top:none}
  .callscreen[data-state="scanning"] .cs-bracket{animation:csbrk 1.1s ease-in-out infinite}
  @keyframes csbrk{50%{box-shadow:0 0 12px var(--em)}}
  .cs-eyebrow{font-size:11px;letter-spacing:.46em;color:var(--em);text-transform:uppercase}
  .cs-name{font-size:32px;font-weight:700;letter-spacing:.05em;color:var(--bn);text-align:center;line-height:1.05;max-width:460px;overflow-wrap:anywhere;text-shadow:0 0 18px #ff45334d}
  .cs-addr{font-size:14px;letter-spacing:.24em;color:var(--sm);margin-top:-5px}
  .cs-call{position:relative;width:148px;height:148px;border-radius:50%;margin:16px 0 6px;cursor:pointer;pointer-events:auto;
    display:flex;align-items:center;justify-content:center;color:var(--em);overflow:hidden;
    background:radial-gradient(circle,#ff45332e 0%,#ff45330d 70%);border:2px solid var(--em);
    box-shadow:0 0 34px #ff45334d, inset 0 0 26px #ff45331f}
  .cs-call:hover{box-shadow:0 0 52px #ff453388, inset 0 0 30px #ff45332e}
  .cs-call:active{transform:scale(.95)}
  .cs-ico{position:relative;z-index:2;display:flex}
  .cs-ico .ico{width:52px;height:52px}
  .cs-sweep{position:absolute;inset:0;border-radius:50%;opacity:0;
    background:conic-gradient(from 0deg, transparent 0deg, #ff45334d 38deg, transparent 70deg)}
  .callscreen[data-state="scanning"] .cs-sweep,.callscreen[data-state="sweeping"] .cs-sweep{opacity:1;animation:cspin 1.5s linear infinite}
  @keyframes cspin{100%{transform:rotate(360deg)}}
  .cs-ring{position:absolute;inset:-2px;border-radius:50%;border:2px solid var(--em);opacity:0;animation:csring 2.4s ease-out infinite;pointer-events:none}
  .cs-ring.r2{animation-delay:.8s}.cs-ring.r3{animation-delay:1.6s}
  @keyframes csring{0%{transform:scale(1);opacity:.6}100%{transform:scale(1.9);opacity:0}}
  .callscreen[data-state="scanning"] .cs-ring,.callscreen[data-state="sweeping"] .cs-ring{animation-duration:1.3s}
  .callscreen[data-state="scanning"] .cs-call,.callscreen[data-state="sweeping"] .cs-call{animation:csbeat 1s ease-in-out infinite}
  @keyframes csbeat{50%{box-shadow:0 0 62px #ff4533c0, inset 0 0 32px #ff45333a}}
  .cs-label{font-size:23px;font-weight:700;letter-spacing:.42em;color:var(--em);padding-left:.42em}
  .callscreen[data-state="scanning"] .cs-label,.callscreen[data-state="sweeping"] .cs-label{animation:csblink 1.1s steps(1) infinite}
  @keyframes csblink{50%{opacity:.5}}
  .cs-status{font-size:13px;letter-spacing:.22em;color:var(--em);text-transform:uppercase;min-height:17px}
  .cs-hint{font-size:12px;letter-spacing:.16em;color:var(--sm)}
  .cs-done{display:none;grid-template-columns:repeat(2,minmax(150px,200px));gap:10px;margin:4px 0 2px;max-width:440px}
  .callscreen[data-state="done"] .cs-done{display:grid}
  .callscreen[data-state="done"] .cs-status{display:none}
  .cs-tile{background:#0d1f1c;border:1px solid #5ff0d83a;border-left:3px solid var(--gh);border-radius:8px;padding:10px 12px;text-align:left;min-height:62px}
  .cs-tk{font-size:10px;letter-spacing:.26em;color:var(--gh);text-transform:uppercase}
  .cs-tv{font-size:18px;font-weight:700;color:var(--bn);line-height:1.1;margin-top:3px;overflow-wrap:anywhere}
  .cs-td{font-size:11px;letter-spacing:.06em;color:var(--sm);margin-top:3px;overflow-wrap:anywhere}
  .cs-tile.wide{grid-column:1 / -1}
  /* done: turns teal, rings stop */
  .callscreen[data-state="done"] .cs-call{color:var(--gh);border-color:var(--gh);
    background:radial-gradient(circle,#5ff0d82e 0%,#5ff0d80d 70%);box-shadow:0 0 36px #5ff0d84d, inset 0 0 26px #5ff0d81f}
  .callscreen[data-state="done"] .cs-ring,.callscreen[data-state="done"] .cs-sweep{display:none}
  .callscreen[data-state="done"] .cs-label,.callscreen[data-state="done"] .cs-status,
  .callscreen[data-state="done"] .cs-eyebrow,.callscreen[data-state="done"] .cs-name{color:var(--gh)}
  .callscreen[data-state="done"] .cs-name{text-shadow:0 0 18px #5ff0d84d}

  /* ---- enhanced R6 motion ---- */
  .cs-frame{z-index:2}
  /* faint CRT scanlines + flash live above the bg, below the frame */
  .callscreen::after{content:"";position:absolute;inset:0;pointer-events:none;z-index:1;
    background:repeating-linear-gradient(0deg,transparent 0 2px,#00000022 2px 3px)}
  .cs-flash{position:absolute;inset:0;pointer-events:none;z-index:4;opacity:0;background:var(--em);mix-blend-mode:screen}
  .cs-flash.go{animation:csflash .34s ease-out}
  @keyframes csflash{0%{opacity:0}12%{opacity:.22;transform:translateX(-3px)}26%{opacity:.05;transform:translateX(3px)}42%{opacity:.15}100%{opacity:0;transform:translateX(0)}}
  /* chromatic RGB-split glitch on the target name while live */
  .cs-name{position:relative}
  .cs-name::before,.cs-name::after{content:attr(data-text);position:absolute;left:0;top:0;width:100%;text-align:center;opacity:0;pointer-events:none}
  .callscreen[data-state="scanning"] .cs-name::before,.callscreen[data-state="sweeping"] .cs-name::before{opacity:.85;color:#ff2d6f;mix-blend-mode:screen;animation:glitchA .85s steps(2,end) infinite}
  .callscreen[data-state="scanning"] .cs-name::after,.callscreen[data-state="sweeping"] .cs-name::after{opacity:.85;color:#28e6ff;mix-blend-mode:screen;animation:glitchB .85s steps(2,end) infinite}
  @keyframes glitchA{0%,100%{transform:translate(0,0);clip-path:inset(0 0 62% 0)}33%{transform:translate(-2px,1px);clip-path:inset(42% 0 22% 0)}66%{transform:translate(2px,-1px);clip-path:inset(8% 0 70% 0)}}
  @keyframes glitchB{0%,100%{transform:translate(0,0);clip-path:inset(62% 0 0 0)}33%{transform:translate(2px,-1px);clip-path:inset(20% 0 42% 0)}66%{transform:translate(-2px,1px);clip-path:inset(72% 0 8% 0)}}
  /* frame + targeting-bracket snap-in when the takeover appears */
  .callscreen.show .cs-frame{animation:csframein .5s cubic-bezier(.2,.8,.2,1)}
  @keyframes csframein{0%{opacity:0;transform:scale(.965)}100%{opacity:1;transform:scale(1)}}
  .callscreen.show .cs-bracket{animation:csbrkin .55s cubic-bezier(.2,.9,.25,1) both}
  .cs-bracket.tl{--bx:-16px;--by:-16px}.cs-bracket.tr{--bx:16px;--by:-16px}
  .cs-bracket.bl{--bx:-16px;--by:16px}.cs-bracket.br{--bx:16px;--by:16px}
  @keyframes csbrkin{0%{opacity:0;transform:translate(var(--bx),var(--by))}70%{opacity:1}100%{opacity:1;transform:translate(0,0)}}
  /* done: staggered tile reveal + count-up handled in JS */
  .callscreen[data-state="done"] .cs-tile{animation:tilein .42s ease-out both}
  .cs-done .cs-tile:nth-child(1){animation-delay:.03s}.cs-done .cs-tile:nth-child(2){animation-delay:.11s}
  .cs-done .cs-tile:nth-child(3){animation-delay:.19s}.cs-done .cs-tile:nth-child(4){animation-delay:.27s}
  .cs-done .cs-tile:nth-child(5){animation-delay:.35s}
  @keyframes tilein{0%{opacity:0;transform:translateY(10px)}100%{opacity:1;transform:translateY(0)}}
  /* tactical segmented progress fill */
  .prog{box-shadow:0 0 8px var(--em)}
  .prog.run,.prog[style*="width"]{background-image:repeating-linear-gradient(90deg,var(--em) 0 7px,#ff45334d 7px 11px)}
  @media (prefers-reduced-motion: reduce){
    .cs-name::before,.cs-name::after,.cs-flash.go,.callscreen.show .cs-frame,.callscreen.show .cs-bracket,
    .callscreen[data-state="done"] .cs-tile{animation:none!important}
  }
</style>
</head>
<body>
<div id="boot">
  <svg class="boot-glyph" viewBox="0 0 120 120" fill="none" stroke="var(--em)" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true">
    <path class="g1" d="M60 14 L92 26 L96 60 Q96 96 60 110 Q24 96 24 60 L28 26 Z"/>
    <path class="g2" d="M34 40 Q46 34 56 42"/>
    <path class="g2" d="M86 40 Q74 34 64 42"/>
    <path class="tl2" d="M38 52 L54 56 L38 61 Z"/>
    <path class="tl2" d="M82 52 L66 56 L82 61 Z"/>
    <path class="g3" d="M44 80 Q60 90 76 80"/>
    <line class="g3" x1="60" y1="66" x2="60" y2="77"/>
  </svg>
  <div class="boot-title">DOKKOS</div>
  <div class="boot-sub">TACTICAL RECON CONSOLE</div>
  <div class="boot-log" id="bootlog"></div>
  <div class="boot-bar"><span id="bootbar"></span></div>
  <div class="boot-enter" id="bootenter">&#9656; TAP TO INITIALIZE</div>
</div>

<div class="corner tl"></div><div class="corner tr"></div><div class="corner bl"></div><div class="corner br"></div>
<div class="scanbeam"></div>
<div class="ambient tel-l" id="tell">LINK <b id="amlink">●</b> SECURE</div>
<div class="ambient tel-r" id="telr">UP <b id="amup">00:00</b> · PKT <b id="ampkt">0</b> · <b id="amstat">NOMINAL</b></div>

<div id="cmdk"><div class="cmdk-box">
  <input class="cmdk-in" id="cmdkin" placeholder="jump to… mode / scan / arp / dns / traffic / timeline / host" autocomplete="off" autocapitalize="off" spellcheck="false">
  <div class="cmdk-list" id="cmdklist"></div>
</div></div>

<div class="scr">
  <div class="top">
    <div class="modetabs" id="modetabs">
      <button class="mtab on" data-mode="net">${''}NETWORK</button>
      <button class="mtab" data-mode="bt">BLUETOOTH</button>
      <button class="mtab" data-mode="wifi">WI-FI</button>
    </div>
    <div class="spacer"></div>
    <div class="stat">Hosts <b id="hostcount">0</b></div>
    <div class="uimode" id="uimode">
      <button class="um" data-um="pro">PRO</button>
      <button class="um on" data-um="r6">R6</button>
    </div>
    <div class="mark" id="mark" title="command palette (Ctrl/Cmd+K)" style="cursor:pointer"><svg class="maskico" width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><path d="M9 12 L11 5 L14 12" fill="none" stroke="var(--em)" stroke-width="2" stroke-linejoin="round"/><path d="M23 12 L21 5 L18 12" fill="none" stroke="var(--em)" stroke-width="2" stroke-linejoin="round"/><path d="M7 12 Q16 10 25 12 L23 21 Q16 27 9 21 Z" fill="none" stroke="var(--em)" stroke-width="2" stroke-linejoin="round"/><path d="M11 16 l3 1 -3 1.5 Z" fill="var(--em)"/><path d="M21 16 l-3 1 3 1.5 Z" fill="var(--em)"/><path d="M13 21 q3 1.5 6 0" fill="none" stroke="var(--em)" stroke-width="1.4"/></svg> Dokk<span>OS</span><small id="ver">recon v4.5</small></div>
    <div class="prog" id="prog"></div>
  </div>


  <main>
    <section class="col list">
      <div class="lbl"><span id="listlabel">Hosts</span> <button class="scanbtn" id="discover">Scan</button>
        <button class="scanbtn alt" id="scanall" title="scan every discovered host in sequence">All</button>
        <button class="hdr-btn" id="mapbtn" title="network map" aria-label="network map"></button></div>
      <select id="scope" class="scope" aria-label="network scope"></select>
      <div id="wifinote" class="wifinote" style="display:none"></div>
      <div id="alertbar" class="alertbar" style="display:none"></div>
      <div id="callbar" class="callbar"></div>
      <div id="hosts"><div class="empty">Pick a scope, then tap Scan to sweep the network for live hosts.</div></div>
    </section>

    <section class="center">
      <div class="tcard" id="tcard">
        <div class="tcard-portrait">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M3 9h18M8 21h8M12 17v4"/></svg>
        </div>
        <div>
          <div class="tcard-name" id="tname">NO TARGET</div>
          <div class="tcard-sub" id="tsub">select a host from the list</div>
        </div>
        <div class="tcard-addr"><small id="taddrlabel">ADDRESS</small><span id="taddr">—</span></div>
        <div class="tcard-status"><span class="tcard-dot"></span><span id="tphase">standby</span></div>
        <button class="dossierbtn" id="dossierbtn" title="host dossier + threat score" style="display:none">DOSSIER</button>
      </div>
      <div class="ports" id="ports" style="display:none"></div>
      <pre class="out" id="out"><span class="hint">// 1. sweep the subnet  // 2. tap a host  // 3. run a scan or CALL
// only scan systems you own or are authorised to test.</span>
</pre>
      <div class="callscreen" id="callscreen">
        <div class="cs-grid"></div>
        <div class="cs-scanline"></div>
        <div class="cs-flash" id="csflash"></div>
        <div class="cs-frame">
          <span class="cs-bracket tl"></span><span class="cs-bracket tr"></span>
          <span class="cs-bracket bl"></span><span class="cs-bracket br"></span>
          <div class="cs-eyebrow" id="cseyebrow">incoming target</div>
          <div class="cs-name" id="csname">TARGET</div>
          <div class="cs-addr" id="csaddr">—</div>
          <button class="cs-call" id="bigcall" aria-label="call target">
            <span class="cs-sweep"></span>
            <span class="cs-ring"></span><span class="cs-ring r2"></span><span class="cs-ring r3"></span>
            <span class="cs-ico" id="csico"></span>
          </button>
          <div class="cs-label" id="cslabel">CALL</div>
          <div class="cs-status" id="csstatus"></div>
          <div class="cs-done" id="csdone"></div>
          <div class="cs-hint" id="cshint">tap to establish contact // run recon</div>
        </div>
      </div>
      <div class="dcard" id="dcard"><div class="dcard-in" id="dcardin"></div></div>
    </section>

    <section class="col rail" id="rail"></section>
  </main>

  <div class="bot">
    <div class="tools" id="tools"></div>
    <button class="stealth on" id="stealth" title="randomise our MAC on scans (nmap --spoof-mac 0)">STEALTH ON</button>
    <button class="gear" id="historybtn" aria-label="detection history" title="detection history / timeline"></button>
    <button class="gear" id="monitorbtn" aria-label="unattended watch" title="start unattended watch"></button>
    <button class="gear" id="reportbtn" aria-label="export report" title="export markdown report"></button>
    <button class="gear" id="gear" aria-label="settings"></button>
  </div>
</div>

<div class="modal" id="settings">
  <div class="sheet">
    <div class="sheet-head"><span>SETTINGS</span><button class="x" id="setclose" aria-label="close">✕</button></div>
    <label class="srow"><span>Default mode</span>
      <select id="set-ui"><option value="r6">R6 (graphics)</option><option value="pro">PRO (terminal)</option></select></label>
    <label class="srow"><span>Default scan</span>
      <select id="set-prof"></select></label>
    <label class="srow"><span>Stealth (random MAC)</span>
      <select id="set-stealth"><option value="on">on</option><option value="off">off</option></select></label>
    <label class="srow"><span>Sound &amp; haptics</span>
      <select id="set-sfx"><option value="on">on</option><option value="off">off</option></select></label>
    <label class="srow"><span>Monitor interface</span>
      <input id="set-wlan" placeholder="wlan0mon" autocomplete="off"></label>
    <label class="srow"><span>Alert webhook</span>
      <input id="set-webhook" placeholder="https://ntfy.sh/your-topic" autocomplete="off"></label>
    <label class="srow"><span>Watch interval (s)</span>
      <input id="set-interval" type="number" min="30" max="3600" placeholder="120" autocomplete="off"></label>
    <div class="srow-note">Mode / scan / stealth are saved on this device. Monitor interface, webhook &amp; interval apply to the running server. Webhook supports ntfy, Slack &amp; Discord URLs.</div>
    <button class="save alt" id="setreset">RESET DETECTION BASELINES</button>
    <button class="save" id="setsave">SAVE</button>
  </div>
</div>
<div class="toast" id="toast"></div>

<div class="modal" id="mapmodal">
  <div class="sheet mapsheet">
    <div class="sheet-head"><span>NETWORK MAP</span><button class="x" id="mapclose" aria-label="close">✕</button></div>
    <div id="mapwrap" class="mapwrap"></div>
    <div class="maprow">
      <div class="maplegend">
        <span class="lg idle">idle</span><span class="lg scanned">scanned</span><span class="lg vuln">vulns</span>
      </div>
      <div id="mapmeta" class="mapmeta"></div>
    </div>
  </div>
</div>

<div class="modal" id="report">
  <div class="sheet">
    <div class="sheet-head"><span>EXPORT REPORT</span><button class="x" id="rpclose" aria-label="close">✕</button></div>
    <div class="srow-note" id="rpcount"></div>
    <button class="save alt" id="rphost">EXPORT SELECTED HOST (.md)</button>
    <button class="save" id="rpsess">EXPORT FULL SESSION (.md)</button>
    <div class="rprow">
      <button class="save alt half" id="rpsnap">SAVE SNAPSHOT</button>
      <button class="save alt half" id="rpdiff">DIFF vs SNAPSHOT</button>
    </div>
    <button class="save alt" id="rppcap">CAPTURE .PCAP (10s → Wireshark)</button>
    <div class="srow-note">Markdown reports download to this device. Snapshot + diff track how the network changes between scans.</div>
  </div>
</div>

<div class="modal" id="timeline">
  <div class="sheet tlsheet">
    <div class="sheet-head"><span>DETECTION TIMELINE</span><button class="x" id="tlclose" aria-label="close">✕</button></div>
    <div class="tl-body-wrap" id="tlbody"></div>
    <button class="save alt" id="tlclear">CLEAR HISTORY</button>
  </div>
</div>

<div class="modal" id="drawer">
  <div class="sheet dsrsheet">
    <div class="sheet-head"><span>HOST DOSSIER</span><button class="x" id="drclose" aria-label="close">✕</button></div>
    <div id="dossier"></div>
  </div>
</div>

<div class="modal" id="topo">
  <div class="sheet toposheet">
    <div class="sheet-head"><span>TRAFFIC TOPOLOGY</span><button class="x" id="topoclose" aria-label="close">✕</button></div>
    <div id="topobody" class="topo-wrap"></div>
    <div id="topometa" class="mapmeta"></div>
    <div class="topo-cols">
      <div class="topo-col"><div class="topo-h">TOP TALKERS</div><div id="topolist"></div></div>
      <div class="topo-col"><div class="topo-h">PROTOCOLS</div><div id="topoproto"></div></div>
    </div>
    <div class="srow-note">Passive capture on your LAN interface. Edges = who talked to whom; <span style="color:var(--em)">red</span> = gateway, <span style="color:var(--gh)">teal</span> = this device.</div>
  </div>
</div>

<div class="modal" id="huntmodal">
  <div class="sheet huntsheet">
    <div class="sheet-head"><span>RSSI HUNT</span><button class="x" id="huntclose" aria-label="close">✕</button></div>
    <div class="hunt-target" id="hunttarget">—</div>
    <div class="hunt-meter"><div class="hunt-fill" id="huntfill"></div></div>
    <div class="hunt-val" id="huntval">— dBm</div>
    <div class="hunt-label" id="huntlabel">listening…</div>
    <div class="srow-note">Walk around — the bar rises as you get closer. Passive: it only listens for the device's signal.</div>
  </div>
</div>

<script>
const ICONS={
  phone:'<path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a1 1 0 0 1-1 1A16 16 0 0 1 3 5a1 1 0 0 1 1-1z"/>',
  stop:'<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
  radar:'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="1.5"/><path d="M12 12l7-4"/>',
  wifi:'<path d="M4 9a14 14 0 0 1 16 0"/><path d="M7.5 12.5a9 9 0 0 1 9 0"/><path d="M10.5 16a4 4 0 0 1 3 0"/><circle cx="12" cy="19" r=".5"/>',
  antenna:'<path d="M12 9v11"/><circle cx="12" cy="6" r="2"/><path d="M7 8a6 6 0 0 1 10 0"/>',
  network:'<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M11 7l-5 9.5"/><path d="M13 7l5 9.5"/>',
  caret:'<path d="M9 6l6 6-6 6"/>',
  square:'<rect x="5" y="5" width="14" height="14" rx="1.5"/>',
  bt:'<path d="M6.5 8.5L17.5 15.5L12 20L12 4L17.5 8.5L6.5 15.5"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  shield:'<path d="M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z"/>',
  chip:'<rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  layers:'<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
  terminal:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
  gear:'<circle cx="12" cy="12" r="3.2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1"/>',
  router:'<rect x="3" y="12" width="18" height="8" rx="2"/><path d="M7 16h.01"/><path d="M11 16h3"/><path d="M9 9a4 4 0 0 1 6 0M6.5 6.5a8 8 0 0 1 11 0"/>',
  server:'<rect x="4" y="4" width="16" height="7" rx="1"/><rect x="4" y="13" width="16" height="7" rx="1"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>',
  desktop:'<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>',
  printer:'<path d="M7 9V3h10v6"/><rect x="4" y="9" width="16" height="7" rx="1.5"/><path d="M7 14h10v6H7z"/>',
  tv:'<rect x="3" y="7" width="18" height="12" rx="1.5"/><path d="M8 3l4 3 4-3"/>',
  map:'<path d="M9 4L3 6v14l6-2 6 2 6-2V4l-6 2-6-2z"/><path d="M9 4v14M15 6v14"/>',
  download:'<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 20h14"/>',
  history:'<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 4v4h4"/><path d="M12 8v4l3 2"/>',
  bell:'<path d="M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6"/><path d="M10 20a2 2 0 0 0 4 0"/>',
  lock:'<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  alert:'<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17v.5"/>',
  pulse:'<path d="M3 12h4l2-6 4 14 2-8h6"/>',
  phone:'<path d="M6 3h4l2 5-3 2a11 11 0 0 0 5 5l2-3 5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 4 5a2 2 0 0 1 2-2"/>'
};
const I=(n,s=22)=>`<svg class="ico" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]||''}</svg>`;
function hostIcon(h){
  const ip=h.addr||"";
  if(/\.1$/.test(ip)) return 'router';
  const v=((h.vendor||"")+" "+(h.os||"")+" "+(h.label||"")).toLowerCase();
  if(/apple|iphone|ipad|samsung|xiaomi|redmi|huawei|honor|oneplus|pixel|android|oppo|vivo|mobile/.test(v)) return 'phone';
  if(/router|gateway|mikrotik|ubiquiti|tp-link|tplink|netgear|asus|cisco|fortinet|openwrt|d-link|zyxel/.test(v)) return 'router';
  if(/printer|laserjet|officejet|canon|epson|brother|lexmark/.test(v)) return 'printer';
  if(/roku|chromecast|firetv|fire tv|appletv|apple tv|\btv\b|vizio|bravia/.test(v)) return 'tv';
  if(/server|nas|synology|qnap|proxmox|vmware|esxi|ubuntu|debian|centos|raspberr/.test(v)) return 'server';
  if(/windows|microsoft|dell|lenovo|hp |acer|desktop/.test(v)) return 'desktop';
  if(/esp32|esp8266|espressif|arduino|tuya|sonoff|shelly|iot/.test(v)) return 'chip';
  return 'square';
}

const NET_SCANS = [
  {id:"quick",    en:"Quick"},
  {id:"services", en:"Services"},
  {id:"full",     en:"All Ports"},
  {id:"os",       en:"OS Detect"},
  {id:"vuln",     en:"Vulns"},
  {id:"deep",     en:"Full Recon"},
];
const BT_SCANS = [
  {id:"info",     en:"Info"},
  {id:"services", en:"Services"},
  {id:"ping",     en:"L2 Ping"},
  {id:"vuln",     en:"Vuln"},
];
const TOOLS = [
  {id:"metasploit",en:"metasploit",icon:"terminal"},
  {id:"airgeddon", en:"airgeddon", icon:"wifi"},
  {id:"wifite",    en:"wifite",    icon:"antenna"},
  {id:"bettercap", en:"bettercap", icon:"network"},
  {id:"bluing",    en:"bluing",    icon:"bt"},
  {id:"sqlmap",    en:"sqlmap",    icon:"chip"},
  {id:"nikto",     en:"nikto",     icon:"search"},
  {id:"hydra",     en:"hydra",     icon:"shield"},
];

const $ = s => document.querySelector(s);
const out=$("#out"), prog=$("#prog"), toast=$("#toast"),
      callscreen=$("#callscreen"), bigcall=$("#bigcall"),
      tcard=$("#tcard"), tname=$("#tname"), tsub=$("#tsub"), taddr=$("#taddr"), tphase=$("#tphase");
let hosts=[], selected=null, mode="net", profile="deep", running=false, ctrl=null, scopes=[];
let lastWifi={aps:[],clients:[]}, scanHost=null, stealth=true, gen=0, wlanMon=null, called=false;
let uiMode="r6", scanPhase=null, scanPct=0, defProfile="deep";
let session={};   // addr -> captured scan findings (for the map + export)
let detailView=false, huntActive=false, huntCtrl=null;
let picked=new Set();   // multi-target "call" selection

const scanSet     = () => mode==="net" ? NET_SCANS : (mode==="bt" ? BT_SCANS : []);
const defaultProf = () => mode==="net" ? defProfile : "info";
const deepProf    = () => mode==="net" ? "deep" : "vuln";

$("#tools").innerHTML = TOOLS.map(t=>`<button class="tool" data-tool="${t.id}">${I(t.icon,14)}${t.en}</button>`).join("");

function scanCounts(){
  const t=out.textContent;
  const g=re=>(t.match(re)||[])[1];
  return {ports:g(/OPEN PORTS \((\d+)\)/), vulns:g(/VULNERABILITIES \((\d+)\)/), cves:g(/CVES \((\d+)\)/)};
}
function esc(x){ return String(x==null?"":x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function parseSummary(){
  // Only parse the appended SUMMARY block — not nmap's raw stream, whose footer
  // ("OS and Service detection performed. Please report…") otherwise hijacks the OS field.
  const raw=out.textContent;
  const si=raw.lastIndexOf("SUMMARY");
  const t = si>=0 ? raw.slice(si) : raw, one=re=>{const m=t.match(re);return m?m[1].trim():null;};
  const dev=t.match(/^DEVICE\s+(\S+)(?:\s+(.+))?/m);
  let vendor=null; if(dev&&dev[2]){ const vm=dev[2].match(/\(([^)]+)\)/); if(vm) vendor=vm[1]; }
  let os=one(/^OS\s+(.+)/m);
  if(os&&/undetermined|Service detection performed|nmap\.org\/submit/i.test(os)) os=null;
  const osd=one(/^OS\s+.+\n\s+(?!guess:)(.+)/m);
  const ports=[]; const pre=/^\s*(\d+)\/(tcp|udp)\s+(\S+)/gm; let pm;
  while((pm=pre.exec(t))) ports.push(pm[1]+"/"+pm[3]);
  return {device:dev?dev[1]:null, vendor, os, osd, ports,
          portCount:one(/OPEN PORTS \((\d+)\)/)||String(ports.length),
          vulns:one(/VULNERABILITIES \((\d+)\)/)||"0",
          cves:one(/CVES \((\d+)\)/), topcve:one(/CVES \(\d+\)\n\s+(CVE-\d{4}-\d+)/)};
}
function tile(k,v,d,wide){
  const num = /^\d+$/.test(String(v)) ? ` data-num="${v}"` : "";
  return `<div class="cs-tile${wide?' wide':''}"><div class="cs-tk">${esc(k)}</div>`+
  `<div class="cs-tv"${num}>${esc(v)}</div>${d?`<div class="cs-td">${esc(d)}</div>`:""}</div>`; }
function doneTiles(){
  const s=parseSummary(), out=[];
  if(s.os) out.push(tile("os", s.os, s.osd, true));
  out.push(tile("open ports", s.portCount, s.ports.length?(s.ports.slice(0,4).join(", ")+(s.ports.length>4?" …":"")):""));
  out.push(tile("vulns", s.vulns));
  if(s.cves) out.push(tile("cves", s.cves, s.topcve));
  if(s.vendor) out.push(tile("vendor", s.vendor));
  return out.join("");
}
function setProg(p){ scanPct=p; prog.classList.remove("run"); prog.style.width=Math.max(2,Math.min(99,p))+"%"; }
function parseProgress(t){
  let ph=null;
  if(/OS detection|Initiating OS/i.test(t)) ph="identifying os";
  else if(/NSE:|Script scan|script scanning|Scanning .* scripts/i.test(t)) ph="running scripts · cve check";
  else if(/Service scan|Initiating Service/i.test(t)) ph="fingerprinting services";
  else if(/SYN Stealth|Connect Scan|Initiating .*Scan/i.test(t)) ph="probing ports";
  else if(/Ping Scan|ARP Ping|host discovery|Initiating Ping/i.test(t)) ph="locating host";
  else if(/RSSI|UUID|bluetoothctl|ManufacturerData/i.test(t)) ph="enumerating device";
  if(ph) scanPhase=ph;
  const m=t.match(/([\d.]+)%\s*done/g);
  if(m){ const v=parseFloat(m[m.length-1]); if(!isNaN(v)) setProg(v); }
  if(running) updateCallScreen();
}
const GLYPHS="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#%&/<>*+=";
function decodeText(el, text, dur){
  if(!el) return;
  text=String(text); el.dataset.text=text;
  if(window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches){ el.textContent=text; return; }
  dur=dur||500;
  const token=(el._dt=(el._dt||0)+1), n=text.length, start=performance.now();
  (function frame(t){
    if(el._dt!==token) return;
    const p=Math.min(1,(t-start)/dur), reveal=Math.floor(p*n);
    let s="";
    for(let i=0;i<n;i++){ const c=text[i];
      s += (c===" "||i<reveal) ? c : GLYPHS[(Math.random()*GLYPHS.length)|0]; }
    el.textContent=s;
    if(p<1) requestAnimationFrame(frame); else el.textContent=text;
  })(start);
}
let _csName="";
function setCsName(text){
  const el=$("#csname"); if(!el) return;
  if(text===_csName){ el.dataset.text=text; return; }
  _csName=text; decodeText(el, text);
}
function animateCounts(){
  if(window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  document.querySelectorAll("#csdone .cs-tv[data-num]").forEach(el=>{
    const target=+el.dataset.num; if(!isFinite(target)||target<=0) return;
    const dur=560, start=performance.now();
    (function f(t){ const p=Math.min(1,(t-start)/dur);
      el.textContent=Math.round(target*(1-Math.pow(1-p,3)));
      if(p<1) requestAnimationFrame(f); else el.textContent=el.dataset.num;
    })(start);
  });
}
let _csState="";
function flashCs(){ const f=$("#csflash"); if(!f) return; f.classList.remove("go"); void f.offsetWidth; f.classList.add("go"); }
function csIco(n){ const e=$("#csico"); if(e) e.innerHTML=I(n,52); }
function updateCallScreen(){
  // Detail/stream actions write to the terminal — hide overlays, show raw output.
  if(detailView){ callscreen.classList.remove("show"); showDcard(false); return; }
  // Wi-Fi with an AP selected -> its details/terminal view.
  if(mode==="wifi" && selected!==null){ callscreen.classList.remove("show"); showDcard(false); return; }
  // v4.2: a selected net/bt target at rest -> the dossier + CALL card (R6 graphic mode).
  if(uiMode==="r6" && selected!==null && !running){
    renderDcard(); showDcard(true); callscreen.classList.remove("show"); return;
  }
  showDcard(false);
  const sel = selected!==null;
  const state = !sel ? (running ? "sweeping" : "sweep")
                     : (running ? "scanning" : (called ? "done" : "idle"));
  // Pro mode only shows the static action prompts; R6 keeps the graphic up throughout.
  const show = (uiMode==="r6") ? true : (state==="idle" || state==="sweep");
  callscreen.classList.toggle("show", show);
  if(!show) return;
  callscreen.dataset.state = state;
  const csChanged = state!==_csState;
  if(csChanged){ flashCs(); _csState=state; }
  if(sel){
    setCsName((hosts[selected].label||"").toUpperCase() || hosts[selected].addr);
    $("#csaddr").textContent = hosts[selected].addr;
  } else {
    setCsName(mode==="net" ? "NETWORK" : (mode==="bt" ? "BLUETOOTH" : "WI-FI"));
    $("#csaddr").textContent = mode==="net" ? (scopes.join("  ")||"no scope") : "in range";
  }
  if(state==="sweep"){
    csIco('radar');
    $("#cseyebrow").textContent="ready";
    $("#cslabel").textContent = mode==="net" ? "SWEEP" : "SCAN";
    $("#csstatus").textContent="";
    $("#cshint").textContent="tap to sweep for "+(mode==="net"?"live hosts":mode==="bt"?"devices":"access points");
  } else if(state==="sweeping"){
    csIco('radar');
    $("#cseyebrow").textContent="sweeping";
    $("#cslabel").textContent = mode==="net" ? "SWEEPING" : "SCANNING";
    $("#csstatus").textContent = mode==="net" ? "locating live hosts" : "listening";
    $("#cshint").textContent="tap to abort";
  } else if(state==="scanning"){
    csIco(mode==="bt"?'bt':'radar');
    $("#cseyebrow").textContent="link active";
    $("#cslabel").textContent="CALLING";
    $("#csstatus").textContent=(scanPhase||"establishing link")+(scanPct?("  ·  "+Math.round(scanPct)+"%"):"");
    $("#cshint").textContent="tap to abort";
  } else if(state==="done"){
    csIco('phone');
    $("#cseyebrow").textContent="link complete";
    $("#cslabel").textContent="COMPLETE";
    if(csChanged || !$("#csdone").children.length){ $("#csdone").innerHTML=doneTiles(); animateCounts(); }
    $("#cshint").textContent="tap to re-scan  //  switch to PRO for full output";
  } else {
    csIco('phone');
    $("#cseyebrow").textContent = mode==="bt" ? "incoming device" : "incoming target";
    $("#cslabel").textContent="CALL";
    $("#csstatus").textContent="";
    $("#cshint").textContent="tap to establish contact // run recon";
  }
}
function setUiMode(m){
  uiMode=m;
  document.querySelectorAll("[data-um]").forEach(b=>b.classList.toggle("on",b.dataset.um===m));
  updateCallScreen();
}
function showDcard(on){
  const d=$("#dcard"); if(d) d.classList.toggle("show",!!on);
  const o=$("#out"); if(o) o.style.display = on?"none":"";
  const tc=$("#tcard"); if(tc) tc.style.display = on?"none":"";
  if(on){ const p=$("#ports"); if(p) p.style.display="none"; }
}
function deselect(){ selected=null; called=false; detailView=false; SFX.tick(); renderCard(); renderRail(); renderHosts(); updateCallScreen(); }
function renderDcard(){
  if(selected===null) return;
  const h=hosts[selected], r=session[h.addr]||{};
  const scanned = !!(r.os||r.ports||r.portCount||r.scanned);
  if(!h.bt && !h.wifi) scanHost = h.addr;   // enable port drill-down from the card
  const ico = h.wifi?'wifi':(h.bt?'bt':hostIcon(h));
  const sc=threatScore(h), band=threatBand(sc);
  const sub = h.vendor || (h.wifi?"access point":(h.bt?"bluetooth device":"network host"));
  const originLbl = h.wifi?"BSSID":(h.bt?"BT ADDRESS":"ADDRESS");
  const verb = scanned ? "RE-CALL" : "CALL";
  const portChips = (r.ports&&r.ports.length)
    ? `<div class="dc-tile wide"><b>services · tap a port to dig</b><div class="dc-ports">`+
      r.ports.map(p=>{const a=p.split("/");return `<button class="dc-port" data-port="${esc(a[0])}" data-svc="${esc(a[1]||'')}">${esc(a[0])}<small>${esc(a[1]||'')}</small></button>`;}).join("")+
      `</div></div>` : "";
  const grid = scanned ? `
    <div class="dc-grid">
      <div class="dc-tile"><b>open ports</b><span class="dc-n">${esc(r.portCount||(r.ports?r.ports.length:0)||0)}</span></div>
      <div class="dc-tile"><b>vulns</b><span class="dc-n${(+r.vulns>0)?' hot':''}">${esc(r.vulns||0)}</span></div>
      <div class="dc-tile"><b>threat</b><span class="dc-n dc-${band}">${sc}</span></div>
      ${r.os?`<div class="dc-tile wide"><b>os</b><span>${esc(r.os)}</span></div>`:""}
      ${portChips}
    </div>` : `<div class="dc-empty">NO RECON ON FILE — tap <b>CALL</b> to establish contact and pull a full profile.</div>`;
  $("#dcardin").innerHTML=`
    <div class="dc-scan"></div>
    <div class="dc-head">
      <div class="dc-portrait${h.isNew?' new':''}">${I(ico,42)}</div>
      <div class="dc-id">
        <div class="dc-name">${esc((h.label||"").toUpperCase()||h.addr)}</div>
        <div class="dc-sub">${esc(sub)}</div>
        <div class="dc-origin"><small>${originLbl}</small> ${esc(h.addr)}</div>
      </div>
      ${(h.isNew||h.suspicious||h.spam)?`<div class="dc-flag">${h.isNew?"NEW":"⚠"}</div>`:""}
    </div>
    ${grid}
    <div class="dc-actions">
      <button class="dc-call" id="dcall">${I('phone',18)} ${verb}</button>
      <button class="dc-cancel" id="dcancel">CANCEL</button>
      ${scanned?`<button class="dc-more" id="dout">OUTPUT</button>`:""}
      ${scanned?`<button class="dc-more" id="dmore">DOSSIER ▸</button>`:""}
    </div>`;
}

/* ---- settings + on-device prefs ---- */
const PK="dokkos:";
function getPref(k,d){ try{ const v=localStorage.getItem(PK+k); return v===null?d:v; }catch(e){ return d; } }
function setPref(k,v){ try{ localStorage.setItem(PK+k,v); }catch(e){} }
function reflectStealth(){ const b=$("#stealth"); b.classList.toggle("on",stealth); b.textContent=stealth?"STEALTH ON":"STEALTH OFF"; }
function loadPrefs(){
  uiMode   = getPref("ui","r6");
  stealth  = getPref("stealth","on")==="on";
  defProfile = getPref("prof","deep");
  profile  = mode==="net" ? defProfile : defaultProf();
  document.querySelectorAll("[data-um]").forEach(b=>b.classList.toggle("on",b.dataset.um===uiMode));
  reflectStealth();
}
function openSettings(){
  $("#set-ui").value     = uiMode;
  $("#set-prof").value   = defProfile;
  $("#set-stealth").value= stealth ? "on" : "off";
  $("#set-sfx").value = SFX.on ? "on" : "off";
  $("#set-wlan").value   = wlanMon || "";
  fetch("/api/monitor/status").then(r=>r.json()).then(d=>{
    $("#set-interval").value = d.interval||120;
  }).catch(()=>{});
  $("#set-webhook").value = webhookUrl || "";
  $("#settings").classList.add("show");
}
function closeSettings(){ $("#settings").classList.remove("show"); }
async function resetBaselines(){
  try{
    await fetch("/api/state/reset",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({what:"all"})});
    showToast("detection baselines cleared");
  }catch(e){ showToast("reset failed"); }
}
let webhookUrl="";
async function saveSettings(){
  uiMode     = $("#set-ui").value;       setPref("ui",uiMode);
  defProfile = $("#set-prof").value;      setPref("prof",defProfile);
  stealth    = $("#set-stealth").value==="on"; setPref("stealth",stealth?"on":"off");
  SFX.on = $("#set-sfx").value==="on"; localStorage.setItem("dokkos:sfx", SFX.on?"on":"off"); if(SFX.on){ SFX.unlock(); SFX.select(); }
  reflectStealth();
  if(mode==="net"){ profile=defProfile; }
  setUiMode(uiMode); renderRail();
  const w=$("#set-wlan").value.trim();
  const wh=$("#set-webhook").value.trim();
  const iv=parseInt($("#set-interval").value,10);
  const body={wlan_mon:w, webhook:wh};
  if(isFinite(iv)) body.monitor_interval=iv;
  try{
    const r=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json(); if(d.ok){ wlanMon=d.wlan_mon||null; webhookUrl=d.webhook||""; renderWifiNote(); }
    else if(d.error){ showToast(d.error); return; }
  }catch(e){}
  closeSettings(); showToast("settings saved");
}

const SCAN_ICONS={quick:'radar',services:'network',full:'layers',os:'chip',vuln:'shield',deep:'radar',
                  info:'search',ping:'antenna'};
function renderTabs(){ renderRail(); }   // scan menu now lives in the rail
function renderRail(){
  if(mode==="wifi"){
    const sel = selected!==null;
    $("#rail").innerHTML =
      `<button class="op${monMode?' on':''}" id="monmode">${I('antenna')}MON: ${monMode?'ON':'OFF'}</button>`+
      `<button class="op" id="rescan">${I('radar')}Rescan</button>`+
      `<button class="op" id="details">${I('search')}Details</button>`+
      `<button class="op" id="stationsbtn">${I('antenna')}Stations</button>`+
      `<button class="op" id="hunt"${sel?'':' disabled'}>${I('radar')}Hunt</button>`+
      `<button class="op" id="probe">${I('antenna')}Probe Watch</button>`+
      `<button class="op" id="deauth1">${I('shield')}Deauth 10s</button>`+
      `<button class="op" id="deauthmon">${I('antenna')}Deauth Watch</button>`+
      `<button class="op" id="abort">${I('stop')}Abort</button>`;
    return;
  }
  const locked = selected===null || running;
  const btns = scanSet().map(s=>
    `<button class="op${s.id===profile?' on':''}" data-scan="${s.id}"${locked?' disabled':''}>`+
    `${I(SCAN_ICONS[s.id]||'radar')}${s.en}</button>`).join("");
  let extra="";
  if(mode==="net") extra =
      `<button class="op" id="webbanner"${locked?' disabled':''}>${I('search')}Web</button>`+
      `<button class="op" id="mdnsbtn"${locked?' disabled':''}>${I('network')}Services</button>`+
      `<button class="op" id="arpscan"${running?' disabled':''}>${I('alert')}ARP Watch</button>`+
      `<button class="op" id="dhcpscan"${running?' disabled':''}>${I('alert')}DHCP Check</button>`+
      `<button class="op" id="dnsbtn"${running?' disabled':''}>${I('network')}DNS Sniff</button>`+
      `<button class="op" id="trafficbtn"${running?' disabled':''}>${I('pulse')}Traffic</button>`;
  else if(mode==="bt") extra =
      `<button class="op" id="gatt"${locked?' disabled':''}>${I('chip')}GATT</button>`+
      `<button class="op" id="hunt"${locked?' disabled':''}>${I('radar')}Hunt</button>`;
  $("#rail").innerHTML = btns + extra + `<button class="op" id="abort">${I('stop')}Abort</button>`;
}
function clearPorts(){ const b=$("#ports"); b.innerHTML=""; b.style.display="none"; }
function renderWifiNote(){
  const n=$("#wifinote");
  if(mode!=="wifi"){ n.style.display="none"; return; }
  const ifc=wlanMon||"wlan0mon";
  n.style.display="";
  n.innerHTML =
    `<b>monitor mode</b> · <code>${ifc}</code>`+
    `<div class="cmd2">enable: <code>sudo airmon-ng start wlan0</code></div>`+
    `<div class="cmd2">back to managed: <code>sudo airmon-ng stop ${ifc}</code> &amp;&amp; <code>sudo systemctl restart NetworkManager</code></div>`;
}
function setMode(m){
  if(m===mode) return;
  gen++;                                  // invalidate any in-flight discovery
  if(running){ try{ if(ctrl) ctrl.abort(); }catch(e){} setRunning(false); }
  mode=m; profile=defaultProf(); hosts=[]; selected=null; called=false; detailView=false; picked.clear(); clearPorts();
  document.querySelectorAll("[data-mode]").forEach(b=>b.classList.toggle("on",b.dataset.mode===m));
  $("#listlabel").textContent = m==='net' ? "Hosts" : (m==='bt' ? "Devices" : "Access Points");
  $("#discover").textContent  = m==='net' ? "Scan" : (m==='bt' ? "BT Scan" : "Wi-Fi Scan");
  $("#mapbtn").style.display = m==='net' ? "" : "none";
  $("#scanall").style.display = m==='net' ? "" : "none";
  clearAlert();
  $("#scope").style.display   = m==='net' ? "" : "none";
  renderWifiNote();
  renderTabs(); renderRail(); renderHosts(); renderCard(); updateCallScreen();
}

function setPhase(t,on){ tphase.textContent=t; tcard.classList.toggle("calling",!!on); }
function renderCard(){
  const has = selected!==null, h = has?hosts[selected]:null;
  tname.textContent = has ? (h.label||"").toUpperCase() : "NO TARGET";
  tsub.textContent  = has ? h.sub : "select a target from the list";
  taddr.textContent = has ? h.addr : "—";
  $("#taddrlabel").textContent = has ? (h.wifi?"BSSID":(h.bt?"BT ADDR":"ADDRESS")) : "ADDRESS";
  tcard.classList.toggle("active", has);
  const db=$("#dossierbtn"); if(db) db.style.display = (has && !h.wifi) ? "" : "none";
}
function setRunning(v){
  running=v;
  if(v){ scanPhase=null; scanPct=0; prog.style.width=""; prog.classList.add("run"); }
  else { prog.classList.remove("run"); prog.style.width="100%"; setTimeout(()=>{ if(!running) prog.style.width="0"; },650); }
  setPhase(v ? "calling…" : (selected!==null ? "ready" : "standby"), v);
  renderRail(); updateCallScreen();
}
function showToast(msg){ toast.textContent=msg; toast.classList.add("show"); setTimeout(()=>toast.classList.remove("show"),2600); }
let alertAction=null;
function setAlert(text, actionLabel, fn, level){
  SFX.alert(); haptic([20,40,20]);
  alertAction = fn || null;
  const bar=$("#alertbar");
  bar.className = "alertbar" + (level==="warn" ? " warn" : "");
  bar.innerHTML = `<span>${esc(text)}</span>` + (actionLabel ? `<button class="albtn" data-alert>${esc(actionLabel)}</button>` : "");
  bar.style.display="";
}
function clearAlert(){ const b=$("#alertbar"); b.style.display="none"; b.innerHTML=""; alertAction=null; }
function write(t,cls){ const n=document.createElement("span"); if(cls)n.className=cls; n.textContent=t; out.appendChild(n); out.scrollTop=out.scrollHeight; }
function cursor(on){ const o=out.querySelector(".cursor"); if(o)o.remove(); if(on){const c=document.createElement("span");c.className="cursor";out.appendChild(c);} }

function renderHosts(){
  $("#hostcount").textContent = hosts.length;
  const box=$("#hosts");
  const empty = mode==='net' ? 'No live hosts yet — pick a scope and tap Scan.'
              : mode==='bt'  ? 'No devices yet — tap BT Scan (needs a Bluetooth adapter, powered on).'
              :                'No APs yet — tap Wi-Fi Scan (needs a monitor-mode interface).';
  if(!hosts.length){ box.innerHTML=`<div class="empty">${empty}</div>`; renderCallbar(); return; }
  box.innerHTML = hosts.map((h,i)=>{
    const ico = selected===i ? 'caret' : (h.wifi ? 'wifi' : (h.bt ? 'bt' : hostIcon(h)));
    let flag='';
    if(h.isNew) flag+='<span class="newbadge">NEW</span>';
    if(h.suspicious||h.spam) flag+=`<span class="warnbadge" title="${esc(h.reason||(h.spam?'possible BLE flood':'suspicious'))}">⚠</span>`;
    if(h.vulns>0) flag+='<span class="vdot" title="vulnerabilities found"></span>';
    else if(h.scanned) flag+='<span class="sdot" title="scanned"></span>';
    const pk=picked.has(i);
    return `<div class="host${selected===i?' on':''}${pk?' picked':''}${h.active?' act':''}">
      <button class="pick${pk?' on':''}" data-pick="${i}" aria-label="mark for call">${pk?'✓':''}</button>
      <button class="hbody" data-i="${i}">${I(ico,16)}
        <span><span class="hn">${esc(h.label)}${flag}</span><span class="hv">${esc(h.sub)}</span></span></button></div>`;
  }).join("");
  renderCallbar();
}
function togglePick(i){
  if(picked.has(i)) picked.delete(i); else picked.add(i);
  SFX.tick(); haptic(6);
  renderHosts();
}
function clearPicked(){ picked.clear(); renderHosts(); }
function renderCallbar(){
  const bar=$("#callbar"); if(!bar) return;
  const n=picked.size;
  if(!n){ bar.classList.remove("show"); bar.innerHTML=""; return; }
  const verb = mode==='net' ? 'SCAN' : (mode==='bt' ? 'CALL' : 'TARGET');
  bar.innerHTML = `${I('phone',18)}<b>${n} TARGET${n>1?'S':''} MARKED</b>`+
    `<button class="cclr" id="callclr">CLEAR</button>`+
    `<button class="cbtn" id="callgo">${verb} ALL</button>`;
  bar.classList.add("show");
}
async function callTargets(){
  if(running){ showToast("a scan is already running"); return; }
  const ids=[...picked];
  if(!ids.length) return;
  SFX.start(); haptic(20);
  showToast(`calling ${ids.length} target${ids.length>1?'s':''}…`);
  for(const i of ids){
    if(!hosts[i]) continue;
    selectHost(i);
    await runScan(profile);
    if(!running){} // per-iteration; runScan manages its own state
  }
  showToast("all marked targets done");
}
function selectHost(i){
  selected=i; called=false; detailView=false;
  SFX.select(); haptic(8);
  renderCard(); renderRail();
  setPhase(running?"calling…":"ready", running);
  renderHosts();
  if(mode==="wifi" && !running){ called=true; showAPDetails(); }
  updateCallScreen();
}

async function loadConfig(){
  const sel=$("#scope");
  try{
    const d=await (await fetch("/api/config")).json();
    scopes=d.targets||[]; wlanMon=d.wlan_mon||null; renderWifiNote();
  }catch(e){ scopes=[]; }
  if(!scopes.length){ sel.innerHTML=`<option value="all">no networks configured</option>`; return; }
  sel.innerHTML = `<option value="all">All networks (${scopes.length})</option>`+
    scopes.map(s=>`<option value="${s}">${s}</option>`).join("");
  updateCallScreen();
}

async function discover(){
  if(running) return; detailView=false; picked.clear();
  if(mode==="bt") return discoverBT();
  if(mode==="wifi") return discoverWifi();
  const g=gen, scope=$("#scope").value||"all";
  const shown = scope==="all" ? (scopes.join(" ")||"(none)") : scope;
  selected=null; called=false;
  setRunning(true); setPhase("discovering…", true);
  out.textContent=""; clearPorts(); write("$ nmap -sn "+(stealth?"--spoof-mac 0 ":"")+shown+"\n\n","cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/discover",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scope,stealth}),signal:ctrl.signal});
    const d=await r.json(); if(g!==gen) return; cursor(false);
    if(d.error){ write("[error] "+d.error+"\n"); }
    else{ hosts=(d.hosts||[]).map(h=>{
        const o={addr:h.ip, ip:h.ip, mac:h.mac||null, label:h.name||h.ip.split(".").slice(-1)[0], name:h.name||null,
                 vendor:h.vendor||null, sub:h.vendor||h.mac||h.ip, bt:false, isNew:!!h.new};
        const prev=session[h.ip]; if(prev){ o.os=prev.os; o.scanned=true; o.vulns=+prev.vulns||0; }
        return o;
      }); selected=null; renderHosts();
      const nu=hosts.filter(h=>h.isNew);
      if(nu.length){
        setAlert(`${nu.length} new device${nu.length>1?"s":""} on the network`, "mark known", async ()=>{
          const devs=nu.map(h=>({mac:h.mac,ip:h.ip,vendor:h.vendor,name:h.name}));
          try{ await fetch("/api/devices/ack",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({devices:devs})}); }catch(e){}
          hosts.forEach(h=>h.isNew=false); renderHosts(); clearAlert(); showToast("devices baselined as known");
        }, "warn");
      } else clearAlert();
      write(`found ${d.count} live host${d.count===1?"":"s"} across ${(d.scanned||[]).length} network${(d.scanned||[]).length===1?"":"s"}.\n`); updateCallScreen(); }
  }catch(e){ if(e.name!=="AbortError"){ cursor(false); write("[error] "+e.message+"\n"); } }
  finally{ if(g===gen) setRunning(false); }
}

async function discoverBT(){
  const g=gen; detailView=false;
  selected=null; called=false;
  setRunning(true); setPhase("scanning bt…", true);
  out.textContent=""; cursor(true);
  ctrl=new AbortController();
  let raw="", cut=false, first=true;
  try{
    const r=await fetch("/api/bt_discover_stream",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const rd=r.body.getReader(), dec=new TextDecoder();
    while(true){ const {done,value}=await rd.read(); if(done)break;
      if(g!==gen) return;
      const chunk=dec.decode(value,{stream:true}); raw+=chunk;
      if(!cut){
        const i=raw.indexOf("@@DEVICES@@");
        if(i>=0){ const vis=chunk.slice(0,chunk.indexOf("@@DEVICES@@")); if(vis){cursor(false);write(vis,first?"cmd":null);first=false;} cut=true; }
        else { cursor(false); write(chunk, first?"cmd":null); first=false; cursor(true); }
      }
    }
    cursor(false);
    let devs=[]; const i=raw.indexOf("@@DEVICES@@");
    if(i>=0){ try{ devs=JSON.parse(raw.slice(i+11)); }catch(e){} }
    hosts=devs.map(x=>{
      const bits=[];
      if(x.type) bits.push(x.type);
      if(x.rssi) bits.push("RSSI "+x.rssi);
      if(typeof x.services==="number") bits.push(x.services+" svc");
      if(x.manufacturer) bits.push("mfr "+x.manufacturer);
      return {addr:x.mac, label:x.name||x.mac, bt:true, info:x, sub:bits.length?bits.join(" · "):x.mac};
    });
    flagBleFlood(hosts);
    renderHosts(); updateCallScreen();
  }catch(e){ if(e.name!=="AbortError"){ cursor(false); write("[error] "+e.message+"\n"); } }
  finally{ if(g===gen) setRunning(false); }
}

// BLE advertisement flooding leaves a signature in a single sweep: lots of
// random-address devices, often many sharing a spoofed name (fake AirPods /
// Android fast-pair popups). Purely an observation of what's already in range.
function flagBleFlood(list){
  const rnd=list.filter(h=>(h.info&&h.info.type||"").toLowerCase()==="random");
  const names={};
  list.forEach(h=>{ const n=(h.label||"").trim(); if(n && h.addr!==n){ names[n]=(names[n]||0)+1; } });
  const cluster=Math.max(0,...Object.values(names));
  const spammy=/airpods|airpod|pencil|apple tv|android|fast ?pair|tile|find my|setup/i;
  const spamNamed=list.filter(h=>spammy.test(h.label||"")).length;
  const score=(rnd.length>=12?2:rnd.length>=8?1:0)+(cluster>=5?2:cluster>=3?1:0)+(spamNamed>=5?1:0);
  list.forEach(h=>{ h.spam = score>=2 && ((h.info&&(h.info.type||"").toLowerCase()==="random") || spammy.test(h.label||"")); });
  if(score>=2){
    const why=[]; if(rnd.length>=8) why.push(rnd.length+" random-address devices");
    if(cluster>=3) why.push(cluster+"× a repeated name"); if(spamNamed>=5) why.push(spamNamed+" pairing-popup names");
    setAlert("possible BLE advertisement flooding: "+why.join(", "), "dismiss", ()=>clearAlert());
  } else clearAlert();
}

async function discoverWifi(){
  const g=gen; detailView=false;
  selected=null; called=false;
  setRunning(true); setPhase("scanning wifi…", true);
  out.textContent=""; clearPorts(); write("$ airodump-ng  (14s capture)\n\n","cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/wifi_scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const d=await r.json(); if(g!==gen) return; cursor(false);
    if(d.error){ write("[error] "+d.error+"\n"); }
    else{
      lastWifi={aps:d.aps||[], clients:d.clients||[]};
      hosts=lastWifi.aps.map(a=>{
        const nc=lastWifi.clients.filter(c=>c.bssid===a.bssid).length;
        const active=parseInt(a.data||"0",10)>0;
        return {addr:a.bssid, label:a.essid, wifi:true, active, ap:a,
          suspicious:!!a.suspicious, reason:a.reason||"", known:!!a.known,
          sub:`ch ${a.channel} · ${a.power}dBm · ${a.enc} · ${active?("▲ "+a.data+" data"):"idle"}${nc?(" · "+nc+" clients"):""}`};
      });
      selected=null; renderHosts();
      const susp=hosts.filter(h=>h.suspicious);
      if(susp.length){
        setAlert(`${susp.length} suspicious AP${susp.length>1?"s":""} — possible evil twin`, "trust current", async ()=>{
          const aps=lastWifi.aps.map(a=>({bssid:a.bssid,essid:a.essid,channel:a.channel}));
          try{ await fetch("/api/aps/ack",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({aps})}); }catch(e){}
          hosts.forEach(h=>{h.suspicious=false;h.known=true;}); renderHosts(); clearAlert(); showToast("current APs baselined as trusted");
        });
      } else clearAlert();
      write(`found ${d.count} access point${d.count===1?"":"s"} on ${d.iface}. tap one for details.\n`);
      if(d.iface){ wlanMon=d.iface; renderWifiNote(); }
      write(`\nrestore managed mode when done: airmon-ng stop ${d.iface||wlanMon||"wlan0mon"} && systemctl restart NetworkManager\n`);
    }
  }catch(e){ if(e.name!=="AbortError"){ cursor(false); write("[error] "+e.message+"\n"); } }
  finally{ if(g===gen) setRunning(false); }
}

async function deauthScan(){
  if(running) return; detailView=true;
  selected=null; called=false;
  setRunning(true); setPhase("deauth sample…", true);
  out.textContent=""; write("$ tshark — 10s passive deauth sample\n  listening for 802.11 deauth / disassoc frames…\n\n","cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/deauth_scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const d=await r.json(); cursor(false);
    if(d.error){ write("[error] "+d.error+"\n"); }
    else{
      write(`captured ${d.total} mgmt frame(s) in ${d.seconds}s  (${d.deauth} deauth, ${d.disassoc} disassoc)\n`);
      write(`rate: ${d.rate}/s\n\n`);
      if(d.top_sources&&d.top_sources.length){ write("top sources:\n","cmd"); d.top_sources.forEach(p=>write(`  ${p[0]}   ${p[1]}\n`)); write("\n"); }
      if(d.top_bssids&&d.top_bssids.length){ write("top BSSIDs:\n","cmd"); d.top_bssids.forEach(p=>write(`  ${p[0]}   ${p[1]}\n`)); write("\n"); }
      if(d.flood){ write("⚠ DEAUTH FLOOD DETECTED\n"); setAlert(`deauth flood: ${d.total} frames in ${d.seconds}s`, "dismiss", ()=>clearAlert()); showToast("⚠ deauth flood detected"); }
      else { write("no flood — deauth volume looks normal.\n"); clearAlert(); }
    }
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); else write("[aborted]\n"); }
  finally{ setRunning(false); setPhase("ready", false); }
}
async function deauthMonitor(){
  if(running) return; detailView=true;
  selected=null; called=false;
  setRunning(true); setPhase("deauth watch…", true);
  out.textContent=""; cursor(true);
  ctrl=new AbortController();
  let first=true, buf="";
  try{
    const r=await fetch("/api/deauth_monitor",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const rd=r.body.getReader(), dec=new TextDecoder();
    while(true){ const {done,value}=await rd.read(); if(done)break;
      buf += dec.decode(value,{stream:true});
      const lines=buf.split("\n"); buf=lines.pop();
      for(const ln of lines){
        if(ln.startsWith("@@ALERT@@")){ const msg=ln.slice(9); setAlert(msg,"dismiss",()=>clearAlert()); showToast("⚠ "+msg); }
        else { cursor(false); write(ln+"\n", first?"cmd":null); first=false; }
      }
      cursor(true);
    }
    if(buf){ cursor(false); write(buf); }
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); else write("\n[stopped]\n"); }
  finally{ setRunning(false); setPhase("ready", false); }
}

async function webBanner(){
  if(selected===null){ showToast("select a host"); return; }
  const h=hosts[selected]; detailView=true;
  let ports=null; const rec=session[h.addr];
  if(rec&&rec.ports&&rec.ports.length) ports=rec.ports.map(p=>{const a=p.split("/");return {port:+a[0],service:a[1]||""};});
  setRunning(true); setPhase("web banner…",true);
  out.textContent=""; write(`$ http banner grab — ${h.addr}\n`+(ports?"  using scanned ports\n\n":"  probing common web ports…\n\n"),"cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/http_banner",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:h.addr,ports}),signal:ctrl.signal});
    const d=await r.json(); cursor(false);
    if(d.error) write("[error] "+d.error+"\n");
    else if(!d.count) write("no HTTP service responded on the probed ports.\n");
    else d.services.forEach(s=>{
      write(`${s.scheme}://${h.addr}:${s.port}   [${s.status}]\n`,"cmd");
      if(s.server)   write(`  server    ${s.server}\n`);
      if(s.title)    write(`  title     ${s.title}\n`);
      if(s.location) write(`  redirect  ${s.location}\n`);
      write("\n");
    });
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
async function mdnsScan(){
  if(selected===null){ showToast("select a host"); return; }
  const h=hosts[selected]; detailView=true;
  setRunning(true); setPhase("service discovery…",true);
  out.textContent=""; write(`$ mDNS / SSDP discovery (filtered to ${h.addr})\n\n`,"cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/mdns",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:h.addr}),signal:ctrl.signal});
    const d=await r.json(); cursor(false);
    if(d.mdns_count){ write(`mDNS services (${d.mdns_count}):\n`,"cmd"); d.mdns.forEach(s=>write(`  ${s.name||s.type}  ·  ${s.type}  ·  :${s.port}\n`)); write("\n"); }
    if(d.ssdp_count){ write(`SSDP / UPnP (${d.ssdp_count}):\n`,"cmd"); d.ssdp.forEach(s=>{ write(`  ${s.server||"device"}\n`); (s.st||[]).forEach(t=>write(`     ${t}\n`)); }); write("\n"); }
    if(!d.mdns_count && !d.ssdp_count) write("no mDNS/SSDP advertisements for this host.\n  (it may not advertise, or avahi-utils isn't installed.)\n");
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
async function gattScan(){
  if(selected===null){ showToast("select a device"); return; }
  const h=hosts[selected]; detailView=true;
  setRunning(true); setPhase("gatt enum…",true);
  out.textContent=""; write(`$ GATT enumeration — ${h.addr}\n  connecting (read-only)…\n\n`,"cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/ble_gatt",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:h.addr}),signal:ctrl.signal});
    const d=await r.json(); cursor(false);
    if(d.error) write("[error] "+d.error+"\n");
    else if(!d.count) write("could not resolve GATT — device may be out of range, paired elsewhere, or not connectable.\n");
    else{
      write(`${d.count} attribute(s):\n\n`);
      d.attributes.forEach(a=>{
        const tag=a.kind==="service"?"SVC ":a.kind==="characteristic"?" └ chr":"   dsc";
        write(`${tag}  ${a.uuid}${a.name?("   "+a.name):""}\n`, a.kind==="service"?"cmd":null);
      });
    }
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
async function probeWatch(){
  if(running) return;
  selected=null; called=false; detailView=true;
  setRunning(true); setPhase("probe watch…",true);
  out.textContent=""; cursor(true);
  ctrl=new AbortController();
  let first=true, buf="";
  try{
    const r=await fetch("/api/probe_listen",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const rd=r.body.getReader(), dec=new TextDecoder();
    while(true){ const {done,value}=await rd.read(); if(done)break;
      buf+=dec.decode(value,{stream:true});
      const lines=buf.split("\n"); buf=lines.pop();
      for(const ln of lines){ cursor(false); write(ln+"\n", first?"cmd":null); first=false; }
      cursor(true);
    }
    if(buf){ cursor(false); write(buf); }
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); else write("\n[stopped]\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
function huntStart(){
  if(selected===null){ showToast("select a target first"); return; }
  const h=hosts[selected], kind = mode==="bt" ? "bt" : "wifi";
  $("#hunttarget").textContent=(h.label||h.addr)+"  ·  "+h.addr;
  $("#huntfill").style.width="0%"; $("#huntfill").className="hunt-fill";
  $("#huntval").textContent="— dBm"; $("#huntlabel").textContent="listening…";
  $("#huntmodal").classList.add("show");
  huntActive=true; huntCtrl=new AbortController();
  (async()=>{
    let buf="";
    try{
      const r=await fetch("/api/hunt",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({kind,target:h.addr}),signal:huntCtrl.signal});
      const rd=r.body.getReader(), dec=new TextDecoder();
      while(huntActive){ const {done,value}=await rd.read(); if(done)break;
        buf+=dec.decode(value,{stream:true});
        const lines=buf.split("\n"); buf=lines.pop();
        for(const ln of lines){ if(ln.startsWith("@@RSSI@@")) huntUpdate(parseInt(ln.slice(8),10)); }
      }
    }catch(e){}
  })();
}
function huntUpdate(rssi){
  if(!isFinite(rssi)) return;
  const pct=Math.max(0,Math.min(100,Math.round((rssi+90)/60*100)));
  const f=$("#huntfill"); f.style.width=pct+"%"; f.className="hunt-fill "+(pct>66?"hot":pct>33?"mid":"cold");
  $("#huntval").textContent=rssi+" dBm";
  $("#huntlabel").textContent = pct>78?"🔥 RIGHT HERE":pct>58?"very warm":pct>40?"warmer":pct>22?"cool":"cold — keep moving";
}
function huntStop(){ huntActive=false; try{ if(huntCtrl) huntCtrl.abort(); }catch(e){} $("#huntmodal").classList.remove("show"); }

async function webBanner(){
  if(selected===null){ showToast("select a host"); return; }
  const h=hosts[selected]; detailView=true;
  let ports=null; const rec=session[h.addr];
  if(rec&&rec.ports&&rec.ports.length) ports=rec.ports.map(p=>{const a=p.split("/");return {port:+a[0],service:a[1]||""};});
  setRunning(true); setPhase("web recon…",true);
  out.textContent=""; write(`$ http banner + TLS — ${h.addr}\n`+(ports?"  using scanned ports\n\n":"  probing common web ports…\n\n"),"cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/http_banner",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:h.addr,ports}),signal:ctrl.signal});
    const d=await r.json(); cursor(false);
    if(d.error) write("[error] "+d.error+"\n");
    else if(!d.count) write("no HTTP service responded on the probed ports.\n");
    else d.services.forEach(s=>{
      write(`${s.scheme}://${h.addr}:${s.port}   [${s.status}]\n`,"cmd");
      if(s.server)   write(`  server    ${s.server}\n`);
      if(s.title)    write(`  title     ${s.title}\n`);
      if(s.location) write(`  redirect  ${s.location}\n`);
      write("\n");
    });
    // TLS certs for any https ports
    let tlsPorts=null;
    if(ports) tlsPorts=ports.filter(p=>p.service&&(p.service.includes("https")||p.service.includes("ssl"))||[443,8443].includes(p.port)).map(p=>p.port);
    const tr=await fetch("/api/tls_cert",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:h.addr,ports:tlsPorts&&tlsPorts.length?tlsPorts:undefined}),signal:ctrl.signal});
    const td=await tr.json();
    if(td.count){ write("TLS certificates:\n","cmd");
      td.certs.forEach(ct=>{
        write(`  :${ct.port}\n`);
        if(ct.subject) write(`    subject   ${ct.subject}\n`);
        if(ct.issuer)  write(`    issuer    ${ct.issuer}\n`);
        if(ct.not_after) write(`    expires   ${ct.not_after}${ct.expired?"  ⚠ EXPIRED":""}\n`);
        if(ct.self_signed) write(`    ⚠ self-signed\n`);
        if(ct.san) write(`    san       ${ct.san}\n`);
        write("\n");
      });
    }
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
async function arpScan(){
  if(running) return; detailView=true;
  selected=null; called=false;
  setRunning(true); setPhase("arp watch…",true);
  out.textContent=""; write("$ ARP-spoof watch (8s passive)\n  looking for one IP claimed by multiple MACs…\n\n","cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/arp_scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const d=await r.json(); cursor(false);
    if(d.error){ write("[error] "+d.error+"\n"); }
    else{
      write(`watched ${d.seen} host(s) on ${d.iface}.  gateway ${d.gateway||"?"}\n\n`);
      if(d.spoof){
        write("⚠ ARP CONFLICT — possible spoofing / MITM:\n","cmd");
        d.conflicts.forEach(c=>write(`  ${c.ip}  →  ${c.macs.join("  ,  ")}\n`));
        setAlert(`ARP conflict: ${d.conflicts[0].ip} has ${d.conflicts[0].macs.length} MACs`,"dismiss",()=>clearAlert());
      } else write("no ARP conflicts — addressing looks clean.\n");
    }
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
async function dhcpScan(){
  if(running) return; detailView=true;
  selected=null; called=false;
  setRunning(true); setPhase("dhcp check…",true);
  out.textContent=""; write("$ DHCP server discovery (broadcast)\n  enumerating who hands out leases…\n\n","cmd"); cursor(true);
  ctrl=new AbortController();
  try{
    const r=await fetch("/api/dhcp_scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const d=await r.json(); cursor(false);
    if(d.error){ write("[error] "+d.error+"\n"); }
    else{
      write(`gateway: ${d.gateway||"?"}\nDHCP servers seen (${d.count}): ${d.servers.join(", ")||"none"}\n\n`);
      if(d.rogue.length){
        write("⚠ ROGUE DHCP — server(s) other than your gateway:\n","cmd");
        d.rogue.forEach(s=>write(`  ${s}\n`));
        setAlert(`rogue DHCP server: ${d.rogue.join(", ")}`,"dismiss",()=>clearAlert());
      } else write("only the gateway is serving DHCP — looks clean.\n");
    }
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
async function capturePcap(){
  showToast("capturing 10s pcap…");
  try{
    const r=await fetch("/api/pcap",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({seconds:10})});
    if(!r.ok){ const d=await r.json().catch(()=>({})); showToast("pcap: "+(d.error||"failed")); return; }
    const blob=await r.blob(), u=URL.createObjectURL(blob);
    const a=document.createElement("a"); a.href=u; a.download="dokkos_capture.pcap"; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(u),1000);
    closeReport(); showToast("pcap saved");
  }catch(e){ showToast("pcap failed"); }
}
async function saveSnapshot(){
  try{
    const r=await fetch("/api/session/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({session})});
    const d=await r.json(); closeReport(); showToast(d.ok?`snapshot saved (${d.hosts} hosts)`:"save failed");
  }catch(e){ showToast("save failed"); }
}
async function showDiff(){
  if(!Object.keys(session).length){ showToast("scan something first"); return; }
  detailView=true; selected=null; called=false; setRunning(false);
  out.textContent=""; write("$ session diff vs last saved snapshot\n\n","cmd");
  try{
    const r=await fetch("/api/session/diff",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({session})});
    const d=await r.json();
    if(!d.has_snapshot){ write("no saved snapshot yet — use Save Snapshot first, re-scan later, then diff.\n"); }
    else if(!d.changed){ write("no changes since the last snapshot.\n"); }
    else d.diffs.forEach(x=>{
      write(`${x.addr}  [${x.status}]\n`,"cmd");
      if(x.added_ports.length) write(`  + opened   ${x.added_ports.join(", ")}\n`);
      if(x.removed_ports.length) write(`  - closed   ${x.removed_ports.join(", ")}\n`);
      if(x.cve_delta) write(`  ${x.cve_delta>0?"+":""}${x.cve_delta} CVEs\n`);
      write("\n");
    });
  }catch(e){ write("[error] "+e.message+"\n"); }
  closeReport(); updateCallScreen();
}
async function scanAll(){
  if(running || mode!=="net"){ return; }
  const queue=hosts.filter(h=>!h.bt&&!h.wifi).map(h=>h.addr);
  if(!queue.length){ showToast("discover hosts first"); return; }
  showToast(`queued ${queue.length} hosts…`);
  for(let i=0;i<queue.length;i++){
    const idx=hosts.findIndex(h=>h.addr===queue[i]); if(idx<0) continue;
    selected=idx; renderCard(); renderRail(); renderHosts();
    await runScan(profile);
    if(mode!=="net") break;   // user switched away
  }
  showToast("sweep-and-scan complete");
}
/* timeline (detection history) */
function evIcon(k){ return k.includes("deauth")||k.includes("flood")?'shield':k.includes("arp")?'alert':k.includes("dhcp")?'network':k.includes("rogue")?'wifi':k.includes("device")?'square':k.includes("monitor")?'bell':'pulse'; }
function ago(ts){ const s=Math.max(0,Math.floor(Date.now()/1000-ts)); if(s<60)return s+"s ago"; if(s<3600)return Math.floor(s/60)+"m ago"; if(s<86400)return Math.floor(s/3600)+"h ago"; return Math.floor(s/86400)+"d ago"; }
async function openTimeline(){
  $("#tlbody").innerHTML='<div class="tl-empty">loading…</div>';
  $("#timeline").classList.add("show");
  try{
    const d=await (await fetch("/api/events")).json();
    if(!d.count){ $("#tlbody").innerHTML='<div class="tl-empty">no events yet — run detections or start the watch.</div>'; return; }
    $("#tlbody").innerHTML=d.events.map(e=>`
      <div class="tl-row ${esc(e.level)}">
        <div class="tl-node">${I(evIcon(e.kind),16)}</div>
        <div class="tl-body"><div class="tl-kind">${esc(e.kind)}</div>
          <div class="tl-detail">${esc(e.detail)}</div>
          <div class="tl-time">${esc(ago(e.ts))}</div></div>
      </div>`).join("");
  }catch(e){ $("#tlbody").innerHTML='<div class="tl-empty">failed to load events.</div>'; }
}
function closeTimeline(){ $("#timeline").classList.remove("show"); }
async function clearTimeline(){ try{ await fetch("/api/events/clear",{method:"POST"}); }catch(e){} openTimeline(); }
/* unattended monitor toggle */
let monitorOn=false;
let monMode=false;
async function toggleMonMode(){
  const enable=!monMode;
  showToast(enable?"enabling monitor mode…":"disabling monitor mode…");
  try{
    const r=await fetch("/api/monitor_mode",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enable})});
    const d=await r.json();
    if(d.error){ showToast(d.error); return; }
    monMode=!!d.enabled; if(d.monitor){ wlanMon=d.monitor; }
    SFX.tick(); haptic(12);
    renderRail(); if(typeof renderWifiNote==="function") renderWifiNote();
    showToast(monMode ? ("monitor mode ON — "+(d.monitor||"?")) : "monitor mode OFF");
  }catch(e){ showToast("error: "+e.message); }
}
async function refreshMonMode(){
  try{ const d=await (await fetch("/api/monitor_mode/status")).json(); monMode=!!d.enabled; if(d.monitor) wlanMon=d.monitor; if(mode==="wifi") renderRail(); }catch(e){}
}
async function refreshMonitor(){
  try{ const d=await (await fetch("/api/monitor/status")).json(); monitorOn=d.running; paintMonitor(d); }catch(e){}
}
function paintMonitor(d){
  const b=$("#monitorbtn"); b.classList.toggle("on",monitorOn);
  b.title = monitorOn ? "unattended watch ON — tap to stop" : "start unattended watch";
}
async function toggleMonitor(){
  try{
    const d=await (await fetch(monitorOn?"/api/monitor/stop":"/api/monitor/start",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"})).json();
    monitorOn=!!d.running; paintMonitor(d);
    if(monitorOn && !d.webhook) showToast("watch on — set a webhook in Settings for alerts");
    else showToast(monitorOn?"unattended watch started":"watch stopped");
  }catch(e){ showToast("monitor error"); }
}
/* host dossier drawer + threat score */
function threatScore(h){
  const r=session[h.addr]||{}; let s=0;
  s+=Math.min(30,(+r.portCount||0)*4);
  s+=Math.min(40,(+r.vulns||0)*20);
  s+=Math.min(20,(+r.cves||0)*4);
  if(h.isNew) s+=10; if(h.suspicious||h.spam) s+=25;
  return Math.min(100,Math.round(s));
}
function threatBand(n){ return n>=66?"hi":n>=33?"mid":"lo"; }
function openDrawer(){
  if(selected===null){ showToast("select a host"); return; }
  const h=hosts[selected], r=session[h.addr]||{};
  const sc=threatScore(h), band=threatBand(sc);
  $("#dossier").innerHTML=`
    <div class="dsr-head"><div><div class="dsr-name">${esc((h.label||"").toUpperCase()||h.addr)}</div>
      <div class="dsr-addr">${esc(h.addr)}${h.vendor?(" · "+esc(h.vendor)):""}</div></div>
      <div class="dsr-score ${band}"><div class="dsr-num">${sc}</div><div class="dsr-lbl">threat</div></div></div>
    <div class="dsr-grid">
      ${r.os?`<div class="dsr-tile wide"><b>OS</b>${esc(r.os)}${r.osd?`<span>${esc(r.osd)}</span>`:""}</div>`:""}
      <div class="dsr-tile"><b>open ports</b>${esc(r.portCount||(r.ports?r.ports.length:0)||0)}${r.ports&&r.ports.length?`<span>${esc(r.ports.slice(0,6).join(", "))}</span>`:""}</div>
      <div class="dsr-tile"><b>vulns</b>${esc(r.vulns||0)}</div>
      ${r.cves?`<div class="dsr-tile"><b>cves</b>${esc(r.cves)}${r.topcve?`<span>${esc(r.topcve)}</span>`:""}</div>`:""}
      ${h.isNew?`<div class="dsr-tile flag"><b>status</b>NEW on network</div>`:""}
      ${(h.suspicious||h.spam)?`<div class="dsr-tile flag"><b>flag</b>${esc(h.reason||"suspicious")}</div>`:""}
      ${!r.os&&!r.ports?`<div class="dsr-tile wide"><b>no scan yet</b><span>run a scan to populate this dossier</span></div>`:""}
    </div>`;
  $("#drawer").classList.add("show");
}
function closeDrawer(){ $("#drawer").classList.remove("show"); }

async function dnsSniff(){
  if(running) return; detailView=true; selected=null; called=false;
  setRunning(true); setPhase("dns sniff…",true);
  out.textContent=""; cursor(true);
  ctrl=new AbortController(); let first=true, buf="";
  try{
    const r=await fetch("/api/dns_sniff",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}",signal:ctrl.signal});
    const rd=r.body.getReader(), dec=new TextDecoder();
    while(true){ const {done,value}=await rd.read(); if(done)break;
      buf+=dec.decode(value,{stream:true}); const lines=buf.split("\n"); buf=lines.pop();
      for(const ln of lines){ cursor(false); write(ln+"\n", first?"cmd":null); first=false; } cursor(true);
    }
    if(buf){cursor(false);write(buf);}
  }catch(e){ cursor(false); if(e.name!=="AbortError") write("[error] "+e.message+"\n"); else write("\n[stopped]\n"); }
  finally{ setRunning(false); setPhase("ready",false); }
}
function stations(){
  if(!lastWifi.aps.length && !lastWifi.clients.length){ showToast("run a Wi-Fi scan first"); return; }
  detailView=true; setRunning(false);
  out.textContent=""; write("$ associated stations (from last Wi-Fi capture)\n\n","cmd");
  const byB={}; lastWifi.clients.forEach(c=>{ (byB[c.bssid]=byB[c.bssid]||[]).push(c); });
  lastWifi.aps.forEach(a=>{
    const cl=byB[a.bssid]||[];
    write(`${esc(a.essid)}  (${a.bssid})  — ${cl.length} client(s)\n`,"cmd");
    cl.forEach(c=>write(`   ${c.station}   ${c.power}dBm   ${c.packets} pkts\n`));
    if(!cl.length) write("   (none seen)\n");
    write("\n");
  });
  const un=byB["(not associated)"]||[];
  if(un.length){ write(`unassociated / probing (${un.length})\n`,"cmd"); un.forEach(c=>write(`   ${c.station}   ${c.power}dBm\n`)); }
  updateCallScreen();
}
function fmtBytes(b){ b=+b||0; if(b>=1e6)return (b/1e6).toFixed(1)+"MB"; if(b>=1e3)return (b/1e3).toFixed(1)+"kB"; return b+"B"; }
async function trafficScan(){
  if(running) return;
  $("#topobody").innerHTML='<div class="topo-load">capturing 12s of traffic…<span class="topo-spin"></span></div>';
  $("#topolist").innerHTML=""; $("#topoproto").innerHTML=""; $("#topometa").textContent="";
  $("#topo").classList.add("show");
  try{
    const r=await fetch("/api/talkers",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({seconds:12})});
    const d=await r.json();
    if(d.error){ $("#topobody").innerHTML='<div class="topo-load">'+esc(d.error)+'</div>'; return; }
    renderTopology(d);
  }catch(e){ $("#topobody").innerHTML='<div class="topo-load">capture failed</div>'; }
}
function renderTopology(d){
  const W=320,H=300,cx=W/2,cy=H/2,R=112;
  const nodes=(d.nodes||[]).slice(0,16);
  if(!nodes.length){ $("#topobody").innerHTML='<div class="topo-load">no IP traffic captured.</div>'; $("#topometa").textContent=""; return; }
  const gw=d.gateway, local=d.local;
  const center = gw && nodes.find(n=>n.ip===gw) ? gw : nodes[0].ip;
  const ring = nodes.filter(n=>n.ip!==center);
  const maxB=Math.max(1,...nodes.map(n=>n.bytes));
  const pos={}; pos[center]={x:cx,y:cy};
  ring.forEach((n,i)=>{ const ang=(i/ring.length)*2*Math.PI - Math.PI/2; pos[n.ip]={x:cx+R*Math.cos(ang), y:cy+R*Math.sin(ang)}; });
  const maxE=Math.max(1,...(d.talkers||[]).map(t=>t.bytes));
  let edges="";
  (d.talkers||[]).forEach(t=>{ const pa=pos[t.a],pb=pos[t.b]; if(!pa||!pb)return;
    const w=(1+(t.bytes/maxE)*4).toFixed(1), op=(0.18+(t.bytes/maxE)*0.55).toFixed(2);
    edges+=`<line x1="${pa.x.toFixed(1)}" y1="${pa.y.toFixed(1)}" x2="${pb.x.toFixed(1)}" y2="${pb.y.toFixed(1)}" stroke="#5ff0d8" stroke-width="${w}" stroke-opacity="${op}" class="topo-edge"/>`;
  });
  let circles="";
  Object.keys(pos).forEach(ip=>{ const p=pos[ip]; const nb=(nodes.find(n=>n.ip===ip)||{}).bytes||0;
    const rr=(6+(nb/maxB)*11).toFixed(1); const isGw=ip===gw, isMe=ip===local;
    const col=isGw?"#e24555":isMe?"#5ff0d8":"#9fb0c3";
    circles+=`<g class="topo-node${isGw?' gw':''}"><circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${rr}" fill="#0d0f16" stroke="${col}" stroke-width="2"/>`+
      `<text x="${p.x.toFixed(1)}" y="${(p.y- (+rr) -5).toFixed(1)}" text-anchor="middle" class="topo-lbl${isGw?' gw':isMe?' me':''}">${esc(ip.split('.').slice(-2).join('.'))}</text></g>`;
  });
  $("#topobody").innerHTML=`<svg viewBox="0 0 ${W} ${H}" class="topo-svg" preserveAspectRatio="xMidYMid meet">${edges}${circles}</svg>`;
  $("#topolist").innerHTML=(d.talkers||[]).slice(0,8).map(t=>`<div class="tk-row"><span class="tk-pair">${esc(t.a)} <i>↔</i> ${esc(t.b)}</span><span class="tk-b">${fmtBytes(t.bytes)}</span></div>`).join("")||'<div class="tl-empty">no flows</div>';
  const maxP=Math.max(1,...(d.protocols||[]).map(p=>p.bytes));
  $("#topoproto").innerHTML=(d.protocols||[]).map(p=>`<div class="pb-row"><span class="pb-name">${esc(p.name)}</span><span class="pb-bar"><span style="width:${Math.round(p.bytes/maxP*100)}%"></span></span><span class="pb-v">${fmtBytes(p.bytes)}</span></div>`).join("")||'<div class="tl-empty">—</div>';
  $("#topometa").textContent=`${d.nodes.length} hosts · ${d.talkers.length} flows · ${fmtBytes(d.total_bytes)} in ${d.seconds}s`;
}
function closeTopo(){ $("#topo").classList.remove("show"); }

function showAPDetails(){
  if(selected===null || !hosts[selected].wifi){ showToast("select an access point"); return; }
  detailView=true; updateCallScreen();
  const a=hosts[selected].ap;
  const cl=lastWifi.clients.filter(c=>c.bssid===a.bssid);
  out.textContent="";
  write(`ACCESS POINT  ${a.essid}\n`,"cmd");
  write(`  bssid     ${a.bssid}\n  channel   ${a.channel}\n  signal    ${a.power} dBm\n  encrypt   ${a.enc}\n  beacons   ${a.beacons}\n  data      ${a.data}  ${parseInt(a.data||"0",10)>0?"(active traffic)":"(idle)"}\n\n`);
  write(`ASSOCIATED CLIENTS (${cl.length})\n`,"cmd");
  if(cl.length) cl.forEach(c=>write(`  ${c.station}   ${c.power}dBm   ${c.packets} pkts\n`));
  else write("  (none seen during this capture)\n");
}

async function pipe(r){
  const rd=r.body.getReader(), dec=new TextDecoder(); let first=true, buf="";
  while(true){ const {done,value}=await rd.read(); if(done)break;
    const chunk=dec.decode(value,{stream:true});
    cursor(false); write(chunk, first?"cmd":null); first=false; cursor(true);
    buf=(buf+chunk).slice(-2500); parseProgress(buf); }
  cursor(false);
}

function renderPorts(){
  const bar=$("#ports");
  const re=/^\s*(\d+)\/(tcp|udp)\s+(\S+)/gm; let m, seen={}, list=[];
  const txt=out.textContent;
  while((m=re.exec(txt))){ const k=m[1]+"/"+m[2]; if(!seen[k]){ seen[k]=1; list.push({port:m[1],svc:m[3]}); } }
  if(!list.length){ clearPorts(); return; }
  bar.style.display="";
  bar.innerHTML = `<span class="portlbl">dig deeper:</span>`+
    list.map(p=>`<button class="port" data-port="${esc(p.port)}" data-svc="${esc(p.svc)}">${esc(p.port)} ${esc(p.svc)}</button>`).join("");
}

async function digPort(port, svc){ detailView=true;
  if(running || !scanHost) return;
  called=true;
  setRunning(true);
  out.textContent=""; cursor(true);
  ctrl=new AbortController();
  let endPhase="complete";
  try{
    const r=await fetch("/api/port_scan",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({target:scanHost,port,service:svc||"",stealth}),signal:ctrl.signal});
    await pipe(r); endPhase=r.ok?"complete":"error";
  }catch(e){ cursor(false);
    if(e.name!=="AbortError"){ write("\n[error] "+e.message+"\n"); endPhase="error"; }
    else { write("\n[aborted]\n"); endPhase="aborted"; } }
  finally{ setRunning(false); setPhase(endPhase,false); renderPorts(); }
}

async function runScan(scanId){
  detailView=false;
  SFX.start(); haptic(12);
  if(running || selected===null){ if(selected===null) showToast("select a target first"); return; }
  profile=scanId; renderTabs();
  called=true;
  setRunning(true);
  out.textContent=""; clearPorts(); cursor(true);
  ctrl=new AbortController();
  let endPhase="complete";
  const bt = hosts[selected].bt;
  scanHost = hosts[selected].addr;
  const ep = bt ? "/api/bt_scan" : "/api/scan";
  try{
    const r=await fetch(ep,{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({scan:scanId,target:hosts[selected].addr,stealth}),signal:ctrl.signal});
    await pipe(r); endPhase=r.ok?"complete":"error";
  }catch(e){ cursor(false);
    if(e.name!=="AbortError"){ write("\n[error] "+e.message+"\n"); endPhase="error"; }
    else { write("\n[aborted]\n"); endPhase="aborted"; } }
  finally{ setRunning(false); setPhase(endPhase, false);
    if(endPhase==="complete"){ SFX.done(); haptic(20); }
    if(!bt){ renderPorts(); if(endPhase==="complete"){ captureSession(scanHost); renderHosts(); } } }
}

function captureSession(addr){
  if(!addr) return;
  const s=parseSummary();
  const h=hosts.find(x=>x.addr===addr) || {};
  session[addr]={addr, ip:addr, label:h.label||addr, vendor:h.vendor||s.vendor||null,
    os:s.os, osd:s.osd, ports:s.ports, portCount:s.portCount,
    vulns:s.vulns, cves:s.cves, topcve:s.topcve, profile, ts:Date.now()};
  if(h.addr){ h.os=s.os; h.scanned=true; h.vulns=+s.vulns||0; }
}

/* ---- export: markdown reports from the session ---- */
function hostMd(rec){
  let m=`## ${rec.label}  (${rec.addr})\n\n`;
  if(rec.vendor) m+=`- **Vendor:** ${rec.vendor}\n`;
  if(rec.os) m+=`- **OS:** ${rec.os}${rec.osd?` — ${rec.osd}`:""}\n`;
  if(rec.profile) m+=`- **Scan profile:** ${rec.profile}\n`;
  m+=`- **Scanned:** ${new Date(rec.ts).toLocaleString()}\n`;
  m+=`\n**Open ports (${rec.portCount||0}):** ${rec.ports&&rec.ports.length?rec.ports.join(", "):"none open"}\n`;
  m+=`\n**Vulnerabilities:** ${rec.vulns||0}\n`;
  if(rec.cves) m+=`\n**CVEs (${rec.cves})${rec.topcve?` — top ${rec.topcve}`:""}**\n`;
  return m+"\n";
}
function sessionMd(){
  const recs=Object.values(session).sort((a,b)=>a.addr.localeCompare(b.addr,undefined,{numeric:true}));
  const withV=recs.filter(r=>+r.vulns>0).length;
  let m=`# DokkOS recon report\n\n`;
  m+=`_Generated ${new Date().toLocaleString()} · ${recs.length} host(s) · scopes: ${scopes.join(", ")||"n/a"}_\n\n`;
  m+=`> Authorized-use recon only. ${withV} host(s) with reported vulnerabilities.\n\n---\n\n`;
  recs.forEach(r=>{ m+=hostMd(r)+"---\n\n"; });
  return m;
}
function dlText(name,text){
  const b=new Blob([text],{type:"text/markdown"}), u=URL.createObjectURL(b);
  const a=document.createElement("a"); a.href=u; a.download=name; document.body.appendChild(a); a.click();
  a.remove(); setTimeout(()=>URL.revokeObjectURL(u),1000);
}
function exportHost(){
  const addr=(selected!==null&&hosts[selected])?hosts[selected].addr:scanHost;
  const rec=session[addr];
  if(!rec){ showToast("scan a host first"); return; }
  dlText(`dokkos_${addr}.md`, `# DokkOS host report\n\n`+hostMd(rec));
  closeReport(); showToast("host report saved");
}
function exportSession(){
  if(!Object.keys(session).length){ showToast("no scans this session yet"); return; }
  dlText(`dokkos_session_${Date.now()}.md`, sessionMd());
  closeReport(); showToast("session report saved");
}
function openReport(){
  const n=Object.keys(session).length;
  $("#rpcount").textContent = n ? `${n} host${n===1?"":"s"} scanned this session` : "no scans yet — run a scan first";
  $("#rphost").disabled = !((selected!==null&&hosts[selected]&&session[hosts[selected].addr]) || (scanHost&&session[scanHost]));
  $("#rpsess").disabled = !n;
  $("#report").classList.add("show");
}
function closeReport(){ $("#report").classList.remove("show"); }

/* ---- network map: radial radar of discovered hosts ---- */
function octet(ip){ const p=(ip||"").split("."); return p[p.length-1]||ip; }
function nodeClass(h){
  const r=session[h.addr];
  if(r && +r.vulns>0) return 'vuln';
  if(h.scanned || r) return 'scanned';
  return 'idle';
}
function openMap(){ buildMap(); $("#mapmodal").classList.add("show"); }
function closeMap(){ $("#mapmodal").classList.remove("show"); }
function buildMap(){
  const idx=[]; hosts.forEach((h,i)=>{ if(!h.bt && !h.wifi) idx.push(i); });
  const cx=300, cy=300;
  const gwI=idx.find(i=>/\.1$/.test(hosts[i].addr));
  const ringI=idx.filter(i=>i!==gwI);
  const N=ringI.length;
  let s=`<svg viewBox="0 0 600 600" xmlns="http://www.w3.org/2000/svg" class="mapsvg">`;
  s+=`<circle cx="${cx}" cy="${cy}" r="232" class="mfield"/>`;
  [232,168,104].forEach(r=>s+=`<circle cx="${cx}" cy="${cy}" r="${r}" class="mring"/>`);
  s+=`<line x1="${cx}" y1="68" x2="${cx}" y2="532" class="mcross"/><line x1="68" y1="${cy}" x2="532" y2="${cy}" class="mcross"/>`;
  s+=`<g class="msweep"><path d="M300 300 L300 68 A232 232 0 0 1 463.9 136.1 Z"/></g>`;
  const rings = N>12 ? [150,212] : (N>6 ? [185] : [160]);
  ringI.forEach((i,k)=>{
    const h=hosts[i];
    const r=rings[k%rings.length];
    const a=(-90 + k*360/Math.max(N,1)) * Math.PI/180;
    const x=cx+r*Math.cos(a), y=cy+r*Math.sin(a);
    s+=`<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" class="mspoke"/>`;
    s+=`<g class="mnode ${nodeClass(h)}${selected===i?' sel':''}" data-mapi="${i}">`;
    s+=`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="21"/>`;
    s+=`<svg x="${(x-9).toFixed(1)}" y="${(y-9).toFixed(1)}" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[hostIcon(h)]||ICONS.square}</svg>`;
    s+=`<text x="${x.toFixed(1)}" y="${(y+36).toFixed(1)}" class="mlabel">${esc(octet(h.addr))}</text></g>`;
  });
  const gw = gwI!==undefined ? hosts[gwI] : null;
  s+=`<g class="mnode center${gw&&selected===gwI?' sel':''}"${gw?` data-mapi="${gwI}"`:''}>`;
  s+=`<circle cx="${cx}" cy="${cy}" r="34"/>`;
  s+=`<svg x="${cx-13}" y="${cy-13}" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${gw?ICONS.router:ICONS.network}</svg>`;
  s+=`<text x="${cx}" y="${cy+52}" class="mlabel">${gw?esc(octet(gw.addr)):'LAN'}</text></g>`;
  s+=`</svg>`;
  $("#mapwrap").innerHTML=s;
  $("#mapmeta").textContent = `${N+(gw?1:0)} host(s) · ${idx.filter(i=>nodeClass(hosts[i])==='vuln').length} with vulns`;
}

async function launchTool(id){
  showToast("launching "+id+"…");
  try{
    const r=await fetch("/api/launch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tool:id})});
    const d=await r.json();
    showToast(d.ok ? d.launched+" opened in a terminal" : "error: "+d.error);
  }catch(e){ showToast("error: "+e.message); }
}

document.addEventListener("click",e=>{
  const md=e.target.closest("[data-mode]");    if(md){ setMode(md.dataset.mode); return; }
  const pk=e.target.closest("[data-pick]");     if(pk){ togglePick(+pk.dataset.pick); return; }
  if(e.target.closest("#callgo")){ callTargets(); return; }
  if(e.target.closest("#callclr")){ clearPicked(); return; }
  if(e.target.closest("#dcall")){ runScan(profile); return; }
  if(e.target.closest("#dout")){ detailView=true; updateCallScreen(); return; }
  if(e.target.closest("#dcancel")){ deselect(); return; }
  if(e.target.closest("#dmore")){ openDrawer(); return; }
  const portc=e.target.closest("[data-port]");  if(portc){ digPort(+portc.dataset.port, portc.dataset.svc); return; }
  const host=e.target.closest("[data-i]");      if(host){ selectHost(+host.dataset.i); return; }
  const tab=e.target.closest("[data-scan]");    if(tab){ runScan(tab.dataset.scan); return; }
  const tool=e.target.closest("[data-tool]");   if(tool){ launchTool(tool.dataset.tool); return; }
  const um=e.target.closest("[data-um]");      if(um){ setUiMode(um.dataset.um); setPref("ui",um.dataset.um); return; }
  if(e.target.closest("#gear")){ openSettings(); return; }
  if(e.target.closest("[data-alert]")){ if(alertAction) alertAction(); return; }
  if(e.target.closest("#mapbtn")){ openMap(); return; }
  if(e.target.closest("#mark")){ openCmdk(); return; }
  const mn=e.target.closest("[data-mapi]"); if(mn){ selectHost(+mn.dataset.mapi); closeMap(); return; }
  if(e.target.closest("#mapclose")||e.target.id==="mapmodal"){ closeMap(); return; }
  if(e.target.closest("#reportbtn")){ openReport(); return; }
  if(e.target.closest("#rphost")){ exportHost(); return; }
  if(e.target.closest("#rpsess")){ exportSession(); return; }
  if(e.target.closest("#rpclose")||e.target.id==="report"){ closeReport(); return; }
  if(e.target.closest("#setclose")){ closeSettings(); return; }
  if(e.target.closest("#setsave")){ saveSettings(); return; }
  if(e.target.closest("#setreset")){ resetBaselines(); return; }
  if(e.target.id==="settings"){ closeSettings(); return; }
  if(e.target.closest("#monmode")){ toggleMonMode(); return; }
  if(e.target.closest("#rescan")){ discoverWifi(); return; }
  if(e.target.closest("#details")){ showAPDetails(); return; }
  if(e.target.closest("#deauth1")){ deauthScan(); return; }
  if(e.target.closest("#deauthmon")){ deauthMonitor(); return; }
  if(e.target.closest("#webbanner")){ webBanner(); return; }
  if(e.target.closest("#mdnsbtn")){ mdnsScan(); return; }
  if(e.target.closest("#arpscan")){ arpScan(); return; }
  if(e.target.closest("#dhcpscan")){ dhcpScan(); return; }
  if(e.target.closest("#dnsbtn")){ dnsSniff(); return; }
  if(e.target.closest("#trafficbtn")){ trafficScan(); return; }
  if(e.target.closest("#stationsbtn")){ stations(); return; }
  if(e.target.closest("#topoclose")||e.target.id==="topo"){ closeTopo(); return; }
  if(e.target.closest("#gatt")){ gattScan(); return; }
  if(e.target.closest("#probe")){ probeWatch(); return; }
  if(e.target.closest("#hunt")){ huntStart(); return; }
  if(e.target.closest("#huntclose")||e.target.id==="huntmodal"){ huntStop(); return; }
  if(e.target.closest("#rpsnap")){ saveSnapshot(); return; }
  if(e.target.closest("#rpdiff")){ showDiff(); return; }
  if(e.target.closest("#rppcap")){ capturePcap(); return; }
  if(e.target.closest("#historybtn")){ openTimeline(); return; }
  if(e.target.closest("#tlclose")||e.target.id==="timeline"){ closeTimeline(); return; }
  if(e.target.closest("#tlclear")){ clearTimeline(); return; }
  if(e.target.closest("#monitorbtn")){ toggleMonitor(); return; }
  if(e.target.closest("#scanall")){ scanAll(); return; }
  if(e.target.closest("#dossierbtn")){ openDrawer(); return; }
  if(e.target.closest("#drclose")||e.target.id==="drawer"){ closeDrawer(); return; }
  if(e.target.closest("#bigcall")){
    if(running){ if(ctrl)ctrl.abort(); }
    else if(selected===null){ discover(); }
    else { runScan(profile); }
    return;
  }
  if(e.target.closest("#discover")){ discover(); return; }
  if(e.target.closest("#abort")){ if(ctrl)ctrl.abort(); return; }
  if(e.target.closest("#stealth")){
    stealth=!stealth;
    const b=$("#stealth"); b.classList.toggle("on",stealth);
    b.textContent = stealth ? "STEALTH ON" : "STEALTH OFF";
    showToast(stealth ? "stealth on — scans use a random MAC" : "stealth off");
    return;
  }
});

$("#gear").innerHTML = I('gear',20);
$("#mapbtn").innerHTML = I('map',18);
$("#reportbtn").innerHTML = I('download',20);
$("#historybtn").innerHTML = I('history',20);
$("#monitorbtn").innerHTML = I('bell',20);
$("#set-prof").innerHTML = NET_SCANS.map(s=>`<option value="${s.id}">${s.en}</option>`).join("");
loadPrefs();
renderTabs();
renderRail();
renderCard();
updateCallScreen();
loadConfig();
refreshMonitor();
refreshMonMode();
if('serviceWorker' in navigator){ window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{})); }

/* ---- v4: audio feedback (game-feel), off unless enabled ---- */
const SFX={ctx:null,on:localStorage.getItem("dokkos:sfx")==="on",
  unlock(){ if(!this.ctx){ try{ this.ctx=new (window.AudioContext||window.webkitAudioContext)(); }catch(e){} } if(this.ctx&&this.ctx.state==="suspended") this.ctx.resume(); },
  blip(freq,dur,type,vol){ if(!this.on||!this.ctx) return; try{
    const o=this.ctx.currentTime, g=this.ctx.createGain(), s=this.ctx.createOscillator();
    s.type=type||"sine"; s.frequency.setValueAtTime(freq,o);
    g.gain.setValueAtTime(0,o); g.gain.linearRampToValueAtTime(vol||0.05,o+0.01);
    g.gain.exponentialRampToValueAtTime(0.0001,o+(dur||0.12));
    s.connect(g); g.connect(this.ctx.destination); s.start(o); s.stop(o+(dur||0.12));
  }catch(e){} },
  tick(){ this.blip(1200,0.04,"square",0.03); },
  select(){ this.blip(660,0.06,"triangle",0.04); },
  start(){ this.blip(340,0.09,"sawtooth",0.05); setTimeout(()=>this.blip(520,0.09,"sawtooth",0.045),70); },
  done(){ this.blip(520,0.1,"sine",0.05); setTimeout(()=>this.blip(780,0.14,"sine",0.05),90); },
  alert(){ this.blip(180,0.16,"square",0.06); setTimeout(()=>this.blip(150,0.2,"square",0.06),150); },
  boot(){ [330,440,554,660].forEach((f,i)=>setTimeout(()=>this.blip(f,0.18,"triangle",0.05),i*120)); }
};
function haptic(ms){ try{ if(navigator.vibrate) navigator.vibrate(ms); }catch(e){} }
document.addEventListener("pointerdown",()=>SFX.unlock(),{once:true});

/* ---- v4: boot sequence ---- */
function runBoot(){
  const el=$("#boot"); if(!el) return;
  if(sessionStorage.getItem("dokkos:booted")==="1"){ el.classList.add("gone"); setTimeout(()=>el.remove(),50); return; }
  const log=$("#bootlog"), bar=$("#bootbar"), enter=$("#bootenter");
  const reduce=window.matchMedia&&window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const line=(html,cls)=>{ const d=document.createElement("div"); if(cls)d.className=cls; d.innerHTML=html; log.appendChild(d); log.scrollTop=log.scrollHeight; };
  const seq=[
    ["> DokkOS kernel "+ (($("#ver")&&$("#ver").textContent)||"v4.0") +" — cold boot","dim"],
    ["> mounting recon subsystems …","dim"],
    ["  [ OK ] scan engine","ok"],["  [ OK ] passive detection","ok"],
    ["  [ OK ] wireless stack","ok"],["  [ OK ] bluetooth stack","ok"],
    ["> probing local interfaces …","dim"],
    ["> establishing operator link …","dim"],
    ["  <span class='em'>&#9656; LINK ESTABLISHED</span>","ok"]
  ];
  let i=0; const step=reduce?0:1;
  function next(){
    if(i<seq.length){ line(seq[i][0],seq[i][1]); bar.style.width=Math.round((i+1)/seq.length*100)+"%";
      if(i===0) SFX.boot();
      if(seq[i][1]==="ok") SFX.tick();
      i++; setTimeout(next, reduce?0: (60+Math.random()*150));
    } else { enter.classList.add("show"); }
  }
  const finish=()=>{ sessionStorage.setItem("dokkos:booted","1"); SFX.done(); haptic(30); el.classList.add("gone"); setTimeout(()=>el.remove(),650); };
  enter.addEventListener("click",finish);
  el.addEventListener("click",()=>finish());  // tap to skip/enter anytime
  setTimeout(next, reduce?0:900);
  if(reduce){ enter.classList.add("show"); }
}

/* ---- v4: ambient telemetry ---- */
function startAmbient(){
  const t0=Date.now(); let pkt=0;
  const stats=["NOMINAL","SWEEPING","LISTENING","SECURE","ARMED"];
  setInterval(()=>{
    const s=Math.floor((Date.now()-t0)/1000);
    const mm=String(Math.floor(s/60)).padStart(2,"0"), ss=String(s%60).padStart(2,"0");
    const up=$("#amup"); if(up) up.textContent=mm+":"+ss;
    pkt += Math.floor(Math.random()*40)+ (running?60:3);
    const pk=$("#ampkt"); if(pk) pk.textContent=pkt.toLocaleString();
    const al=$("#amlink"); if(al) al.style.color = running? "var(--em)":"var(--gh)";
    const st=$("#amstat"); if(st){ st.textContent = running? "SWEEPING" : (monitorOn? "WATCHING":"NOMINAL"); }
  },1000);
}

/* ---- v4: command palette ---- */
const CMDS=[
  {t:"Network mode",k:"mode",i:"network",run:()=>setMode("net")},
  {t:"Bluetooth mode",k:"mode",i:"bluetooth",run:()=>setMode("bt")},
  {t:"Wi-Fi mode",k:"mode",i:"wifi",run:()=>setMode("wifi")},
  {t:"Discover / Scan network",k:"action",i:"radar",run:()=>{setMode("net");discover();}},
  {t:"Scan all hosts",k:"action",i:"radar",run:()=>{setMode("net");scanAll();}},
  {t:"ARP-spoof watch",k:"detect",i:"alert",run:()=>{setMode("net");arpScan();}},
  {t:"Rogue-DHCP check",k:"detect",i:"alert",run:()=>{setMode("net");dhcpScan();}},
  {t:"DNS sniff",k:"detect",i:"network",run:()=>{setMode("net");dnsSniff();}},
  {t:"Traffic topology",k:"view",i:"pulse",run:()=>{setMode("net");trafficScan();}},
  {t:"Wi-Fi stations",k:"view",i:"antenna",run:()=>{setMode("wifi");stations();}},
  {t:"Detection timeline",k:"view",i:"history",run:()=>openTimeline()},
  {t:"Network map",k:"view",i:"map",run:()=>{setMode("net");openMap&&openMap();}},
  {t:"Toggle unattended watch",k:"action",i:"bell",run:()=>toggleMonitor()},
  {t:"Export / report",k:"action",i:"download",run:()=>openReport()},
  {t:"Settings",k:"action",i:"gear",run:()=>openSettings()},
];
let cmdkSel=0, cmdkItems=[];
function openCmdk(){ $("#cmdk").classList.add("show"); const inp=$("#cmdkin"); inp.value=""; renderCmdk(""); setTimeout(()=>inp.focus(),30); }
function closeCmdk(){ $("#cmdk").classList.remove("show"); }
function renderCmdk(q){
  q=(q||"").toLowerCase().trim();
  let list=CMDS.map(c=>({...c}));
  hosts.forEach((h,idx)=>{ const nm=(h.label||h.addr||""); list.push({t:"Host · "+nm,k:"host",i:"square",run:()=>{selectHost(idx);}}); });
  cmdkItems = q? list.filter(c=>c.t.toLowerCase().includes(q)||c.k.includes(q)) : list.slice(0,12);
  cmdkSel=0;
  const L=$("#cmdklist");
  if(!cmdkItems.length){ L.innerHTML='<div class="cmdk-empty">no matches</div>'; return; }
  L.innerHTML=cmdkItems.map((c,i)=>`<div class="cmdk-row${i===0?' sel':''}" data-ci="${i}"><span class="ci">${I(c.i,16)}</span><span class="ct">${esc(c.t)}</span><span class="ck">${esc(c.k)}</span></div>`).join("");
}
function cmdkMove(d){ const rows=[...document.querySelectorAll(".cmdk-row")]; if(!rows.length)return;
  rows[cmdkSel]&&rows[cmdkSel].classList.remove("sel"); cmdkSel=(cmdkSel+d+rows.length)%rows.length;
  rows[cmdkSel].classList.add("sel"); rows[cmdkSel].scrollIntoView({block:"nearest"}); }
function cmdkRun(i){ const c=cmdkItems[i!=null?i:cmdkSel]; if(!c)return; closeCmdk(); SFX.select(); try{ c.run(); }catch(e){} }
document.addEventListener("keydown",e=>{
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="k"){ e.preventDefault(); $("#cmdk").classList.contains("show")?closeCmdk():openCmdk(); return; }
  if(!$("#cmdk").classList.contains("show")) return;
  if(e.key==="Escape") closeCmdk();
  else if(e.key==="ArrowDown"){ e.preventDefault(); cmdkMove(1); }
  else if(e.key==="ArrowUp"){ e.preventDefault(); cmdkMove(-1); }
  else if(e.key==="Enter"){ e.preventDefault(); cmdkRun(); }
});
$("#cmdkin").addEventListener("input",e=>renderCmdk(e.target.value));
$("#cmdklist").addEventListener("click",e=>{ const r=e.target.closest(".cmdk-row"); if(r) cmdkRun(+r.dataset.ci); });
$("#cmdk").addEventListener("click",e=>{ if(e.target.id==="cmdk") closeCmdk(); });

runBoot();
startAmbient();
</script>
</body>
</html>"""


def install_service(args):
    """Generate a systemd unit so the console + unattended watch survive reboots."""
    app_path = os.path.abspath(__file__)
    workdir = os.path.dirname(app_path)
    targets = " ".join(args.targets) if getattr(args, "targets", None) else ""
    wlan = f" --wlan-mon {args.wlan_mon}" if getattr(args, "wlan_mon", None) else ""
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 5000)
    exec_line = (f"{sys.executable} {app_path} {targets}"
                 f" --host {host} --port {port}{wlan}").replace("  ", " ").strip()
    unit = (
        "[Unit]\n"
        "Description=DokkOS recon & passive-detection console\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_line}\n"
        f"WorkingDirectory={workdir}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "# runs as root so tshark/nmap raw capture works; change User= to drop privileges\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    target = "/etc/systemd/system/dokkos.service"
    wrote = None
    try:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(unit)
        wrote = target
    except OSError:
        fallback = os.path.join(workdir, "dokkos.service")
        try:
            with open(fallback, "w", encoding="utf-8") as fh:
                fh.write(unit)
            wrote = fallback
        except OSError:
            wrote = None
    print("---- dokkos.service ----")
    print(unit)
    if wrote == target:
        print(f"[ok] wrote {target}")
        print("     enable on boot:  sudo systemctl daemon-reload && "
              "sudo systemctl enable --now dokkos")
    elif wrote:
        print(f"[note] not root — wrote a copy to {wrote}")
        print(f"       install it:  sudo cp {wrote} {target} && "
              "sudo systemctl daemon-reload && sudo systemctl enable --now dokkos")
    else:
        print("[note] couldn't write a file — copy the unit above to "
              f"{target} yourself.")
    print("     bind beyond localhost (to reach it from your phone) by adding "
          "--host 0.0.0.0 to ExecStart — and set a reverse proxy / token first.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DokkOS — interactive local recon console",
        epilog="examples:\n"
               "  python app.py                       # auto-detect local networks\n"
               "  python app.py 10.0.0.0/24           # one network\n"
               "  python app.py 192.168.0.0/16 10.0.0.0/24 scanme.nmap.org\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*",
                        help="networks/hosts to make scannable (CIDR, IP, or hostname). "
                             "Default: auto-detect every network this host is on.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default 127.0.0.1 — keep it local)")
    parser.add_argument("--port", type=int, default=5000, help="port (default 5000)")
    parser.add_argument("--wlan-mon", dest="wlan_mon", default=None,
                        help="monitor-mode wireless interface for Wi-Fi recon "
                             "(e.g. wlan0mon). Default: auto-detect.")
    parser.add_argument("--install", action="store_true",
                        help="install any missing tools (apt + pip), then continue. "
                             "Needs root for apt — run with sudo.")
    parser.add_argument("--check", action="store_true",
                        help="report which tools are present/missing and exit.")
    parser.add_argument("--install-service", dest="install_service", action="store_true",
                        help="write a systemd unit to run DokkOS headless on boot, then exit.")
    args = parser.parse_args()

    if args.install_service:
        install_service(args)
        raise SystemExit(0)

    present, miss_apt, miss_pip = check_dependencies()
    if args.check:
        print("present:", ", ".join(present) or "(none)")
        print("missing apt:", " ".join(miss_apt) or "(none)")
        print("missing pip:", " ".join(miss_pip) or "(none)")
        raise SystemExit(0)
    if args.install:
        install_dependencies()
    # Always show a per-app present/missing report on launch.
    report_dependencies()

    if args.wlan_mon:
        WIFI_MON = args.wlan_mon

    chosen = []
    for t in args.targets:
        v = validate_target(t)
        if v:
            chosen.append(v)
        else:
            print(f"[skip] invalid target: {t}")
    if not chosen:
        chosen = detect_local_networks()
        if chosen:
            print("[auto] detected local networks:", ", ".join(chosen))
    if not chosen:
        chosen = ["192.168.1.0/24"]
        print("[warn] couldn't auto-detect networks; defaulting to 192.168.1.0/24")
        print("       pass explicit targets, e.g.: python app.py 10.0.0.0/24")
    SCAN_TARGETS[:] = chosen
    print("Scan scopes:", ", ".join(SCAN_TARGETS))

    try:
        loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        print("\n" + "!" * 64)
        print(f"[WARNING] binding to {args.host}, not loopback.")
        print("  DokkOS has NO authentication and can run scans and launch tools")
        print("  (often as root). Anyone who can reach this address can drive it.")
        print("  Only do this on a trusted, isolated network — otherwise use 127.0.0.1.")
        print("!" * 64 + "\n")

    print(f"DokkOS on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)
