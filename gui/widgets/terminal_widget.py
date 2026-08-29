# HAWK — Hostile Assessment War-Kit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0
#
# Attribution "Created by Lorenzo Serafini" must be preserved in all
# redistributed and Derivative Works — see NOTICE for details.

"""
HAWK - Terminal Output Widget v1.0
Font 14+. ANSI stripped. Smart parsers with contextual explanations.
Non-standard port detection built-in.
"""

import os
import re
import tkinter as tk
import customtkinter as ctk
from datetime import datetime
from utils.config import COLORS, SESSIONS_DIR, SZ, SERVICE_PORT_MAP, APP_VERSION


# ─── ANSI stripper ────────────────────────────────────────────────────────────
_ANSI = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
def _strip(t): return _ANSI.sub('', t)

# ─── Nmap / masscan progress detection ───────────────────────────────────────
# Nmap:    "SYN Stealth Scan Timing: About 43.50% done; ETC: 12:34 (0:01:45 remaining)"
_NMAP_PCT_RE  = re.compile(r'About\s+([\d.]+)%\s+done')
_NMAP_ETA_RE  = re.compile(r'\(([^)]*remaining)\)')
_NMAP_PHASE_RE = re.compile(r'^(\S.*?)\s+Timing:')
# Nmap with -v: "Initiating SYN Stealth Scan at 09:11" / "Completed SYN Stealth Scan at 09:12, 105.72s elapsed"
_NMAP_INIT_RE = re.compile(r'^Initiating\s+(.+?)\s+at\s+\d{2}:\d{2}', re.I)
_NMAP_DONE_RE = re.compile(r'^Completed\s+(.+?)\s+at\s+\d{2}:\d{2}', re.I)
# "Stats:" header line — skip it (contains no progress info)
_NMAP_STATS_RE = re.compile(r'^Stats:\s')
# Masscan: "rate:  1.00-kpps, 23.45% done,   0:01:23 remaining, found=5"
_MASSCAN_PCT_RE = re.compile(r'rate:.*?([\d.]+)%\s+done')
_MASSCAN_ETA_RE = re.compile(r'([\d:]+)\s+remaining')
# Rustscan: "Open 192.168.1.10:80"  and  "[~] Starting Script(s)"
_RUSTSCAN_OPEN_RE   = re.compile(r'^Open\s+\S+:\d+', re.I)
_RUSTSCAN_SCRIPT_RE = re.compile(r'\[~\]\s*Starting\s+Script', re.I)


# Phase → (start_pct, end_pct) mapping.  A fast scan (--top-ports 100, -T4)
# may emit only a single "Timing: About X% done" line (or none), so we lean
# on the Initiating/Completed markers that `-v` reliably prints for every
# phase.  This way even a 2-second scan shows movement.
def _map_nmap_phase(name_lower: str):
    table = (
        ("arp ping",         ( 0,  5)),
        ("ping scan",        ( 0,  5)),
        ("parallel dns",     ( 5,  8)),
        ("syn stealth",      ( 8, 50)),
        ("connect scan",     ( 8, 50)),
        ("ack scan",         ( 8, 50)),
        ("udp scan",         ( 8, 50)),
        ("xmas",             ( 8, 50)),
        ("fin scan",         ( 8, 50)),
        ("null scan",        ( 8, 50)),
        ("maimon",           ( 8, 50)),
        ("service scan",     (50, 75)),
        ("os detection",     (75, 88)),
        ("traceroute",       (88, 92)),
        ("nse",              (92, 98)),
        ("script scanning",  (92, 98)),
    )
    for substr, rng in table:
        if substr in name_lower:
            return rng
    return (None, None)


# ─── Finding explanations ─────────────────────────────────────────────────────
EXPLANATIONS = {
    "/admin/":              "This path responds without authentication or with weak credentials. Try admin:admin, admin:password, or use Hydra HTTP-GET for brute force.",
    "/backup":              "Backup directories often contain config files, database dumps or private keys. Browse manually and check contents.",
    "/phpmyadmin":          "Database admin panel exposed. Try default credentials: root:(empty), root:root, admin:admin.",
    "x-frame-options":      "Missing header — clickjacking possible. The app may be embeddable in an attacker-controlled iframe.",
    "x-content-type":       "MIME sniffing enabled. Browser may misinterpret file types — potential XSS vector.",
    "server:":              "Server version disclosed. Search for CVEs: searchsploit <software> <version>",
    "sql syntax":           "Possible SQL injection. Run: sqlmap -u 'http://target/page?id=1' --dbs --batch",
    # SMB message-signing is handled by _explain_smb_signing (it depends
    # on whether signing is REQUIRED), not by a flat keyword lookup.
    "ms17-010":             "CVE-2017-0144 — EternalBlue. High probability of RCE on unpatched systems. Go to Exploitation and select the EternalBlue preset.",
    "eternal":              "EternalBlue potentially exploitable. Use msfconsole: exploit/windows/smb/ms17_010_eternalblue",
    "anonymous":            "Anonymous login allowed. Connect without credentials and list available files.",
    "default credentials":  "Default credentials accepted. Change them immediately in a real engagement.",
    "heartbleed":           "CVE-2014-0160 — OpenSSL memory disclosure. Can leak private keys and session tokens.",
    "shellshock":           "CVE-2014-6271 — Bash RCE via environment variables. Test CGI endpoints.",
    "log4shell":            "CVE-2021-44228 — Log4j RCE. Extremely critical. Send JNDI payload to trigger.",
}


def _explain_smb_signing(low: str) -> str:
    """Explain an nmap SMB message-signing line.

    nmap reports it as e.g. `message_signing: required` /
    `message_signing: disabled` (smb-security-mode) or
    `Message signing enabled and required` / `... but not required`
    (smb2-security-mode).  Signing REQUIRED is the SECURE case: NTLM
    relay to this host is blocked.  A flat keyword lookup annotated
    EVERY signing line "relayable", inverting the finding when signing
    was required (W-01).
    """
    # "required" but NOT "not required" → the secure, non-relayable case.
    if "required" in low and "not required" not in low:
        return ("SMB signing REQUIRED — NTLM relay to this host is "
                "blocked (not a relay target).")
    return ("SMB signing not required — vulnerable to NTLM relay "
            "(ntlmrelayx). Capture a hash and relay it to other hosts.")


def _explain(line: str, seen=None) -> str:
    low = line.lower()
    # SMB signing is relay-relevant only when NOT required — decide from
    # the line itself instead of a flat keyword (W-01).
    if "message signing" in low or "message_signing" in low:
        expl = _explain_smb_signing(low)
    else:
        expl = ""
        for kw, e in EXPLANATIONS.items():
            if kw in low:
                expl = e
                break
    if not expl:
        return ""
    # Show each distinct hint at most ONCE per tool run.  A verbose tool
    # (dirb testing /phpMyAdmin/setup/<word> for every wordlist entry)
    # would otherwise repeat "Database admin panel exposed" dozens of
    # times — drowning the output and faking many exposed panels.
    if seen is not None:
        if expl in seen:
            return ""
        seen.add(expl)
    return expl


# ─── Smart parsers ────────────────────────────────────────────────────────────

def _parse_nmap(lines):
    out = []
    seen = set()
    open_ports = []
    for line in lines:
        l = _strip(line.strip())
        m = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)', l, re.I)
        if m:
            port, proto, svc, rest = int(m.group(1)), m.group(2), m.group(3), m.group(4)
            out.append(("finding", f"  {proto.upper():3}  {port:<6} {svc:<12} {rest.strip()}"))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"       → {exp}"))
            open_ports.append((port, proto, svc))
        elif l.lower().startswith("nmap scan report"):
            out.append(("info", f"  {l}"))
        elif re.search(r'os details|device type|running:', l, re.I):
            out.append(("info", f"  {l}"))
        elif l.startswith("|") or "script output" in l.lower():
            out.append(("dim", f"  {l}"))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"       → {exp}"))
    return out, open_ports


def _parse_gobuster(lines):
    out = []
    seen = set()
    import re as _re
    # Gobuster: /path (Status: 200) [Size: 1234]
    GB_RE = _re.compile(
        r'^(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]')
    # FFUF: similar or JSON-ish output
    status_counts = {}
    entries = []
    for line in lines:
        l = _strip(line.strip())
        m = GB_RE.match(l)
        if m:
            path, status, size = m.group(1), m.group(2), m.group(3)
            code = int(status)
            status_counts[code] = status_counts.get(code, 0) + 1
            # Color-code by status
            if code == 200:
                tag = "finding"
                icon = "✓"
            elif code in (301, 302, 307):
                tag = "info"
                icon = "→"
            elif code in (401, 403):
                tag = "warn"
                icon = "⊘"
            else:
                tag = "dim"
                icon = "·"
            out.append((tag,
                        f"  {icon} {path:<40} [{status}]  {size}B"))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"       → {exp}"))
            entries.append(path)
        elif "(Status:" in l or (l.startswith("/") and "Status" in l):
            # Fallback for non-standard format
            out.append(("finding", f"  {l}"))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"       → {exp}"))
    # Summary line at the end
    if entries:
        summary_parts = []
        for code in sorted(status_counts.keys()):
            summary_parts.append(f"{code}:{status_counts[code]}")
        out.append(("info",
                     f"\n  ── {len(entries)} paths found  "
                     f"({', '.join(summary_parts)})"))
    return out


def _parse_nikto(lines):
    out = []
    seen = set()
    for line in lines:
        l = _strip(line.strip())
        if l.startswith("+ ") and "Target" not in l and "0 error" not in l:
            out.append(("finding", f"  {l}"))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"       → {exp}"))
        elif l.startswith("- Nikto"):
            out.append(("info", f"  {l}"))
    return out


def _parse_enum4linux(lines):
    out = []
    seen = set()
    keys = ["domain name:", "domain sid:", "server:", "os:", "share",
            "user:", "group", "password policy", "workgroup",
            "membership", "native os", "netbios"]
    for line in lines:
        l = _strip(line.strip())
        if any(k in l.lower() for k in keys) and l:
            out.append(("finding", f"  {l}"))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"       → {exp}"))
    return out


def _parse_hydra(lines):
    out = []
    for line in lines:
        l = _strip(line.strip())
        if "[" in l and ("login:" in l.lower() or "password:" in l.lower()):
            out.append(("finding", f"  {l}"))
            out.append(("dim",
                        "       → Credentials found! Added to Credential Store. "
                        "Try on all open services."))
        elif l.startswith("[ERROR]"):
            out.append(("error", f"  {l}"))
    return out


def _parse_whois(lines):
    """
    WHOIS parser that:
     - detects private-IP/reserved-space whois answers (ARIN/IANA boilerplate)
     - hides legal boilerplate / terms-of-use / comment blocks
     - keeps only the useful org/contact/netblock fields
    """
    from utils.target_validator import is_private_ip

    out  = []
    keep = ["registrant", "organization", "orgname", "org-name",
            "country", "countrycode", "name server", "nserver",
            "registrar", "creation date", "created", "updated",
            "expiry", "expires", "admin", "tech",
            "netname", "netrange", "cidr", "netblock", "inetnum",
            "descr", "role", "abuse"]
    skip = ["terms of use", "copyright", "#", "% ", "whois server",
            "the data", "by submitting", "by the following",
            "all rights reserved", "for more information"]

    # 1. Check if the *subject* of the whois lookup is a private range
    first_ip = None
    for line in lines[:40]:
        l = _strip(line.strip())
        m = re.search(r'(?:NetRange|inetnum|CIDR)[:\s]+([0-9./\s\-]+)', l, re.I)
        if m:
            ip_token = re.search(r'\d+\.\d+\.\d+\.\d+', m.group(1))
            if ip_token:
                first_ip = ip_token.group(0)
                break

    if first_ip and is_private_ip(first_ip):
        out.append(("warn",
                    f"  ⚠  {first_ip} is in a PRIVATE/RESERVED range — "
                    "WHOIS shows only IANA allocation info, no real owner."))
        out.append(("dim",
                    "       → WHOIS is useless for lab/internal IPs. "
                    "Move on: arp-scan, nmap, enum4linux."))
        return out

    seen = set()
    for line in lines:
        l = _strip(line.strip())
        low = l.lower()
        if not l or len(l) < 3:
            continue
        if any(k in low for k in skip):
            continue
        if ":" not in l:
            continue
        if any(k in low for k in keep):
            # Dedupe identical lines (ARIN repeats abuse contacts)
            if l in seen:
                continue
            seen.add(l)
            out.append(("finding", f"  {l}"))
    if not out:
        out.append(("dim", "  — WHOIS returned no usable owner information."))
    return out


def _parse_masscan(lines):
    """
    Parse masscan output. Recognizes:
      Discovered open port 22/tcp on 192.168.1.10
      Discovered open port 3306/tcp on 10.0.0.5
    Returns (parsed, open_ports) mimicking _parse_nmap.
    """
    out = []
    open_ports = []
    seen = set()
    for line in lines:
        l = _strip(line.strip())
        m = re.search(
            r'Discovered\s+open\s+port\s+(\d+)/(tcp|udp)\s+on\s+'
            r'([\d.a-fA-F:]+)', l, re.I)
        if m:
            port, proto, host = int(m.group(1)), m.group(2), m.group(3)
            key = (host, port, proto)
            if key in seen:
                continue
            seen.add(key)
            out.append(("finding",
                        f"  {proto.upper():3}  {port:<6} open  on {host}"))
            open_ports.append((port, proto, "unknown"))
        # Skip "rate: ... % done ... remaining" progress lines — the
        # progress bar already shows live status; dumping every tick
        # into the terminal floods output (200+ lines per scan).

    if open_ports:
        ports_str = ",".join(str(p) for p, _, _ in sorted(open_ports))
        out.append(("dim",
                    f"       → Follow up: nmap -sV -sC -p {ports_str} <target>"))
    return out, open_ports


def _parse_traceroute(lines):
    """
    Traceroute / tracepath / mtr parser.
    Explains * * * hops, OPSEC warnings, suggests -T/-I/-U alternatives.
    """
    out = []
    hops = []
    star_hops = 0
    total_hops = 0
    final_reached = False
    target_ip = None

    for line in lines:
        l = _strip(line.strip())
        if not l:
            continue
        # Header: "traceroute to 1.2.3.4 (1.2.3.4), 30 hops max..."
        m = re.match(r'traceroute to\s+(\S+)', l, re.I)
        if m:
            target_ip = m.group(1)
            out.append(("info", f"  {l}"))
            continue
        # Hop line: "  1  192.168.1.1  0.5 ms  0.4 ms  0.5 ms"
        m = re.match(r'^\s*(\d+)\s+(.*)$', l)
        if m:
            hop_num = int(m.group(1))
            rest = m.group(2)
            total_hops = max(total_hops, hop_num)
            if "* * *" in rest or re.fullmatch(r'(\*\s*)+', rest):
                star_hops += 1
                out.append(("dim", f"  {hop_num:>3}  * * *   (no reply)"))
                hops.append((hop_num, None))
            else:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', rest)
                if ip_match and target_ip and ip_match.group(1) == target_ip:
                    final_reached = True
                out.append(("finding", f"  {l}"))
                hops.append((hop_num, rest))

    # Explanations
    out.append(("", ""))
    if star_hops == 0:
        out.append(("dim",
                    "  → Clean path. Every hop answered ICMP TTL-exceeded."))
    elif star_hops >= total_hops * 0.4:
        out.append(("warn",
                    f"  ⚠  {star_hops}/{total_hops} hops returned * * *."))
        out.append(("dim",
                    "     → These routers drop/rate-limit ICMP or a firewall "
                    "silently discards the probe. Try:"))
        out.append(("dim",
                    "         traceroute -T -p 80   <target>   # TCP/80  (often passes firewalls)"))
        out.append(("dim",
                    "         traceroute -I        <target>   # ICMP echo"))
        out.append(("dim",
                    "         tcptraceroute        <target> 443"))
    else:
        out.append(("dim",
                    f"  → {star_hops} silent hop(s) — typical of load-balanced "
                    "core routers. Not a blocker."))

    if not final_reached and target_ip:
        out.append(("warn",
                    "  ⚠  Target never replied on the last hop — "
                    "final router may filter all trace probes."))

    out.append(("dim",
                "  OPSEC: traceroute is LOUD. Every intermediate router logged "
                "your source IP. Use a VPN/pivot in real engagements."))
    return [(lv, ln) for lv, ln in out if ln != "" or lv == ""]


def _parse_dig(lines):
    """dig / host / nslookup output."""
    out = []
    in_answer = False
    for line in lines:
        l = _strip(line.strip())
        if not l or l.startswith(";;") and "ANSWER SECTION" in l.upper():
            in_answer = True
            out.append(("info", f"  {l}"))
            continue
        if l.startswith(";"):
            if "status:" in l.lower() or "flags:" in l.lower():
                out.append(("dim", f"  {l}"))
            continue
        # Answer record:  domain. 3600 IN A 1.2.3.4
        m = re.match(
            r'^(\S+)\.?\s+\d+\s+IN\s+(A|AAAA|MX|NS|TXT|CNAME|SOA|PTR)\s+(.+)$',
            l, re.I)
        if m:
            name, rtype, val = m.group(1), m.group(2).upper(), m.group(3)
            out.append(("finding", f"  {rtype:<5} {name:<30} → {val}"))
    return out


def _parse_geoip(lines):
    """Parse 'geoiplookup', ipinfo.io, ip-api outputs."""
    out = []
    keep = ["country", "region", "city", "latitude", "longitude",
            "isp", "org", "as", "timezone", "postal"]
    for line in lines:
        l = _strip(line.strip())
        low = l.lower()
        if ":" in l and any(k in low for k in keep):
            out.append(("finding", f"  {l}"))
        elif re.search(r'geoip\s+\S+\s+edition', low):
            out.append(("dim", f"  {l}"))
    return out


def _parse_asn(lines):
    """Parse asn / bgp lookup results (e.g. whois.cymru.com, asnlookup)."""
    out = []
    for line in lines:
        l = _strip(line.strip())
        low = l.lower()
        if not l:
            continue
        if re.search(r'\bAS\d+\b', l):
            out.append(("finding", f"  {l}"))
        elif any(k in low for k in ["origin", "prefix", "asn", "as name"]):
            out.append(("finding", f"  {l}"))
    return out


def _parse_whatweb(lines):
    out = []
    for line in lines:
        l = _strip(line.strip())
        if "http" in l.lower() and "[" in l:
            out.append(("finding", f"  {l}"))
    return out


def _parse_wafw00f(lines):
    """Parse wafw00f output.

    wafw00f prints a large ASCII-art banner (______/\\_____ etc.) and then
    useful lines such as:
        [*] Checking http://target/
        [+] The site http://target/ is behind XYZ (Vendor) WAF.
        [-] No WAF detected by the generic detection
        [~] Number of requests: 8
    We skip banner lines (pure ASCII art, version line, author line) and
    keep the [*/+/-/~] status lines plus any line naming a detected WAF.
    """
    out = []
    # Banner detection: lines that are >60% non-alphanum characters
    # (the ASCII logo) OR contain only dashes/underscores/slashes/spaces.
    banner_re = re.compile(r"^[\s_\-\/\\\|\^\*\.\(\)\[\]]+$")
    skip_keywords = ("sandro gauci", "enablesecurity", "wafw00f :",
                     "version", "copyleft")
    for line in lines:
        l = _strip(line.strip())
        if not l:
            continue
        low = l.lower()
        # Skip pure banner art
        if banner_re.match(l):
            continue
        # Non-alphanumeric density heuristic
        alnum = sum(1 for c in l if c.isalnum() or c.isspace())
        if len(l) > 10 and alnum / max(len(l), 1) < 0.4:
            continue
        if any(k in low for k in skip_keywords):
            continue
        # Keep only meaningful status / result lines
        if l.startswith(("[+]", "[-]", "[*]", "[~]", "[!]")) or \
           "waf" in low or "behind" in low or "detected" in low or \
           "checking http" in low:
            tag = "finding" if l.startswith("[+]") or "behind" in low \
                else ("info" if l.startswith(("[*]", "[~]")) else "dim")
            out.append((tag, f"  {l}"))
    return out


def _parse_nuclei(lines):
    out = []
    seen = set()
    for line in lines:
        l = _strip(line.strip())
        if re.search(r'\[(critical|high|medium|low)\]', l, re.I):
            out.append(("finding", f"  {l}"))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"       → {exp}"))
        elif "[INF]" in l and "http" in l.lower():
            out.append(("info", f"  {l}"))
    return out


def _parse_generic(lines):
    out = []
    seen = set()
    for line in lines:
        l = _strip(str(line).strip() if not isinstance(line, tuple)
                   else line[1].strip())
        if not l:
            continue
        low = l.lower()
        if any(k in low for k in ["open", "found", "[+]", "success", "vuln",
                                   "discovered", "login:", "password:",
                                   "critical", "[high]", "[medium]",
                                   "vulnerable"]):
            out.append(("finding", l))
            exp = _explain(l, seen)
            if exp:
                out.append(("dim", f"  → {exp}"))
        elif any(k in low for k in ["error", "failed", "[!]", "denied",
                                     "not found", "no such"]):
            out.append(("error", l))
    return out


TOOL_PARSERS = {
    "nmap":        lambda lines: _parse_nmap(lines)[0],
    "masscan":     lambda lines: _parse_masscan(lines)[0],
    "gobuster":    _parse_gobuster,
    "ffuf":        _parse_gobuster,
    "nikto":       _parse_nikto,
    "enum4linux":  _parse_enum4linux,
    "enum4linux-ng": _parse_enum4linux,
    "hydra":       _parse_hydra,
    "whois":       _parse_whois,
    "whatweb":     _parse_whatweb,
    "wafw00f":     _parse_wafw00f,
    "nuclei":      _parse_nuclei,
    "traceroute":  _parse_traceroute,
    "tracepath":   _parse_traceroute,
    "mtr":         _parse_traceroute,
    "dig":         _parse_dig,
    "host":        _parse_dig,
    "nslookup":    _parse_dig,
    "geoiplookup": _parse_geoip,
    "ipinfo":      _parse_geoip,
    "asn":         _parse_asn,
    "cymru":       _parse_asn,
}


# ─── Terminal Widget ──────────────────────────────────────────────────────────

class TerminalWidget(ctk.CTkFrame):

    LEVEL_COLORS = {
        "info":    COLORS["text_dim"],
        "finding": COLORS["text_green"],
        "success": "#40A060",
        "error":   COLORS["text_red"],
        "warn":    COLORS["text_yellow"],
        "cmd":     COLORS["text_cyan"],
        "dim":     COLORS["text_muted"],
        "sep":     COLORS["border_dim"],
        "section": COLORS["text_green"],
    }

    def __init__(self, parent, app, **kwargs):
        super().__init__(
            parent,
            fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=4,
            **kwargs)
        self.app         = app
        self._lines      = []
        # Autoscroll coalescing: `see("end")` used to run once PER LINE,
        # from an after(0) also scheduled per line.  A verbose scan
        # emitting thousands of lines a second turned that into
        # thousands of forced scrolls and saturated the event loop.
        self._scroll_pending = False
        self._trim_announced = False
        self._smart_mode = self._load_smart_pref()
        self._pending    = {}   # tool_name → [raw lines]
        self._progress_labels = {}  # tool_name → (tk.Label, tk.StringVar)
        self._progress_max    = {}  # tool_name → highest pct seen (no-rewind clamp)
        self._port_scan_seen  = {}  # tool_name → bool — guards NSE pre-scan
        self._build_ui()

    @staticmethod
    def _load_smart_pref() -> bool:
        try:
            import json
            prefs_path = os.path.join(SESSIONS_DIR, ".preferences.json")
            if os.path.exists(prefs_path):
                with open(prefs_path) as f:
                    return json.load(f).get("smart_mode", True)
        except Exception:
            pass
        return True

    def _f(self, key="term", bold=False):
        return ctk.CTkFont(family="Courier New", size=SZ.get(key, 13),
                           weight="bold" if bold else "normal")

    def _build_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_header"],
                           height=34, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew", padx=1, pady=(1, 0))
        hdr.grid_columnconfigure(0, weight=1)
        hdr.grid_propagate(False)

        ctk.CTkLabel(hdr, text="  TERMINAL OUTPUT",
                     font=self._f("lg", True),
                     text_color=COLORS["text_dim"], anchor="w").grid(
            row=0, column=0, sticky="w", padx=10, pady=4)

        self._smart_var = ctk.BooleanVar(value=self._smart_mode)
        ctk.CTkCheckBox(
            hdr, text="Smart output",
            variable=self._smart_var,
            onvalue=True, offvalue=False,
            font=self._f("sm"), text_color=COLORS["text_muted"],
            fg_color=COLORS["border_green"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"],
            checkmark_color=COLORS["bg_primary"],
            width=18, height=18,
            command=self._toggle_smart,
        ).grid(row=0, column=1, padx=10, pady=4)

        btn_f = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_f.grid(row=0, column=2, sticky="e", padx=6)
        for lbl, cmd, col, w in [
            ("OPEN SHELL", self._open_shell, COLORS["text_green"], 100),
            ("SAV",        self._save,       COLORS["text_dim"],   38),
            ("CLR",        self.clear,       COLORS["text_red"],   38),
        ]:
            ctk.CTkButton(
                btn_f, text=lbl, width=w, height=22,
                font=self._f("xs", True),
                fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
                border_color=col, border_width=1,
                text_color=col, corner_radius=2, command=cmd,
            ).pack(side="left", padx=2)

        self._textbox = ctk.CTkTextbox(
            self,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_dim"],
            font=self._f("term"),
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"],
            border_width=0, corner_radius=0,
            wrap="none", activate_scrollbars=True,
        )
        self._textbox.grid(row=1, column=0, sticky="nsew", padx=1, pady=(0, 1))
        self._register_tags()

        self._append(f"[*] HAWK v{APP_VERSION} — session not started", "dim")
        self._append("─" * 68, "sep")
        self._append("[*] Set target IP and start a session to begin.", "dim")
        self._append("─" * 68, "sep")
        self._check_nmap_caps()

    def _check_nmap_caps(self):
        """One-time check at startup: warn the user if nmap/masscan don't
        have cap_net_raw set.  Without caps, HAWK falls back to sudo, which
        breaks the real-time progress bar (sudo's pty relay buffers
        --stats-every output).  Running setup_nmap_caps.sh once fixes it."""
        try:
            from utils.runner import has_raw_caps
            missing = [b for b in ("nmap", "masscan") if not has_raw_caps(b)]
            if not missing:
                return
            self._append("", "sep")
            self._append(
                "  ⚠  nmap/masscan missing cap_net_raw — "
                "scans will use sudo (slower, no live progress bar).",
                "warn")
            self._append(
                "     To enable real-time progress bars, run ONCE:",
                "dim")
            self._append(
                "         ./setup_nmap_caps.sh",
                "cmd")
            self._append("─" * 68, "sep")
        except Exception:
            pass

    def _register_tags(self):
        inner = self._textbox._textbox
        for level, color in self.LEVEL_COLORS.items():
            inner.tag_config(level, foreground=color)
        inner.tag_config("progress", foreground=COLORS["text_cyan"])

    def _toggle_smart(self):
        self._smart_mode = self._smart_var.get()
        mode = "Smart (findings only)" if self._smart_mode else "Verbose (raw output)"
        self.write(f"[*] Output mode: {mode}", "dim")
        # Persist preference
        try:
            import json
            prefs_path = os.path.join(SESSIONS_DIR, ".preferences.json")
            prefs = {}
            if os.path.exists(prefs_path):
                with open(prefs_path) as f:
                    prefs = json.load(f)
            prefs["smart_mode"] = self._smart_mode
            with open(prefs_path, "w") as f:
                json.dump(prefs, f)
        except Exception:
            pass

    # ─── Public API ──────────────────────────────────────────────────────────

    def write(self, text: str, level: str = "info"):
        self.after(0, lambda: self._append(_strip(text), level))

    def output_callback(self, line: str, tool_name: str, level: str = "info",
                        mirror_live: bool = False):
        """Route a tool output line: intercept nmap/masscan progress into
        the bar, otherwise buffer (smart mode) or append (verbose).

        ``mirror_live`` forces every non-progress line to the terminal as it
        arrives even in smart mode.  Discovery runs (network sweep) need it:
        a smart-mode sweep buffers all output until done, so on a long range
        the operator sees nothing and aborts blind (finding F-26).  Progress
        lines still feed the bar only — they are never echoed as text.
        """
        line = _strip(line)
        # ── Nmap / masscan progress interception (smart & raw mode) ──
        if _NMAP_STATS_RE.match(line):
            return               # skip "Stats: ..." header line

        # Nmap phase starts: "Initiating SYN Stealth Scan at 09:11"
        init_m = _NMAP_INIT_RE.match(line)
        if init_m:
            phase_raw = init_m.group(1).strip()
            phase_low = phase_raw.lower()
            # With `-sC` nmap runs NSE pre-scanning (rDNS, broadcast scripts,
            # etc.) BEFORE the port scan — if we take that Initiating NSE at
            # face value the bar jumps straight to 92 % before the real scan
            # has even begun.  Skip NSE until we've actually seen a port
            # scan phase for this tool.
            is_nse = "nse" in phase_low or "script scanning" in phase_low
            if is_nse and not self._port_scan_seen.get(tool_name, False):
                return
            # Mark that port-scan phase has started so the NSE guard above
            # flips from "pre-scan mode" to "post-scan mode".
            if any(k in phase_low for k in (
                    "syn stealth", "connect scan", "ack scan", "udp scan",
                    "xmas", "fin scan", "null scan", "maimon")):
                self._port_scan_seen[tool_name] = True
            lo, hi = _map_nmap_phase(phase_low)
            if lo is not None:
                self.after(0, lambda p=float(lo), ph=phase_raw, tn=tool_name:
                          self._update_progress(p, ph, "", tn))
            return

        # Nmap phase completes: "Completed SYN Stealth Scan at 09:12, 105.72s elapsed"
        done_m = _NMAP_DONE_RE.match(line)
        if done_m:
            phase_raw = done_m.group(1).strip()
            phase_low = phase_raw.lower()
            # Mirror the NSE pre-scan guard above.
            is_nse = "nse" in phase_low or "script scanning" in phase_low
            if is_nse and not self._port_scan_seen.get(tool_name, False):
                return
            lo, hi = _map_nmap_phase(phase_low)
            if hi is not None:
                self.after(0, lambda p=float(hi), ph=f"{phase_raw} done", tn=tool_name:
                          self._update_progress(p, ph, "", tn))
            return

        # Rustscan-specific markers (rustscan discovers ports then delegates
        # the deep-dive to nmap; nmap's own Initiating/Completed lines after
        # that reuse the mapping above).
        if _RUSTSCAN_OPEN_RE.match(line):
            self.after(0, lambda tn=tool_name:
                      self._update_progress(25.0, "Discovering ports", "", tn))
            return
        if _RUSTSCAN_SCRIPT_RE.search(line):
            self.after(0, lambda tn=tool_name:
                      self._update_progress(50.0, "Deep scan (nmap)", "", tn))
            return

        # Nmap progress: "SYN Stealth Scan Timing: About 43.50% done"
        pct_m = _NMAP_PCT_RE.search(line)
        if pct_m:
            raw_pct = float(pct_m.group(1))
            eta_m = _NMAP_ETA_RE.search(line)
            eta   = eta_m.group(1) if eta_m else ""
            ph_m  = _NMAP_PHASE_RE.match(line)
            phase = ph_m.group(1) if ph_m else "Scanning"
            # Map nmap's "X% done within current phase" to overall progress
            # using the phase's (lo, hi) range.  Without this the bar would
            # rewind to e.g. 20% when Service scan reports "About 20% done"
            # even though we're really at 50%+20%*(75-50) = 55%.
            lo, hi = _map_nmap_phase(phase.lower())
            if lo is not None:
                pct = lo + (raw_pct / 100.0) * (hi - lo)
            else:
                pct = raw_pct
            self.after(0, lambda p=pct, ph=phase, e=eta, tn=tool_name:
                      self._update_progress(p, ph, e, tn))
            # Still buffer for smart mode if active.  A live-mirrored run
            # (sweep) never buffers: the bar already carries the progress %,
            # so the text line is simply dropped here.
            if self._smart_mode and not mirror_live:
                if tool_name not in self._pending:
                    self._pending[tool_name] = []
                self._pending[tool_name].append(line)
            return

        # Masscan progress: "rate: 1.00-kpps, 23.45% done, 0:01:23 remaining"
        mc_m = _MASSCAN_PCT_RE.search(line)
        if mc_m:
            pct   = float(mc_m.group(1))
            eta_m = _MASSCAN_ETA_RE.search(line)
            eta   = (eta_m.group(1) + " remaining") if eta_m else ""
            self.after(0, lambda p=pct, e=eta, tn=tool_name:
                      self._update_progress(p, "Masscan", e, tn))
            if self._smart_mode and not mirror_live:
                if tool_name not in self._pending:
                    self._pending[tool_name] = []
                self._pending[tool_name].append(line)
            return
        if not self._smart_mode or mirror_live:
            self.after(0, lambda: self._append(line, level))
            return
        if tool_name not in self._pending:
            self._pending[tool_name] = []
        self._pending[tool_name].append(line)

    def flush_tool_output(self, tool_name: str, binary: str = "",
                          suggest_deeper: bool = True):
        # Finish this scan's progress bar (show 100% or clear)
        if tool_name in self._progress_labels:
            if binary.lower() in ("nmap", "masscan", "rustscan"):
                self._finish_progress(tool_name)
            else:
                self._clear_progress(tool_name)
        raw = self._pending.pop(tool_name, [])
        if not raw:
            return

        # Use specialized parsers that return (parsed, open_ports)
        if binary.lower() == "nmap":
            parsed, open_ports = _parse_nmap(raw)
            # NOTE: non-standard port dialog is handled by TargetIntelWidget
            # (once per session, deduplicated). Do not call it here.
        elif binary.lower() == "masscan":
            parsed, open_ports = _parse_masscan(raw)
        else:
            parser = TOOL_PARSERS.get(binary.lower()) or \
                     TOOL_PARSERS.get(tool_name.lower().split()[0],
                                      _parse_generic)
            parsed = parser(raw)

        if parsed:
            for level, line in parsed:
                self.after(0, lambda lv=level, ln=line: self._append(ln, lv))
            self._check_cross_references(parsed)
        else:
            self.after(0, lambda: self._append(
                f"  — No notable findings from {tool_name}.", "dim"))

        # Check for 0 open ports (quick scan).  Host-discovery runs
        # (nmap -sn) never touch a port, so "no open ports found — run
        # NMAP Full" would be nonsense advice: those callers opt out.
        if binary.lower() == "nmap" and suggest_deeper:
            if not any("finding" == lv for lv, _ in parsed):
                self.after(200, lambda: self._suggest_deeper_scan(tool_name))

    def _check_nonstandard_ports(self, open_ports: list):
        """Alert if a service is on a non-default port."""
        for port, proto, svc in open_ports:
            svc_clean = svc.lower().split("?")[0].strip()
            default_port = SERVICE_PORT_MAP.get(svc_clean)
            if default_port and port != default_port:
                target = self.app.get_target()
                self.after(0, lambda p=port, s=svc_clean, t=target: [
                    self._append(
                        f"  ⚠  Non-standard port: {s.upper()} detected on "
                        f"port {p} (default: {SERVICE_PORT_MAP.get(s, '?')})",
                        "warn"),
                    self._show_nonstandard_dialog(s, p, t),
                ])

    def _show_nonstandard_dialog(self, service, port, target):
        from gui.dialogs import NonStandardPortDialog
        NonStandardPortDialog(
            self, service, port, target, self.app,
            callback_netcat=lambda cmd, p, s: self._run_netcat(cmd, p, s),
        )

    def _run_netcat(self, cmd: str, port: int, service: str):
        self.section(f"SERVICE VERIFY  ·  port {port}")
        self.write(f"  $ {cmd}", "cmd")
        from utils.runner import ToolRunner
        ToolRunner(
            output_callback=self.output_callback,
            done_callback=lambda n, rc, log: self.flush_tool_output(n, "nc"),
        ).run(cmd, f"nc-{port}")

    def _suggest_deeper_scan(self, tool_name: str):
        target = self.app.get_target()
        try:
            from gui.dialogs import NoPortsFoundDialog
            NoPortsFoundDialog(
                self, tool_name, target,
                callback_deeper=lambda: self.write(
                    "  [*] Run NMAP Full (-p-) from the Port Scanning card.", "dim"),
            )
        except Exception:
            self.write(
                "  [*] No open ports found on scanned range. Consider NMAP Full (-p-) from the Port Scanning card.",
                "dim",
            )

    def _check_cross_references(self, parsed: list):
        sess = self.app.session_manager.current
        if not sess:
            return
        creds = sess.get_credentials()
        if not creds:
            return

        text_blob = " ".join(
            str(l).lower() for _, l in parsed if isinstance(l, str))
        has_login = any(k in text_blob for k in
                        ("login", "/admin", "auth", "password", "credential"))
        if not has_login:
            return

        target_raw = (self.app.get_target() or "").strip()
        target_host = target_raw
        if "://" in target_raw:
            try:
                from urllib.parse import urlsplit
                target_host = urlsplit(target_raw).hostname or target_raw
            except Exception:
                pass
        target_host = target_host.lower()

        svc = None
        for needle, name in (("https://", "HTTPS"), ("http://", "HTTP"),
                             (" ssh", "SSH"), (" ftp", "FTP"),
                             (" smb", "SMB"), (" rdp", "RDP"),
                             (" mysql", "MYSQL"), (" mssql", "MSSQL"),
                             (" winrm", "WINRM")):
            if needle in text_blob:
                svc = name
                break

        def applies(c):
            host_ok = (not c.host) or c.host.lower() == target_host
            svc_ok  = (not c.services) or (svc is None) or (svc in c.services)
            return host_ok and svc_ok

        matches = [c for c in creds if applies(c)]
        if not matches:
            return

        def _secret(c):
            if c.cracked_pass:
                return c.cracked_pass
            if c.password:
                return c.password
            if c.hash_val:
                return c.hash_val[:12] + "…(hash)"
            return "?"

        def _fmt(c):
            svcs = "+".join(c.services) if c.services else "any"
            host = c.host or "any"
            src  = c.source_phase or "?"
            return (f"            • {c.username or '<no-user>'}:{_secret(c)}  "
                    f"({svcs}, host: {host}, src: {src})")

        svc_label = svc or "this service"
        header = (f"  ↗ Credential Store reuse hint — {len(matches)} "
                  f"pre-existing credential(s) may apply on {svc_label}. "
                  f"(These are NOT new findings; they were already in the "
                  f"store before this scan.)")
        lines = [_fmt(c) for c in matches[:5]]
        if len(matches) > 5:
            lines.append(f"            … +{len(matches)-5} more in store")

        def _emit_all():
            self._append(header, "finding")
            for ln in lines:
                self._append(ln, "info")

        self.after(0, _emit_all)

    def clear(self):
        self._textbox.configure(state="normal")
        tw = self._textbox._textbox
        # Destroy all embedded progress labels before clearing
        for entry in self._progress_labels.values():
            try:
                entry[0].destroy()
            except Exception:
                pass
        self._progress_labels.clear()
        self._progress_max.clear()
        self._port_scan_seen.clear()
        tw.delete("1.0", "end")
        self._lines.clear()
        # Wipe persisted lines from the current session as well — the user
        # pressed CLR, they don't want them saved on the next SAVE.
        try:
            sess = self.app.session_manager.current
            if sess is not None:
                sess.terminal_lines = []
        except Exception:
            pass
        self._append("[*] Terminal cleared.", "dim")
        self._append("─" * 68, "sep")

    def section(self, title: str):
        bar = "─" * max(0, 64 - len(title))
        self._append("", "sep")
        self._append(f"  ┌─ {title} {bar}", "section")
        self._append("", "sep")

    def opsec_notes(self, phase_id: str):
        from utils.config import OPSEC_NOTES
        notes = OPSEC_NOTES.get(phase_id, [])
        if not notes:
            return
        self._append("", "sep")
        self._append(
            "  ┌─ OPSEC NOTES — what this phase generated ─────────────────",
            "section")
        self._append(
            "  These notes are for your final report. "
            "The Blue Team may have detected:", "dim")
        self._append("", "sep")
        for artifact, countermeasure in notes:
            self._append(f"  ⚠  {artifact}", "warn")
            self._append(f"     Countermeasure category: {countermeasure}", "dim")
            self._append("", "sep")

    # ─── Internal ────────────────────────────────────────────────────────────

    # Retained scrollback.  Beyond this the OLDEST lines are dropped
    # from both the widget and the in-memory buffer — and the operator
    # is told once, in the terminal itself.  Silent truncation would
    # leave a log that looks complete and isn't.
    _MAX_LINES  = 20000
    _TRIM_CHUNK = 5000

    def _append(self, text: str, level: str = "info"):
        tw = self._textbox._textbox
        self._textbox.configure(state="normal")
        tw.insert("end", text + "\n", level)
        self._textbox.configure(state="disabled")
        now = datetime.now()
        self._lines.append((level, text, now))
        if len(self._lines) > self._MAX_LINES:
            self._trim_scrollback()
        self._request_scroll()
        # Persist every visible line into the active session so SAVE
        # captures the full terminal history without any extra work.
        try:
            sess = self.app.session_manager.current
            if sess is not None:
                sess.append_terminal_line(text, level, now.isoformat())
        except Exception:
            pass

    def _request_scroll(self):
        """Coalesce autoscroll into one idle callback per burst."""
        if self._scroll_pending:
            return
        self._scroll_pending = True

        def _do():
            self._scroll_pending = False
            try:
                self._textbox._textbox.see("end")
            except Exception:
                pass

        try:
            self.after_idle(_do)
        except Exception:
            self._scroll_pending = False

    def _trim_scrollback(self):
        """Drop the oldest chunk of scrollback, once it is over the cap."""
        drop = self._TRIM_CHUNK
        del self._lines[:drop]
        tw = self._textbox._textbox
        try:
            self._textbox.configure(state="normal")
            tw.delete("1.0", f"{drop + 1}.0")
            self._textbox.configure(state="disabled")
        except Exception:
            pass
        if not self._trim_announced:
            self._trim_announced = True
            note = (f"[!] Terminal scrollback capped at "
                    f"{self._MAX_LINES} lines — older output is being "
                    f"dropped from this view and from the session "
                    f"snapshot. Full tool output stays in outputs/.")
            try:
                self._textbox.configure(state="normal")
                tw.insert("1.0", note + "\n", "warn")
                self._textbox.configure(state="disabled")
            except Exception:
                pass

    # ─── Per-scan progress bars (embedded tk.Label + StringVar) ────────────
    #
    # Each running scan gets a tk.Label embedded in the textbox via
    # window_create().  A StringVar drives the text so Tk's variable-trace
    # mechanism guarantees the widget redraws on every .set() call.
    #
    #   self._progress_labels = { tool_name: (tk.Label, tk.StringVar) }

    @staticmethod
    def _bar_text(pct: float, phase: str = "", eta: str = "") -> str:
        filled = int(pct / 100 * 20)
        empty  = 20 - filled
        bar    = "█" * filled + "░" * empty
        parts  = [f"  [{bar}]  {pct:5.1f}%"]
        if phase:
            parts.append(f"— {phase}")
        if eta:
            parts.append(f"({eta})")
        return "  ".join(parts)

    def _update_progress(self, pct: float, phase: str = "",
                         eta: str = "", tool_name: str = ""):
        """Create or update the embedded progress-bar label for *tool_name*."""
        # Never rewind the bar.  Phases emit updates out of order during
        # rustscan's nmap handoff, and nmap's "About X% done" is scoped to
        # the current phase — clamping to the max we've seen keeps the
        # bar monotonic (users never see it jump backward mid-scan).
        entry_existing = self._progress_labels.get(tool_name)
        if entry_existing is None:
            # First update for this tool → reset the no-rewind tracker
            # AND the NSE pre-scan guard (fresh scan, no phases seen yet).
            self._progress_max[tool_name] = 0.0
            self._port_scan_seen.pop(tool_name, None)
        prev_max = self._progress_max.get(tool_name, 0.0)
        if pct < prev_max and pct < 99.5:
            pct = prev_max
        else:
            self._progress_max[tool_name] = pct

        text = self._bar_text(pct, phase, eta)
        try:
            entry = entry_existing
            if entry:
                lbl, var = entry
                if lbl.winfo_exists():
                    var.set(text)          # StringVar.set → auto-redraw
                    return

            # First call — create StringVar + Label, embed in textbox
            tw = self._textbox._textbox
            var = tk.StringVar(value=text)
            lbl = tk.Label(
                tw,
                textvariable=var,
                font=("Courier New", SZ.get("term", 13)),
                fg=COLORS["text_cyan"],
                bg=COLORS["bg_card"],
                anchor="w",
                padx=0, pady=0,
                borderwidth=0,
                highlightthickness=0,
            )
            self._textbox.configure(state="normal")
            tw.window_create("end", window=lbl)
            tw.insert("end", "\n")
            self._textbox.configure(state="disabled")
            tw.see("end")
            self._progress_labels[tool_name] = (lbl, var)
        except Exception as e:
            print(f"[HAWK] progress bar error: {e}")

    def _finish_progress(self, tool_name: str = ""):
        """Mark this scan's bar as 100 % Complete (green)."""
        entry = self._progress_labels.pop(tool_name, None)
        self._progress_max.pop(tool_name, None)
        self._port_scan_seen.pop(tool_name, None)
        if not entry:
            return
        try:
            lbl, var = entry
            if lbl.winfo_exists():
                bar  = "█" * 20
                var.set(f"  [{bar}]  100.0%  — Complete  ✓")
                lbl.configure(fg="#40A060")
        except Exception as e:
            print(f"[HAWK] finish progress error: {e}")

    def _clear_progress(self, tool_name: str = ""):
        """Silently remove this scan's bar."""
        entry = self._progress_labels.pop(tool_name, None)
        self._progress_max.pop(tool_name, None)
        self._port_scan_seen.pop(tool_name, None)
        if not entry:
            return
        try:
            lbl, var = entry
            if lbl.winfo_exists():
                lbl.destroy()
        except Exception:
            pass

    def _abort_progress(self, tool_name: str = "", reason: str = ""):
        """Stop this scan's bar in a distinct 'ran, but did not succeed'
        state.

        Unlike _finish_progress (100% green check, which reads as
        success) this leaves an empty amber bar carrying the real reason
        — used when a probe completed but the service is absent/
        unreachable (e.g. SNMP 161/udp closed), where a green tick would
        misreport a dead port as a successful scan.
        """
        entry = self._progress_labels.pop(tool_name, None)
        self._progress_max.pop(tool_name, None)
        self._port_scan_seen.pop(tool_name, None)
        if not entry:
            return
        try:
            lbl, var = entry
            if lbl.winfo_exists():
                tail = f"  — {reason}" if reason else "  — stopped"
                var.set(f"  [{'░' * 20}]{tail}")
                lbl.configure(fg="#C08040")   # amber: ran, no service
        except Exception as e:
            print(f"[HAWK] abort progress error: {e}")

    def restore_lines(self, lines: list):
        """Reload terminal output from a session snapshot.

        `lines` is a list of dicts {ts, level, text}. We re-render each
        line into the textbox WITHOUT pushing it back to session.terminal_lines
        (the session already owns them) by calling the low-level textbox
        API directly instead of _append().
        """
        try:
            self._textbox.configure(state="normal")
            tb = self._textbox._textbox
            tb.delete("1.0", "end")
            self._lines.clear()
            entries = lines or []
            # ONE insert for the whole history, then colour each line via
            # tag ranges.  The old per-line insert() forced a Text-widget
            # relayout PER LINE, freezing LOAD for 20-30 s on a session
            # with a few thousand lines (a single nuclei/sqlmap run).  A
            # single insert relays out once; tag_add just marks ranges.
            if entries:
                tb.insert("end",
                          "".join(e.get("text", "") + "\n" for e in entries))
            line_no = 1
            for entry in entries:
                lvl  = entry.get("level", "info")
                text = entry.get("text", "")
                span = text.count("\n") + 1
                try:
                    tb.tag_add(lvl, f"{line_no}.0", f"{line_no + span}.0")
                except Exception:
                    pass
                line_no += span
                # Parse ts back to datetime for the in-memory buffer
                try:
                    ts = datetime.fromisoformat(entry.get("ts", ""))
                except Exception:
                    ts = datetime.now()
                self._lines.append((lvl, text, ts))
            self._textbox.configure(state="disabled")
            tb.see("end")
        except Exception as e:
            print(f"[HAWK] terminal restore failed: {e}")

    def _open_shell(self):
        """Launch a native Kali terminal (qterminal/xfce4/gnome/konsole/xterm).

        Working directory: ``<HAWK>/outputs/`` (created at import in
        utils.config) — this is where ALL HAWK-driven tool artefacts
        land (bloodhound-python zips, ldapdomaindump folders,
        kerberoast/asrep hash files, /etc/hosts helper tempfiles,
        certipy esc1.pfx, etc.).  Previously the default was
        ``~/hawk/`` which scattered files outside the HAWK directory
        the user cloned/runs from; consolidating under
        ``<HAWK>/outputs/`` keeps every artefact next to the source.

        If a target is set, export $TARGET so the shell can
        ``echo $TARGET`` or ``nmap $TARGET`` etc. without retyping.
        Also exports $DOMAIN / $DC_IP when the session has them so
        kerberos-aware one-liners are two keystrokes away.
        """
        from utils.runner import open_native_shell
        from utils.config import OUTPUTS_DIR
        import os as _os
        target = self.app.get_target() if hasattr(self.app, "get_target") else ""
        title = f"HAWK — shell ({target})" if target else "HAWK — shell"

        # OUTPUTS_DIR is created at utils.config import time, but
        # belt-and-suspenders mkdir here in case something nuked
        # the dir between import and shell-open.
        workdir = OUTPUTS_DIR
        try:
            _os.makedirs(workdir, exist_ok=True)
        except OSError:
            from utils.config import BASE_DIR
            workdir = BASE_DIR

        # Collect optional exports from the current session.
        domain = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                domain = getattr(sess, "target_domain", "") or ""
        except Exception:
            pass

        # Build the initial command.  We use printf (no escapes to
        # explode in weird locale settings), print a small "welcome"
        # banner that tells the user WHERE they landed + WHAT env is
        # set + hides the raw cd/export lines that used to leak into
        # the terminal.  `set -a` + sourcing doesn't work for env
        # vars the sub-bash needs; we export them inline before
        # exec bash.
        lines = [f"cd {_os.path.expandvars(workdir)!r}"]
        if target:
            lines.append(f"export TARGET={target!r}")
        if domain:
            lines.append(f"export DOMAIN={domain!r}")
        env_setup = "; ".join(lines)

        # Pretty welcome banner — colored, 3 lines, not noisy.
        banner_parts = [
            f"\\e[36m╭─ HAWK shell  "
            f"{'— target ' + target if target else '(no target)'}"
            + (f" / domain {domain}" if domain else "")
            + "\\e[0m",
            f"\\e[36m│  cwd: {workdir}\\e[0m",
        ]
        if target:
            banner_parts.append(
                "\\e[36m│  $TARGET is set"
                + (" — $DOMAIN is set" if domain else "")
                + "\\e[0m")
        banner_parts.append("\\e[36m╰\\e[0m")
        banner = "printf '%s\\n' " + " ".join(
            f"$'{b}'" for b in banner_parts)

        script = f"{env_setup} 2>/dev/null; {banner}"
        ok = open_native_shell(title, script)
        if ok:
            self.write(f"[+] Shell opened ({title})  "
                       f"cwd={workdir}  "
                       f"TARGET={target or '(unset)'}", "success")
        else:
            self.write("[!] No terminal emulator found (install xterm).",
                       "error")

    def _save(self):
        os.makedirs(SESSIONS_DIR, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(SESSIONS_DIR, f"terminal_{ts}.txt")
        with open(path, "w") as f:
            for level, line, stamp in self._lines:
                ts_str = stamp.strftime("%H:%M:%S")
                f.write(f"[{ts_str}] {line}\n")
        self.write(f"[+] Saved → {path}", "success")
