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
HAWK - Configuration
Font sizes 14+ throughout. All text in English.
Single source of truth for APP_VERSION — consumed by hawk.py, splash,
terminal banner, report generator, status bar.
"""

APP_NAME       = "HAWK"
APP_FULL_NAME  = "Hostile Assessment War-Kit"
APP_VERSION    = "1.5.0"
APP_AUTHOR     = "HAWK Project — Open Source"
APP_GITHUB     = "https://github.com/yourusername/hawk"
APP_DISCLAIMER = "Authorized use only · Educational & CTF purposes"

# Version of the HAWK ↔ plugin contract this build implements.
# Independent from APP_VERSION. See argus/docs/plugin-contract.md §1
# for the semver compatibility rules HAWK applies when loading plugins.
HAWK_API_VERSION = "1.0.0"

# ─── REPORT BRANDING ──────────────────────────────────────────────────────────
# Engagement-level branding rendered on the client-facing report.  All
# fields optional: empty values are simply omitted (a HAWK-only report
# still generates).  Defaults live here as the single source; an operator
# overrides per-engagement via configs/report_branding.json (kept inside
# the HAWK tree, loaded by modules.report.branding) without editing code.
#   firm_name   — the testing firm / consultancy name
#   prepared_by — analyst or team name
#   client_name — the assessed organisation
#   logo_path   — optional image (abs or BASE_DIR-relative); embedded as a
#                 base64 data URI so the HTML stays self-contained
REPORT_BRANDING = {
    "firm_name":   "",
    "prepared_by": "",
    "client_name": "",
    "logo_path":   "",
}

# ─── COLORS ───────────────────────────────────────────────────────────────────
COLORS = {
    "bg_primary":    "#0B0F14",
    "bg_secondary":  "#111820",
    "bg_card":       "#161D26",
    "bg_card_hover": "#1C2535",
    "bg_header":     "#0E1419",
    "border_green":  "#00C8C8",
    "border_dim":    "#243040",
    "border_red":    "#C84040",
    "border_amber":  "#E8A020",
    "text_green":    "#00C8C8",
    "text_bright":   "#D0D8E0",
    # text_dim is the secondary text colour used in dialog notes,
    # tool row descriptions, terminal dim lines, etc.  Bumped from
    # #7A90A8 → #B0C0D0 so it stays readable on the dark background
    # across every dialog in the app (the old value washed out to
    # near-invisible in note_boxes).
    "text_dim":      "#B0C0D0",
    "text_muted":    "#3A4E62",
    "text_white":    "#E8F0F8",
    "text_red":      "#C84040",
    "text_yellow":   "#E8A020",
    "text_cyan":     "#00C8C8",
    "text_orange":   "#D06820",
    "status_ready":   "#7A90A8",
    "status_running": "#E8A020",
    "status_done":    "#40A060",
    "status_error":   "#C84040",
    "status_skipped": "#3A4E62",
    "sev_info":      "#7A90A8",
    "sev_low":       "#40A060",
    "sev_medium":    "#E8A020",
    "sev_high":      "#D06820",
    "sev_critical":  "#C84040",
    "honeypot":      "#C84040",
    "ids_warn":      "#E8A020",
    "dmz_warn":      "#D06820",
    "fw_warn":       "#E8A020",
    "tab_blink":     "#00C8C8",
}

# ─── FONTS — all 14+ ──────────────────────────────────────────────────────────
SZ = {
    "xs":    12,   # tiny labels, badges
    "sm":    13,   # secondary text
    "md":    14,   # body / descriptions
    "lg":    15,   # tool names, buttons
    "xl":    17,   # card headers / phase names
    "xxl":   20,   # section titles
    "banner": 10,  # ascii banner (fixed size)
    "term":   13,  # terminal output
    "status": 12,  # status bar
}

def F(size_key="md", bold=False):
    """Helper: return CTkFont. Import and call in widgets."""
    import customtkinter as ctk
    return ctk.CTkFont(
        family="Courier New",
        size=SZ.get(size_key, 14),
        weight="bold" if bold else "normal",
    )

# ─── WINDOW ───────────────────────────────────────────────────────────────────
WINDOW = {
    "width":      1440,
    "height":     900,
    "min_width":  1100,
    "min_height": 680,
    "title": f"{APP_NAME} — {APP_FULL_NAME} v{APP_VERSION}",
}

# ─── BANNER ───────────────────────────────────────────────────────────────────
BANNER = r"""
  ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
  ██║  ██║██╔══██╗██║    ██║██║ ██╔╝
  ███████║███████║██║ █╗ ██║█████╔╝
  ██╔══██║██╔══██║██║███╗██║██╔═██╗
  ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝"""

BANNER_SUBTITLE = "  Hostile Assessment War-Kit  —  Open Source Pentest Suite"
BANNER_LINE     = "  " + "─" * 56

SPLASH_MESSAGES = [
    "  [*] Initializing HAWK framework...",
    "  [*] Loading kill chain modules...",
    "  [*] Detecting installed tools...",
    "  [*] Checking Kali Linux environment...",
    "  [*] Loading defense detection rules...",
    "  [*] Setting up session manager...",
    "  [+] All modules loaded. Ready.",
]

# ─── KILL CHAIN PHASES ────────────────────────────────────────────────────────
KILL_CHAIN_PHASES = [
    {
        "id": "recon", "index": 1, "icon": "01",
        "name": "RECONNAISSANCE",
        "short": "RECON", "color": "#7A90A8",
        "desc": "Passive & active information gathering on the target",
        "network_note": (
            "WHOIS queries external registrar databases (IANA, RIPE, ARIN) over the internet. "
            "DNS lookups contact your configured resolver and authoritative nameservers. "
            "theHarvester scrapes Google, Bing and Shodan — your IP will appear in their logs."
        ),
        "ping_note": (
            "If PING does not respond, the host could be: (1) offline, "
            "(2) blocking inbound ICMP via firewall rules, or (3) a honeypot "
            "configured to drop ICMP. Try TCP-based checks before concluding the host is down."
        ),
    },
    {
        "id": "scanning", "index": 2, "icon": "02",
        "name": "PORT SCANNING",
        "short": "SCAN", "color": "#7A90A8",
        "desc": "Port discovery and service fingerprinting",
        "network_note": (
            "Sends SYN/ACK/UDP packets directly to the target. "
            "Stateful firewalls and IDS (Snort, Suricata) will log this traffic. "
            "High-speed scans (masscan, -T5) are easily detected."
        ),
    },
    {
        "id": "enumeration", "index": 3, "icon": "03",
        "name": "ENUMERATION",
        "short": "ENUM", "color": "#7A90A8",
        "desc": "Deep service enumeration: web, SMB, FTP, SSH, SNMP",
        "network_note": (
            "Actively connects to and probes services on the target. "
            "Web directory brute-forcing generates hundreds of HTTP requests per second "
            "and is detected by most WAFs and fail2ban. SMB enumeration is logged "
            "in Windows Event Log (IDs 4625, 4776)."
        ),
    },
    {
        # WEB ASSAULT — inserted between ENUMERATION and VULN ANALYSIS.
        # Once enum surfaces HTTP/HTTPS services, Oracle turns a bare
        # URL into an attack plan: tech fingerprint, auth flow, API
        # surface, exposures, CVEs — and hands off the right tools
        # pre-filled.  Sits BEFORE VULN ANALYSIS because its output
        # drives which CVEs are worth probing against this specific
        # stack.  Running generic vuln scans blind is expensive and
        # tells a WAF you're fishing.
        "id": "web_assault", "index": 4, "icon": "04",
        "name": "WEB ASSAULT",
        "short": "ASSAULT", "color": "#7A90A8",
        "desc": "Oracle profiles the tech stack + CVEs. "
                "Bloody Crawl maps the real endpoint surface. "
                "Together they give you the full web attack plan.",
        "network_note": (
            "Web Assault tools are ACTIVE recon — every probe hits the "
            "target.  Fingerprinting leaves normal HTTP access-log "
            "entries; nuclei CVE templates are identifiable signatures; "
            "JS crawling (katana) executes the app's own code. "
            "WAFs (Cloudflare, Akamai, Imperva) will see most of this. "
            "Authorized targets only."
        ),
    },
    {
        "id": "vuln_scan", "index": 5, "icon": "05",
        "name": "VULNERABILITY ANALYSIS",
        "short": "VULN", "color": "#7A90A8",
        "desc": "CVE scanning, web vulns, Greenbone/OpenVAS integration",
        "network_note": (
            "Connects to target services and sends vulnerability-specific probes. "
            "Nikto sends identifiable headers — most WAFs detect it instantly. "
            "Greenbone/OpenVAS generates thousands of requests and is very noisy. "
            "Nuclei may contact its cloud API to update templates."
        ),
    },
    {
        "id": "exploitation", "index": 6, "icon": "06",
        "name": "EXPLOITATION",
        "short": "EXPLOIT", "color": "#7A90A8",
        "desc": "Exploit via MSF, brute force — authorized targets only",
        "network_note": (
            "Actively attempts to exploit vulnerabilities on the target. "
            "EternalBlue generates anomalous SMB traffic visible in Sysmon (Event ID 7045). "
            "Hydra brute force generates hundreds of failed logins — "
            "fail2ban blocks after 5-10 attempts by default."
        ),
    },
    {
        # AD PENTESTING follows EXPLOITATION in the kill chain: once
        # you've got an initial foothold / a valid domain credential
        # (via bruteforce, password spray, or AS-REP without preauth),
        # the AD-specific attack chain (Kerberoast / DCSync / Certipy /
        # RBCD) starts here.  Placed BEFORE POST-EXPLOITATION because
        # DCSync / Golden Ticket forging produces the domain-wide
        # credentials that POST-EXPLOIT consumes for privesc/persistence.
        "id": "ad_pentesting", "index": 7, "icon": "07",
        "name": "AD PENTESTING",
        "short": "AD", "color": "#7A90A8",
        "desc": "Active Directory attacks — Kerberoast, AS-REP, Certipy, DCSync",
        "network_note": (
            "Heavy Kerberos, LDAP and SMB traffic against the Domain "
            "Controller. AS-REP roasting and Kerberoasting generate "
            "Event ID 4768/4769 on the DC. BloodHound collection pulls "
            "thousands of LDAP queries — visible in DC event logs. "
            "DCSync (secretsdump) triggers Event ID 4662 on every dir-"
            "replication call and is the canonical trigger for UEBA/ATA."
        ),
    },
    {
        "id": "post_exploit", "index": 8, "icon": "08",
        "name": "POST-EXPLOITATION",
        "short": "POST", "color": "#7A90A8",
        "desc": "Privilege escalation, persistence, credential extraction",
        "network_note": (
            "Scripts (linpeas, winpeas, pspy) are downloaded from GitHub. "
            "Requires outbound internet from the attacker machine. "
            "Reading /etc/shadow or dumping SAM requires root/SYSTEM on the target."
        ),
    },
    {
        "id": "lateral", "index": 9, "icon": "09",
        "name": "LATERAL MOVEMENT",
        "short": "LATERAL", "color": "#7A90A8",
        "desc": "Pivoting, tunneling, moving through the network",
        "network_note": (
            "Creates persistent TCP tunnels (chisel, ligolo). "
            "These appear as anomalous outbound connections in firewall logs. "
            "Pass-the-Hash generates NTLM authentications from unusual IPs — "
            "detected by Windows ATA and UEBA tools."
        ),
    },
    {
        "id": "reporting", "index": 10, "icon": "10",
        "name": "REPORTING",
        "short": "REPORT", "color": "#7A90A8",
        "desc": "Generate a Markdown pentest report with all findings",
        "network_note": None,
    },
]

# ─── STATUS ───────────────────────────────────────────────────────────────────
STATUS_READY   = "READY"
STATUS_RUNNING = "RUNNING"
STATUS_DONE    = "DONE"
STATUS_ERROR   = "ERROR"
STATUS_SKIPPED = "SKIPPED"

# ─── NMAP SCAN OPTIONS ────────────────────────────────────────────────────────
NMAP_SCAN_TYPES = {
    "SYN Stealth (-sS)":        {"flag": "-sS",  "desc": "Half-open SYN scan. Fast, stealthy. Requires root.", "sudo": True},
    "TCP Connect (-sT)":        {"flag": "-sT",  "desc": "Full TCP connection. No root needed. More visible.", "sudo": False},
    "UDP Scan (-sU)":           {"flag": "-sU",  "desc": "Scan UDP ports. Slow but finds hidden services.", "sudo": True},
    "ACK Scan (-sA)":           {"flag": "-sA",  "desc": "Maps firewall rules — doesn't detect open ports.", "sudo": True},
    "FIN / Xmas / Null (-sF)":  {"flag": "-sF",  "desc": "Stealthy scans that bypass some firewalls.", "sudo": True},
    "Version Detection (-sV)":  {"flag": "-sV",  "desc": "Probe open ports to identify service versions.", "sudo": False},
    "OS Detection (-O)":        {"flag": "-O",   "desc": "Attempt to identify target OS via TCP/IP fingerprint.", "sudo": True},
    "Script Scan (-sC)":        {"flag": "-sC",  "desc": "Run default NSE scripts on open ports.", "sudo": False},
    "Vuln Scripts":             {"flag": "--script vuln", "desc": "Run vulnerability-detection NSE scripts.", "sudo": False},
}

NMAP_TIMING = {
    "T0 — Paranoid (very slow, max stealth)":  "-T0",
    "T1 — Sneaky (slow, low profile)":         "-T1",
    "T2 — Polite (slower, less bandwidth)":    "-T2",
    "T3 — Normal (default)":                   "-T3",
    "T4 — Aggressive (fast, recommended)":     "-T4",
    "T5 — Insane (very fast, noisy)":          "-T5",
}

NMAP_EVASION = {
    "Fragment packets (-f)":            "-f",
    "Decoy scan (-D RND:5)":            "-D RND:5",
    "Spoof source port (--source-port 53)": "--source-port 53",
    "Random data (--data-length 25)":   "--data-length 25",
    "Bad checksum (--badsum)":          "--badsum",
    "Append random data (--append-output)": "--append-output",
}

NMAP_PORT_SCOPES = {
    "Top 100 (fast, ~30s)":         "-F",
    "Top 1000 (default, ~2min)":    "--top-ports 1000",
    "Well-known 1–1023 (~1min)":    "-p 1-1023",
    "All 65535 (slow, ~15min)":     "-p-",
    "Custom (enter below)":         "CUSTOM",
}

# Extra boolean flags shown in the "Extra Flags" section of the
# nmap Custom Scan Builder dialog.  Kept independent from
# NMAP_SCAN_TYPES (which gates by scan-type radio) and NMAP_EVASION
# (which is firewall-bypass specific) — these are general-purpose
# modifiers that the operator commonly toggles on top of the scan
# type they've already chosen.
NMAP_EXTRA_FLAGS = {
    "-A":           "Aggressive (-O + -sV + -sC + --traceroute combined)",
    "--reason":     "Print the reason a port is reported as open/closed/filtered",
    "--open":       "Show only open (or possibly-open) ports",
    "-n":           "No DNS resolution — faster, avoids leaking lookups",
    "--traceroute": "Trace hop path to target",
    "-vv":          "Extra verbose output",
}

# ─── WAF EVASION OPTIONS ──────────────────────────────────────────────────────
WAF_EVASION_OPTIONS = {
    "URL encode payload":           "Use %XX encoding for special chars (e.g. %27 for ')",
    "Double URL encode":            "Encode the percent sign itself: %2527 instead of %27",
    "Case variation":               "Mix upper/lower case: SeLeCt instead of SELECT",
    "Add null bytes":               "Insert %00 between characters to break signatures",
    "Custom User-Agent":            "Set a legitimate browser UA to bypass agent-based rules",
    "Add X-Forwarded-For header":   "Spoof internal IP: X-Forwarded-For: 127.0.0.1",
    "HTTP verb tampering":          "Try HEAD, OPTIONS, PUT instead of GET/POST",
    "Multipart encoding":           "Submit POST data as multipart/form-data",
    "Use nikto with evasion (-evasion 1-9)": "nikto built-in evasion modes",
}

# ─── WORDLISTS ────────────────────────────────────────────────────────────────
WORDLISTS = {
    "linux": {
        "users":    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "passwords":"/usr/share/wordlists/rockyou.txt",
        "label":    "Linux/Unix  (root, www-data, ubuntu...)",
    },
    "windows": {
        "users":    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "passwords":"/usr/share/wordlists/rockyou.txt",
        "label":    "Windows  (administrator, SYSTEM, Guest...)",
    },
    "both": {
        "users":    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "passwords":"/usr/share/wordlists/rockyou.txt",
        "label":    "Both  (combined list)",
    },
}

# Fallback paths to check in order
WORDLIST_PATHS_USERS = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/wordlists/metasploit/unix_users.txt",
    "/usr/share/wordlists/metasploit/default_usernames.txt",
    "/usr/share/wordlists/dirb/others/names.txt",
]

WORDLIST_PATHS_PASS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/metasploit/password.lst",
    "/usr/share/wordlists/fasttrack.txt",
]

# ─── HASH MODES ───────────────────────────────────────────────────────────────
HASH_MODES = {
    "NTLM":        {"mode": "1000",  "label": "NTLM (Windows SAM)"},
    "MD5":         {"mode": "0",     "label": "MD5"},
    "SHA1":        {"mode": "100",   "label": "SHA1"},
    "SHA256":      {"mode": "1400",  "label": "SHA256"},
    "bcrypt":      {"mode": "3200",  "label": "bcrypt ($2a$)"},
    "md5crypt":    {"mode": "500",   "label": "md5crypt ($1$) — Linux shadow"},
    "sha512crypt": {"mode": "1800",  "label": "sha512crypt ($6$) — Linux shadow"},
    "NetNTLMv2":   {"mode": "5600",  "label": "NetNTLMv2 (responder)"},
}

# ─── OPSEC NOTES (English) ────────────────────────────────────────────────────
OPSEC_NOTES = {
    "recon": [
        ("WHOIS/DNS queries are logged by resolvers, registrars and ISPs.",
         "Use anonymous resolvers or Tor for more discreet passive recon."),
        ("theHarvester contacts Google, Bing and Shodan.",
         "Your attacker IP appears in their access logs."),
        ("PING and traceroute are visible to any NIDS.",
         "Skip them if stealth is a priority and use TCP-based host discovery instead."),
    ],
    "scanning": [
        ("A full nmap scan generates ~65,000 SYN packets.",
         "Detected by any SIEM with basic rules (Snort, Suricata)."),
        ("Masscan at high rates is extremely noisy.",
         "Consider -T2 or throttling to reduce detection probability."),
        ("UDP scans generate ICMP port-unreachable responses.",
         "Logged by stateful firewalls."),
    ],
    "enumeration": [
        ("Gobuster/ffuf generate hundreds of HTTP requests per second.",
         "Detected by WAF and fail2ban. ModSecurity blocks most directory fuzzers."),
        ("enum4linux uses legacy SMB protocols.",
         "Logged in Windows Event Log (IDs 4625, 4776, 4771)."),
        ("SNMP queries with wrong community strings generate SNMP traps.",
         "Network team may receive alerts."),
    ],
    "vuln_scan": [
        ("Nikto sends identifiable User-Agent headers.",
         "Most WAFs block it instantly. Try --useragent to customize."),
        ("Nuclei sends CVE-specific payloads.",
         "Detected by updated IDS signatures."),
        ("Greenbone/OpenVAS generates thousands of requests over minutes.",
         "Use only in lab or with explicit written authorization."),
    ],
    "exploitation": [
        ("EternalBlue generates anomalous SMB traffic.",
         "Triggers Sysmon Event ID 7045. Visible in Splunk/ELK."),
        ("Hydra SSH brute generates hundreds of failed logins.",
         "Logged in /var/log/auth.log. fail2ban blocks after 5-10 attempts."),
        ("Reverse shells create outbound connections on non-standard ports.",
         "Detected by egress firewall rules and DLP systems."),
    ],
    "post_exploit": [
        ("linpeas/winpeas read system files and run dozens of commands.",
         "Some EDR solutions flag enumeration scripts on execution."),
        ("Reading /etc/shadow requires root.",
         "Logged by auditd if syscall auditing is enabled."),
        ("SAM dump requires SYSTEM privileges.",
         "Detected by modern EDR (CrowdStrike, Defender ATP, SentinelOne)."),
    ],
    "lateral": [
        ("Chisel/ligolo create persistent TCP tunnels.",
         "Appear as anomalous outbound connections in firewall logs."),
        ("Pass-the-Hash generates NTLM auth from unusual IPs.",
         "Detected by Windows ATA, Microsoft Defender Identity."),
        ("SSH tunneling is encrypted but the pattern is anomalous.",
         "Logged as SSH session with port forwarding active."),
    ],
}

# ─── GREENBONE INSTALL ────────────────────────────────────────────────────────
GREENBONE_INSTALL_STEPS = [
    ("Update package repository",  "sudo apt update"),
    ("Install GVM packages",       "sudo apt install -y gvm"),
    ("Run initial GVM setup",      "sudo gvm-setup"),
    ("Start GVM services",         "sudo gvm-start"),
    ("Verify installation",        "sudo gvm-check-setup"),
]

# ─── NON-STANDARD PORT SERVICES ───────────────────────────────────────────────
# If these strings appear in nmap output on non-default ports, flag to user
SERVICE_PORT_MAP = {
    "ssh":     22,
    "ftp":     21,
    "telnet":  23,
    "smtp":    25,
    "http":    80,
    "https":   443,
    "smb":     445,
    "rdp":     3389,
    "mysql":   3306,
    "mssql":   1433,
    "vnc":     5900,
}

# ─── PATHS ────────────────────────────────────────────────────────────────────
import os
BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
ASSETS_DIR   = os.path.join(BASE_DIR, "assets")
# Target-profile dictionaries built by the TARGET crack strategy.
# Kept inside the HAWK tree (not in ~/hawk/) so all HAWK-generated
# artifacts live under the same root the user cloned / runs from.
DICTS_DIR    = os.path.join(BASE_DIR, "dicts")
# AD-pentesting tool outputs (ntds dump, kerberoast, asreproast,
# ldapdump, certipy esc1.pfx) — also kept inside the HAWK tree
# instead of ~/hawk/ so the user can find every artefact next to
# the source they cloned.  Path-substitution in cmd_templates uses
# the `{outputs}` placeholder which resolves to this directory.
OUTPUTS_DIR  = os.path.join(BASE_DIR, "outputs")
# Third-party scripts HAWK downloads for on-target execution (linpeas,
# winPEAS, PrivescCheck, pspy, chisel, ligolo) and the output exfiltrated
# back from the target.  A DEDICATED directory, not OUTPUTS_DIR: the PEAS
# workflow serves this directory over HTTP to the target, so it must never
# hold session state, credentials or AD loot.  Before this existed the
# downloads landed in the process working directory — normally BASE_DIR
# itself, which is exactly what that HTTP server must not expose.
PAYLOADS_DIR = os.path.join(BASE_DIR, "payloads")
# Runtime-only directories.  HAWK is intentionally portable: a user can
# copy the whole hawkc folder into ~/hawkc, run `python3 hawk.py`, and all
# persistent files produced by the app stay under this tree.  The only
# persistent writes outside it are the system files listed in
# ALLOWED_EXTERNAL_WRITES below, each written with operator consent
# through a privilege prompt; `require_writable()` is the gate and
# tests/test_containment_static.py holds the whole policy to the code.
TMP_DIR      = os.path.join(BASE_DIR, "tmp")
CACHE_DIR    = os.path.join(BASE_DIR, "cache")
LOGS_DIR     = os.path.join(BASE_DIR, "logs")
CONFIGS_DIR  = os.path.join(BASE_DIR, "configs")
# Client-facing report deliverables (HTML / CSV / Markdown produced by
# the report engine).  Kept in a DEDICATED directory rather than
# SESSIONS_DIR (machine session state, rewritten constantly) or
# OUTPUTS_DIR (offensive tool intermediates: ntds dumps, kerberoast,
# certipy pfx) because a polished deliverable is its own artifact class
# the operator hands to the client — it should be trivial to find and
# not interleaved with session JSON or loot.
REPORTS_DIR  = os.path.join(BASE_DIR, "reports")

RUNTIME_DIRS = (
    SESSIONS_DIR,
    DICTS_DIR,
    OUTPUTS_DIR,
    PAYLOADS_DIR,
    TMP_DIR,
    CACHE_DIR,
    LOGS_DIR,
    CONFIGS_DIR,
    REPORTS_DIR,
)

for _dir in RUNTIME_DIRS:
    os.makedirs(_dir, exist_ok=True)

_BASE_DIR_REAL = os.path.realpath(os.path.abspath(BASE_DIR))

# The complete list of files HAWK may write outside its own tree.  Every
# one of them is a system-integration file that only works at a fixed
# path, is written through a privilege prompt the operator answers, and
# is reversible from the GUI.  Nothing may be added here without the
# same three properties.
#   /etc/hosts               AD/CTF name resolution — HAWK-tagged lines
#                            only, added and removed by utils/hosts_helper.
#   /etc/proxychains4.conf   pivot configuration.  proxychains4 reads its
#   /etc/proxychains.conf    config from a fixed system path, and the
#                            operator's own `proxychains4 <tool>` commands
#                            read the same file, so a copy inside the HAWK
#                            tree would configure nothing.  The .hawk_backup
#                            twin is the pre-write copy of the original.
ALLOWED_EXTERNAL_WRITES = {
    "/etc/hosts",
    "/etc/proxychains4.conf",
    "/etc/proxychains4.conf.hawk_backup",
    "/etc/proxychains.conf",
    "/etc/proxychains.conf.hawk_backup",
}


def is_within_base(path: str) -> bool:
    """True if path resolves inside the HAWK application directory."""
    if not path:
        return False
    real = os.path.realpath(os.path.abspath(path))
    return real == _BASE_DIR_REAL or real.startswith(_BASE_DIR_REAL + os.sep)


def is_allowed_external_write(path: str) -> bool:
    """True for the small allowlist of explicit system integration files."""
    if not path:
        return False
    return os.path.realpath(os.path.abspath(path)) in ALLOWED_EXTERNAL_WRITES


def require_within_base(path: str, purpose: str = "path") -> str:
    """Return an absolute path or raise if a write would escape hawkc."""
    real = os.path.realpath(os.path.abspath(path))
    if not is_within_base(real):
        raise ValueError(f"Refusing {purpose} outside HAWK folder: {real}")
    return real


def require_writable(path: str, purpose: str = "write") -> str:
    """Gate for a persistent write: inside the tree, or explicitly allowed.

    This is the one place `ALLOWED_EXTERNAL_WRITES` is consulted.  Call it
    before writing any path that is not built from one of the constants
    above — the caller keeps the ValueError, which is always a bug in
    HAWK, not an operator mistake.
    """
    real = os.path.realpath(os.path.abspath(path))
    if is_within_base(real) or is_allowed_external_write(real):
        return real
    raise ValueError(
        f"Refusing {purpose}: {real} is outside the HAWK folder and is "
        f"not one of the allowed system files "
        f"({', '.join(sorted(ALLOWED_EXTERNAL_WRITES))})")


def contained_sibling(source_path: str, suffix: str,
                      fallback_dir: str = OUTPUTS_DIR) -> str:
    """Where to write a HAWK-generated file derived from `source_path`.

    Next to the source when the source already lives inside the HAWK tree
    (the normal case — PEAS output exfiltrated into payloads/), otherwise
    inside `fallback_dir`.  The operator can point a file picker at
    anything in $HOME; what HAWK writes back never leaves the tree.

    `suffix` replaces the source extension, e.g. ".txt".
    """
    stem = os.path.splitext(os.path.abspath(source_path))[0]
    if is_within_base(stem):
        return stem + suffix
    return os.path.join(fallback_dir, os.path.basename(stem) + suffix)


def hawk_path(*parts: str, create_parent: bool = False) -> str:
    """Build a path rooted at BASE_DIR and optionally create its parent."""
    path = require_within_base(os.path.join(BASE_DIR, *parts))
    if create_parent:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    return path
