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
HAWK - Target Intel Widget v1.0
- Nmap vuln scripts findings → auto-populate intel
- Per-finding MSF launch button with pre-configured editable dialog
- OS Detection merge (don't overwrite existing ports)
- Single nonstandard port popup (flag)
- Spinner on all operations
"""

import customtkinter as ctk
import re

from utils.config import COLORS, SZ, TMP_DIR

def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")

SPINNER_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

# Sentinel label for the credential picker dropdown in connect dialogs.
# When selected, the user is telling HAWK "ignore the store, I'm typing
# the username/password manually below".  Default selection at dialog
# open so we never auto-fill fields the user might want to leave blank.
_MANUAL_ENTRY_LABEL = "✎  Manual entry — type credentials below"


# ─── Aware-suggestion helpers ────────────────────────────────────────────────
def _nmap_already_run(app) -> bool:
    """True if any nmap / masscan / rustscan port scan has completed."""
    try:
        done = app.get_completed_tools()
    except Exception:
        return False
    scan_ids = {
        "nmap_quick", "nmap_full", "nmap_service", "nmap_vuln",
        "nmap_os", "nmap_top", "nmap_custom", "masscan", "rustscan",
    }
    return bool(scan_ids & done)


def _nmap_os_already_run(app) -> bool:
    try:
        done = app.get_completed_tools()
    except Exception:
        return False
    return bool({"nmap_os", "nmap_service", "nmap_full"} & done)

# Vulnerability name → MSF exploit mapping
VULN_EXPLOIT_MAP = {
    # Each key maps to a LIST of (module_path, short_label) tuples.
    # Multiple entries mean "this vuln has several MSF modules that
    # target it — let the user pick" (exploit vs psexec variant vs
    # scanner-only, DoS vs RCE, etc.).  Single-entry lists keep the
    # old 1:1 behaviour unchanged from the user's perspective.
    #
    # Convention: put the "most useful for a pentester" module FIRST —
    # that's the default selection when the picker opens.  Typical
    # ordering: full-RCE exploit → pass-the-hash variant → check-only
    # scanner → DoS.  Users that just want the usual one hit Enter.
    "ms17-010": [
        ("exploit/windows/smb/ms17_010_eternalblue",
         "EternalBlue — SYSTEM shell via SMBv1 overflow"),
        ("exploit/windows/smb/ms17_010_psexec",
         "psexec variant — no creds needed (uses a named pipe), "
         "more reliable / less crash-prone than the kernel overflow"),
        ("auxiliary/scanner/smb/smb_ms17_010",
         "scanner — check-only, no shell"),
    ],
    "ms17_010":      "__alias__ms17-010",
    "eternalblue":   "__alias__ms17-010",
    "eternal":       "__alias__ms17-010",
    "cve-2017-0144": "__alias__ms17-010",
    "ms08-067": [
        ("exploit/windows/smb/ms08_067_netapi",
         "MS08-067 — SYSTEM shell via Server Service overflow"),
    ],
    "ms08_067":      "__alias__ms08-067",
    "cve-2008-4250": "__alias__ms08-067",
    "ms10-061": [
        ("exploit/windows/smb/ms10_061_spoolss",
         "Print Spooler — SYSTEM shell via MS10-061"),
    ],
    "bluekeep": [
        ("exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
         "BlueKeep RCE — SYSTEM via RDP use-after-free"),
        ("auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
         "scanner — check-only"),
    ],
    "cve_2019_0708": "__alias__bluekeep",
    "cve-2019-0708": "__alias__bluekeep",
    "heartbleed": [
        ("auxiliary/scanner/ssl/openssl_heartbleed",
         "Heartbleed — leak server memory (64 KB / request)"),
    ],
    "cve-2014-0160": "__alias__heartbleed",
    "shellshock": [
        ("exploit/multi/http/apache_mod_cgi_bash_env_exec",
         "Shellshock via CGI — RCE as web user"),
    ],
    "cve-2014-6271": "__alias__shellshock",
    "tomcat": [
        ("exploit/multi/http/tomcat_mgr_upload",
         "Tomcat manager upload — RCE via malicious WAR"),
        ("auxiliary/scanner/http/tomcat_mgr_login",
         "scanner — brute manager creds"),
    ],
    "jenkins": [
        ("exploit/multi/http/jenkins_script_console",
         "Script console — RCE (needs admin)"),
        ("exploit/multi/http/jenkins_metaprogramming",
         "Metaprogramming RCE (older Jenkins, unauth)"),
    ],
    "ms12-020": [
        ("auxiliary/dos/windows/rdp/ms12_020_maxchannelids",
         "MS12-020 DoS — BSOD via RDP MaxChannelIDs"),
    ],
    "ms10-054": [
        ("auxiliary/dos/windows/smb/ms10_054_queryfs_pool_overflow",
         "MS10-054 DoS — SMB pool overflow"),
    ],
    "doublepulsar": [
        ("exploit/windows/smb/smb_doublepulsar_rce",
         "DoublePulsar — SYSTEM via NSA implant"),
    ],
    "drupalgeddon": [
        ("exploit/multi/http/drupal_drupageddon",
         "Drupalgeddon — SQLi→RCE on Drupal 7 < 7.32"),
    ],
    "cve-2014-3704": "__alias__drupalgeddon",
    "cve_2014_3704": "__alias__drupalgeddon",
    "log4shell": [
        ("exploit/multi/http/log4shell_header_injection",
         "Log4Shell via Header Injection — RCE as Java user"),
        ("auxiliary/scanner/http/log4shell_scanner",
         "scanner — probe for vulnerability without exploit"),
    ],
    "cve-2021-44228": "__alias__log4shell",
    "ms15-034": [
        ("auxiliary/dos/http/ms15_034_ulonglongadd",
         "MS15-034 DoS — BSOD IIS via crafted Range header"),
        ("auxiliary/scanner/http/ms15_034",
         "scanner — check-only"),
    ],
    "cve-2015-1635": "__alias__ms15-034",
    "proxyshell": [
        ("exploit/windows/http/exchange_proxyshell_rce",
         "ProxyShell — RCE on Exchange 2013-2019"),
    ],
    "proxylogon": [
        ("exploit/windows/http/exchange_proxylogon_rce",
         "ProxyLogon — RCE on Exchange 2013-2019"),
    ],
    "struts": [
        ("exploit/multi/http/struts2_content_type_ognl",
         "Struts2 OGNL — RCE via Content-Type header"),
    ],
    "cve-2017-5638": "__alias__struts",
    "vsftpd": [
        ("exploit/unix/ftp/vsftpd_234_backdoor",
         "vsftpd 2.3.4 backdoor — bind shell on port 6200 (root, no creds)"),
    ],
    "vsftpd_234":    "__alias__vsftpd",
    "cve-2011-2523": "__alias__vsftpd",
    "distcc": [
        ("exploit/unix/misc/distcc_exec",
         "DistCC daemon RCE — arbitrary command execution as distcc user"),
    ],
    "cve-2004-2687": "__alias__distcc",
    "unreal": [
        ("exploit/unix/irc/unreal_ircd_3281_backdoor",
         "UnrealIRCd 3.2.8.1 backdoor — bind shell as root, no creds"),
    ],
    "unrealircd":    "__alias__unreal",
    "cve-2010-2075": "__alias__unreal",
    "samba": [
        ("exploit/multi/samba/usermap_script",
         "Samba usermap_script — RCE as root via username metachar (CVE-2007-2447)"),
        ("auxiliary/scanner/smb/smb_version",
         "scanner — detect Samba version only"),
    ],
    "usermap_script": "__alias__samba",
    "cve-2007-2447":  "__alias__samba",
    "java_rmi": [
        ("exploit/multi/misc/java_rmi_server",
         "Java RMI Registry RCE — code execution via deserialization"),
    ],
    # Bare "rmi" (3 chars) was a substring overmatch — it triggered on
    # words like "permissions-policy", "permanent", "form" in unrelated
    # finding descriptions and proposed java_rmi_server on nginx banners,
    # missing-headers lists, etc. Use word-prefix variants only.
    "java rmi":      "__alias__java_rmi",
    "rmi registry":  "__alias__java_rmi",
    "cve-2011-3556": "__alias__java_rmi",
    "ingreslock": [
        ("exploit/unix/misc/ingreslock",
         "Ingreslock backdoor (port 1524) — pre-planted root shell"),
    ],
    "twiki": [
        ("exploit/unix/webapp/twiki_maketext",
         "TWiki maketext Perl RCE — command execution as web user"),
    ],
    "cve-2012-5371": "__alias__twiki",
    "tikiwiki": [
        ("exploit/unix/webapp/tikiwiki_graph_formula_exec",
         "TikiWiki graph formula RCE — command injection as web user"),
    ],

    # ── Exim SMTP — string format vulnerabilities (Metasploitable, old Debian) ──
    "exim_string_format": [
        ("exploit/unix/smtp/exim4_string_format",
         "Exim 4.x < 4.69 string format RCE — pre-auth shell as 'mail' user (CVE-2010-4344)"),
        ("exploit/unix/local/exim4_string_format",
         "Exim 4.x < 4.73 local privesc — 'mail' / unprivileged user → root (CVE-2010-4345)"),
    ],
    "cve-2010-4344":         "__alias__exim_string_format",
    "cve2010-4344":          "__alias__exim_string_format",
    "smtp-vuln-cve2010-4344":"__alias__exim_string_format",
    "cve-2010-4345":         "__alias__exim_string_format",
    "cve2010-4345":          "__alias__exim_string_format",
    "smtp-vuln-cve2010-4345":"__alias__exim_string_format",

    # ── MySQL auth bypass (CVE-2012-2122) ───────────────────────────────────
    "mysql_authbypass": [
        ("auxiliary/scanner/mysql/mysql_authbypass_hashdump",
         "MySQL/MariaDB auth bypass via memcmp() return-value abuse + hash dump (CVE-2012-2122)"),
    ],
    "cve-2012-2122":         "__alias__mysql_authbypass",
    "mysql-vuln-cve2012-2122":"__alias__mysql_authbypass",

    # ── Web / DoS ─────────────────────────────────────────────────────────────
    "slowloris": [
        ("auxiliary/dos/http/slowloris",
         "Slowloris DoS — exhaust web server sockets via slow HTTP "
         "(CVE-2007-6750)"),
    ],
    "cve-2007-6750":            "__alias__slowloris",
    "http-slowloris-check":     "__alias__slowloris",
    "http-slowloris":           "__alias__slowloris",

    "php_cgi": [
        ("exploit/multi/http/php_cgi_arg_injection",
         "PHP-CGI argument injection RCE (CVE-2012-1823)"),
    ],
    "cve-2012-1823":            "__alias__php_cgi",
    "php-cgi":                  "__alias__php_cgi",

    "axis2": [
        ("exploit/multi/http/axis2_deployer",
         "Apache Axis2 admin deployer RCE — needs admin creds"),
        ("auxiliary/scanner/http/axis_local_file_include",
         "Axis2 LFI scanner — read /etc/passwd, etc."),
    ],
    "axis_local_file_include":  "__alias__axis2",

    "glassfish": [
        ("exploit/multi/http/glassfish_deployer",
         "GlassFish admin auth RCE via WAR upload"),
        ("auxiliary/scanner/http/glassfish_login",
         "GlassFish brute force / default-cred check"),
    ],

    "jboss": [
        ("exploit/multi/http/jboss_deploymentfilerepository",
         "JBoss DeploymentFileRepository RCE — unauth WAR upload"),
        ("exploit/multi/http/jboss_seam_upload_exec",
         "JBoss Seam 2 unauth file upload (CVE-2010-1871)"),
        ("auxiliary/scanner/http/jboss_vulnscan",
         "JBoss console version scanner"),
    ],
    "cve-2010-1871":            "__alias__jboss",

    "wordpress_shell_upload": [
        ("exploit/unix/webapp/wp_admin_shell_upload",
         "WordPress admin → PHP shell upload (needs admin creds)"),
    ],
    "wp-admin-shell":           "__alias__wordpress_shell_upload",

    "joomla_rce": [
        ("exploit/multi/http/joomla_http_header_rce",
         "Joomla HTTP header object injection RCE (CVE-2015-8562)"),
    ],
    "cve-2015-8562":            "__alias__joomla_rce",

    "elasticsearch_rce": [
        ("exploit/multi/elasticsearch/script_mvel_rce",
         "Elasticsearch script API RCE via MVEL (CVE-2014-3120)"),
    ],
    "cve-2014-3120":            "__alias__elasticsearch_rce",

    "iis_webdav": [
        ("exploit/windows/iis/iis_webdav_scstoragepathfromurl",
         "IIS 6.0 WebDAV stack overflow → SYSTEM (CVE-2017-7269)"),
    ],
    "cve-2017-7269":            "__alias__iis_webdav",

    # ── Windows / AD post-2018 RCE & priv-esc ────────────────────────────────
    "zerologon": [
        ("auxiliary/admin/dcerpc/cve_2020_1472_zerologon",
         "ZeroLogon — Netlogon priv-esc to Domain Admin (CVE-2020-1472)"),
    ],
    "cve-2020-1472":            "__alias__zerologon",
    "smb-vuln-cve-2020-1472":   "__alias__zerologon",

    "printnightmare": [
        ("exploit/windows/dcerpc/cve_2021_1675_printnightmare",
         "PrintNightmare — Print Spooler driver-load RCE "
         "(CVE-2021-34527 / CVE-2021-1675)"),
    ],
    "cve-2021-34527":           "__alias__printnightmare",
    "cve-2021-1675":            "__alias__printnightmare",

    "petitpotam": [
        ("auxiliary/scanner/dcerpc/petitpotam",
         "PetitPotam EFS/MS-EFSRPC NTLM relay coercion (CVE-2021-36942)"),
    ],
    "cve-2021-36942":           "__alias__petitpotam",

    "smbghost": [
        ("exploit/windows/smb/cve_2020_0796_smbghost",
         "SMBGhost SMBv3 compression RCE → SYSTEM (CVE-2020-0796)"),
        ("auxiliary/dos/windows/smb/cve_2020_0796_smbghost",
         "SMBGhost DoS — BSOD via SMBv3 compression"),
        ("auxiliary/scanner/smb/smb_ms_17_010",
         "scanner — check if SMBv3 compression is enabled"),
    ],
    "cve-2020-0796":            "__alias__smbghost",
    "smb-vuln-cve-2020-0796":   "__alias__smbghost",

    # ── SMB / Samba misc ──────────────────────────────────────────────────────
    "samba_symlink": [
        ("auxiliary/admin/smb/samba_symlink_traversal",
         "Samba symlink traversal — arbitrary file read via shared dir"),
    ],
    "samba-symlink-traversal":  "__alias__samba_symlink",

    # ── SSH user enumeration (auth-bypass-adjacent) ──────────────────────────
    "ssh_enumusers": [
        ("auxiliary/scanner/ssh/ssh_enumusers",
         "SSH user-enumeration via timing/error oracle (CVE-2018-15473)"),
    ],
    "cve-2018-15473":           "__alias__ssh_enumusers",
    "ssh-enum-users":           "__alias__ssh_enumusers",

    # ── VNC ──────────────────────────────────────────────────────────────────
    "realvnc_auth_bypass": [
        ("auxiliary/scanner/vnc/vnc_none_auth",
         "VNC None-auth scanner — finds servers accepting connections "
         "with no password (CVE-2006-2369 family)"),
    ],
    "cve-2006-2369":            "__alias__realvnc_auth_bypass",
    "vnc-none-auth":            "__alias__realvnc_auth_bypass",

    # ── NFS / Rsync / network shares ─────────────────────────────────────────
    "nfs_showmount": [
        ("auxiliary/scanner/nfs/nfsmount",
         "NFS export enumeration — lists mountable shares without auth"),
    ],
    "nfs-showmount":            "__alias__nfs_showmount",

    "rsync_module_list": [
        ("auxiliary/scanner/rsync/modules_list",
         "rsync module enumeration — lists exposed module names anonymously"),
    ],
    "rsync-modules":            "__alias__rsync_module_list",

    # ── Cisco / network devices (occasionally on lab targets) ───────────────
    "cisco_smart_install": [
        ("auxiliary/scanner/misc/cisco_smart_install",
         "Cisco Smart Install scanner — finds devices with SMI "
         "exposed (config exfil possible)"),
    ],
    "smi-discovery":            "__alias__cisco_smart_install",

    # ── Redis / MongoDB unauth ───────────────────────────────────────────────
    "redis_unauth": [
        ("exploit/linux/redis/redis_replication_cmd_exec",
         "Redis 4.x/5.x replication RCE (no auth, CVE-2022-0543 family)"),
    ],
    "cve-2022-0543":            "__alias__redis_unauth",

    # ── HTTP misc info disclosure ────────────────────────────────────────────
    "robots_txt": [
        ("auxiliary/scanner/http/robots_txt",
         "robots.txt enumeration — reveals hidden paths/admin pages"),
    ],
    "git_repo_exposed": [
        ("auxiliary/scanner/http/git_scanner",
         ".git directory exposed — enables source code dump via "
         "git-dumper / wget recursive"),
    ],

    # ── Drupal extras (Drupalgeddon-2 + 3) ───────────────────────────────────
    "drupalgeddon2": [
        ("exploit/unix/webapp/drupal_drupalgeddon2",
         "Drupalgeddon2 — pre-auth RCE on Drupal 7.58/8.5.0 "
         "(CVE-2018-7600)"),
    ],
    "cve-2018-7600":            "__alias__drupalgeddon2",
    "drupalgeddon3": [
        ("exploit/unix/webapp/drupal_restws_exec",
         "Drupalgeddon3 — RCE on Drupal 8.x with REST module "
         "(CVE-2018-7602)"),
    ],
    "cve-2018-7602":            "__alias__drupalgeddon3",

    # ── Confluence (HTB classic) ─────────────────────────────────────────────
    "confluence_ognl": [
        ("exploit/multi/http/atlassian_confluence_namespace_ognl_injection",
         "Confluence OGNL injection RCE (CVE-2022-26134)"),
    ],
    "cve-2022-26134":           "__alias__confluence_ognl",

    # ── Spring / Java enterprise ─────────────────────────────────────────────
    "spring4shell": [
        ("exploit/multi/http/spring_framework_rce_spring4shell",
         "Spring4Shell — Spring Framework RCE via classloader "
         "(CVE-2022-22965)"),
    ],
    "cve-2022-22965":           "__alias__spring4shell",

    # ── ProxyNotShell (Exchange 2022) ────────────────────────────────────────
    "proxynotshell": [
        ("exploit/windows/http/exchange_proxynotshell_rce",
         "ProxyNotShell — Exchange RCE chain (CVE-2022-41040 + 41082)"),
    ],
    "cve-2022-41040":           "__alias__proxynotshell",
    "cve-2022-41082":           "__alias__proxynotshell",
}


def _get_exploits_for_vuln(title: str, description: str) -> list:
    """Return a list of (module_path, label) tuples that could exploit
    this vulnerability.  Multiple matches are deduped on module_path
    while preserving order (most-useful first).  Returns [] when no
    match is found.

    Two-stage lookup:
    1. VULN_EXPLOIT_MAP — static, curated list.  Always checked first so
       human-written descriptions (with pick-order and better labels)
       take priority over auto-indexed entries.
    2. MSF Index — dynamic, auto-built from the local Metasploit module
       tree.  Activated when ``utils.msf_index`` is ready (background
       thread finished).  Adds any module that references a CVE ID found
       in the finding title or description and that isn't already covered
       by the static map.

    Handles ``__alias__`` redirects in VULN_EXPLOIT_MAP so multiple
    keyword-key variants (``ms17-010``, ``ms17_010``, ``eternalblue``, ...)
    resolve to the same canonical entry without duplicating the list."""
    combined = (title + " " + description).lower()
    out = []
    seen_modules = set()

    # ── Stage 1: curated static map ──────────────────────────────────────
    for key, value in VULN_EXPLOIT_MAP.items():
        if key not in combined:
            continue
        # Resolve alias → canonical list
        if isinstance(value, str) and value.startswith("__alias__"):
            target = value[len("__alias__"):]
            value = VULN_EXPLOIT_MAP.get(target)
            if value is None:
                continue
        # Legacy shape safety: allow bare strings too
        if isinstance(value, str):
            entries = [(value, value.rsplit("/", 1)[-1])]
        else:
            entries = value
        for mod, label in entries:
            if mod in seen_modules:
                continue
            seen_modules.add(mod)
            out.append((mod, label))

    # ── Stage 2: dynamic MSF index (CVE cross-reference) ─────────────────
    # Extract all CVE IDs from title + description, then look each one
    # up in the auto-built index.  Only add entries whose module path
    # isn't already covered by Stage 1 (dedup on seen_modules).
    try:
        from utils import msf_index as _mi
        if _mi.is_ready():
            full_text = title + " " + description
            for _m in re.finditer(r'CVE-(\d{4}-\d+)', full_text, re.I):
                cve_key = _m.group(1)          # e.g. "2011-2523"
                for entry in _mi.lookup(f"CVE-{cve_key}"):
                    mod = entry.get("path", "")
                    if not mod or mod in seen_modules:
                        continue
                    seen_modules.add(mod)
                    label = entry.get("label") or mod.rsplit("/", 1)[-1]
                    out.append((mod, label))
    except Exception:
        pass

    # ── Stage 3: keyword search in MSF index ────────────────────────────
    # For searchsploit findings, extract software name + version from
    # the title and search the MSF module tree by keywords.
    if not out:
        try:
            from utils import msf_index as _mi
            if _mi.is_ready():
                sw_match = re.search(
                    r'([A-Za-z][A-Za-z0-9_-]{2,})\s+'
                    r'(\d+(?:\.\d+)+)',
                    title)
                if sw_match:
                    sw_name = sw_match.group(1).lower()
                    sw_ver = sw_match.group(2)
                    # Reject IP-shaped "versions" (e.g. "on 10.129.26.122")
                    # which are addresses, not software versions, and would
                    # otherwise feed garbage keywords into the MSF search.
                    is_ipv4 = bool(re.fullmatch(
                        r'(?:\d{1,3}\.){3}\d{1,3}', sw_ver)) and all(
                        0 <= int(o) <= 255 for o in sw_ver.split("."))
                    # Skip OS names and common English words that precede
                    # an IP/port/count in finding titles ("on 10.x.x.x",
                    # "at 192.168...", "of 3 hosts" — none are software).
                    skip = {"linux", "windows", "microsoft", "ubuntu",
                            "debian", "centos", "red", "apple", "mac",
                            "on", "in", "at", "to", "of", "the", "from",
                            "for", "with", "via", "and", "or", "by"}
                    if not is_ipv4 and sw_name not in skip:
                        hits = _mi.search_by_keywords(
                            [sw_name], max_results=5)
                        for entry in hits:
                            mod = entry.get("path", "")
                            if mod and mod not in seen_modules:
                                seen_modules.add(mod)
                                label = (entry.get("label")
                                         or mod.rsplit("/", 1)[-1])
                                out.append((mod, label))
        except Exception:
            pass

    return out


def _get_exploit_for_vuln(title: str, description: str) -> str:
    """Legacy wrapper — returns the first matching module path or ''.
    New code should prefer _get_exploits_for_vuln() so multi-module
    vulns can show the picker dialog."""
    hits = _get_exploits_for_vuln(title, description)
    return hits[0][0] if hits else ""

__all__ = [
    "COLORS", "SZ", "TMP_DIR", "SPINNER_FRAMES", "_MANUAL_ENTRY_LABEL",
    "VULN_EXPLOIT_MAP", "_f", "_nmap_already_run", "_nmap_os_already_run",
    "_get_exploits_for_vuln", "_get_exploit_for_vuln",
]
