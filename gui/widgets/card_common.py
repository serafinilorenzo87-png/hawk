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
HAWK - Kill Chain Card Widget v1.0
- Port-aware routing for all tools
- Hydra: wordlist dropdown from metasploit/seclists + browse
- MSF card: check DB + guide user
- Nmap custom: free command field
- Right-click context menu on all entries
- smbclient/crackmapexec → auto-populate intel
- ssh_banner/ftp_anon port-aware fix
- No popup for 0 ports found
- WinRM excluded from HTTP tools
"""

import customtkinter as ctk
import os
import glob
import shlex

from utils.config import (
    COLORS, STATUS_READY, STATUS_RUNNING, STATUS_DONE, STATUS_ERROR, SZ,
    CACHE_DIR, TMP_DIR,
)
from utils.clipboard import add_context_menu, apply_context_menus_recursive

from utils.runner import ToolRunner, MultiRunner, MetasploitRunner, GreenBoneRunner
from utils.session import Credential

STATUS_STYLE = {
    STATUS_READY:   {"bg": COLORS["bg_card"],  "fg": COLORS["text_muted"],  "text": "READY"},
    STATUS_RUNNING: {"bg": "#1C1500",           "fg": COLORS["text_yellow"], "text": "RUNNING"},
    STATUS_DONE:    {"bg": "#0A1A0E",           "fg": "#40A060",             "text": "DONE"},
    STATUS_ERROR:   {"bg": "#1A0A0A",           "fg": COLORS["text_red"],    "text": "ERROR"},
    "SKIPPED":      {"bg": COLORS["bg_card"],   "fg": COLORS["text_muted"],  "text": "SKIP"},
}
TOOL_STATUS_ICONS = {
    "ready":   ("○", COLORS["text_muted"]),
    "running": ("◉", COLORS["text_yellow"]),
    "done":    ("●", "#40A060"),
    "error":   ("✗", COLORS["text_red"]),
}

ACCESS_GATED_PHASES = {"lateral", "post_exploit"}

WEB_TOOLS = {
    # TOOL IDS, like SMB_TOOLS below — tests/test_dialog_contracts
    # asserts every one of them exists in the module registry.  A bare
    # "gobuster" alias used to sit here; the registered ids are
    # gobuster_dir and gobuster_dns.
    "gobuster_dir", "gobuster_dns",
    "ffuf", "nikto", "nikto_ssl",
    "nuclei", "wpscan", "sqlmap", "wafw00f", "whatweb", "dirb",
}
SMB_TOOLS = {
    # These are TOOL IDS, not binary names — tests/test_dialog_contracts
    # asserts every one of them exists in the module registry.
    # "crackmapexec_smb" used to sit here and matches no tool at all.
    "enum4linux", "netexec", "smbclient_list",
    # rpcclient MUST live here — otherwise the dispatcher in
    # card_routes_scan._route_tool falls through to the generic
    # `_run_raw(tool, tool.build_command(target))` path and launches
    # the raw `rpcclient -U '' -N <target>` interactive template,
    # which hangs forever on the prompt (no stdin in HAWK).  Routing
    # through `_route_smb_tool` triggers `_show_rpcclient_dialog`
    # (batch / interactive choice + auth) which is the correct UX.
    "rpcclient",
}
WINRM_BANNERS = ["microsoft-httpapi", "wsman", "winrm", "httpapi", "ncacn_http"]

# Whitelist of TRUE HTTP/HTTPS services - only these get web tools
TRUE_HTTP_SERVICES = [
    "http", "https", "http-alt", "https-alt", "ssl/http",
    "apache", "nginx", "iis", "lighttpd", "httpd",
    "tomcat", "jenkins", "jboss", "weblogic", "glassfish",
    "struts", "wordpress", "drupal",
]

# Wordlist directories to scan
WORDLIST_DIRS = [
    "/usr/share/metasploit-framework/data/wordlists",
    "/usr/share/seclists/Usernames",
    "/usr/share/seclists/Passwords",
    "/usr/share/wordlists",
]


def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")


from utils.clipboard import add_context_menu


from utils.clipboard import apply_context_menus_recursive


def collect_known_hosts(app, target_ip: str) -> list:
    """Return a list of (label, host) for every host the operator might
    plausibly want to target — IP, session domain, plus any HAWK-tagged
    /etc/hosts entries (vhosts added by the DNS helper or earlier ffuf
    finds). Domain is listed FIRST when present; IP is the fallback.
    """
    domain = ""
    vhosts = []
    try:
        sess = app.session_manager.current
        if sess:
            domain = (getattr(sess, "target_domain", "") or "").strip()
            from utils.hosts_helper import list_hawk_entries
            for e in list_hawk_entries():
                for h in e.get("hostnames", []):
                    if h and h not in vhosts:
                        vhosts.append(h)
    except Exception:
        pass

    out = []
    if domain and domain != target_ip:
        out.append((f"🌐  {domain}  (domain)", domain))
    for vh in vhosts:
        if vh != domain and vh != target_ip:
            out.append((f"🌐  {vh}  (vhost)", vh))
    out.append((f"🔢  {target_ip}  (IP)", target_ip))
    return out


def attach_host_dropdown(parent, app, target_ip: str, url_var,
                         pack_kwargs: dict | None = None):
    """Attach a "Host" OptionMenu above a URL CTkEntry.

    When the user picks a different host the URL string in ``url_var``
    is rewritten with the new hostname (scheme, port and path are
    preserved). When only one host is available the dropdown is hidden
    so we don't clutter the dialog.
    """
    from urllib.parse import urlparse, urlunparse
    options = collect_known_hosts(app, target_ip)
    if len(options) <= 1:
        return None

    label_to_host = {lbl: h for lbl, h in options}
    labels = [lbl for lbl, _ in options]

    fr = ctk.CTkFrame(parent, fg_color="transparent")
    fr.pack(**(pack_kwargs or {"fill": "x", "padx": 24, "pady": (4, 2)}))
    ctk.CTkLabel(
        fr, text="Host:", font=_f("md", True),
        text_color=COLORS["text_bright"], anchor="w",
        width=60,
    ).pack(side="left")

    # Pick the default by matching whatever host is in the URL right now.
    current_host = ""
    try:
        current_host = (urlparse(url_var.get()).hostname or "").strip()
    except Exception:
        pass
    default_label = labels[0]
    for lbl, h in options:
        if h == current_host:
            default_label = lbl
            break

    host_var = ctk.StringVar(value=default_label)

    def _on_change(_=None):
        new_host = label_to_host.get(host_var.get())
        if not new_host:
            return
        try:
            pu = urlparse(url_var.get().strip())
            netloc = (f"{new_host}:{pu.port}"
                      if pu.port else new_host)
            url_var.set(urlunparse(pu._replace(netloc=netloc)))
        except Exception:
            pass

    ctk.CTkOptionMenu(
        fr, values=labels, variable=host_var,
        font=_f("sm"), height=28,
        fg_color=COLORS["bg_card"],
        button_color=COLORS["border_dim"],
        dropdown_fg_color=COLORS["bg_secondary"],
        dropdown_text_color=COLORS["text_bright"],
        text_color=COLORS["text_bright"], corner_radius=3,
        command=_on_change,
    ).pack(side="left", fill="x", expand=True, padx=(8, 0))

    return host_var


def verify_host_or_prompt(parent, app, hostname: str, fallback_ip: str,
                          on_proceed) -> None:
    """Resolvability gate for web tools that target a hostname.

    If `hostname` resolves, calls `on_proceed(hostname)` immediately.
    Otherwise pops a 3-button modal:

        [ADD TO /etc/hosts]  → async pkexec add of (fallback_ip, [hostname]),
                                then on_proceed(hostname)
        [USE IP INSTEAD]     → on_proceed(fallback_ip)
        [CANCEL]             → no callback

    The host added to /etc/hosts gets the HAWK marker so the existing
    DNS HELPER can clean it up on session delete or shutdown.
    """
    from utils.hosts_helper import (resolvable,
                                     add_entries_async)

    # Fast path: hostname resolves (DNS, mDNS, /etc/hosts), no UI needed.
    if not hostname or resolvable(hostname):
        try:
            on_proceed(hostname or fallback_ip)
        except Exception as e:
            import sys as _s
            print(f"[HAWK] verify_host_or_prompt fast-path cb: {e}",
                  file=_s.stderr)
        return

    # Slow path: doesn't resolve. Ask the user.
    win = ctk.CTkToplevel(parent)
    win.title("HAWK — Hostname does not resolve")
    win.geometry("560x300")
    win.resizable(False, False)
    win.transient(parent)
    try:
        win.grab_set()
    except Exception:
        pass

    ctk.CTkLabel(
        win,
        text="🌐  Hostname unresolved",
        font=ctk.CTkFont(family="Courier New", size=15, weight="bold"),
        text_color=COLORS.get("text_yellow", "#FFCC00"),
    ).pack(padx=16, pady=(16, 4))

    ctk.CTkLabel(
        win,
        text=(f"'{hostname}' does not resolve from this machine.\n\n"
              f"You can map it to {fallback_ip} in /etc/hosts (HAWK-tagged "
              f"so it gets cleaned up automatically), use the IP directly, "
              f"or cancel."),
        font=ctk.CTkFont(family="Courier New", size=12),
        text_color=COLORS.get("text_bright", "#E0E0E0"),
        wraplength=500, justify="left",
    ).pack(padx=16, pady=(0, 8))

    status_lbl = ctk.CTkLabel(
        win, text="",
        font=ctk.CTkFont(family="Courier New", size=11),
        text_color=COLORS.get("text_dim", "#808080"))
    status_lbl.pack(padx=16, pady=(0, 4))

    btn_frame = ctk.CTkFrame(win, fg_color="transparent")
    btn_frame.pack(pady=(4, 12))

    def _close():
        try:
            win.grab_release()
        except Exception:
            pass
        try:
            win.destroy()
        except Exception:
            pass

    def _on_add():
        # Disable buttons + status feedback. The pkexec auth runs on a
        # worker thread; result is posted back via `app.after` to keep
        # Tk single-threaded.
        for child in btn_frame.winfo_children():
            try:
                child.configure(state="disabled")
            except Exception:
                pass
        status_lbl.configure(
            text="…  waiting for sudo/polkit",
            text_color=COLORS.get("text_yellow", "#FFCC00"))

        def _added(ok, msg):
            def _apply():
                if ok:
                    status_lbl.configure(
                        text=f"✓  {msg}",
                        text_color=COLORS.get("text_green", "#00FF41"))
                    try:
                        sess = app.session_manager.current
                        if sess:
                            entry = {"ip": fallback_ip,
                                     "hostname": hostname}
                            existing = getattr(sess, "hawk_hosts_entries",
                                               [])
                            if entry not in existing:
                                sess.hawk_hosts_entries.append(entry)
                                sess._touch()
                    except Exception:
                        pass
                    _close()
                    try:
                        on_proceed(hostname)
                    except Exception as e:
                        import sys as _s
                        print(f"[HAWK] verify_host on_proceed (add): {e}",
                              file=_s.stderr)
                else:
                    status_lbl.configure(
                        text=f"✗  {msg}",
                        text_color=COLORS.get("text_red", "#FF5555"))
                    # Re-enable so the user can try again or pick another option
                    for child in btn_frame.winfo_children():
                        try:
                            child.configure(state="normal")
                        except Exception:
                            pass
            try:
                app.after(0, _apply)
            except Exception:
                _apply()

        add_entries_async([(fallback_ip, [hostname])], _added)

    def _on_use_ip():
        _close()
        try:
            on_proceed(fallback_ip)
        except Exception as e:
            import sys as _s
            print(f"[HAWK] verify_host on_proceed (ip): {e}", file=_s.stderr)

    ctk.CTkButton(
        btn_frame, text="ADD TO /etc/hosts",
        width=180, height=32,
        font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
        fg_color="#002200", hover_color="#003300",
        border_color=COLORS.get("text_green", "#00FF41"), border_width=1,
        text_color=COLORS.get("text_green", "#00FF41"),
        corner_radius=3, command=_on_add,
    ).pack(side="left", padx=6)

    ctk.CTkButton(
        btn_frame, text=f"USE IP ({fallback_ip})",
        width=180, height=32,
        font=ctk.CTkFont(family="Courier New", size=12),
        fg_color=COLORS.get("bg_card", "#0A0A0A"),
        hover_color="#1A1A1A",
        border_color=COLORS.get("border_dim", "#333333"), border_width=1,
        text_color=COLORS.get("text_bright", "#E0E0E0"),
        corner_radius=3, command=_on_use_ip,
    ).pack(side="left", padx=6)

    ctk.CTkButton(
        btn_frame, text="CANCEL",
        width=100, height=32,
        font=ctk.CTkFont(family="Courier New", size=12),
        fg_color=COLORS.get("bg_card", "#0A0A0A"),
        hover_color="#1A1A1A",
        border_color=COLORS.get("border_dim", "#333333"), border_width=1,
        text_color=COLORS.get("text_dim", "#808080"),
        corner_radius=3, command=_close,
    ).pack(side="left", padx=6)


def _shq(p: str) -> str:
    """Shell-quote a path if it contains whitespace or shell metacharacters.

    Used wherever wordlist paths (or other filesystem paths) get interpolated
    into a shell command. Filenames under /usr/share/seclists/ include folders
    like "Default-Credentials/Oracle EBS" with embedded spaces — without
    quoting, hydra/gobuster/ffuf/etc. parse them as two arguments and break.
    shlex.quote returns the input unchanged when no quoting is required,
    so it's safe to call unconditionally.
    """
    import shlex
    if p is None:
        return "''"
    return shlex.quote(str(p))


def _find_wordlists() -> dict:
    """Scan system for available wordlists. Returns {label: path}."""
    found = {}
    for d in WORDLIST_DIRS:
        if os.path.isdir(d):
            for f in sorted(glob.glob(os.path.join(d, "**", "*.txt"),
                                      recursive=True)):
                label = f.replace(d + "/", "")
                found[label] = f
    return found


def _get_user_wordlists(detected_os: str = "") -> list:
    """Return a prioritised list of username wordlists.

    Ranking strategy:
      1. CURATED canonical lists from SecLists / Kali (highest quality,
         no language-specific garbage).
      2. Windows AD lists pushed to top when detected_os=='windows'.
      3. Whatever else the filesystem offers with sensible keywords.
      4. NO rockyou — it's a *password* wordlist, returning it here
         wastes the user's time clicking the wrong thing.

    Language-specific lists (spanish, french, …) and weird "names"
    lists are explicitly filtered OUT because they generate hours of
    wasted Kerberoast / userenum runs.
    """
    # 1.  CURATED — ordered by RUNTIME (smallest/fastest first), not
    # by name.  Previous order put the 10M-line "xato-net-10-million"
    # wordlists at the top as default picks — that's wrong for AS-REP
    # roast / kerbrute runs: a single 10M list = 24+ hours against a
    # DC that responds at ~100 req/s, and 99.9 % of those names don't
    # exist on any real AD.  The correct pentester workflow is:
    #   1. top-usernames-shortlist (20)  — 2-second smoke test
    #   2. Names/names.txt (~10k)        — 2-minute first pass
    #   3. jsmith.txt (~48k)             — 10-minute deeper pass
    #   4. xato 10M                      — overnight / last resort
    #
    # Each line's label carries an explicit runtime hint so the user
    # knows what they're committing to before clicking RUN.
    CURATED = [
        # Fast first passes
        ("★  top-usernames-shortlist.txt  (~20 lines — 2 sec)",
         "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"),
        ("★  top-20.txt  (quick smoke test — 2 sec)",
         "/usr/share/seclists/Usernames/top-20.txt"),
        # Default appliance / vendor accounts
        ("cirt-default-usernames.txt  (default appliance logins — 10 sec)",
         "/usr/share/seclists/Usernames/cirt-default-usernames.txt"),
        # Linux / Unix service accounts
        ("unix-users.txt  (top Linux services — 30 sec)",
         "/usr/share/seclists/Usernames/Linux/unix-users.txt"),
        # Medium AD lists — good for real pentest first-pass
        ("★  Names/names.txt  (~10 k first names — 2 min)",
         "/usr/share/seclists/Usernames/Names/names.txt"),
        ("jsmith.txt  (~48 k realistic usernames — 10 min)",
         "/usr/share/seclists/Usernames/Names/jsmith.txt"),
        # Honeypot captures (real-world bruteforce targets)
        ("Honeypot-Captures/usernames.txt  (real-world — ~2 min)",
         "/usr/share/seclists/Usernames/Honeypot-Captures/usernames.txt"),
        # HEAVY — last-resort lists, explicit warning
        ("⚠  xato-net-10-million-usernames-dup.txt  (10 M — 24+ hrs!)",
         "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"),
        ("⚠  xato-net-10-million-usernames.txt  (10 M — 24+ hrs!)",
         "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"),
    ]

    # 2. Windows → push AD-friendly lists to the top.  Linux/Unix →
    # push unix-users first.  Everything else keeps curated order.
    os_lower = (detected_os or "").lower()
    if "windows" in os_lower:
        def _rank(entry):
            lbl = entry[0].lower()
            if "xato" in lbl: return 0
            if "names" in lbl: return 1
            if "top-usernames-shortlist" in lbl: return 2
            if "cirt" in lbl: return 3
            return 9
        curated_sorted = sorted(CURATED, key=_rank)
    elif any(k in os_lower for k in ("linux", "unix", "bsd")):
        def _rank(entry):
            lbl = entry[0].lower()
            if "unix" in lbl: return 0
            if "xato" in lbl: return 1
            return 9
        curated_sorted = sorted(CURATED, key=_rank)
    else:
        curated_sorted = CURATED

    result = [(lbl, p) for lbl, p in curated_sorted if os.path.isfile(p)]

    # 3. Supplementary discovery from _find_wordlists() — only for
    # paths that are OBVIOUSLY user lists AND don't stink of
    # language-specific / protocol-specific wordlists we don't want.
    EXCLUDE_TOKENS = (
        "password", "passwd", "pwd", "rockyou",
        # language / regional noise
        "spanish", "italian", "french", "german", "portuguese",
        "cantonese", "chinese", "japanese", "korean", "dutch",
        "polish", "russian", "arabic", "turkish", "hungarian",
        # protocol / data-type noise that "user" grep would snag
        "_hash", "keepass", "base64", "email", "wifi", "ssid",
    )
    KEEP_TOKENS = (
        "user", "login", "account", "admin", "unix_user",
        "default_user", "top-user",
    )

    already = {p for _, p in result}
    for label, path in _find_wordlists().items():
        lbl_low = label.lower()
        if path in already:
            continue
        if any(x in lbl_low for x in EXCLUDE_TOKENS):
            continue
        if not any(k in lbl_low for k in KEEP_TOKENS):
            continue
        result.append((label, path))

    return result


def _get_pass_wordlists() -> list:
    """Get wordlists suitable for passwords."""
    all_wl = _find_wordlists()
    pass_wl = []
    keywords = ["pass", "pwd", "secret", "common", "rockyou", "unix_pass",
                 "mirai_pass", "probable", "top-pass"]
    for label, path in all_wl.items():
        if any(k in label.lower() for k in keywords):
            pass_wl.append((label, path))
    if not any("rockyou" in p for _, p in pass_wl):
        if os.path.isfile("/usr/share/wordlists/rockyou.txt"):
            pass_wl.append(("rockyou.txt ★ recommended",
                             "/usr/share/wordlists/rockyou.txt"))
    return sorted(pass_wl, key=lambda x: x[0])


def _get_dir_wordlists(detected_os: str = "", kind: str = "generic") -> list:
    """Get wordlists suitable for web directory brute-force.

    Returns (label, path) tuples sorted with the best default first.
    If *detected_os* contains 'windows' we prefer IIS/ASP wordlists;
    otherwise we prefer generic ones (dirbuster, dirb, raft).

    When *kind* is "api", prepend the SecLists API wordlists so the
    default selection in the picker matches the operator's intent
    (the FUZZ button on a Target Intel finding under /api/, /v1/,
    /rest/ etc. flips this on).
    """
    API_WORDLISTS = [
        ("api-endpoints (SecLists)",
         "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"),
        ("api-endpoints-res (SecLists)",
         "/usr/share/seclists/Discovery/Web-Content/api/"
         "api-endpoints-res.txt"),
        ("actions-lowercase (SecLists API)",
         "/usr/share/seclists/Discovery/Web-Content/api/"
         "actions-lowercase.txt"),
        ("objects-lowercase (SecLists API)",
         "/usr/share/seclists/Discovery/Web-Content/api/"
         "objects-lowercase.txt"),
    ]
    # Curated options — order is default priority
    CURATED = [
        ("directory-list-2.3-medium (dirbuster)",
         "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
        ("directory-list-2.3-small (dirbuster)",
         "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"),
        ("common.txt (dirb)",
         "/usr/share/wordlists/dirb/common.txt"),
        ("big.txt (dirb)",
         "/usr/share/wordlists/dirb/big.txt"),
        ("raft-medium-directories (SecLists)",
         "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        ("raft-small-words (SecLists)",
         "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"),
        ("quickhits.txt (SecLists)",
         "/usr/share/seclists/Discovery/Web-Content/quickhits.txt"),
    ]
    # Windows-specific extras — pushed to top when OS is Windows.
    # NOTE: we deliberately DON'T include `raft-medium-files.txt` here.
    # That list is a file-name wordlist (entries end with `.`) designed
    # to be used WITHOUT extension appending.  Passing it to gobuster dir
    # with `-x` produces malformed `..aspx` paths → 400-spam.  For file
    # discovery, the FFUF card is the right tool instead.
    WIN_EXTRAS = [
        ("IIS.fuzz.txt (SecLists)",
         "/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt"),
    ]
    result = []
    if kind == "api":
        for lbl, p in API_WORDLISTS:
            if os.path.isfile(p):
                result.append((lbl + " ★ API", p))
    is_win = "windows" in (detected_os or "").lower()
    if is_win:
        for lbl, p in WIN_EXTRAS:
            if os.path.isfile(p):
                result.append((lbl + " ★ Windows", p))
    for lbl, p in CURATED:
        if os.path.isfile(p):
            result.append((lbl, p))
    # Fallback: scan generic wordlist dirs for anything with 'dir' in name
    if not result:
        for lbl, p in _find_wordlists().items():
            if "dir" in lbl.lower() or "common" in lbl.lower():
                result.append((lbl, p))
    return result


def _get_dns_wordlists() -> list:
    """Get wordlists suitable for DNS subdomain enumeration."""
    CURATED = [
        ("subdomains-top1million-5000 (SecLists)",
         "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        ("subdomains-top1million-20000 (SecLists)",
         "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"),
        ("subdomains-top1million-110000 (SecLists)",
         "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"),
        ("namelist.txt (SecLists)",
         "/usr/share/seclists/Discovery/DNS/namelist.txt"),
        ("bitquark-subdomains-top100000 (SecLists)",
         "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"),
        ("fierce-hostlist.txt (SecLists)",
         "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt"),
    ]
    result = []
    for lbl, p in CURATED:
        if os.path.isfile(p):
            result.append((lbl, p))
    if not result:
        for lbl, p in _find_wordlists().items():
            if "dns" in lbl.lower() or "subdomain" in lbl.lower():
                result.append((lbl, p))
    return result

__all__ = [
    "COLORS", "STATUS_READY", "STATUS_RUNNING", "STATUS_DONE", "STATUS_ERROR",
    "SZ", "CACHE_DIR", "TMP_DIR", "STATUS_STYLE", "TOOL_STATUS_ICONS",
    "ACCESS_GATED_PHASES", "WEB_TOOLS", "SMB_TOOLS", "WINRM_BANNERS",
    "TRUE_HTTP_SERVICES", "WORDLIST_DIRS", "_f", "_shq", "_find_wordlists",
    "_get_user_wordlists", "_get_pass_wordlists", "_get_dir_wordlists",
    "_get_dns_wordlists", "add_context_menu", "apply_context_menus_recursive",
    "verify_host_or_prompt", "collect_known_hosts", "attach_host_dropdown",
]
