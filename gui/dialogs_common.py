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
HAWK - Dialogs v1.0
- Greenbone install: 10-second countdown popup watching xterm for password
- Selectable text: CTkTextbox (disabled) for all technical content
- OS detection dialog fixed (grab_set)
- Netcat with service-specific verification commands
"""

import os
import re
import customtkinter as ctk
from utils.config import (
    COLORS, NMAP_SCAN_TYPES, NMAP_TIMING, NMAP_EVASION, NMAP_PORT_SCOPES,
    NMAP_EXTRA_FLAGS,
    WAF_EVASION_OPTIONS, WORDLISTS, WORDLIST_PATHS_USERS, WORDLIST_PATHS_PASS,
    HASH_MODES, GREENBONE_INSTALL_STEPS, SZ,
)



from utils.clipboard import add_context_menu

def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")


def _center_window(win, w, h):
    win.update_idletasks()
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    x = max(0, (sw - w) // 2)
    y = max(0, (sh - h) // 2)
    win.geometry(f"{w}x{h}+{x}+{y}")


def _autosize_window(win, min_w=400, min_h=220, pad_w=40, pad_h=40, max_ratio=0.92):
    """Resize dialog to fit its content without clipping text."""
    try:
        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        req_w = min(max(int(win.winfo_reqwidth()) + pad_w, min_w), int(sw * max_ratio))
        req_h = min(max(int(win.winfo_reqheight()) + pad_h, min_h), int(sh * max_ratio))
        cur_w = max(req_w, win.winfo_width())
        cur_h = max(req_h, win.winfo_height())
        _center_window(win, cur_w, cur_h)
    except Exception:
        pass


def _make_win(parent, title, w, h, on_close=None):
    """Build a HAWK dialog Toplevel.

    `on_close` is invoked when the dialog goes away through the window
    manager's X button.  Tk's default for WM_DELETE_WINDOW is a bare
    destroy(), so without this every one of the dialogs built here could
    be dismissed with the X while the caller kept waiting for a callback
    it would never get.  Callers that only need "the window disappears"
    can keep ignoring the parameter — the default handler still routes
    through _safe_destroy (grab_release + destroy), which is what the
    CLOSE/CANCEL buttons do.
    """
    win = ctk.CTkToplevel(parent)
    # Hide immediately — CTkToplevel flashes onto the screen at its
    # native small size the instant it's created, then jumps to the real
    # geometry after widgets are packed and _autofit runs.  That's the
    # "dialog glitch" the user sees.  We pop it back into view at the
    # end of the build chain so the first frame the user sees is the
    # finished layout.
    win.withdraw()
    win.title(title)
    win.resizable(True, True)
    win.configure(fg_color=COLORS["bg_primary"])
    win.update_idletasks()
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    # Use requested size but allow auto-grow, cap at 90% screen
    win_w = min(max(w, 500), int(sw * 0.9))
    win_h = min(max(h, 300), int(sh * 0.9))
    win.geometry(f"{win_w}x{win_h}+{(sw-win_w)//2}+{(sh-win_h)//2}")
    win.minsize(min(w, 480), 280)

    # Closing with the X must take the same route as the dialog's own
    # CLOSE button, callback included.
    def _on_wm_delete():
        _safe_destroy(win)
        if on_close is not None:
            try:
                on_close()
            except Exception:
                pass
    win.protocol("WM_DELETE_WINDOW", _on_wm_delete)

    ctk.CTkFrame(win, fg_color=COLORS["border_green"],
                 height=2, corner_radius=0).pack(fill="x")

    # Auto-resize to fit content after widgets are placed
    def _autofit():
        try:
            win.update_idletasks()
            req_w = max(win.winfo_reqwidth(), win_w)
            req_h = max(win.winfo_reqheight(), win_h)
            final_w = min(req_w + 20, int(sw * 0.9))
            final_h = min(req_h + 20, int(sh * 0.9))
            x = max(0, (sw - final_w) // 2)
            y = max(0, (sh - final_h) // 2)
            win.geometry(f"{final_w}x{final_h}+{x}+{y}")
        except Exception:
            pass

    win.after(150, _autofit)
    win.after(400, _autofit)

    # Apply right-click context menus to all text widgets in this dialog
    def _apply_ctx():
        try:
            from utils.clipboard import apply_context_menus_recursive
            apply_context_menus_recursive(win)
        except Exception:
            pass
    win.after(300, _apply_ctx)

    # Reveal the dialog after all layout work is done — no grab_set() here.
    # HAWK dialogs are intentionally NON-MODAL: the operator may need to
    # read the terminal, check Target Intel, or open a second dialog while
    # a config window is open.  grab_set() blocks all other windows in the
    # same Tk application and causes an apparent "freeze" when two or more
    # dialogs are open simultaneously (nested grabs conflict silently in Tk).
    def _reveal():
        try:
            if win.winfo_exists():
                win.deiconify()
                win.lift()
                win.focus_force()
        except Exception:
            pass
    win.after(420, _reveal)

    return win


def _title(win, text):
    ctk.CTkLabel(win, text=text, font=_f("xl", True),
                 text_color=COLORS["text_bright"]).pack(pady=(14, 6))


def _sub(win, text, color=None, wrap=520):
    ctk.CTkLabel(win, text=text, font=_f("md"),
                 text_color=color or COLORS["text_dim"],
                 wraplength=wrap, justify="center").pack(pady=3)


def _note_box(win, text, color=None, selectable=False, text_color=None):
    """Info box.  `color` sets the *border* colour only.  Use `text_color`
    to override the text colour explicitly; defaults to COLORS["text_dim"].
    If selectable=True the content is rendered in a copyable CTkTextbox.
    """
    txt_c  = text_color or COLORS["text_dim"]   # text is ALWAYS readable
    brd_c  = color      or COLORS["border_dim"]  # border may be any accent

    fr = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                      border_color=brd_c,
                      border_width=1, corner_radius=4)
    fr.pack(fill="x", padx=24, pady=6)

    if selectable:
        # Count lines for height
        lines = text.count("\n") + 1
        h = max(60, min(lines * 20 + 16, 180))
        box = ctk.CTkTextbox(
            fr, height=h, font=_f("md"),
            fg_color="transparent",
            text_color=txt_c,
            border_width=0, corner_radius=0,
            wrap="word")
        box.pack(fill="x", padx=8, pady=6)
        box.insert("1.0", text)
        box.configure(state="disabled")
        add_context_menu(box)
    else:
        ctk.CTkLabel(fr, text=text, font=_f("md"),
                     text_color=txt_c,
                     wraplength=500, justify="left",
                     anchor="w").pack(padx=12, pady=8, anchor="w")


def _lane_banner(win, lane):
    """Render the two-line RUN ON / OUTPUT lane banner at the top of a
    post-exploit action dialog.

    Colour encodes WHERE the command runs (green=Kali, cyan=target shell,
    grey=nothing); the OUTPUT line carries what happens to the output.  This
    is the dialog-side twin of the card-face chip — together they make the
    post-exploit flow answer, up front, the two questions the operator has:
    where do I run this, and where does the output go.

    No-op for an empty/unknown lane, so callers can pass ``tool.lane``
    unconditionally.
    """
    try:
        from modules.base import LANE_BANNER
        from gui.widgets.card_common import lane_color
    except Exception:
        return
    info = LANE_BANNER.get(lane or "")
    if not info:
        return
    _chip, run_on, output = info
    color = lane_color(lane)
    fr = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                      border_color=color, border_width=1, corner_radius=4)
    fr.pack(fill="x", padx=24, pady=(8, 4))
    ctk.CTkLabel(fr, text=run_on, font=_f("md", True),
                 text_color=color, anchor="w",
                 justify="left").pack(fill="x", padx=12, pady=(8, 0))
    ctk.CTkLabel(fr, text=output, font=_f("sm"),
                 text_color=COLORS["text_dim"], anchor="w",
                 justify="left", wraplength=560).pack(fill="x", padx=12,
                                                      pady=(0, 8))


def _selectable_text(parent, text, color=None, height=None):
    """
    A selectable text widget (CTkTextbox disabled) for commands/paths/CVEs.
    User can click and copy content.

    Sets the `_hawk_bubble_wheel` flag on both the CTkTextbox and
    the underlying tk.Text — this tells utils.mousewheel's global
    handler to ROUTE wheel events to the surrounding
    CTkScrollableFrame instead of trapping them inside this small
    code block.  Without the flag, hovering over a snippet
    deadlocks the wheel and the user can't scroll the outer dialog
    (the "rotellina si inceppa" bug).
    """
    lines = text.count("\n") + 1
    h = height or max(30, min(lines * 20 + 10, 200))
    box = ctk.CTkTextbox(
        parent, height=h, font=_f("md"),
        fg_color=COLORS["bg_card"],
        text_color=color or COLORS["text_bright"],
        border_color=COLORS["border_dim"], border_width=1,
        corner_radius=3, wrap="word")
    box.pack(fill="x", padx=24, pady=4)
    box.insert("1.0", text)
    box.configure(state="disabled")
    # Wheel-bubble: same trick used in the manual-privesc checklist.
    try:
        box._hawk_bubble_wheel = True
        # The internal tk.Text is what actually receives the
        # <MouseWheel>/<Button-4>/<Button-5> events; flagging it too
        # makes _has_bubble_flag short-circuit and the global
        # handler walks up to the outer CTkScrollableFrame.
        box._textbox._hawk_bubble_wheel = True
    except Exception:
        pass
    return box


def _recommended(win, text="Recommended: PROCEED"):
    ctk.CTkLabel(win, text=f"  ★  {text}",
                 font=_f("md", True), text_color=COLORS["text_green"],
                 fg_color=COLORS["bg_card"],
                 corner_radius=3).pack(pady=(6, 2))


def _divider(win):
    ctk.CTkFrame(win, height=1,
                 fg_color=COLORS["border_dim"]).pack(fill="x", padx=20, pady=8)


def _btn_row(win):
    f = ctk.CTkFrame(win, fg_color="transparent")
    f.pack(pady=14)
    return f


def _btn(parent, text, cmd, primary=False, danger=False, warn=False, w=120):
    bc = (COLORS["border_green"]  if primary else
          COLORS["text_red"]      if danger  else
          COLORS["border_amber"]  if warn    else
          COLORS["border_dim"])
    tc = (COLORS["text_green"]    if primary else
          COLORS["text_red"]      if danger  else
          COLORS["text_yellow"]   if warn    else
          COLORS["text_dim"])
    ctk.CTkButton(
        parent, text=text, width=w, height=34,
        font=_f("md", primary or danger),
        fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
        border_color=bc, border_width=1, text_color=tc,
        corner_radius=4, command=cmd,
    ).pack(side="left", padx=6)


def _safe_destroy(win):
    try:
        win.grab_release()
    except Exception:
        pass
    try:
        win.destroy()
    except Exception:
        pass


SERVICE_VERIFY_COMMANDS = {
    "http": {
        "hint": "Web service. Banner-grab + curl headers + try whatweb.",
        "commands": [
            ("netcat banner",    "nc -nv {target} {port}"),
            ("curl headers",     "curl -I -v http://{target}:{port}/"),
            ("whatweb",          "whatweb -a 1 http://{target}:{port}/"),
        ],
    },
    "https": {
        "hint": "TLS web service. Inspect cert + headers.",
        "commands": [
            ("openssl client",   "openssl s_client -connect {target}:{port} -servername {target}"),
            ("curl headers",     "curl -k -I -v https://{target}:{port}/"),
            ("whatweb",          "whatweb -a 1 https://{target}:{port}/"),
        ],
    },
    "ssh": {
        "hint": "SSH service. Grab banner, check host key + supported algos.",
        "commands": [
            ("netcat banner",    "nc -nv {target} {port}"),
            ("ssh-keyscan",      "ssh-keyscan -p {port} {target}"),
            ("nmap ssh-auth",    "nmap -Pn -p {port} --script ssh-auth-methods,ssh2-enum-algos {target}"),
        ],
    },
    "ftp": {
        "hint": "FTP service. Try anonymous + grab banner.",
        "commands": [
            ("netcat banner",    "nc -nv {target} {port}"),
            ("ftp anonymous",    "ftp -nv {target} {port}"),
            ("nmap ftp scripts", "nmap -Pn -p {port} --script ftp-anon,ftp-syst {target}"),
        ],
    },
    "smb": {
        "hint": "SMB / NetBIOS. Enumerate shares + OS fingerprint.",
        "commands": [
            # -I / min-protocol / lanman mirror the smbclient_list
            # cmd_template (modules/enumeration.py SMBCLIENT_COMPAT_FLAGS):
            # a bare `-N` fails with NT_STATUS_RESOURCE_NAME_NOT_FOUND on
            # Server 2008 R2 (W-05).
            ("smbclient list",   "smbclient -L //{target} -p {port} -N "
                                 "-I {target} "
                                 "--option='client min protocol=NT1' "
                                 "--option='client lanman auth=yes'"),
            ("nxc smb",          "nxc smb {target} -u '' -p ''"),
            ("nmap smb scripts", "nmap -Pn -p {port} --script smb-os-discovery,smb-enum-shares {target}"),
        ],
    },
    "rdp": {
        "hint": "RDP service. Test reachability + NLA support.",
        "commands": [
            ("xfreerdp test",    "xfreerdp {rdp_flags} /v:{target}:{port}"),
            ("nmap rdp scripts", "nmap -Pn -p {port} --script rdp-enum-encryption,rdp-ntlm-info {target}"),
            ("rdesktop",         "rdesktop -u '' {target}:{port}"),
        ],
    },
    "mysql": {
        "hint": "MySQL / MariaDB. Try anonymous + version probe.",
        "commands": [
            ("mysql client",     "mysql -h {target} -P {port} -u root --skip-ssl"),
            ("nmap mysql",       "nmap -Pn -p {port} --script mysql-info,mysql-empty-password {target}"),
            ("netcat banner",    "nc -nv {target} {port}"),
        ],
    },
    "postgresql": {
        "hint": "PostgreSQL. Try default creds + version probe.",
        "commands": [
            ("psql client",      "psql -h {target} -p {port} -U postgres"),
            ("nmap pgsql",       "nmap -Pn -p {port} --script pgsql-brute {target}"),
            ("netcat banner",    "nc -nv {target} {port}"),
        ],
    },
    "mssql": {
        "hint": "Microsoft SQL Server. Probe instance + try sa.",
        "commands": [
            ("nmap mssql info",  "nmap -Pn -p {port} --script ms-sql-info,ms-sql-empty-password {target}"),
            ("impacket mssql",   "impacket-mssqlclient -p {port} {target}"),
            ("netcat banner",    "nc -nv {target} {port}"),
        ],
    },
    "ldap": {
        "hint": "LDAP / Active Directory. Anonymous bind + base DN probe.",
        "commands": [
            ("ldapsearch anon",  "ldapsearch -x -H ldap://{target}:{port} -s base namingcontexts"),
            ("nmap ldap",        "nmap -Pn -p {port} --script ldap-rootdse,ldap-search {target}"),
            ("nxc ldap",         "nxc ldap {target} -u '' -p ''"),
        ],
    },
    "redis": {
        "hint": "Redis. Often unauthenticated — try INFO directly.",
        "commands": [
            ("redis-cli info",   "redis-cli -h {target} -p {port} info"),
            ("nmap redis-info",  "nmap -Pn -p {port} --script redis-info {target}"),
            ("netcat banner",    "nc -nv {target} {port}"),
        ],
    },
    "vnc": {
        "hint": "VNC. Probe auth scheme + try no-auth.",
        "commands": [
            ("nmap vnc-info",    "nmap -Pn -p {port} --script vnc-info,realvnc-auth-bypass {target}"),
            ("vncviewer",        "vncviewer {target}:{port}"),
            ("netcat banner",    "nc -nv {target} {port}"),
        ],
    },
    "smtp": {
        "hint": "SMTP. Banner + VRFY/EXPN user enumeration.",
        "commands": [
            ("netcat banner",    "nc -nv {target} {port}"),
            ("nmap smtp",        "nmap -Pn -p {port} --script smtp-commands,smtp-enum-users {target}"),
            ("smtp-user-enum",   "smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t {target} -p {port}"),
        ],
    },
    "telnet": {
        "hint": "Telnet. Cleartext — banner-grab + try login.",
        "commands": [
            ("netcat banner",    "nc -nv {target} {port}"),
            ("telnet client",    "telnet {target} {port}"),
            ("nmap telnet",      "nmap -Pn -p {port} --script telnet-encryption,telnet-ntlm-info {target}"),
        ],
    },
    "winrm": {
        "hint": "Windows Remote Management. HTTP-based, try evil-winrm.",
        "commands": [
            ("nxc winrm",        "nxc winrm {target} -u '' -p ''"),
            ("evil-winrm",       "evil-winrm -i {target} -P {port} -u USER -p PASS"),
            ("curl wsman",       "curl -k -v http://{target}:{port}/wsman"),
        ],
    },
    "unknown": {
        "hint": "Unknown service — probe with netcat first to identify the protocol.",
        "commands": [
            ("netcat banner",    "nc -nv {target} {port}"),
            ("nmap version",     "nmap -Pn -sV -p {port} --version-intensity 9 {target}"),
            ("amap fingerprint", "amap -bqv {target} {port}"),
        ],
    },
}


def _get_service_info(service: str) -> dict:
    """
    Resolve a service name (nmap-style, possibly 'https-alt', 'ms-wbt-server',
    'microsoft-ds', etc.) to the right SERVICE_VERIFY_COMMANDS entry.

    IMPORTANT: must use EXACT + prefix match, NEVER substring match.
    Old behaviour did `if key in low` which matched e.g. "http" inside "https"
    and always returned HTTP info for HTTPS / any string containing "http".
    That was the "HTTP always set even when user picks another service" bug.
    """
    if not service:
        return SERVICE_VERIFY_COMMANDS["unknown"]
    low = service.lower().strip().split("/")[0].split("-")[0]

    # Common nmap aliases → canonical keys
    ALIASES = {
        "www":          "http",
        "http-proxy":   "http",
        "http-alt":     "http",
        "ssl":          "https",
        "microsoft":    "smb",        # microsoft-ds
        "netbios":      "smb",
        "wsman":        "winrm",
        "ms":           "mssql",      # ms-wbt-server handled below; keep narrow
        "mariadb":      "mysql",
        "ldap":         "smb",        # LDAP tooling overlaps with smb enumeration
    }
    if low in ALIASES:
        return SERVICE_VERIFY_COMMANDS[ALIASES[low]]

    # Exact match wins first (handles "https" before falling back to "http")
    if low in SERVICE_VERIFY_COMMANDS:
        return SERVICE_VERIFY_COMMANDS[low]

    # Prefix match — only if the service string STARTS WITH a known key.
    # Check longer keys first so "https" is preferred over "http".
    for key in sorted(SERVICE_VERIFY_COMMANDS.keys(), key=len, reverse=True):
        if low.startswith(key):
            return SERVICE_VERIFY_COMMANDS[key]

    return SERVICE_VERIFY_COMMANDS["unknown"]


__all__ = [
    "os", "re", "ctk", "COLORS", "NMAP_SCAN_TYPES", "NMAP_TIMING",
    "NMAP_EVASION", "NMAP_PORT_SCOPES", "NMAP_EXTRA_FLAGS",
    "WAF_EVASION_OPTIONS",
    "WORDLISTS", "WORDLIST_PATHS_USERS", "WORDLIST_PATHS_PASS",
    "HASH_MODES", "GREENBONE_INSTALL_STEPS", "SZ", "add_context_menu",
    "_f", "_center_window", "_autosize_window", "_make_win", "_title",
    "_sub", "_note_box", "_lane_banner", "_selectable_text",
    "_recommended", "_divider",
    "_btn_row", "_btn", "_safe_destroy", "_get_service_info",
    "SERVICE_VERIFY_COMMANDS",
]
