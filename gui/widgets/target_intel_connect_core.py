# HAWK — Hostile Assessment WorKit
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
import tkinter as tk
import os
import re
import time
import threading
import subprocess
import shlex
import json
import socket
import tempfile
import shutil
from datetime import datetime

from gui.widgets.target_intel_common import *

class TargetIntelConnectCoreMixin:
    def _canonical_service(self, port: int, proto: str, svc: str,
                           banner: str = "") -> str:
        """Return canonical service name for well-known 'disguised' ports.

        Decision order (banner first, port as fallback):
          1. If the banner clearly names a real web server (Apache/IIS/…)
             keep what nmap said — do NOT force WinRM.
          2. If the banner clearly names WinRM → WinRM.
          3. If the banner is silent/ambiguous AND the port is IANA-assigned
             to WinRM (5985/5986), assume WinRM — note the assumption.
          4. 593 and 135 with HTTP-ish label become http-rpc-epmap / msrpc.
        """
        s = (svc or "").lower().strip()
        p = int(port) if str(port).isdigit() else 0
        b = (banner or "").lower()

        # ── 5985/5986: WinRM vs real web server ──────────────────────────
        if p in (5985, 5986):
            # Real web server banner → trust it
            if any(t in b for t in self._WEB_SERVER_TOKENS):
                return svc
            # Explicit WinRM signal in banner
            if any(t in b for t in self._WINRM_TOKENS):
                return "winrm"
            # Ambiguous: port is IANA-reserved for WinRM, use as heuristic
            # only when nmap's label is http-ish or empty.
            if s in self._HTTPISH or s == "":
                return "winrm"
            return svc

        # ── 593: RPC-over-HTTP endpoint mapper ───────────────────────────
        if p == 593 and s in self._HTTPISH:
            return "http-rpc-epmap"

        # ── 135: Microsoft RPC endpoint mapper ───────────────────────────
        if p == 135 and s in self._HTTPISH:
            return "msrpc"

        return svc

    def _is_real_http(self, svc: str, port: int) -> bool:
        """True only when the service is a genuinely browsable HTTP/HTTPS
        endpoint — used to gate gobuster/ffuf/nikto/wafw00f so they don't
        attack WinRM, RPC-over-HTTP, or other HTTP-ish-but-not-web ports."""
        s = (svc or "").lower().strip()
        p = int(port) if str(port).isdigit() else 0
        # Exclude canonical non-web services even if they slip through
        if s in ("winrm", "http-rpc-epmap", "msrpc"):
            return False
        if p in (5985, 5986, 593, 135):
            return False
        # Accept well-known web ports or explicit http/https service tags
        if s in ("http", "https", "http-proxy", "http-alt", "ssl/http"):
            return True
        if p in (80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 8090):
            return True
        return False

    def _terminal_cmd_for(self, svc: str, port: int) -> str:
        """Return the connect-command template for this service, or ''.
        Falls back to well-known port when svc is 'unknown'.
        Resolves xfreerdp → xfreerdp3/2 dynamically.  The {compat}
        placeholder is left intact — callers (e.g. _refresh_preview) are
        expected to substitute it at render time via _apply_compat()."""
        key = (svc or "").lower().split("?")[0].strip()
        if key in self._CONNECT_CMDS:
            tpl = self._CONNECT_CMDS[key]
        else:
            # Port-based fallback for unknown services
            port_map = {22: "ssh", 21: "ftp", 23: "telnet", 25: "smtp",
                        80: "http", 443: "https", 445: "smb", 139: "smb",
                        3306: "mysql", 5432: "postgresql",
                        1433: "mssql", 3389: "rdp", 5985: "winrm", 5986: "winrm",
                        5900: "vnc", 6379: "redis", 27017: "mongodb"}
            alt = port_map.get(port)
            tpl = self._CONNECT_CMDS.get(alt, "") if alt else ""
        # Resolve xfreerdp → installed version + version-aware flags.
        # RDP has its own compat flag pipeline (_rdp_compat_flags already
        # handles legacy TLS levels), so we don't route it through
        # {compat} — keeps the two systems independent.
        if tpl and "xfreerdp" in tpl:
            from modules.base import _resolve_freerdp, _rdp_compat_flags
            tpl = tpl.replace("xfreerdp", _resolve_freerdp(), 1)
            tpl = tpl.replace("{rdp_flags}", _rdp_compat_flags())
        return tpl

    def _current_generation(self, port: int = None) -> str:
        """Return "modern" | "legacy" | "unknown" for the current target.

        When `port` is provided, per-port overrides (_per_port_overrides)
        take precedence over the target-wide classification — this lets
        the user force legacy on just port 3306 without affecting port
        445.  With no port argument, falls back to target-wide."""
        fp = self._get_fingerprint()
        if not fp:
            return "unknown"
        try:
            if port is not None and hasattr(fp, "classify_generation_for_port"):
                return fp.classify_generation_for_port(port)
            return fp.classify_generation()
        except Exception:
            return getattr(fp, "target_generation", "unknown") or "unknown"

    def _get_fingerprint(self):
        """Resolve the current OSFingerprint.  The widget keeps the live
        fingerprint on self._fp (merged across scans); returns None when
        no fingerprint exists yet (e.g. before any scan ran)."""
        return getattr(self, "_fp", None)

    def _compat_flags_for(self, svc: str, generation: str = None,
                           port: int = None) -> str:
        """Return the protocol-specific compat-flag string for this service.

        generation="modern"  → always returns "" (clean commands)
        generation="legacy"  → returns the full compat string
        generation="unknown" → returns the compat string (safe default:
                                                pentest posture = make
                                                it work, extra flags
                                                are harmless on modern
                                                servers)
        Services without a compat entry return "" regardless.

        When `port` is given and `generation` is None, the port-scoped
        classification is used (respects per-port overrides)."""
        if generation is None:
            generation = self._current_generation(port)
        if generation == "modern":
            return ""
        key = (svc or "").lower().split("?")[0].strip()
        key = self._COMPAT_ALIASES.get(key, key)
        return self._COMPAT_FLAGS.get(key, "")

    def _apply_compat(self, tpl: str, svc: str, host: str = "",
                       generation: str = None, port: int = None) -> str:
        """Substitute {compat} in a command template.  {host} inside the
        compat string itself (e.g. SMB's "-I {host}") is also expanded
        if a host value is supplied.

        `port` is forwarded to _compat_flags_for so per-port overrides
        are honored when `generation` isn't explicitly passed."""
        if not tpl or "{compat}" not in tpl:
            return tpl
        flags = self._compat_flags_for(svc, generation, port)
        if host:
            flags = flags.replace("{host}", host)
        # Collapse "  " → " " left over from an empty {compat} expansion.
        out = tpl.replace("{compat}", flags)
        import re as _re
        out = _re.sub(r"\s{2,}", " ", out).strip()
        return out

    def _pick_best_cred(self, svc: str, port: int):
        """Return the most appropriate Credential for the given service, or
        None. Preference order:
         1. A credential whose services list names this service (cleartext first).
         2. A cleartext credential (any service).
         3. A hash credential (any service).
         Returns None if the store is empty.

        Anonymous/guest/null-username credentials are REJECTED for
        services whose protocol rejects anonymous auth — see
        _NO_ANON_CONNECT_SERVICES.  This prevents the Connect dialog
        from pre-filling RDP/WinRM/MSSQL with anonymous:anonymous just
        because the store has an FTP anonymous cred.
        """
        try:
            sess = self.app.session_manager.current
            if not sess:
                return None
            creds = sess.get_credentials() or []
        except Exception:
            return None
        if not creds:
            return None

        svc_low = (svc or "").lower().split("?")[0].strip()
        # Pre-filter anonymous creds out when the service rejects them.
        if svc_low in self._NO_ANON_CONNECT_SERVICES:
            creds = [c for c in creds
                     if (c.username or "").strip().lower()
                         not in self._ANON_USERNAMES]
            if not creds:
                return None

        # Pass 1: service-match, cleartext
        for c in creds:
            if c.cred_type == "cleartext" and c.password and \
               any(svc_low in s.lower() for s in (c.services or [])):
                return c
        # Pass 2: any cleartext with password
        for c in creds:
            if c.cred_type == "cleartext" and c.password:
                return c
        # Pass 3: service-match, hash
        for c in creds:
            if c.cred_type == "hash" and c.hash_val and \
               any(svc_low in s.lower() for s in (c.services or [])):
                return c
        # Pass 4: any hash cred
        for c in creds:
            if c.cred_type == "hash" and c.hash_val:
                return c
        return None

    def _resolve_service(self, svc: str, port: int) -> str:
        """Map a (service-name, port) pair to a canonical HAWK service key.

        Resolution order (first match wins):
          1.  ``svc`` is an exact key in ``_SERVICE_PROFILES``.
          2.  ``svc`` is an exact key in ``_PROFILE_ALIASES``.
          3.  ``svc`` contains a substring listed in ``_SVC_SUBSTRING_RULES``.
          4.  ``port`` is in ``_PORT_SERVICE_MAP`` (extended port table).
          5.  Return ``svc`` unchanged — caller decides what to do.

        Examples
        --------
        >>> self._resolve_service("vsftpd 2.3.4", 21)      → "ftp"
        >>> self._resolve_service("ccproxy-ftp", 2121)     → "ftp"
        >>> self._resolve_service("OpenSSH 7.6p1", 22222)  → "ssh"
        >>> self._resolve_service("tcpwrapped", 2121)      → "ftp"  (port fallback)
        >>> self._resolve_service("unknown", 8080)         → "http" (port fallback)
        >>> self._resolve_service("unknown", 9999)         → "unknown"
        """
        s = (svc or "").lower().split("?")[0].strip()

        # 1. Exact profile match
        if s in self._SERVICE_PROFILES:
            return s
        # 2. Exact alias
        if s in self._PROFILE_ALIASES:
            return self._PROFILE_ALIASES[s]
        # 3. Substring match (ordered)
        for needle, canon in self._SVC_SUBSTRING_RULES:
            if needle in s:
                return canon
        # 4. Port-based fallback
        if port in self._PORT_SERVICE_MAP:
            return self._PORT_SERVICE_MAP[port]
        # 5. Unknown — return as-is
        return s

    def _get_profile(self, svc_key: str):
        """Resolve a service key to its profile (with alias lookup)."""
        if svc_key in self._SERVICE_PROFILES:
            return self._SERVICE_PROFILES[svc_key]
        aliased = self._PROFILE_ALIASES.get(svc_key)
        if aliased and aliased in self._SERVICE_PROFILES:
            return self._SERVICE_PROFILES[aliased]
        return None

    def _canonical_profile_key(self, svc_key: str) -> str:
        """Collapse aliases AND substring matches into the profile's
        canonical key.  Used by the captured-action dispatcher and by
        _action_is_captured() — any new substring rule added to
        _SVC_SUBSTRING_RULES is automatically honoured here.
        """
        s = (svc_key or "").lower().split("?")[0].strip()
        if s in self._SERVICE_PROFILES:
            return s
        if s in self._PROFILE_ALIASES:
            return self._PROFILE_ALIASES[s]
        for needle, canon in self._SVC_SUBSTRING_RULES:
            if needle in s:
                return canon
        return s

    def _build_brute_actions(self, svc_key: str) -> list:
        """Return synthesized brute / brute_creds action dicts for the
        given service, or [] when no preset is registered.  Used by
        ``_show_connect_dialog`` to extend the static profile actions
        list with brute force options.

        For password-only protocols (VNC, Redis) only the ``brute``
        action is generated — the ``brute_creds`` action requires a
        username field that the protocol doesn't have.
        """
        canon = self._canonical_profile_key(svc_key)
        preset = self._BRUTE_PRESETS.get(canon)
        if not preset:
            return []

        proto      = preset["proto"]
        tool       = preset.get("tool", "Hydra")
        pwd_only   = preset.get("password_only", False)
        needs_path = preset.get("needs_path", False)

        out = []

        # ── Native-client connect ────────────────────────────────────────
        # Emit FIRST when the preset defines `native_creds_tpl` so the
        # user sees a real "open a client session with these creds" option
        # at the top of the dropdown.  This replaces the old "Login with
        # known credentials" which was actually `hydra -t 1` and gave the
        # user a one-shot validation, not an interactive session — the
        # label was misleading.  We now expose BOTH:
        #   - Connect with known credentials → native client (mysql>, etc.)
        #   - Validate credentials (Hydra)   → hydra -t 1 quick yes/no
        # Manual cred input is supported by picking 'Type credentials
        # manually' from the cred picker above the action list — the
        # user/pass fields then accept whatever the user types.
        native_tpl = preset.get("native_creds_tpl")
        if native_tpl:
            out.append({
                "id":    "connect_creds",
                "label": "Connect with known credentials",
                "what": (
                    "Logs in via the native client and drops you at the "
                    "service's own interactive prompt (mysql>, postgres=#, "
                    "redis-cli>, mongosh>, …).  This is a normal client "
                    "connection — no hydra, no brute, just the credentials "
                    "you supply.  Pick a credential from the store above, "
                    "or choose 'Type credentials manually' to enter your own."
                ),
                "tpl":   native_tpl,
                "mode":  "auth",
                "needs": [],
            })

        if tool == "netexec":
            # netexec is the canonical brute tool for protocols where
            # hydra's module is unreliable or absent: WinRM (no hydra
            # module at all) and SMB (hydra's smb module only speaks
            # SMBv1 — on SMB2/3 it dies with "[ERROR] invalid reply
            # from target" before sending the first creds).  `proto`
            # comes from the preset and selects the right nxc backend
            # ("smb", "winrm", ...).
            out.append({
                "id":    "brute",
                "label": f"Brute force (netexec {proto})",
                "what": (
                    "Tries username/password combinations from wordlists "
                    "via netexec.  Note: on Windows AD this may LOCK OUT "
                    "accounts after 3-5 fails — the lockout-warning popup "
                    "lets you switch to a safer strategy (password spray "
                    "or kerbrute) before the brute starts."
                ),
                "tpl": (f"netexec {proto} {{host}} -u {{users_wl}} "
                        f"-p {{pass_wl}} --continue-on-success"),
                "mode": "anon",
                "needs": ["users_wl", "pass_wl"],
            })
            out.append({
                "id":    "brute_creds",
                "label": f"Validate credentials (netexec {proto})",
                "what": (f"Single user/pass yes/no check via "
                         f"`netexec {proto}`.  For an actual interactive "
                         f"session, use the service profile's "
                         f"'Interactive shell' / 'Connect' actions."),
                "tpl": (f"netexec {proto} {{host}} -u {{user}} "
                        f"-p '{{pass}}'"),
                "mode": "auth",
                "needs": [],
            })
            # SMB-specific: surface Hydra-smb as an explicit legacy
            # fallback so operators who really need it (e.g. very old
            # SMB1-only targets) can still find it, while the default
            # action stays on netexec.  Label flags the SMB1-only
            # limitation so nobody falls into the "invalid reply"
            # trap by accident.
            if proto == "smb":
                out.append({
                    "id":    "brute_legacy_hydra",
                    "label": "Brute force (Hydra smb — LEGACY, SMB1 only)",
                    "what": (
                        "Hydra's smb module only speaks SMBv1.  On "
                        "SMB2/3 targets (Win Server 2008 R2+, modern "
                        "Samba) it dies with `[ERROR] invalid reply "
                        "from target` before sending the first credential. "
                        "Use only when you know the target is SMBv1-only "
                        "(very old XP / 2003 hosts).  Prefer the "
                        "`Brute force (netexec smb)` action above for "
                        "everything else."
                    ),
                    "tpl": (f"hydra -L {{users_wl}} -P {{pass_wl}} "
                            f"-s {{port}} -t 4 -f {{host}} smb"),
                    "mode":  "anon",
                    "needs": ["users_wl", "pass_wl"],
                })
            return out

        # Hydra path (most services).
        if pwd_only:
            # VNC / Redis — password only, hydra wants -P without -L
            tpl = (f"hydra -P {{pass_wl}} -s {{port}} -t 4 -f "
                   f"{{host}} {proto}")
            out.append({
                "id":    "brute",
                "label": f"Brute force ({tool}) — password wordlist",
                "what": (
                    f"Tries each password in the wordlist against {proto.upper()}.  "
                    f"This protocol does not have user-side auth — only a "
                    f"shared password.  Edit the wordlist path to use a "
                    f"different list."
                ),
                "tpl":   tpl,
                "mode":  "anon",
                "needs": ["pass_wl"],
            })
            return out

        # ── Hydra command building ──────────────────────────────────────
        # Hydra supports two syntaxes:
        #   1. Positional:  hydra [opts] HOST -s PORT PROTO [PATH]
        #   2. URL form:    hydra [opts] PROTO://HOST:PORT[/PATH]
        # For HTTP/HTTPS modules we MUST use the URL form (or pass the
        # path as a separate trailing arg) — older HAWK templates were
        # concatenating the path to the host token (`host{path}`), which
        # produced URLs like `192.168.176.138//` (double slash, since
        # the default path is "/") and made hydra reject the syntax with
        # rc=255.  URL form is the cleanest and safest across hydra 8/9.
        if needs_path:
            brute_tpl = (
                f"hydra -L {{users_wl}} -P {{pass_wl}} -t 4 -f "
                f"{proto}://{{host}}:{{port}}{{path}}")
            creds_tpl = (
                f"hydra -l {{user}} -p '{{pass}}' -t 1 "
                f"{proto}://{{host}}:{{port}}{{path}}")
        else:
            brute_tpl = (
                f"hydra -L {{users_wl}} -P {{pass_wl}} -s {{port}} "
                f"-t 4 -f {{host}} {proto}")
            creds_tpl = (
                f"hydra -l {{user}} -p '{{pass}}' -s {{port}} -t 1 "
                f"{{host}} {proto}")

        out.append({
            "id":    "brute",
            "label": f"Brute force ({tool})",
            "what": (
                f"Tries username/password combinations from wordlists via "
                f"hydra {proto}.  Edit the wordlist paths below.  "
                + ("Lockout warning will appear before launch on AD-attached "
                   "services to let you choose a safer strategy."
                   if preset.get("lockout_aware") else "")
            ),
            "tpl":   brute_tpl,
            "mode":  "anon",
            "needs": (["users_wl", "pass_wl", "path"] if needs_path
                      else ["users_wl", "pass_wl"]),
        })
        out.append({
            "id":    "brute_creds",
            "label": f"Validate credentials ({tool})",
            "what": (
                f"Single user/pass yes/no check via {tool} -t 1.  Useful "
                f"as a quick sanity verification on a stolen credential "
                f"without running a full brute.  Does NOT drop you at the "
                f"service's interactive prompt — for that, pick 'Connect "
                f"with known credentials' (when available) or use the "
                f"profile's static connect actions."
            ),
            "tpl":   creds_tpl,
            "mode":  "auth",
            "needs": (["path"] if needs_path else []),
        })

        # ── SSH-specific: ncrack alternative for legacy targets ─────────
        # Hydra 9.x uses libssh 0.10+ which refuses to negotiate the
        # legacy MAC/KEX/cipher algorithms that old SSH servers (Cisco,
        # Metasploitable, embedded boxes) only support — every brute
        # exits in <1s with `kex error: no match for method mac algo`.
        # Ncrack uses its own SSH implementation that's permissive
        # about legacy algos, so we expose it as a parallel action.
        # Both action_ids start with "brute" → BG bar routing applies.
        if canon == "ssh":
            out.append({
                "id":    "brute_ncrack",
                "label": "Brute force (Ncrack — works on legacy SSH)",
                "what": (
                    "Same as Hydra brute but uses ncrack, whose SSH "
                    "implementation accepts legacy MAC/KEX/cipher "
                    "algorithms (hmac-md5, hmac-sha1, "
                    "diffie-hellman-group1-sha1, aes128-cbc, etc.).  "
                    "USE THIS when Hydra fails on Metasploitable / Cisco "
                    "/ old IoT SSH servers with `kex error: no match for "
                    "method mac algo`."
                ),
                "tpl": (f"ncrack -p {{port}} -U {{users_wl}} "
                        f"-P {{pass_wl}} -T4 ssh://{{host}}"),
                "mode":  "anon",
                "needs": ["users_wl", "pass_wl"],
            })
            out.append({
                "id":    "brute_creds_ncrack",
                "label": "Validate credentials (Ncrack — legacy SSH)",
                "what": (
                    "Single user/pass yes/no check via ncrack.  Use when "
                    "Hydra rejects the target's legacy SSH algorithms.  "
                    "For an actual interactive session pick 'Password "
                    "authentication' or 'Non-interactive password "
                    "(sshpass)' from the SSH profile actions above."
                ),
                "tpl": (f"ncrack -p {{port}} --user {{user}} "
                        f"--pass '{{pass}}' ssh://{{host}}"),
                "mode":  "auth",
                "needs": [],
            })

        return out

    def _build_brute_extras(self, svc_key: str) -> dict:
        """Return additional ``extras`` entries (user/pass wordlist input
        fields) needed by the brute actions of this service.  Merged into
        the static profile extras at dialog-open time so the user can
        edit the wordlist paths."""
        canon = self._canonical_profile_key(svc_key)
        preset = self._BRUTE_PRESETS.get(canon)
        if not preset:
            return {}
        out = {}
        if not preset.get("password_only", False):
            out["users_wl"] = {
                "label":   "Users wordlist",
                "default": preset.get("users_wl", ""),
                "hint":    "Path to a username wordlist (one user per line)",
            }
        out["pass_wl"] = {
            "label":   "Passwords wordlist",
            "default": preset.get("pass_wl", ""),
            "hint":    "Path to a password wordlist (one password per line)",
        }
        return out

    def _action_is_captured(self, svc_key: str, action_id: str) -> bool:
        """True if this (service, action) should be run inside HAWK and
        parsed, False if it needs an interactive xterm."""
        key = self._canonical_profile_key(svc_key)
        return action_id in self._CAPTURE_ACTIONS.get(key, set())

    def _connect_in_terminal(self, port: int, svc: str):
        """Open the CONNECT dialog — choose mode (anonymous / from cred
        store / manual) before launching the terminal, so we don't fire
        off a doomed command with bogus defaults."""
        target = self.app.get_target()
        if not target:
            self.app.terminal.write("  [!] No target set.", "error")
            return

        # Unified resolver — handles exact/alias/substring/port fallback
        # so that ProFTPD on 2121, OpenSSH on 2222, custom HTTPS on 9443,
        # etc. all map to the right canonical key.
        svc_key = self._resolve_service(svc, port)

        if not self._terminal_cmd_for(svc_key, port):
            self.app.terminal.write(
                f"  [!] No connect command known for {svc} on port {port}.",
                "warn")
            return

        # Gather applicable credentials from the store.  SERVICES THAT
        # REJECT ANONYMOUS AUTH BY PROTOCOL (RDP, WinRM, MSSQL, VNC,
        # mysql/postgres with auth modes) should NOT have the Connect
        # dialog auto-fill their auth fields with anonymous/guest/null
        # creds — it's misleading (will always fail LOGON_FAILURE) and
        # wastes a click.  We silently drop those creds from the list
        # the Connect dialog sees on those services; the user can still
        # select them manually from the Credential Store panel if they
        # really want to try.
        sess = self.app.session_manager.current
        creds = []
        try:
            if sess:
                creds = sess.get_credentials() or []
        except Exception:
            creds = []

        # Filter anonymous creds for services that reject anonymous
        # auth (uses the shared class constants so the rule stays in
        # one place — see _NO_ANON_CONNECT_SERVICES docstring).
        svc_norm = (svc_key or "").lower().split("?")[0].strip()
        if svc_norm in self._NO_ANON_CONNECT_SERVICES:
            creds = [c for c in creds
                     if (c.username or "").strip().lower()
                         not in self._ANON_USERNAMES]

        self._show_connect_dialog(target, port, svc, svc_key, creds)

    def _save_connect_creds_on_launch(self, *_args, **_kwargs) -> None:
        """Deprecated no-op.  Kept as a stub for any external caller.

        Save-on-launch was removed because the resulting "[unverified]"
        entries cluttered the Credential Store with guesses the user
        typed into the dialog — most of which never authenticated.
        Credentials are now added ONLY when a captured parser confirms
        login success (see ``_mark_creds_verified`` in
        ``target_intel_parsers.py``).
        """
        return

