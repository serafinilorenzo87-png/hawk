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
import tkinter as tk
import os
import re
import glob
import time
import subprocess
import threading
import shlex
import json
import zipfile
import tempfile
import shutil
import socket
import random
import string
import uuid
from datetime import datetime
from html import unescape as _html_unescape
from pathlib import Path

from utils.runner import ToolRunner, MultiRunner, MetasploitRunner, GreenBoneRunner
from utils.session import Credential
from gui.widgets.card_common import *


def parse_html_forms(html: str, base_url: str) -> list:
    """Extract {action, method, fields, has_password, file_inputs}.

    The tag's attributes are read separately instead of positionally.
    The old pattern was

        <form\\b[^>]*action=[...][^>]*(?:method=[...])?[^>]*>

    where the greedy `[^>]*` after the action swallowed the rest of the
    tag and the OPTIONAL method group then matched empty.  `method` was
    therefore None for every form ever crawled, so all of them —
    including login POSTs — were recorded and reported as GET.  Forms
    with no action attribute were skipped entirely.

    An absent or empty action submits to the current URL (HTML spec),
    not to "/".
    """
    from urllib.parse import urljoin as _urljoin

    forms = []
    for form_m in re.finditer(
            r'<form\b([^>]*)>([\s\S]{0,2000}?)</form>', html, re.I):
        attrs = form_m.group(1)
        block = form_m.group(2)
        action_m = re.search(
            r'action=["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(
            r'method=["\']?([A-Za-z]+)', attrs, re.I)
        action = _urljoin(
            base_url, (action_m.group(1) if action_m else "") or "")
        method = (method_m.group(1) if method_m else "GET").upper()
        fields = re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\']', block, re.I)
        has_pwd = bool(re.search(
            r'type=["\']password["\']', block, re.I))
        # File upload detection — any input type=file makes this a
        # candidate for the upload-bypass test in Inject.
        file_inputs = re.findall(
            r'<input[^>]+type=["\']file["\'][^>]*name=["\']'
            r'([^"\']+)["\']', block, re.I) + re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]+'
            r'type=["\']file["\']', block, re.I)
        forms.append({
            "action": action, "method": method,
            "fields": fields[:10], "has_password": has_pwd,
            "file_inputs": file_inputs,
        })
    return forms


class CardOracleRoutesMixin:
    def _route_web_oracle(self, tool):
        """Open the URL-confirmation dialog and launch WebOracleRunner.

        The dialog pre-fills the URL from Target Intel's first HTTP/
        HTTPS service so a typical run is just two clicks.  User can
        override to point at a sub-path (e.g. `/admin/`) or a
        completely different URL.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.web_oracle import (WebOracleRunner,
                                       normalize_target_url,
                                       detect_available_binaries)

        # Pre-fill URL: explicit override (e.g. from target_intel's
        # ATTACK NEW VHOSTS button) wins; otherwise first HTTP/HTTPS
        # service on the target if known, else `http://<target>/`.
        # Prefer the session domain over the raw IP — Oracle's
        # whatweb/httpx/nuclei all hit different content via vhost
        # routing.
        target = self._get_target() or ""
        host_pref = target
        try:
            sess = self.app.session_manager.current
            if sess:
                d = (getattr(sess, "target_domain", "") or "").strip()
                if d and d != target:
                    host_pref = d
        except Exception:
            pass
        default_url = ""
        try:
            override = getattr(self, "_attack_url_override", "") or ""
            if override:
                default_url = override
                # Single-shot override — clear it so a later manual
                # open of the dialog doesn't keep prefilling stale data.
                self._attack_url_override = ""
        except Exception:
            pass
        fp = self._get_fp()
        if not default_url and fp:
            for p, _proto, svc, _ban in fp.open_ports:
                svc_low = (svc or "").lower()
                if "https" in svc_low or "ssl/http" in svc_low:
                    default_url = f"https://{host_pref}:{p}/"
                    break
                if "http" in svc_low and p not in (5985, 5986, 135, 593):
                    default_url = f"http://{host_pref}:{p}/"
                    break
        if not default_url and host_pref:
            default_url = f"http://{host_pref}/"

        win = _make_win(self, "Web Oracle — target URL", 700, 520)
        _title(win, "ORACLE — target URL")
        _sub(win,
             "Oracle profiles the target webapp and recommends the "
             "next attack steps.",
             COLORS["text_dim"])

        # Binary detection banner — tells the user what Oracle will
        # actually do with the tools available right now.
        bins = detect_available_binaries()
        present = [n for n in ("whatweb", "httpx", "nuclei",
                                "katana", "ffuf", "curl")
                   if bins.get(n)]
        missing = [n for n in ("whatweb", "httpx", "nuclei",
                                "katana", "ffuf")
                   if not bins.get(n)]
        _note_box(
            win,
            "Installed binaries Oracle will use:\n"
            f"  ✓  {', '.join(present) or '(none)'}\n"
            + (f"  ✗  missing (will skip): {', '.join(missing)}\n"
               if missing else "")
            + "\nMissing binaries only downgrade coverage — the scan "
              "still runs with whatever is available.",
            COLORS["border_dim"])

        url_var = ctk.StringVar(value=default_url)
        # Host dropdown above the URL field — auto-rewrites the hostname
        # on selection. Hidden when only the IP is available.
        from gui.widgets.card_common import attach_host_dropdown
        attach_host_dropdown(win, self.app, target, url_var)
        ctk.CTkLabel(win, text="URL:", font=_f("md", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=24, pady=(6, 2))
        entry = ctk.CTkEntry(
            win, textvariable=url_var, font=_f("md"), height=32,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3,
            placeholder_text="http://target/ or https://target:8443/admin/")
        entry.pack(fill="x", padx=24, pady=(0, 4))
        add_context_menu(entry)

        ctk.CTkLabel(
            win,
            text=("Typical runtime: 45-90 seconds.  All probes are "
                  "active — WAFs will see them.  Point at the app "
                  "root unless you want a sub-path focus "
                  "(e.g. /admin/, /api/v1/)."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=620, justify="left", anchor="w",
        ).pack(fill="x", padx=24, pady=(0, 8))

        def _launch():
            raw = url_var.get().strip()
            if not raw:
                self.app.terminal.write(
                    "[!] Web Oracle cancelled — URL is required.",
                    "warn")
                return
            url0 = normalize_target_url(raw)

            # DNS gate: if the URL hostname is a non-resolving FQDN,
            # offer to add it to /etc/hosts or fall back to the IP.
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url0)
            host_in_url = (parsed.hostname or "").strip()

            if host_in_url and target and host_in_url != target:
                from gui.widgets.card_common import verify_host_or_prompt

                def _proceed_with(final_host):
                    final_url = url0
                    if final_host != host_in_url:
                        netloc = (f"{final_host}:{parsed.port}"
                                  if parsed.port else final_host)
                        final_url = urlunparse(parsed._replace(
                            netloc=netloc))
                    _do_launch(final_url)

                verify_host_or_prompt(self, self.app, host_in_url,
                                      target, _proceed_with)
                return

            _do_launch(url0)

        def _do_launch(url):
            _safe_destroy(win)
            self._set_tool_status(tool.id, "running")
            self.set_status(STATUS_RUNNING)
            self.app.terminal.section(f"ORACLE  ·  {url}")
            # Record the run in executed_tools (dot restore on reload +
            # tool history); finish is applied by the _on_done below.
            self._record_tool_start(tool, f"web_oracle {url}")

            # Bind shared state to this target.  If the user changed
            # target since the last pipeline run, AssaultState wipes
            # the previous payloads.  set_step("oracle","running")
            # surfaces in the pipeline UI bar.
            state = getattr(self.app, "assault_state", None)
            if state is not None:
                if state.target_url != url:
                    state.bind_target(url)
                else:
                    state.reset_cancel()
                state.set_step("oracle", "running")

            def _done(name, rc, log, profile=None,
                       recommendations=None):
                # WebOracleRunner always passes 5 args; the fallback
                # path through KillChainCard's generic done is never
                # hit here because we inject our own callback.
                # Push results to AssaultState BEFORE _on_done so the
                # pipeline UI bar reflects the completed state when it
                # repaints on tool finish.
                if state is not None and profile:
                    try:
                        for t in profile.get("tech", []) or []:
                            name_t = (t.get("name") or "" if isinstance(t, dict) else str(t))
                            if name_t:
                                state.add_tech(name_t)
                        for ap in profile.get("api_endpoints", []) or []:
                            from utils.assault_state import ApiEndpoint
                            state.add_api_endpoint(ApiEndpoint(
                                url=ap.get("url", ""),
                                kind=ap.get("kind", "rest"),
                                method=ap.get("method", "GET"),
                                status=int(ap.get("status", 0) or 0),
                                title=ap.get("path", ""),
                                framework=ap.get("framework", ""),
                                notes=ap.get("content_type", "")))
                        for ex in profile.get("exposures", []) or []:
                            state.add_exposure(
                                ex.get("path") or ex.get("url", ""),
                                ex.get("severity", "info"),
                                ex.get("note", ""))
                        state.set_step(
                            "oracle",
                            "error" if state.is_cancelled() else "done")
                    except Exception as e:
                        self.app.terminal.write(
                            f"  [!] AssaultState push failed: {e}",
                            "warn")
                try:
                    self._on_done(tool, name, rc, log)
                except Exception:
                    pass
                # Show the post-scan dialog on the UI thread.
                if profile is not None:
                    self.app.after(
                        0,
                        lambda: self._show_web_oracle_result(
                            tool, profile, recommendations or []))

            runner = WebOracleRunner(
                output_callback=self.app.terminal.output_callback,
                done_callback=_done,
                ui_dispatcher=getattr(self.app, "ui_call", None))
            self._tool_runners[tool.id] = runner
            runner.run(url=url, tool_name=tool.name)

        row = _btn_row(win)
        _btn(row, "START ORACLE", _launch, primary=True, w=180)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _route_bloody_crawl(self, tool):
        """Config dialog + launch for Bloody Crawl."""
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy)
        from utils.clipboard import add_context_menu

        target = self._get_target() or ""
        host_pref = target
        try:
            sess = self.app.session_manager.current
            if sess:
                d = (getattr(sess, "target_domain", "") or "").strip()
                if d and d != target:
                    host_pref = d
        except Exception:
            pass
        # Explicit override (e.g. from target_intel ATTACK NEW VHOSTS)
        # wins over the fingerprint-based default.
        default_url = ""
        try:
            override = getattr(self, "_attack_url_override", "") or ""
            if override:
                default_url = override
                self._attack_url_override = ""
        except Exception:
            pass
        fp = self._get_fp()
        if not default_url and fp:
            for p, _proto, svc, _ban in fp.open_ports:
                svc_low = (svc or "").lower()
                if "https" in svc_low or "ssl/http" in svc_low:
                    default_url = f"https://{host_pref}:{p}/"
                    break
                if "http" in svc_low and p not in (5985, 5986, 135, 593):
                    default_url = f"http://{host_pref}:{p}/"
                    break
        if not default_url and host_pref:
            default_url = f"http://{host_pref}/"

        win = _make_win(self, "Bloody Crawl — target URL", 720, 560)
        _title(win, "BLOODY CRAWL — Smart Endpoint Extractor")
        _sub(win,
             "Extracts real endpoints from HTML, probes each one, "
             "follows redirects, detects IDOR patterns.",
             COLORS["text_dim"])

        _note_box(
            win,
            "Unlike gobuster/ffuf, Bloody Crawl reads what the app "
            "actually exposes (links, forms, JS references) instead "
            "of guessing from a wordlist.\n\n"
            "Best workflow: Bloody Crawl first (visible surface), "
            "then gobuster (hidden paths).",
            COLORS["border_dim"])

        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=0, pady=(0, 4))

        # URL — host dropdown sits above and rewrites on change.
        url_var = ctk.StringVar(value=default_url)
        from gui.widgets.card_common import attach_host_dropdown
        attach_host_dropdown(body, self.app, target, url_var)
        ctk.CTkLabel(body, text="Target URL:", font=_f("md", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(fill="x", padx=24, pady=(6, 2))
        url_entry = ctk.CTkEntry(
            body, textvariable=url_var, font=_f("md"), height=32,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3,
            placeholder_text="http://target/ or https://target:8443/")
        url_entry.pack(fill="x", padx=24, pady=(0, 8))
        add_context_menu(url_entry)

        # Options row
        opts = ctk.CTkFrame(body, fg_color="transparent")
        opts.pack(fill="x", padx=24, pady=(4, 4))

        # Depth
        ctk.CTkLabel(opts, text="Crawl depth:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(side="left")
        depth_var = ctk.StringVar(value="2")
        ctk.CTkEntry(
            opts, textvariable=depth_var,
            font=_f("sm"), height=28, width=50,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3).pack(side="left", padx=(4, 16))

        # IDOR range
        ctk.CTkLabel(opts, text="IDOR range:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"],
                     anchor="w").pack(side="left")
        idor_var = ctk.StringVar(value="20")
        ctk.CTkEntry(
            opts, textvariable=idor_var,
            font=_f("sm"), height=28, width=50,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3).pack(side="left", padx=(4, 16))

        # Follow redirects
        follow_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts, text="Follow redirects",
            variable=follow_var,
            font=_f("sm"), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            width=16, height=16).pack(side="left")

        # Option hints — depth is clamped 1-5, and "IDOR range" is not
        # self-explanatory.
        ctk.CTkLabel(
            body,
            text=("Depth 1-5 (2 recommended; higher is much heavier on "
                  "link-rich sites).  IDOR range = max sequential ID "
                  "tested per numeric endpoint."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=660, justify="left", anchor="w",
        ).pack(fill="x", padx=24, pady=(2, 4))

        # JS extraction
        js_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            body, text="Extract endpoints from inline JavaScript "
                       "(fetch, axios, XMLHttpRequest, window.location)",
            variable=js_var,
            font=_f("sm"), text_color=COLORS["text_bright"],
            fg_color=COLORS["border_green"],
            border_color=COLORS["border_dim"],
            width=16, height=16).pack(anchor="w", padx=24, pady=(4, 8))

        ctk.CTkLabel(
            body,
            text=("Typical runtime: ~10-30s at depth 2. Higher depth or "
                  "link-heavy sites are much heavier; a global safety "
                  "budget (time / requests / endpoints) stops runaway "
                  "crawls automatically. All probes are active."),
            font=_f("xs"), text_color=COLORS["text_dim"],
            wraplength=660, justify="left", anchor="w",
        ).pack(fill="x", padx=24, pady=(0, 8))

        def _launch():
            raw = url_var.get().strip()
            if not raw:
                self.app.terminal.write(
                    "[!] Bloody Crawl cancelled — URL required.", "warn")
                return
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(raw)
            if not parsed.scheme:
                raw = "http://" + raw
                parsed = urlparse(raw)
            host_in_url = (parsed.hostname or "").strip()

            if host_in_url and target and host_in_url != target:
                from gui.widgets.card_common import verify_host_or_prompt

                def _proceed_with(final_host):
                    final_url = raw
                    if final_host != host_in_url:
                        netloc = (f"{final_host}:{parsed.port}"
                                  if parsed.port else final_host)
                        final_url = urlunparse(parsed._replace(
                            netloc=netloc))
                    _do_launch(final_url)

                verify_host_or_prompt(self, self.app, host_in_url,
                                      target, _proceed_with)
                return

            _do_launch(raw)

        def _do_launch(final_url):
            _safe_destroy(win)

            # Depth / IDOR range are free-text: parse defensively (a
            # non-numeric value must not crash the launch) and clamp to the
            # supported range, telling the operator when their value was
            # adjusted (e.g. depth 8 -> 5).
            def _clamped_int(raw, default, lo, hi, label):
                try:
                    val = int(str(raw).strip())
                except (TypeError, ValueError):
                    val = default
                clamped = max(lo, min(hi, val))
                if clamped != val:
                    self.app.terminal.write(
                        f"  [*] {label} {val} out of range — using "
                        f"{clamped} (allowed {lo}-{hi}).", "dim")
                return clamped

            depth = _clamped_int(depth_var.get() or "2", 2, 1, 5,
                                 "Crawl depth")
            idor_max = _clamped_int(idor_var.get() or "20", 20, 5, 100,
                                    "IDOR range")
            follow = follow_var.get()
            extract_js = js_var.get()

            self._set_tool_status(tool.id, "running")
            self.set_status(STATUS_RUNNING)
            self.app.terminal.section(f"BLOODY CRAWL  ·  {final_url}")
            # Record the run in executed_tools (dot restore on reload +
            # tool history); finish is applied by _on_done (worker/crash).
            self._record_tool_start(tool, f"bloody_crawl {final_url}")

            # Cooperative STOP: the worker runs in a thread and polls
            # assault_state.is_cancelled() every loop, so register a tiny
            # runner whose kill() flips that flag (and _kill_requested, for
            # _on_done's abort guard) and turn the tool-row RUN button into
            # STOP.  _on_done resets it when the worker winds down.
            class _CrawlStopHandle:
                def __init__(self, app):
                    self._app = app
                    self._kill_requested = False

                def kill(self):
                    self._kill_requested = True
                    st = getattr(self._app, "assault_state", None)
                    if st is not None:
                        st.cancel()
                    return True

            self._tool_runners[tool.id] = _CrawlStopHandle(self.app)
            self._toggle_run_btn(tool, True)

            # The worker has no top-level try/except — if it raises
            # (network blip, parser error, …) the thread dies silently
            # and the status icon stays "running" (yellow dot) forever.
            # Wrap it so we always reset the status and dispatch _on_done
            # even on crash.
            import threading, traceback
            def _wrapped():
                try:
                    self._bloody_crawl_worker(
                        tool, final_url, depth, idor_max, follow,
                        extract_js)
                except Exception as e:
                    tb = traceback.format_exc()
                    def _fail():
                        self.app.terminal.write(
                            f"  [!] Bloody Crawl crashed: {e}", "warn")
                        for ln in tb.splitlines()[-6:]:
                            self.app.terminal.write(f"    {ln}", "dim")
                        self._on_done(tool, tool.name, 1, [])
                    self.app.after(0, _fail)
            t = threading.Thread(target=_wrapped, daemon=True)
            t.start()

        row = _btn_row(win)
        _btn(row, "START CRAWL", _launch, primary=True, w=180)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    @staticmethod
    def _build_param_urls(start_url, params, good_paths=None):
        """Reconstruct ``base?param=value`` URLs from crawled GET query
        parameters, for the SQLMap picker.

        The SQLMap target picker (``_collect_sqlmap_candidates``) does not
        read AssaultState or discovered_web_paths — it text-scans Target
        Intel finding descriptions for ``https?://host:port/...?name=...``
        URLs whose host matches its own ``base_url`` (which always carries
        an explicit ``:port``).  So the URLs are emitted with a canonical
        ``host:port`` taken from the crawl start URL (adding the default
        port when the URL omits it), otherwise a default-port target would
        never match and SQLMap would silently see nothing.

        ``good_paths`` (optional) is the set of URL paths whose endpoint
        actually resolved to a usable status — when given, params on any
        other path (dead links: 404/400 TWiki placeholders and the like)
        are dropped so the picker is not flooded with unreachable targets.

        One URL per (path, set-of-parameter-names); a representative value
        per parameter (the sample seen during the crawl, sanitised of any
        character that would truncate the picker's URL regex, else ``1``).
        """
        from urllib.parse import urlparse, urlunparse
        sp = urlparse(start_url or "")
        scheme = sp.scheme or "http"
        host = sp.hostname or ""
        port = sp.port or (443 if scheme == "https" else 80)
        netloc = f"{host}:{port}" if host else ""

        groups = {}   # path -> {name: value}, first value wins
        order = []
        for p in params or []:
            if (getattr(p, "where", "query") or "query") != "query":
                continue
            if (getattr(p, "method", "GET") or "GET").upper() != "GET":
                continue
            name = (getattr(p, "name", "") or "").strip()
            if not name:
                continue
            path = urlparse(getattr(p, "url", "") or "").path or "/"
            if good_paths is not None and path not in good_paths:
                continue
            if path not in groups:
                groups[path] = {}
                order.append(path)
            if name not in groups[path]:
                val = re.sub(r"[\s'\"<>()]", "",
                             (getattr(p, "sample", "") or "").strip())
                groups[path][name] = val or "1"

        out, seen = [], set()
        for path in order:
            names = groups[path]
            if not names:
                continue
            key = (path, frozenset(names))
            if key in seen:
                continue
            seen.add(key)
            query = "&".join(f"{n}={v}" for n, v in names.items())
            out.append(urlunparse((scheme, netloc, path, "", query, "")))
        return out

    def _bloody_crawl_worker(self, tool, start_url, max_depth,
                              idor_max, follow_redirects, extract_js):
        """Background worker — fetches, parses, probes, recurses."""
        import re
        import subprocess
        import time
        from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl
        from utils.assault_state import (Param, UploadForm, JwtToken)

        terminal = self.app.terminal
        log = []
        t0 = time.time()
        req_count = [0]   # every curl request the crawl/IDOR phase makes

        # ── AssaultState binding ─────────────────────────────────────
        # First-class citizen now: rebind the shared state to the
        # current crawl target, mark the crawl step "running", and
        # reset cancellation.  All collected parameters/forms/JWTs
        # are pushed back into AssaultState so Inject and JWT can
        # auto-feed.
        state = getattr(self.app, "assault_state", None)
        if state is not None:
            # bind_target wipes prior data — only rebind if the user
            # actually changed target.  Otherwise we'd lose Oracle's
            # tech_stack from a previous step in the same pipeline.
            if state.target_url != start_url:
                state.bind_target(start_url)
            else:
                state.reset_cancel()
            state.set_step("crawl", "running")

        def _state_cancelled() -> bool:
            return state is not None and state.is_cancelled()

        # JWT detection regex — the standard 3-part base64url shape.
        # Matches what Crawl finds in Set-Cookie / Authorization /
        # response bodies.  Two segments minimum (header.payload),
        # optional signature for `alg:none` tokens.
        JWT_RE = re.compile(
            r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
            r'(?:\.[A-Za-z0-9_-]{0,512})?\b')

        def _harvest_jwts_from_headers(raw_response: str, seen_at_url: str):
            """Scan response headers (Set-Cookie, Authorization, X-Auth-*)
            for JWT-shaped strings and push them to AssaultState."""
            if state is None or not raw_response:
                return
            head, _sep, _body = raw_response.partition("\r\n\r\n")
            for line in head.splitlines():
                low = line.lower()
                if not (low.startswith("set-cookie:")
                        or low.startswith("authorization:")
                        or low.startswith("x-auth")):
                    continue
                for m in JWT_RE.finditer(line):
                    state.add_jwt(JwtToken(
                        token=m.group(0),
                        source=("cookie" if low.startswith("set-cookie:")
                                else "header"),
                        where=line.split(":", 1)[0].strip(),
                        seen_at=seen_at_url,
                    ))

        def _harvest_params_from_url(url: str, source: str = "crawl"):
            """Pull query-string parameters out of a URL and push each
            (url-without-query, param_name) into AssaultState as a GET
            query param.  POST body params are harvested separately
            from forms."""
            if state is None:
                return
            try:
                p = urlparse(url)
            except Exception:
                return
            if not p.query:
                return
            base = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
            for name, value in parse_qsl(p.query, keep_blank_values=True):
                if not name:
                    continue
                state.add_parameter(Param(
                    url=base, name=name, method="GET", where="query",
                    sample=value[:64], source=source))

        STATIC_EXT = {
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
            ".mp3", ".mp4", ".webm", ".webp", ".pdf",
        }

        def _write(msg, tag="dim"):
            terminal.write(f"  {msg}", tag)
            log.append((time.time(), msg))

        BINARY_TYPES = {
            "application/octet-stream", "application/pdf",
            "application/zip", "application/gzip",
            "application/x-tar", "application/x-bzip2",
            "application/x-7z-compressed", "application/x-rar",
            "application/vnd.tcpdump.pcap", "application/cap",
            "image/png", "image/jpeg", "image/gif", "image/webp",
            "image/svg+xml", "video/mp4", "video/webm",
            "audio/mpeg", "audio/ogg",
        }

        def _head_content_type(url, timeout=5):
            try:
                req_count[0] += 1
                r = subprocess.run(
                    ["curl", "-s", "-I", "--max-time", str(timeout), url],
                    capture_output=True, text=True, timeout=timeout + 3)
                for line in (r.stdout or "").splitlines():
                    if line.lower().startswith("content-type:"):
                        return line.split(":", 1)[1].strip().split(";")[0].strip().lower()
            except Exception:
                pass
            return ""

        def _fetch(url, timeout=10):
            ct = _head_content_type(url)
            if ct in BINARY_TYPES:
                _write(f"  ⊘ Skipping binary ({ct}): "
                       f"{urlparse(url).path}", "dim")
                return ""
            try:
                args = ["curl", "-s", "-D", "-",
                        "--max-time", str(timeout),
                        "--max-filesize", "524288", url]
                if follow_redirects:
                    args.insert(2, "-L")
                req_count[0] += 1
                r = subprocess.run(
                    args, capture_output=True, text=True,
                    timeout=timeout + 5)
                return r.stdout or ""
            except Exception:
                return ""

        def _probe(url, timeout=8):
            try:
                args = ["curl", "-s", "-o", "/dev/null",
                        "-w", "%{http_code}|%{redirect_url}|%{size_download}",
                        "--max-time", str(timeout)]
                args.append(url)
                req_count[0] += 1
                r = subprocess.run(
                    args, capture_output=True, text=True, timeout=timeout + 5)
                parts = (r.stdout or "").strip().split("|")
                if len(parts) >= 3:
                    return {
                        "status": int(parts[0]) if parts[0].isdigit() else 0,
                        "redirect": parts[1] or "",
                        "size": int(parts[2]) if parts[2].isdigit() else 0,
                    }
            except Exception:
                pass
            return {"status": 0, "redirect": "", "size": 0}

        def _follow_chain(url, max_hops=5):
            chain = [url]
            current = url
            for _ in range(max_hops):
                try:
                    req_count[0] += 1
                    r = subprocess.run(
                        ["curl", "-s", "-o", "/dev/null",
                         "-w", "%{http_code}|%{redirect_url}",
                         "--max-time", "5", current],
                        capture_output=True, text=True, timeout=10)
                    parts = (r.stdout or "").strip().split("|")
                    code = int(parts[0]) if parts[0].isdigit() else 0
                    redir = parts[1] if len(parts) > 1 else ""
                    if code in (301, 302, 303, 307, 308) and redir:
                        chain.append(redir)
                        current = redir
                    else:
                        break
                except Exception:
                    break
            return chain

        def _normalize(url):
            p = urlparse(url)
            netloc = p.hostname or ""
            port = p.port
            if port and not ((p.scheme == "http" and port == 80)
                             or (p.scheme == "https" and port == 443)):
                netloc = f"{netloc}:{port}"
            return urlunparse((p.scheme, netloc, p.path, "", "", ""))

        JS_EXT = {".js"}

        def _extract_endpoints(html, base_url):
            """Returns (endpoints, js_urls, param_full).

            endpoints are normalised (query-stripped); js_urls feed the JS
            secrets scanner; param_full are the same-host full URLs that
            carry a query string, kept so their GET params can be harvested
            (the endpoint set drops them)."""
            raw_refs = set()
            for pat in [
                r'href=["\']([^"\'#]+)["\']',
                r'action=["\']([^"\'#]+)["\']',
                r'src=["\']([^"\'#]+)["\']',
                r'data-url=["\']([^"\'#]+)["\']',
                r'data-href=["\']([^"\'#]+)["\']',
                r'data-src=["\']([^"\'#]+)["\']',
                r'content=["\'][^"\']*url=([^"\';\s]+)',
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.replace\(["\']([^"\']+)["\']\)',
                r'location\.assign\(["\']([^"\']+)["\']\)',
            ]:
                for m in re.finditer(pat, html, re.I):
                    raw_refs.add(m.group(1))

            if extract_js:
                for pat in [
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.\w+\(["\']([^"\']+)["\']',
                    r'\.get\(["\']([^"\']+)["\']',
                    r'\.post\(["\']([^"\']+)["\']',
                    r'\.put\(["\']([^"\']+)["\']',
                    r'\.delete\(["\']([^"\']+)["\']',
                    r'XMLHttpRequest[^;]*open\(["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                    r'endpoint:\s*["\']([^"\']+)["\']',
                    r'apiUrl:\s*["\']([^"\']+)["\']',
                    r'baseURL:\s*["\']([^"\']+)["\']',
                ]:
                    for m in re.finditer(pat, html, re.I):
                        raw_refs.add(m.group(1))

            resolved = set()
            js_urls = set()
            param_full = set()   # same-host full URLs that carry a query
            base_host = urlparse(base_url).hostname
            for ep in raw_refs:
                if ep.startswith(("javascript:", "mailto:", "tel:", "data:")):
                    continue
                # Decode HTML entities in the raw href/action (e.g. the
                # &amp; that separates query params) so the query parses
                # into real parameter names, not "amp;<name>".
                ep = _html_unescape(ep)
                full = urljoin(base_url, ep)
                fp = urlparse(full)
                if fp.hostname != base_host:
                    continue
                ext = fp.path.rsplit(".", 1)[-1].lower() if "." in fp.path else ""
                if f".{ext}" in JS_EXT:
                    js_urls.add(_normalize(full))
                    continue
                if f".{ext}" in STATIC_EXT:
                    continue
                # Keep the query-bearing full URL: _normalize() strips the
                # query for the endpoint set, so the GET params would be
                # lost for harvesting otherwise.
                if fp.query:
                    param_full.add(full)
                resolved.add(_normalize(full))
            return resolved, js_urls, param_full

        # A trailing number is not always an object id.  `/api/v2`
        # matches `^(.*?)(\d+)$` just as well as `/user/2` does, and
        # the whole API then got probed as an IDOR range.  Reject
        # prefixes whose last path token is a version marker.
        VERSION_PREFIX_RE = re.compile(r'(?i)(?:^|/)v(?:er|ersion)?$')

        def _detect_idor(endpoints):
            idor_candidates = []
            # The numeric id must be a WHOLE trailing path segment
            # (/users/123), not digits glued to a word.  Without the
            # leading `/` anchor, wiki/topic names that merely end in a
            # number (TestTopic0, TWikiUpgradeTo01Dec2000, Page2) were read
            # as "prefix + sequential id" and enumerated as bogus IDOR
            # candidates.  Real REST ids (/orders/42) stay a full segment
            # and are still detected.
            ID_RE = re.compile(r'^(.*/)(\d+)/?$')
            prefix_map = {}
            for ep in endpoints:
                path = urlparse(ep).path
                m = ID_RE.match(path)
                if m:
                    prefix = m.group(1)
                    if VERSION_PREFIX_RE.search(prefix.rstrip('/')):
                        continue
                    num = int(m.group(2))
                    prefix_map.setdefault(prefix, []).append((num, ep))
            for prefix, items in prefix_map.items():
                if len(items) >= 1:
                    idor_candidates.append({
                        "prefix": prefix,
                        "found_ids": sorted([n for n, _ in items]),
                        "sample_urls": [u for _, u in sorted(items)[:5]],
                    })
            return idor_candidates

        # ── Main crawl ──────────────────────────────────────────
        start_url = _normalize(start_url)
        _write(f"[*] Starting crawl from {start_url}", "info")

        all_endpoints = {}  # url → probe result
        all_js_urls = set()  # .js files for secrets scan
        visited = set()
        visited_html = {}   # url → html body (for inline JS scan)
        queue = [(start_url, 0)]  # (url, depth)
        redirect_chains = {}
        forms_found = []

        # Global safety budget.  max_depth + dedup alone do NOT bound the
        # work: a crawler-trap (calendars, pagination, near-infinite query
        # spaces) or a slow target lets the crawl grow as branching^depth
        # (times redirect/IDOR probes) into many minutes / tens of
        # thousands of requests.  Stop on ANY of: endpoints discovered,
        # total requests, or wall-clock seconds.  These are target-agnostic
        # ceilings a normal depth-2 crawl never reaches — they only fire on
        # runaway spaces; default depth stays 2.  Bounding requests is also
        # production hygiene: don't hammer the client's app or trip WAF/IDS.
        MAX_ENDPOINTS    = 1500
        MAX_REQUESTS     = 2500
        MAX_SECONDS      = 180
        MAX_IDOR_TARGETS = 8      # cap sequential-ID enumeration candidates
        _cap_hit = [False]

        def _time_or_req_exhausted():
            return (req_count[0] >= MAX_REQUESTS
                    or (time.time() - t0) >= MAX_SECONDS)

        def _over_budget():
            return (len(all_endpoints) >= MAX_ENDPOINTS
                    or _time_or_req_exhausted())

        def _cap_notice():
            if _cap_hit[0]:
                return
            _cap_hit[0] = True
            if req_count[0] >= MAX_REQUESTS:
                why = f"request budget ({MAX_REQUESTS} requests)"
            elif (time.time() - t0) >= MAX_SECONDS:
                why = f"time budget ({MAX_SECONDS}s)"
            else:
                why = f"endpoint cap ({MAX_ENDPOINTS})"
            _write(f"[!] Crawl {why} reached — stopping to stay bounded. "
                   f"Narrow the scope or lower the depth for a focused "
                   f"re-run.", "warn")

        while queue:
            if _state_cancelled():
                _write("[!] Crawl cancelled by user.", "warn")
                break
            if _over_budget():
                _cap_notice()
                break
            current_url, depth = queue.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            _write(f"[depth {depth}] Fetching {current_url}")
            raw = _fetch(current_url)
            if not raw:
                _write(f"  ✗ No response from {current_url}", "warn")
                continue

            # JWT detection on response headers (Set-Cookie etc.)
            _harvest_jwts_from_headers(raw, current_url)

            # Query-string params on the fetched URL itself.
            _harvest_params_from_url(current_url)

            header_body = raw.split("\r\n\r\n", 1)
            html = header_body[1] if len(header_body) > 1 else raw
            visited_html[current_url] = html

            # Body-level JWT detection — covers JSON responses that
            # echo the user's token, "logged in" pages that print it,
            # etc.  Cap to a few hits to avoid quadratic dedup.
            for jm in JWT_RE.finditer(html):
                if state is not None:
                    state.add_jwt(JwtToken(
                        token=jm.group(0), source="body",
                        where="response body",
                        seen_at=current_url))

            endpoints, js_found, param_full = _extract_endpoints(
                html, current_url)
            all_js_urls.update(js_found)
            new_count = len(endpoints - set(all_endpoints.keys()))
            _write(f"  → Extracted {len(endpoints)} endpoints "
                   f"({new_count} new)")

            # Harvest GET query params from the query-bearing links.  The
            # endpoints above are normalised (query stripped), so the
            # params have to come from the full URLs.  These are what Inject
            # tests and what the parameterised-URL block (SQLMap picker)
            # is built from.
            for u in param_full:
                _harvest_params_from_url(u)

            for form in parse_html_forms(html, current_url):
                action = form["action"]
                method = form["method"]
                fields = form["fields"]
                has_pwd = form["has_password"]
                file_inputs = form["file_inputs"]
                forms_found.append(form)

                # Push form (and any upload variant) into AssaultState.
                if state is not None:
                    state.add_form({
                        "action": action, "method": method,
                        "fields": fields[:10], "has_password": has_pwd,
                    })
                    # Each named input becomes a body param so Inject
                    # can target POST form fields too, not just query.
                    for fname in fields[:10]:
                        state.add_parameter(Param(
                            url=action, name=fname, method=method,
                            where="body", source="crawl"))
                    for ffield in file_inputs:
                        state.add_upload_form(UploadForm(
                            url=action, method=method or "POST",
                            file_field=ffield,
                            other_fields=[f for f in fields[:10]
                                          if f != ffield],
                        ))

            for ep in endpoints:
                if ep in all_endpoints:
                    continue
                if _over_budget():
                    _cap_notice()
                    break
                probe = _probe(ep)
                all_endpoints[ep] = probe

                status_icon = {
                    200: "✓", 301: "→", 302: "→", 307: "→",
                    401: "🔒", 403: "⊘", 404: "✗", 500: "⚠",
                }.get(probe["status"], "?")
                _write(f"  {status_icon} [{probe['status']}] {urlparse(ep).path}"
                       f"  ({probe['size']}B)"
                       f"{'  → ' + probe['redirect'] if probe['redirect'] else ''}")

                if probe["status"] in (301, 302, 303, 307, 308):
                    chain = _follow_chain(ep)
                    if len(chain) > 1:
                        redirect_chains[ep] = chain
                        for hop in chain[1:]:
                            hop_clean = _normalize(hop)
                            if hop_clean not in all_endpoints:
                                hop_probe = _probe(hop_clean)
                                all_endpoints[hop_clean] = hop_probe
                                _write(f"    → [{hop_probe['status']}] "
                                       f"{urlparse(hop_clean).path}  "
                                       f"({hop_probe['size']}B)  "
                                       f"(from redirect)")
                                if (depth < max_depth
                                        and hop_probe["status"] == 200):
                                    queue.append((hop_clean, depth + 1))
                    elif probe["redirect"]:
                        redir_clean = _normalize(
                            urljoin(ep, probe["redirect"]))
                        if redir_clean not in all_endpoints:
                            redir_probe = _probe(redir_clean)
                            all_endpoints[redir_clean] = redir_probe
                            _write(f"    → [{redir_probe['status']}] "
                                   f"{urlparse(redir_clean).path}  "
                                   f"({redir_probe['size']}B)  "
                                   f"(from redirect)")
                            if (depth < max_depth
                                    and redir_probe["status"] == 200):
                                queue.append((redir_clean, depth + 1))

                if depth < max_depth and probe["status"] == 200:
                    queue.append((ep, depth + 1))

        # ── JS Secrets scan ────────────────────────────────────
        from utils.web_findings import (
            JsSecret, Severity as WFSeverity,
            JS_SECRET_PATTERNS, deduplicate_secrets, mask_secret)

        target_host = urlparse(start_url).hostname or ""

        def _scan_content(content, source_label):
            """Scan text for secret patterns. Returns list[JsSecret]."""
            hits = []
            for line_num, line in enumerate(
                    content.splitlines(), 1):
                for pname, pattern, sev, _ in JS_SECRET_PATTERNS:
                    for m in re.finditer(pattern, line):
                        value = (m.group(1) if m.lastindex
                                 else m.group(0))
                        if pname == "Internal IP Address" \
                                and value == target_host:
                            continue
                        if pname == "Email Address" \
                                and value.endswith((
                                    "@example.com",
                                    "@example.org",
                                    "@localhost",
                                    "@test.com")):
                            continue
                        hits.append(JsSecret(
                            pattern_name=pname,
                            severity=sev,
                            matched_value=value,
                            source_file=source_label,
                            line_number=line_num,
                            context=line.strip()[:200],
                        ))
            return hits

        js_secrets_found = []
        if extract_js and not _state_cancelled():
            # Scan inline <script> blocks from crawled pages
            inline_count = 0
            for crawled_url, crawled_html in visited_html.items():
                for script_m in re.finditer(
                        r'<script[^>]*>([\s\S]*?)</script>',
                        crawled_html, re.I):
                    block = script_m.group(1).strip()
                    if len(block) < 20:
                        continue
                    hits = _scan_content(
                        block,
                        f"{urlparse(crawled_url).path} (inline)")
                    js_secrets_found.extend(hits)
                    inline_count += len(hits)

            # Scan external .js files
            if all_js_urls:
                _write(f"\n[*] JS Secrets scan: {len(all_js_urls)} "
                       f"external JS file(s)"
                       f"{f', {inline_count} inline hit(s)' if inline_count else ''}",
                       "info")
                for js_url in sorted(all_js_urls):
                    js_path = urlparse(js_url).path
                    _write(f"  Scanning {js_path}...")
                    try:
                        r = subprocess.run(
                            ["curl", "-s", "--max-time", "10",
                             "--max-filesize", "2097152", js_url],
                            capture_output=True, text=True,
                            timeout=15)
                        js_content = r.stdout or ""
                    except Exception:
                        js_content = ""
                    if not js_content:
                        _write(f"    ✗ Empty or unreachable", "dim")
                        continue
                    hits = _scan_content(js_content, js_path)
                    js_secrets_found.extend(hits)
                    if hits:
                        _write(f"    → {len(hits)} match(es)",
                               "success")
            elif inline_count:
                _write(f"\n[*] JS Secrets scan: {inline_count} "
                       "inline hit(s), no external JS files",
                       "info")

            if js_secrets_found:
                js_findings = deduplicate_secrets(js_secrets_found)
                _write(f"\n[+] JS Secrets: {len(js_secrets_found)} "
                       f"matches → {len(js_findings)} unique "
                       f"finding(s)", "success")
                sev_colors = {
                    WFSeverity.CRITICAL: "error",
                    WFSeverity.HIGH: "warn",
                }
                for jf in js_findings:
                    tag = sev_colors.get(jf.severity, "info")
                    _write(f"  [{jf.severity.value.upper()}] "
                           f"{jf.title}", tag)
                    for ev in jf.evidence:
                        _write(f"    {ev}", "dim")
            else:
                if all_js_urls:
                    _write("  [*] No secrets found.", "dim")
                js_findings = []
        else:
            js_findings = []

        # ── IDOR detection ──────────────────────────────────────
        idor_results = _detect_idor(
            [u for u, p in all_endpoints.items() if p["status"] in (200, 301, 302)])

        idor_findings = []
        if idor_results:
            # Cap the number of sequential-ID patterns probed: each does
            # idor_max+1 requests, so an unbounded candidate list is its own
            # explosion (and noisy enumeration against a live target).
            idor_probe = idor_results[:MAX_IDOR_TARGETS]
            extra = len(idor_results) - len(idor_probe)
            _write(f"\n[*] IDOR detection: {len(idor_results)} "
                   f"candidate pattern(s)"
                   + (f" — probing first {len(idor_probe)} "
                      f"({extra} more skipped to stay bounded)"
                      if extra else ""), "info")
            parsed_base = urlparse(start_url)
            for idor in idor_probe:
                if _state_cancelled():
                    _write("  [!] IDOR detection cancelled by user.", "warn")
                    break
                if _time_or_req_exhausted():
                    _cap_notice()
                    break
                _write(f"  Testing {idor['prefix']}[0..{idor_max}]...")
                sizes = {}
                for i in range(idor_max + 1):
                    test_url = urlunparse((
                        parsed_base.scheme, parsed_base.netloc,
                        f"{idor['prefix']}{i}", "", "", ""))
                    p = _probe(test_url, timeout=5)
                    if p["status"] in (200, 301, 302):
                        sizes[i] = p["size"]
                        big = "  [BIG]" if p["size"] > 100_000 else ""
                        if i not in idor["found_ids"]:
                            _write(f"    [+] {idor['prefix']}{i} "
                                   f"→ {p['status']} ({p['size']}B)"
                                   f"{big}", "success")
                        else:
                            _write(f"      {idor['prefix']}{i} "
                                   f"→ {p['status']} ({p['size']}B)"
                                   f"{big}")
                total = idor_max + 1
                # One accessible id is the page we already crawled —
                # nothing was enumerated, so there is nothing to
                # report.  Enumeration needs at least two.
                if len(sizes) < 2:
                    if sizes:
                        _write(f"  [-] only {len(sizes)}/{total} ID(s) "
                               f"accessible under {idor['prefix']} — no "
                               f"enumerable range, not reported")
                    continue
                unique_sizes = len(set(sizes.values()))
                idor["probed"] = sizes
                idor["unique_sizes"] = unique_sizes
                idor["accessible_count"] = len(sizes)
                idor_findings.append(idor)
                if unique_sizes > 1:
                    _write(f"  ⚠ Enumerable IDs, content varies: "
                           f"{len(sizes)}/{total} accessible, "
                           f"{unique_sizes} distinct sizes — "
                           f"verify authorisation manually", "warn")
                elif len(sizes) == total:
                    _write(f"  [?] All {total} IDs return same size "
                           f"({list(sizes.values())[0]}B) — might be "
                           f"a generic response, verify manually.")
                else:
                    _write(f"  [+] {len(sizes)}/{total} IDs accessible",
                           "success")

        elapsed = time.time() - t0

        # ── Build Target Intel finding ──────────────────────────
        secrets_tag = (f", {len(js_findings)} JS secret(s)"
                       if js_findings else "")
        _write(f"\n[+] Crawl complete: {len(all_endpoints)} endpoints, "
               f"{len(redirect_chains)} redirect chains, "
               f"{len(idor_findings)} IDOR candidates"
               f"{secrets_tag} — {elapsed:.1f}s", "success")

        parts = []
        parts.append(f"Bloody Crawl — {len(all_endpoints)} endpoints "
                     f"mapped in {elapsed:.1f}s\n")

        # Group by status
        by_status = {}
        for url, p in sorted(all_endpoints.items()):
            by_status.setdefault(p["status"], []).append(
                (urlparse(url).path, p["size"], url))

        STATUS_ORDER = [200, 301, 302, 307, 401, 403, 404, 500]
        shown = set()
        for code in STATUS_ORDER:
            if code not in by_status:
                continue
            shown.add(code)
            items = by_status[code]
            label = {200: "OK", 301: "Redirect", 302: "Redirect",
                     307: "Redirect", 401: "Auth Required",
                     403: "Forbidden", 404: "Not Found",
                     500: "Server Error"}.get(code, str(code))
            parts.append(f"  [{code} {label}] ({len(items)} endpoints):")
            for path, size, full_url in items[:20]:
                sz = f"  ({size}B)" if size else ""
                parts.append(f"    {path}{sz}")
            if len(items) > 20:
                parts.append(f"    ... and {len(items) - 20} more")

        for code in sorted(by_status.keys()):
            if code in shown:
                continue
            items = by_status[code]
            parts.append(f"  [{code}] ({len(items)} endpoints):")
            for path, size, _ in items[:10]:
                sz = f"  ({size}B)" if size else ""
                parts.append(f"    {path}{sz}")

        # Redirect chains
        if redirect_chains:
            parts.append(f"\n{'─' * 50}")
            parts.append(f"REDIRECT CHAINS ({len(redirect_chains)}):\n")
            for src, chain in list(redirect_chains.items())[:15]:
                parts.append(
                    f"  {urlparse(src).path}")
                for i, hop in enumerate(chain[1:], 1):
                    parts.append(f"    {'→'} {hop}")

        # Forms
        if forms_found:
            # Dedup identical forms and float login/password forms to the
            # top (the actionable ones); cap the list so a form-heavy app
            # (every wiki edit/attach page carries a form) can't bury the
            # signal under hundreds of lines.
            _seen_forms = set()
            _uniq_forms = []
            for f in forms_found:
                key = (f.get("method"), f.get("action"),
                       bool(f.get("has_password")))
                if key in _seen_forms:
                    continue
                _seen_forms.add(key)
                _uniq_forms.append(f)
            _uniq_forms.sort(
                key=lambda f: 0 if f.get("has_password") else 1)
            FORMS_SHOWN = 25
            parts.append(f"\n{'─' * 50}")
            parts.append(f"FORMS DETECTED ({len(_uniq_forms)} unique):\n")
            for f in _uniq_forms[:FORMS_SHOWN]:
                pwd_tag = " 🔑 LOGIN FORM" if f["has_password"] else ""
                parts.append(
                    f"  {f['method']} {f['action']}{pwd_tag}")
                if f["fields"]:
                    parts.append(
                        f"    fields: {', '.join(f['fields'])}")
            if len(_uniq_forms) > FORMS_SHOWN:
                parts.append(
                    f"  … and {len(_uniq_forms) - FORMS_SHOWN} more "
                    f"(login/password forms shown first)")

        # Parameterised URLs — reconstructed base?param= targets for the
        # SQLMap picker, which text-scans finding descriptions for such
        # URLs (it reads neither AssaultState nor discovered_web_paths).
        # Content pages without parameters are intentionally left out so
        # they don't flood the picker; so are params on dead links
        # (404/400 TWiki placeholders) via the resolved-status set.
        _good_paths = {
            urlparse(u).path
            for u, pr in all_endpoints.items()
            if pr.get("status") not in (0, 400, 404)
        }
        param_urls = self._build_param_urls(
            start_url,
            state.get_parameters() if state is not None else [],
            _good_paths)
        if param_urls:
            PARAM_SHOWN = 50
            total_params = len(param_urls)
            parts.append(f"\n{'─' * 50}")
            parts.append(
                f"PARAMETERISED URLS ({total_params}"
                + (f", showing first {PARAM_SHOWN}"
                   if total_params > PARAM_SHOWN else "")
                + "):\n")
            parts.append(
                "  URLs with query parameters — SQLmap injection targets:")
            for u in param_urls[:PARAM_SHOWN]:
                parts.append(f"    {u}")
            if total_params > PARAM_SHOWN:
                parts.append(
                    f"    … and {total_params - PARAM_SHOWN} more")

        # Login/password forms → discovered_web_paths, so the Hydra HTTP
        # picker offers the crawl's real auth endpoints.  Only password
        # forms are kept (content pages would flood the picker).
        login_paths = []
        _seen_login = set()
        _target_host = (urlparse(start_url).hostname or "").lower()
        for f in forms_found:
            if not f.get("has_password"):
                continue
            action = f.get("action") or ""
            if not action or action in _seen_login:
                continue
            # Only forms on the target host — crawled docs embed external
            # example forms (e.g. twiki.org change-password) that must not
            # be offered to Hydra as if they were on the target.
            if (urlparse(action).hostname or "").lower() != _target_host:
                continue
            _seen_login.add(action)
            probe = all_endpoints.get(_normalize(action))
            login_paths.append({
                "path": action,
                "status": int(probe["status"]) if probe else 200,
                "size": int(probe["size"]) if probe else 0,
            })

        # IDOR
        if idor_findings:
            parts.append(f"\n{'─' * 50}")
            for idor in idor_findings:
                varies = idor["unique_sizes"] > 1
                header = ("⚠ IDOR CANDIDATE (content varies per ID)"
                          if varies else "IDOR CANDIDATE")
                parts.append(f"{header}: {idor['prefix']}[ID]\n")
                parts.append(
                    f"  Accessible: {idor['accessible_count']}/"
                    f"{idor_max + 1} IDs  |  "
                    f"Unique sizes: {idor['unique_sizes']}")
                if varies:
                    # NOT a confirmation.  All HAWK observed is that
                    # sequential ids are reachable and return different
                    # bodies — which is how every per-object endpoint
                    # behaves, authorised or not.  Confirming IDOR
                    # needs two identities, and HAWK only ever used
                    # one.  The old wording ("IDOR CONFIRMED — other
                    # users' data is likely exposed") went into the
                    # client report as a finding.
                    parts.append(
                        "  → Content varies per ID. That is normal for "
                        "any per-object endpoint and is NOT proof of "
                        "an authorisation flaw: HAWK probed with a "
                        "single identity. Confirm per step 5 below "
                        "before reporting.")
                probed = idor.get("probed", {})
                big_ids = [i for i, sz in probed.items()
                           if sz > 100_000]
                if big_ids:
                    parts.append(
                        f"\n  [BIG FILES] IDs with >100KB responses "
                        f"(may be PCAP, backup, dump):")
                    for bid in sorted(big_ids)[:15]:
                        sz = probed[bid]
                        human = (f"{sz / 1_048_576:.1f}MB" if sz > 1_000_000
                                 else f"{sz / 1024:.0f}KB")
                        parts.append(
                            f"    {idor['prefix']}{bid}  ({human})")
            # Exploitation guidance once, after all candidates — it is
            # identical for every candidate, so repeating it per-candidate
            # only buried the list.
            parts.append(
                "\n  HOW TO EXPLOIT (applies to the candidates above):\n"
                "    1. Visit each accessible ID in the browser\n"
                "    2. Check if the content changes between IDs\n"
                "    3. If yes → different users' data is exposed\n"
                "    4. Download the BIG files — they may contain "
                "credentials, PCAPs, or backups\n"
                "    5. Log in as user A → note your ID → try "
                "user B's ID\n"
                "    6. In Burp Intruder: set ID as payload, "
                "Numbers 0-1000, sort by response length")

        # JS Secrets summary in the main finding
        if js_findings:
            parts.append(f"\n{'─' * 50}")
            parts.append(
                f"JS SECRETS ({len(js_findings)} unique):\n")
            for jf in js_findings:
                parts.append(
                    f"  [{jf.severity.value.upper()}] {jf.title}")
                for ev in jf.evidence[:3]:
                    parts.append(f"    {ev}")

        desc = "\n".join(parts)

        # Severity — escalate based on findings
        severity = "info"
        has_critical_secret = any(
            jf.severity == WFSeverity.CRITICAL
            for jf in js_findings)
        has_high_secret = any(
            jf.severity == WFSeverity.HIGH
            for jf in js_findings)
        if has_critical_secret:
            severity = "critical"
        elif idor_findings:
            severity = "high"
        elif has_high_secret:
            severity = "high"
        elif forms_found and any(f["has_password"] for f in forms_found):
            severity = "medium"
        elif redirect_chains:
            severity = "medium"

        # Title scoped to the actual start_url so re-running Bloody
        # Crawl on a *different* vhost / port / base path lands as a
        # separate finding instead of mistakenly merging into the
        # first one.  The merge-by-title logic in add_auto_finding
        # then correctly: same scope → run #2, different scope → new
        # finding starting at run #1.
        title = f"Bloody Crawl on {start_url}"

        def _push():
            # replace=True: each Bloody Crawl run is a COMPLETE snapshot of
            # the crawl, so a rerun must SUPERSEDE the previous card instead
            # of appending another full listing (which stacked two crawls'
            # forms/params/IDOR into one ever-growing wall).  Per-run history
            # stays in occurrences.  Same shape as nuclei / nikto / the
            # dir-busters.
            self.app.target_intel.add_auto_finding(
                title=title, description=desc,
                severity=severity, source="Bloody Crawl", replace=True)
            # Login/password forms feed the Hydra HTTP picker.
            if login_paths:
                try:
                    sess = self.app.session_manager.current
                    if sess is not None:
                        sess.add_discovered_web_paths(login_paths)
                except Exception as e:
                    print(f"[HAWK] Bloody Crawl discovered_web_paths "
                          f"save failed: {e}")
            for jf in js_findings:
                # raw_description = same render_description but with
                # un-masked values.  Passed in-memory only (stripped
                # at session-save time) so the Info-dialog SHOW RAW
                # toggle can switch the EVIDENCE block locally.
                #
                # We prefix BOTH descriptions with the actual scanned
                # URL ("Source URL: ...").  The Info-dialog FETCH
                # SOURCE button parses that line to know which vhost
                # / port served the bundle — without it, HAWK falls
                # back to the session's target_domain, which on
                # multi-vhost boxes (e.g. silentium.htb +
                # staging.silentium.htb) lands on the wrong vhost
                # and gets the SPA shell back instead of the JS
                # bundle.
                src_line = f"Source URL: {start_url}\n"
                masked_desc = src_line + jf.render_description()
                raw_desc = (
                    src_line + jf.render_description(raw=True)
                    if jf.raw_evidence else "")
                self.app.target_intel.add_auto_finding(
                    title=jf.title,
                    description=masked_desc,
                    severity=jf.severity.value,
                    source="Bloody Crawl",
                    raw_description=raw_desc)
            if state is not None:
                state.set_crawl_endpoints(len(all_endpoints))
                state.set_step(
                    "crawl",
                    "error" if state.is_cancelled() else "done")
            self._on_done(tool, tool.name, 0,
                          [(t, m) for t, m in log])
        self.app.after(0, _push)

    def _jump_to_intel(self, run_id: str):
        """Close the current Toplevel (so the user lands cleanly on
        Target Intel) and call app.navigate_to_run_id to switch tab
        + scroll to the finding."""
        try:
            self.app.navigate_to_run_id(run_id, "intel")
        except Exception as e:
            print(f"[HAWK] _jump_to_intel({run_id}) failed: {e}")

    def _show_web_oracle_result(self, tool, profile, recommendations):
        """Post-scan dialog: structured summary + action buttons.

        Sections:
          TECH STACK | EXPOSURES | API SURFACE | AUTH | KNOWN CVEs |
          STACK/FEDERATION FLAGS | RECOMMENDED NEXT STEPS

        Every CVE and every notable exposure is ALSO pushed to Target
        Intel with a shared run_id so the user can cross-navigate via
        the "→ INTEL" button on each row.  The full profile itself
        gets a summary finding so the history of Oracle runs is
        queryable without reopening this dialog.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                 _btn_row, _btn, _safe_destroy,
                                 _selectable_text)
        from utils.run_id import new_run_id

        url = profile.get("url", "?")

        # ── Push findings to Target Intel BEFORE opening the dialog
        # so the "→ INTEL" buttons we render below are guaranteed to
        # find something to jump to.  All share a base run_id so they
        # land visually grouped in Target Intel.
        base_rid = new_run_id()
        intel = getattr(self.app, "target_intel", None)

        # Map CVE id → run_id assigned to its finding, so each row's
        # "→ INTEL" button can navigate to the right entry.
        cve_rid_map = {}
        expo_rid_map = {}

        if intel is not None:
            try:
                # Summary finding (always created, acts as the
                # cross-link hub for the run).
                tech = profile.get("tech") or []
                apis = profile.get("apis") or []
                auth = profile.get("auth") or {}
                expos = profile.get("exposures") or []
                cves = profile.get("cves") or []
                desc_lines = [
                    f"Web Oracle scan of {url}.",
                    "",
                    f"  Tech signals  : {len(tech)}",
                    f"  APIs          : {len(apis)}",
                    f"  Exposures     : {len(expos)}",
                    f"  CVEs          : {len(cves)}",
                    f"  Auth type     : {auth.get('type', 'n/a')}",
                ]
                if tech:
                    desc_lines += ["", "Tech stack (top 15):"]
                    for t in tech[:15]:
                        ver = f" {t.get('version')}" \
                              if t.get("version") else ""
                        desc_lines.append(
                            f"  · {t['name']}{ver}")
                # Honest severity: take the MAX rank actually present
                # in cves + exposures (critical < high < medium < low
                # < info).  Counting nuclei "Missing Security Headers"
                # (severity=info) as a HIGH summary was misleading —
                # operator skipped the card and missed the few real
                # cves / exposures elsewhere.
                _SEV_RANK = {"critical": 0, "high": 1, "medium": 2,
                             "low": 3, "info": 4}
                _max_sev = "info"
                # NB: the loop var MUST NOT be named `_f` — `_f` is the
                # module-level font factory used by every CTkLabel in
                # this function (font=_f("md", True), …).  Naming the
                # loop var `_f` shadowed the font factory with the last
                # dict of the iterable, and every subsequent
                # `font=_f(...)` call raised
                #   TypeError: 'dict' object is not callable
                # which killed the dialog rendering mid-build → the
                # operator saw a black window with no content.  Using
                # `_finding` keeps the iteration intent clear without
                # touching the font name.
                for _finding in list(cves) + list(expos):
                    _s = (_finding.get("severity") or "info").lower()
                    if _SEV_RANK.get(_s, 4) < _SEV_RANK.get(_max_sev,
                                                              4):
                        _max_sev = _s
                # Stable title (no counts) so re-running Oracle on the
                # same URL updates this one summary card instead of
                # stacking a new one every time the exposure/CVE count
                # changes (e.g. 1 -> 20 exposures between runs).  The
                # counts live in the description; replace=True refreshes
                # it to the latest run.  Same fix shape as the dir-buster
                # / enum4linux stable-title findings.
                intel.add_auto_finding(
                    title=f"ORACLE — {url}",
                    description="\n".join(desc_lines),
                    severity=_max_sev,
                    source="Web Oracle",
                    replace=True,
                    linked_run_id=base_rid)

                # One finding per CVE so severity / search work.
                for c in cves:
                    rid = new_run_id()
                    cve_rid_map[c.get("id", "")] = rid
                    intel.add_auto_finding(
                        title=f"{c.get('id', 'CVE?')}  ·  "
                              f"{c.get('name', '')[:70]}",
                        description=(
                            f"Detected by nuclei during Web Oracle "
                            f"scan of {url}.\n"
                            f"\nSeverity: {c.get('severity', '?')}\n"
                            f"Tags: "
                            f"{', '.join(c.get('tags', []) or [])}\n"
                            f"\nNext step:  searchsploit "
                            f"{c.get('id', '')}  —  pivot to a "
                            f"working exploit, OR `nuclei -id "
                            f"{c.get('id', '')}` to re-verify."),
                        severity=c.get("severity") or "medium",
                        source="Web Oracle / nuclei",
                        linked_run_id=rid)

                # One finding per high/critical exposure.  Info-level
                # exposures (robots Disallow listings, login forms)
                # stay in the dialog only — Target Intel would flood.
                for e in expos:
                    sev = e.get("severity", "info")
                    if sev not in ("high", "critical", "medium"):
                        continue
                    rid = new_run_id()
                    expo_rid_map[e.get("path", "")] = rid
                    intel.add_auto_finding(
                        title=f"EXPOSURE  ·  "
                              f"{e.get('path', '?')}  "
                              f"[{e.get('status', '?')}]",
                        description=(
                            f"Discovered by Web Oracle probes on "
                            f"{url}.\n"
                            f"\nPath    : {e.get('path', '')}\n"
                            f"Status  : {e.get('status', '')}\n"
                            f"Severity: {sev}\n"
                            + (f"\nNote    : {e['note']}"
                                if e.get('note') else "")
                            + "\n\nInvestigate manually — these paths "
                              "frequently leak credentials, source "
                              "code, or admin panels."),
                        severity=sev,
                        source="Web Oracle",
                        linked_run_id=rid)
            except Exception as e:
                print(f"[HAWK] oracle target-intel push failed: {e}")

        # Dialog size — bumped from 820×760 to 960×900 so the user
        # sees TECH STACK through RECOMMENDED NEXT STEPS without
        # scrolling on a 1080p display.  _make_win caps at 92% of
        # screen so laptops still fit.
        win = _make_win(self, f"Web Oracle — result", 960, 900)
        _title(win, "ORACLE — attack plan")
        _sub(win, f"target: {url}", COLORS["text_dim"])

        _outer = win
        body = ctk.CTkScrollableFrame(
            _outer, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 2))
        win = body

        # ── §1 Tech stack ──────────────────────────────────────────
        ctk.CTkLabel(
            win, text="  ◇  TECH STACK",
            font=_f("md", True), text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(8, 2))
        tech = profile.get("tech") or []
        if tech:
            techs_str = "\n".join(
                f"  · {t['name']}"
                + (f"  {t['version']}" if t.get("version") else "")
                + (f"   [{t.get('source')}]"
                    if t.get("source") else "")
                for t in tech[:30])
            _note_box(win, techs_str, selectable=True)
        else:
            _note_box(win, "  (no fingerprint signals collected)")

        # ── §2 Exposures (high/critical = clickable row with → INTEL
        # button; info-level stay in a compact text box to avoid row
        # explosion) ──────────────────────────────────────────────────
        ctk.CTkLabel(
            win, text="  ◇  EXPOSURES",
            font=_f("md", True), text_color=COLORS["text_yellow"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(12, 2))
        expos = profile.get("exposures") or []
        high_expos = [e for e in expos if e.get("severity")
                      in ("high", "critical", "medium")]
        low_expos  = [e for e in expos if e.get("severity")
                      not in ("high", "critical", "medium")]

        if high_expos:
            for e in high_expos[:15]:
                sev = e.get("severity", "info")
                marker = {"critical": "⚠⚠", "high": "⚠",
                          "medium": "•"}.get(sev, "·")
                ef = ctk.CTkFrame(
                    win, fg_color=COLORS["bg_card"],
                    border_color=(COLORS["text_red"]
                                  if sev == "critical"
                                  else COLORS["border_amber"]),
                    border_width=1, corner_radius=3)
                ef.pack(fill="x", padx=24, pady=2)
                inner = ctk.CTkFrame(ef, fg_color="transparent")
                inner.pack(fill="x", padx=6, pady=4)
                ctk.CTkLabel(
                    inner,
                    text=f"  {marker}  [{e.get('status', '?')}]  "
                         f"{e.get('path', '')}    sev={sev}",
                    font=_f("sm"),
                    text_color=COLORS["text_bright"],
                    anchor="w",
                ).pack(side="left", fill="x", expand=True)
                rid = expo_rid_map.get(e.get("path", ""))
                if rid:
                    _btn(inner, "→ INTEL",
                         lambda r=rid: self._jump_to_intel(r),
                         w=90)

        if low_expos:
            lines = []
            for e in low_expos[:30]:
                sev = e.get("severity", "info")
                marker = {"low": "·", "info": " "}.get(sev, " ")
                lines.append(
                    f"  {marker}  [{e.get('status', '?')}]  "
                    f"{e.get('path', '')}    sev={sev}")
            _note_box(win, "\n".join(lines), selectable=True)

        if not expos:
            _note_box(win, "  (no public exposures flagged)")

        # ── §2b API surface ────────────────────────────────────────
        apis = profile.get("apis") or []
        if apis:
            ctk.CTkLabel(
                win, text="  ◇  API SURFACE",
                font=_f("md", True),
                text_color=COLORS["text_cyan"],
                anchor="w",
            ).pack(fill="x", padx=24, pady=(12, 2))
            lines = []
            for a in apis[:20]:
                lines.append(
                    f"  [{a.get('kind', '?')}]  {a.get('path', '')}")
            _note_box(win, "\n".join(lines), selectable=True)

        # ── §2c Auth mechanism ────────────────────────────────────
        auth = profile.get("auth") or {}
        if auth:
            ctk.CTkLabel(
                win, text="  ◇  AUTH",
                font=_f("md", True),
                text_color=COLORS["text_cyan"],
                anchor="w",
            ).pack(fill="x", padx=24, pady=(12, 2))
            lines = [f"  type         {auth.get('type', '?')}"]
            if auth.get("login_path"):
                lines.append(
                    f"  login_path   {auth['login_path']}")
            if auth.get("fields"):
                lines.append(
                    f"  fields       "
                    f"{', '.join(auth['fields'][:6])}")
            _note_box(win, "\n".join(lines), selectable=True)

        # ── §3 CVEs (each a clickable row → INTEL) ─────────────────
        ctk.CTkLabel(
            win, text="  ◇  KNOWN CVEs",
            font=_f("md", True), text_color=COLORS["text_red"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(12, 2))
        cves = profile.get("cves") or []
        if cves:
            for c in cves[:20]:
                sev = c.get("severity") or "?"
                cf = ctk.CTkFrame(
                    win, fg_color=COLORS["bg_card"],
                    border_color=(COLORS["text_red"]
                                  if sev in ("critical", "high")
                                  else COLORS["border_amber"]),
                    border_width=1, corner_radius=3)
                cf.pack(fill="x", padx=24, pady=2)
                inner = ctk.CTkFrame(cf, fg_color="transparent")
                inner.pack(fill="x", padx=6, pady=4)
                ctk.CTkLabel(
                    inner,
                    text=(f"  {c.get('id', '?'):<20}  "
                          f"sev={sev:<8}  "
                          f"{c.get('name', '')[:55]}"),
                    font=_f("sm"),
                    text_color=COLORS["text_bright"],
                    anchor="w",
                ).pack(side="left", fill="x", expand=True)
                rid = cve_rid_map.get(c.get("id", ""))
                if rid:
                    _btn(inner, "→ INTEL",
                         lambda r=rid: self._jump_to_intel(r),
                         w=90)
        else:
            _note_box(win, "  (no nuclei CVE matches in first pass)")

        # ── §3b Regional / federation flags ────────────────────────
        # These are hints, not actionable recommendations — they
        # tell the operator what kind of environment the app is in
        # (federated SSO provider, local-market CMS, ERP stack)
        # without naming countries.  The operator knows the target
        # context and uses the hint to pick their own pivot.
        rflags = profile.get("regional_flags") or []
        if rflags:
            ctk.CTkLabel(
                win, text="  ◇  STACK / FEDERATION FLAGS",
                font=_f("md", True),
                text_color=COLORS["text_yellow"],
                anchor="w",
            ).pack(fill="x", padx=24, pady=(12, 2))
            for f in rflags[:10]:
                ff = ctk.CTkFrame(
                    win, fg_color=COLORS["bg_card"],
                    border_color=COLORS["border_amber"],
                    border_width=1, corner_radius=3)
                ff.pack(fill="x", padx=24, pady=4)
                ctk.CTkLabel(
                    ff, text=f"  ⚑  {f.get('tag', '?')}",
                    font=_f("md", True),
                    text_color=COLORS["text_yellow"],
                    anchor="w",
                ).pack(fill="x", padx=8, pady=(6, 2))
                ctk.CTkLabel(
                    ff, text=f.get("detail", ""),
                    font=_f("sm"), text_color=COLORS["text_bright"],
                    anchor="w", justify="left", wraplength=720,
                ).pack(fill="x", padx=8, pady=(0, 2))
                if f.get("hint"):
                    ctk.CTkLabel(
                        ff, text=f"  → {f['hint']}",
                        font=_f("sm"),
                        text_color=COLORS["text_cyan"],
                        anchor="w", justify="left", wraplength=720,
                    ).pack(fill="x", padx=8, pady=(0, 6))

        # ── §4 Recommendations ─────────────────────────────────────
        ctk.CTkLabel(
            win, text="  ◇  RECOMMENDED NEXT STEPS",
            font=_f("md", True), text_color=COLORS["text_cyan"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(12, 4))
        if not recommendations:
            _note_box(
                win,
                "No automated recommendations derived from this "
                "profile yet.  Check Tech/Exposures above, pivot "
                "manually from there.")
        else:
            for rec in recommendations:
                rf = ctk.CTkFrame(
                    win, fg_color=COLORS["bg_card"],
                    border_color=COLORS["border_green"],
                    border_width=1, corner_radius=3)
                rf.pack(fill="x", padx=24, pady=4)
                ctk.CTkLabel(
                    rf, text=f"  → {rec.get('action', '?')}",
                    font=_f("md", True),
                    text_color=COLORS["text_green"],
                    anchor="w",
                ).pack(fill="x", padx=8, pady=(6, 2))
                ctk.CTkLabel(
                    rf, text=rec.get("reason", ""),
                    font=_f("sm"), text_color=COLORS["text_bright"],
                    anchor="w", justify="left", wraplength=720,
                ).pack(fill="x", padx=8, pady=(0, 4))
                # If the rec maps to a HAWK tool, render a big green
                # button that fires launch_tool_prefilled.  Otherwise
                # show a selectable command.
                if rec.get("tool_id"):
                    tid = rec["tool_id"]
                    pf = dict(rec.get("prefill") or {})
                    pf.setdefault("_origin", "Web Oracle")
                    btn_row = ctk.CTkFrame(rf, fg_color="transparent")
                    btn_row.pack(fill="x", padx=8, pady=(0, 6))
                    _btn(btn_row,
                         f"RUN IN HAWK — {tid}",
                         lambda t=tid, p=pf:
                             self.launch_tool_prefilled(t, p),
                         primary=True, w=280)
                elif rec.get("command"):
                    _selectable_text(
                        rf, rec["command"],
                        color=COLORS["text_bright"], height=50)

        # ── Footer buttons ─────────────────────────────────────────
        win = _outer
        row = _btn_row(win)
        _btn(row, "CLOSE",
             lambda: _safe_destroy(win), primary=True, w=140)

