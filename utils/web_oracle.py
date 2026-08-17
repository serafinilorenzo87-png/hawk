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
HAWK — Web Oracle orchestrator.

Runs multiple web-recon binaries in parallel against a target URL,
aggregates their outputs into a structured WebappProfile dict, and
invokes a done_callback on the UI thread with:

    (tool_name, return_code, log, profile, recommendations)

Binary set (tiered — missing ones are skipped gracefully):
  Core (required)         → whatweb, httpx, nuclei
  Optional (auto-added)   → katana, ffuf, gau, arjun
  Curl-based probes       → /robots.txt, /sitemap.xml, /.git/HEAD,
                            /.env, /graphql (introspection ping)

Phase 1 of the Web Oracle rollout implements:
  · Binary detection + parallel launch
  · Per-binary stdout streaming to the HAWK terminal
  · Basic output aggregation (raw blobs per binary)
  · A minimal WebappProfile with tech strings from whatweb/httpx

Phase 2 and 3 add: crawling, deep HTML parsing, recommendations
engine, regional patterns, CVE mapping.  The profile & recommendations
keys are already reserved in the dict shape so Phase 1 output is a
strict subset of the final schema.
"""

from __future__ import annotations

import os
import re
import json
import shlex
import shutil
import threading
import subprocess
from typing import Optional
from utils.config import CACHE_DIR, CONFIGS_DIR, TMP_DIR


def _tool_env() -> dict:
    env = os.environ.copy()
    xdg_data = os.path.join(CACHE_DIR, "xdg-data")
    for d in (CONFIGS_DIR, CACHE_DIR, xdg_data, TMP_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
    env["XDG_CONFIG_HOME"] = CONFIGS_DIR
    env["XDG_CACHE_HOME"] = CACHE_DIR
    env["XDG_DATA_HOME"] = xdg_data
    env["TMPDIR"] = TMP_DIR
    return env


# ─── Binary discovery ────────────────────────────────────────────────

def _bin_path(name: str) -> Optional[str]:
    """Resolve a binary's absolute path, or None if not installed.

    Checks $PATH first, then falls back to Go-install defaults
    (~/go/bin, ~/.local/bin) since httpx/nuclei/katana are commonly
    installed via `go install` and end up outside the system PATH
    on fresh Kali.

    On Kali the `httpx` binary ships as `httpx-toolkit` (the apt
    package name) to avoid a namespace clash with the Python
    `httpx` library — when both are installed `shutil.which("httpx")`
    returns the Python CLI, which rejects ProjectDiscovery flags
    (e.g. `-silent` parsed as `-s` → "No such option: -s").  So for
    "httpx" we probe `httpx-toolkit` FIRST and fall back only if the
    toolkit binary isn't installed.
    """
    candidates = [name]
    if name == "httpx":
        candidates = ["httpx-toolkit", "httpx"]

    for cand_name in candidates:
        hit = shutil.which(cand_name)
        if hit:
            return hit
        for d in (os.path.expanduser("~/go/bin"),
                  os.path.expanduser("~/.local/bin"),
                  "/usr/local/bin",
                  "/opt/tools/" + cand_name):
            cand = os.path.join(d, cand_name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def detect_available_binaries() -> dict:
    """One-shot probe.  Returns {binary_name: path_or_None}.

    The logical name "httpx" is mapped internally to "httpx" OR
    "httpx-toolkit" (Kali's apt package).  Callers that spawn the
    binary should use the resolved path directly instead of the
    logical name.

    Extra validation for ``httpx``: on Kali installs that have the
    Python ``httpx`` library CLI (from python3-httpx) but NOT the
    ProjectDiscovery toolkit, ``shutil.which("httpx")`` returns the
    wrong binary.  We probe ``-version`` and ensure the output looks
    like ProjectDiscovery's; otherwise we mark the binary as missing
    so the rest of Oracle gracefully skips its phase.
    """
    out = {}
    for name in ("whatweb", "httpx", "nuclei",
                 "katana", "ffuf", "gau", "arjun",
                 "curl"):
        out[name] = _bin_path(name)
    # Validate httpx is actually ProjectDiscovery.  The Python
    # ``httpx`` CLI rejects ``-silent`` with "No such option: -s".
    if out.get("httpx"):
        if not _is_projectdiscovery_httpx(out["httpx"]):
            out["httpx"] = None
    return out


def _is_projectdiscovery_httpx(path: str) -> bool:
    """True when the binary at ``path`` is ProjectDiscovery's httpx
    fingerprinter (Go) and not the Python httpx library CLI.
    """
    try:
        r = subprocess.run([path, "-version"],
                           capture_output=True, text=True, timeout=5,
                           env=_tool_env())
        blob = (r.stdout or "") + (r.stdout or "") + (r.stderr or "")
        # ProjectDiscovery prints things like
        #   "Current Version: vX.Y.Z" or "[INF] Current httpx version vX.Y.Z"
        # The Python httpx CLI prints a Click usage page and exits 2.
        if "Current" in blob and "version" in blob.lower():
            return True
        if "projectdiscovery" in blob.lower():
            return True
    except Exception:
        return False
    return False


# ─── URL normalization ──────────────────────────────────────────────

def normalize_target_url(raw: str, default_scheme: str = "http") -> str:
    """Turn an IP, host, host:port or URL into a canonical URL.

    Oracle accepts any of these from the Target Intel card / user
    prompt and routes through one normaliser so downstream binaries
    get a consistent input:

        192.168.1.10          → http://192.168.1.10/
        example.com           → http://example.com/
        example.com:8080      → http://example.com:8080/
        https://example.com/x → https://example.com/x  (passthrough)
    """
    s = (raw or "").strip()
    if not s:
        return ""
    if not re.match(r"^https?://", s, re.I):
        s = f"{default_scheme}://{s}"
    # Guarantee a trailing slash on the bare authority so binaries
    # that expect path-having URLs (some nuclei templates) don't
    # blow up.
    from urllib.parse import urlsplit, urlunsplit
    p = urlsplit(s)
    if not p.path:
        s = urlunsplit((p.scheme, p.netloc, "/", p.query, p.fragment))
    return s


def _summarize_nuclei_line(raw: str) -> Optional[str]:
    """Compact one-liner for a nuclei JSONL finding.

    The raw line includes `request` and `response` fields which can each
    be ~20 KB of HTML — fine for the profile builder, terrible for the
    terminal (it duplicates the same body N times, once per template).
    Returns None if parsing fails so the caller can fall back to raw.
    """
    try:
        d = json.loads(raw)
    except Exception:
        return None
    info = d.get("info") or {}
    sev = (info.get("severity") or "?").lower()
    name = info.get("name") or d.get("template-id") or "?"
    matched = d.get("matched-at") or d.get("host") or ""
    matcher = d.get("matcher-name") or ""
    extracted = d.get("extracted-results") or []
    parts = [f"[{sev}]", name]
    if matcher:
        parts.append(f"({matcher})")
    if matched:
        parts.append(f"@ {matched}")
    if extracted:
        sample = ", ".join(str(x) for x in extracted[:3])
        if len(extracted) > 3:
            sample += f", +{len(extracted)-3}"
        parts.append(f"⇒ {sample}")
    return " ".join(parts)


# ─── Runner ─────────────────────────────────────────────────────────

class WebOracleRunner:
    """Parallel orchestrator for the Web Oracle phase.

    Lifecycle mirrors the other HAWK runners (see utils.runner) so
    the Kill Chain card wiring works out-of-the-box:

        r = WebOracleRunner(
            output_callback=terminal.output_callback,
            done_callback=lambda n, rc, log, profile, recs: ...,
            ui_dispatcher=app.ui_call)
        r.run(url="http://target/")

    `done_callback` is called exactly once with the aggregated profile.
    If the caller is also used elsewhere (e.g. the KillChainCard's
    generic done_callback that expects only 3 args), pass a wrapper
    that matches that signature.
    """

    def __init__(self, output_callback=None, done_callback=None,
                 ui_dispatcher=None):
        self.output_callback = output_callback
        self.done_callback   = done_callback
        self.ui_dispatcher   = ui_dispatcher

        self._log: list = []            # [(level, line), ...]
        self._log_lock = threading.Lock()
        self._binary_results: dict = {}   # binary_name -> raw stdout
        self._results_lock = threading.Lock()
        self._threads: list = []
        self._running = False
        self._cancelled = False

    # ── Public API ──────────────────────────────────────────────────
    @staticmethod
    def is_available() -> bool:
        """Oracle needs at least ONE of its three core binaries.  In
        practice whatweb is always present on Kali — if even that is
        missing the user probably isn't on a pentest distro and we
        don't want to silently produce an empty profile."""
        return bool(_bin_path("whatweb") or _bin_path("httpx") or
                    _bin_path("nuclei"))

    def run(self, url: str, tool_name: str = "ORACLE"):
        """Kick off the parallel scan.  Non-blocking — use callbacks.

        `url` must already be normalised (call normalize_target_url
        yourself if taking raw user input).
        """
        if self._running:
            self._emit("[hawk] Oracle already running — ignore.",
                       tool_name, "warn")
            return
        self._running = True
        self._cancelled = False
        self._log = []
        self._binary_results = {}

        t = threading.Thread(
            target=self._orchestrate,
            args=(url, tool_name),
            daemon=True)
        t.start()

    def kill(self):
        """Best-effort cancel.  Individual subprocesses check the
        flag and terminate themselves; already-buffered output still
        flushes through the callback."""
        self._cancelled = True

    def get_log(self) -> list:
        with self._log_lock:
            return list(self._log)

    # ── Internals ───────────────────────────────────────────────────
    def _emit(self, line: str, tool_name: str, level: str = "info"):
        """Thread-safe line emit: appends to log + forwards to UI."""
        with self._log_lock:
            self._log.append((level, line))
        if self.output_callback:
            try:
                if self.ui_dispatcher:
                    self.ui_dispatcher(
                        self.output_callback, line, tool_name, level)
                else:
                    self.output_callback(line, tool_name, level)
            except Exception:
                pass

    def _orchestrate(self, url: str, tool_name: str):
        """Top-level thread — probes binaries, spawns worker threads,
        waits for all to finish, aggregates, fires done_callback."""
        try:
            bins = detect_available_binaries()
            self._emit(
                f"  [oracle] target: {url}", tool_name, "info")
            present = [n for n, p in bins.items() if p]
            missing = [n for n, p in bins.items() if not p]
            self._emit(
                f"  [oracle] binaries present: {', '.join(present)}",
                tool_name, "dim")
            if missing:
                self._emit(
                    f"  [oracle] skipping (not installed): "
                    f"{', '.join(missing)}",
                    tool_name, "dim")

            # ── Workers — each runs its binary, streams output, stores
            # the aggregated stdout under _binary_results[name].
            workers = []
            if bins.get("whatweb"):
                workers.append(("whatweb",
                                self._run_whatweb, bins["whatweb"], url))
            if bins.get("httpx"):
                workers.append(("httpx",
                                self._run_httpx, bins["httpx"], url))
            if bins.get("nuclei"):
                workers.append(("nuclei",
                                self._run_nuclei, bins["nuclei"], url))
            # Curl-based probes are cheap — always run, they're just
            # HEAD/GET requests for specific paths.
            if bins.get("curl"):
                workers.append(("curl-probes",
                                self._run_curl_probes, bins["curl"], url))
                # Also fetch the homepage HTML body so the profile
                # builder can parse <meta generator>, forms, script
                # src, and other structural hints that whatweb and
                # httpx don't surface.
                workers.append(("html-home",
                                self._run_html_home, bins["curl"], url))
                # robots.txt body (path hints) — often exposes admin
                # paths, /wp-admin, API roots the rest of the pipeline
                # wouldn't have discovered.
                workers.append(("robots-body",
                                self._run_robots_body, bins["curl"], url))

            # Katana crawl — SPA-aware JS execution, far better than
            # gobuster/ffuf for single-page apps.  Skipped if not
            # installed (user sees it in the missing-binaries banner).
            if bins.get("katana"):
                workers.append(("katana",
                                self._run_katana, bins["katana"], url))

            for name, _fn, _path, _url in workers:
                with self._results_lock:
                    self._binary_results[name] = ""

            threads = []
            for name, fn, path, u in workers:
                t = threading.Thread(
                    target=self._worker_wrapper,
                    args=(name, fn, path, u, tool_name),
                    daemon=True)
                t.start()
                threads.append(t)

            # Wait (with safety ceiling — no single Oracle run should
            # block past 5 minutes; something's wrong if it does).
            for t in threads:
                t.join(timeout=300)

            self._emit(
                "  [oracle] all workers complete — aggregating profile.",
                tool_name, "info")

            profile = self._build_profile(url)
            # API discovery — framework-aware probes that depend on
            # the tech_stack just built.  Runs after _build_profile so
            # we can pick the right paths (Spring → /actuator/*,
            # Flask → /graphql, …).  Results merge back into the
            # profile + push to AssaultState so Bloody Crawl & Inject
            # can use them.
            try:
                api_findings = self._run_api_discovery(url, profile)
                if api_findings:
                    profile.setdefault("api_endpoints", []).extend(
                        api_findings)
            except Exception as e:
                self._emit(
                    f"  [oracle:api] discovery crashed: {e}",
                    tool_name, "warn")

            recommendations = self._recommend(profile)

            self._emit(
                f"  [oracle] profile: {len(profile.get('tech', []))} "
                f"tech signals, "
                f"{len(profile.get('exposures', []))} exposures, "
                f"{len(recommendations)} recommendations.",
                tool_name, "success")
        except Exception as e:
            self._emit(
                f"  [oracle] orchestrator crash: {e}",
                tool_name, "error")
            profile = {}
            recommendations = []
        finally:
            self._running = False
            self._dispatch_done(tool_name, 0,
                                 self.get_log(),
                                 profile, recommendations)

    def _worker_wrapper(self, name, fn, path, url, tool_name):
        """Catch-all around a worker so one binary crashing doesn't
        kill the orchestrator thread."""
        try:
            fn(path, url, tool_name, name)
        except Exception as e:
            self._emit(
                f"  [oracle:{name}] crashed: {e}", tool_name, "error")

    def _stream_cmd(self, argv: list, tool_name: str, label: str,
                    timeout: int = 120, merge_stderr: bool = True,
                    stdin_data: Optional[str] = None):
        """Run `argv`, stream each stdout line to the terminal with a
        per-tool prefix, return the full stdout as a string.

        stderr is merged into stdout by default (most recon binaries
        emit status lines on stderr that are useful to see).
        """
        if self._cancelled:
            return ""
        try:
            stderr_to = (subprocess.STDOUT if merge_stderr
                         else subprocess.DEVNULL)
            p = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=stderr_to,
                stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
                text=True, bufsize=1, env=_tool_env())
            if stdin_data is not None:
                try:
                    p.stdin.write(stdin_data + "\n")
                    p.stdin.close()
                except Exception:
                    pass
        except Exception as e:
            self._emit(f"  [oracle:{label}] spawn failed: {e}",
                       tool_name, "error")
            return ""
        buf = []
        # Nuclei JSONL embeds the full HTTP request+response per finding.
        # Streaming the raw line floods the terminal (one ~20 KB HTML body
        # per matched template).  Keep the raw JSON in `buf` for the profile
        # builder, but emit a compact one-liner to the UI.
        is_nuclei_jsonl = (label == "nuclei")
        try:
            for line in p.stdout:
                if self._cancelled:
                    try:
                        p.terminate()
                    except Exception:
                        pass
                    break
                line = line.rstrip("\n")
                buf.append(line)
                display = line
                if is_nuclei_jsonl and line.startswith("{"):
                    display = _summarize_nuclei_line(line) or line
                self._emit(f"  [{label}] {display}", tool_name, "info")
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._emit(f"  [oracle:{label}] timeout — killing.",
                       tool_name, "warn")
            try:
                p.kill()
            except Exception:
                pass
        except Exception as e:
            self._emit(f"  [oracle:{label}] read error: {e}",
                       tool_name, "error")
        out = "\n".join(buf)
        with self._results_lock:
            self._binary_results[label] = out
        return out

    # ── Per-binary workers ─────────────────────────────────────────
    def _run_whatweb(self, path, url, tool_name, label):
        # Aggression level 3 = a few extra probes without being too
        # loud.  -a 4 is full-on fingerprint-bombing — leave that for
        # user override in Phase 2.
        #
        # ``--color=never`` is critical: when stdout is a pipe (which
        # it always is here) some whatweb builds still emit ANSI
        # colour codes around plugin tokens like ``Title``.  The
        # extra ``\x1b[0m`` between ``Title`` and ``[`` breaks the
        # ``Plugin[value]`` regex in ``_build_profile`` and silently
        # produces a 0-tech-signals profile even though whatweb
        # detected everything correctly.  Forcing colour off makes
        # the parser deterministic.
        self._stream_cmd(
            [path, "--color=never", "-a", "3", "--no-errors", url],
            tool_name, label, timeout=60)

    def _run_httpx(self, path, url, tool_name, label):
        # Pipe URL via stdin — works with ProjectDiscovery Go httpx
        # (which reads targets from stdin) and avoids the `-u` flag
        # that doesn't exist in the Python httpx CLI.
        argv = [path, "-silent", "-json",
                "-status-code", "-title", "-tech-detect",
                "-tls-grab", "-cdn", "-server", "-jarm",
                "-follow-redirects", "-timeout", "10"]
        self._stream_cmd(argv, tool_name, label, timeout=60,
                         stdin_data=url)

    def _run_nuclei(self, path, url, tool_name, label):
        # Heavy tags (fuzzing, CVE) are skipped on the first pass —
        # we want quick coverage, not a 30-minute full nuclei run.
        # The post-scan dialog will offer "nuclei full CVE" as a
        # recommended next step for the user to fire manually.
        argv = [path, "-u", url, "-silent",
                "-tags", "tech,exposure,default-logins,misconfig",
                "-severity", "info,low,medium,high,critical",
                "-rate-limit", "50", "-timeout", "10",
                "-jsonl"]
        self._stream_cmd(argv, tool_name, label, timeout=180)

    def _run_katana(self, path, url, tool_name, label):
        """Katana crawler — JS-aware, handles React/Vue SPAs where
        classic crawlers (gobuster/ffuf) discover nothing because
        routes are assembled client-side.

        Flags:
          -d 2       depth 2 (root + 1 hop) — enough for a fingerprint
                     pass, deeper is a separate user-driven run
          -jc        enable JavaScript endpoint parsing
          -silent    suppress the banner
          -json      structured lines for the profile builder
          -kf all    every known form of URL extraction (sitemap,
                     robots, HTML links, JS files)
          -c 10      concurrency — polite but not glacial
        """
        argv = [path, "-u", url, "-d", "2", "-jc", "-silent",
                "-json", "-kf", "all", "-c", "10", "-timeout", "10"]
        self._stream_cmd(argv, tool_name, label, timeout=180)

    def _run_html_home(self, path, url, tool_name, label):
        """Fetch the target URL's HTML body and store it verbatim in
        _binary_results["html-home"].  _build_profile parses it for
        structural hints (meta generator, forms, script src).

        Capped at 512 KB so a misbehaving target streaming endless
        HTML doesn't pin memory.  Redirects followed (-L) up to 3.
        """
        try:
            r = subprocess.run(
                [path, "-s", "-L", "-k", "--max-redirs", "3",
                 "--max-filesize", "524288",  # 512 KB cap
                 "-A", "Mozilla/5.0 (HAWK Oracle recon)",
                 "-m", "15", url],
                capture_output=True, text=True, timeout=20,
                errors="replace", env=_tool_env())
            body = r.stdout or ""
        except Exception as e:
            self._emit(f"  [oracle:{label}] fetch failed: {e}",
                       tool_name, "warn")
            body = ""
        with self._results_lock:
            self._binary_results[label] = body
        if body:
            self._emit(
                f"  [{label}] fetched {len(body)} bytes of homepage",
                tool_name, "dim")

    def _run_robots_body(self, path, url, tool_name, label):
        """Pull the body of /robots.txt.  Disallowed paths are often
        the most interesting attack surface — admin panels, staging
        endpoints, backup locations."""
        from urllib.parse import urlsplit, urljoin
        base = urlsplit(url)
        robots_url = urljoin(
            f"{base.scheme}://{base.netloc}/", "robots.txt")
        try:
            r = subprocess.run(
                [path, "-s", "-L", "-k", "--max-redirs", "2",
                 "--max-filesize", "65536",
                 "-m", "10", robots_url],
                capture_output=True, text=True, timeout=15,
                errors="replace", env=_tool_env())
            body = r.stdout or ""
        except Exception:
            body = ""
        with self._results_lock:
            self._binary_results[label] = body
        if body and ("disallow" in body.lower() or
                     "allow" in body.lower()):
            self._emit(
                f"  [{label}] robots.txt has "
                f"{body.lower().count('disallow')} Disallow lines",
                tool_name, "info")

    def _run_curl_probes(self, path, url, tool_name, label):
        """Probe a short list of interesting paths with curl -I.

        These are the "silver bullets" of web recon — files that,
        when accessible, hand over secrets or tell you a ton about
        the app.  We just want to know if each path exists (HEAD)
        and what status it returns.  The heavy parsing happens in
        _build_profile().
        """
        from urllib.parse import urlsplit, urljoin
        import uuid as _uuid
        base = urlsplit(url)
        root = f"{base.scheme}://{base.netloc}/"

        probes = [
            "/robots.txt",
            "/sitemap.xml",
            "/.git/HEAD",
            "/.env",
            "/.DS_Store",
            "/server-status",
            "/server-info",
            "/phpinfo.php",
            "/graphql",
            "/api",
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/.well-known/security.txt",
            "/admin",
            "/administrator",
            "/wp-login.php",
            "/user/login",
        ]

        # Soft-404 baseline: hit a guaranteed-nonexistent path first.
        # Real 404 servers respond 404; SPAs / catch-all routers respond
        # 200 with a constant-sized error shell. We use size+content-type
        # to flag probes that match the baseline as soft-404.
        def _probe(target_url):
            try:
                r = subprocess.run(
                    [path, "-s", "-o", "/dev/null",
                     "-w", "%{http_code}|%{size_download}|%{content_type}",
                     "-m", "8", "-k", "-L", "--max-redirs", "3",
                     target_url],
                    capture_output=True, text=True, timeout=12,
                    env=_tool_env())
                parts = (r.stdout or "").strip().split("|")
                if len(parts) >= 3:
                    return {
                        "status": parts[0],
                        "size":   int(parts[1]) if parts[1].isdigit() else 0,
                        "ct":     (parts[2] or "").split(";")[0].strip().lower(),
                    }
            except Exception:
                return None
            return None

        baseline = _probe(urljoin(root, _uuid.uuid4().hex))

        def _is_soft404(p):
            if not baseline or not p:
                return False
            if p["status"] != baseline["status"]:
                return False
            if p["ct"] != baseline["ct"]:
                return False
            bs = baseline["size"] or 1
            return abs(p["size"] - bs) / bs < 0.05

        lines = []
        for p in probes:
            if self._cancelled:
                break
            target_url = urljoin(root, p.lstrip("/"))
            pr = _probe(target_url)
            if not pr:
                lines.append(f"ERR  {p}")
                continue
            code = pr["status"]
            if _is_soft404(pr):
                # Mark as soft-404: written to results so _build_profile
                # can skip it; not surfaced to the terminal.
                lines.append(f"SOFT404 {p}")
                continue
            lines.append(f"{code} {p}")
            if code and code not in ("404", "000"):
                self._emit(
                    f"  [probe] {p}  →  HTTP {code}",
                    tool_name, "info")
        with self._results_lock:
            self._binary_results[label] = "\n".join(lines)

    # ── Aggregation / recommendations (Phase 1 stubs) ──────────────
    def _build_profile(self, url: str) -> dict:
        """Phase 1: minimal profile — extract tech strings from
        whatweb's one-line summary and httpx's JSON line.  Deep
        parsing lives in Phase 2 (see utils/web_oracle_profile.py).
        """
        profile = {
            "url":            url,
            "tech":           [],     # [{"name":..,"version":..,"source":".."}]
            "auth":           None,   # dict or None
            "apis":           [],     # [{"kind":..,"path":..}]
            "exposures":      [],     # [{"path":..,"status":..,"severity":".."}]
            "cves":           [],     # [{"id":..,"template":..,"severity":".."}]
            "regional_flags": [],     # populated in Phase 3
            "headers":        {},
            "tls":            {},
            "raw":            dict(self._binary_results),
        }
        ww = self._binary_results.get("whatweb", "") or ""
        # Strip ANSI escape sequences as a safety net.  Even with
        # ``--color=never`` passed to whatweb, some builds (or older
        # apt versions) keep emitting bold/colour codes.  Without
        # this strip the regex below sees "Title\x1b[0m[..." and
        # silently misses every plugin.
        if "\x1b[" in ww:
            ww = re.sub(r"\x1b\[[0-9;]*m", "", ww)
        # whatweb normal output: one line per URL, comma-separated
        # "PluginName[version]" entries.  Grab them with a simple
        # regex — Phase 2 will wire the JSON (-v --log-json) path.
        for m in re.finditer(r"([A-Za-z][A-Za-z0-9._-]+)\[([^\]]+)\]",
                              ww):
            profile["tech"].append({
                "name":    m.group(1),
                "version": m.group(2),
                "source":  "whatweb",
            })
        # httpx JSON line → dict.  httpx wraps into a single JSON
        # object per URL with -json, so extract it.
        hx = self._binary_results.get("httpx", "") or ""
        for line in hx.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            profile["headers"] = d.get("header", {}) or {}
            profile["tls"] = d.get("tls", {}) or {}
            for t in (d.get("tech") or []):
                profile["tech"].append({
                    "name": t, "version": "", "source": "httpx"})
            profile["status"]      = d.get("status_code")
            profile["title"]       = d.get("title", "")
            profile["server"]      = d.get("webserver", "")
            profile["content_len"] = d.get("content_length", 0)
            break

        # curl-probes aggregated output → exposures.
        curl = self._binary_results.get("curl-probes", "") or ""
        for line in curl.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            code, pth = parts[0], " ".join(parts[1:])
            if code in ("200", "301", "302", "403"):
                sev = "medium"
                if pth in ("/.env", "/.git/HEAD", "/.DS_Store",
                           "/phpinfo.php", "/server-status"):
                    sev = "high" if code == "200" else "low"
                profile["exposures"].append({
                    "path": pth, "status": code, "severity": sev})

        # nuclei JSONL lines → cves + tech + exposures.
        nc = self._binary_results.get("nuclei", "") or ""
        for line in nc.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            info = d.get("info", {}) or {}
            tmpl_id = d.get("template-id", "") or ""
            name = info.get("name", "") or tmpl_id
            severity = (info.get("severity") or "info").lower()
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            if "cve" in tags or (tmpl_id.upper().startswith("CVE-")):
                profile["cves"].append({
                    "id":       tmpl_id,
                    "name":     name,
                    "severity": severity,
                    "tags":     tags,
                })
            elif "exposure" in tags or "misconfig" in tags:
                profile["exposures"].append({
                    "path":     d.get("matched-at", "") or d.get(
                                    "host", ""),
                    "status":   "nuclei",
                    "severity": severity,
                    "template": tmpl_id,
                })
            elif "tech" in tags:
                profile["tech"].append({
                    "name":    name,
                    "version": (info.get("metadata", {}) or {}).get(
                                "version", ""),
                    "source":  "nuclei",
                })

        # ── Deep HTML parse (homepage body) ─────────────────────────
        html = self._binary_results.get("html-home", "") or ""
        if html:
            # <meta name="generator" content="..."> — WordPress/Joomla/
            # Drupal and many custom CMSes emit this, it's the single
            # most reliable CMS tag.
            for m in re.finditer(
                    r'<meta\s+[^>]*name=["\']generator["\']'
                    r'[^>]*content=["\']([^"\']+)["\']', html, re.I):
                profile["tech"].append({
                    "name":    "generator",
                    "version": m.group(1)[:80],
                    "source":  "html-meta",
                })

            # <form action=...> — auth form detection.  If there's a
            # password field we flag it as a login surface.
            for m in re.finditer(
                    r'<form\b[^>]*action=["\']([^"\']*)["\'][^>]*>'
                    r'([\s\S]{0,1500}?)</form>', html, re.I):
                action = m.group(1).strip() or "/"
                block  = m.group(2)
                has_pwd = bool(re.search(
                    r'<input[^>]+type=["\']password["\']', block, re.I))
                # Collect input names for body-template hints.
                names = re.findall(
                    r'<input[^>]+name=["\']([^"\']+)["\']',
                    block, re.I)
                if has_pwd:
                    if profile.get("auth") is None:
                        profile["auth"] = {
                            "type":       "form",
                            "login_path": action,
                            "fields":     names[:8],
                        }
                    profile["exposures"].append({
                        "path":     action,
                        "status":   "form",
                        "severity": "info",
                        "note":     "login form (password field)",
                    })

            # <script src="..."> — library fingerprints (jquery, react,
            # angular, vue, bootstrap...) and bundled API endpoints.
            for m in re.finditer(
                    r'<script\b[^>]*src=["\']([^"\']+)["\']',
                    html, re.I):
                src = m.group(1)
                lib = ""
                for needle in ("jquery", "react", "angular", "vue",
                               "bootstrap", "ember", "backbone",
                               "next", "nuxt", "svelte"):
                    if needle in src.lower():
                        lib = needle
                        break
                if lib:
                    profile["tech"].append({
                        "name":    lib,
                        "version": "",
                        "source":  "html-script",
                    })

            # JWT hunting in inline JS — bearer tokens sometimes leak
            # straight into the page.
            jwt_hint = re.search(
                r'eyJ[A-Za-z0-9_-]{10,}\.'
                r'eyJ[A-Za-z0-9_-]{10,}\.'
                r'[A-Za-z0-9_-]{10,}', html)
            if jwt_hint:
                profile["exposures"].append({
                    "path":     "/ (inline JS)",
                    "status":   "jwt-leak",
                    "severity": "high",
                    "note":     "JWT-shaped token in page HTML — "
                                "decode with jwt_tool.",
                    "sample":   jwt_hint.group(0)[:40] + "…",
                })

            # GraphQL client hints in JS (apollo, urql, relay).
            for needle in ("apollo-client", "apollographql",
                            "urql", "relay-runtime"):
                if needle in html.lower():
                    profile["apis"].append({
                        "kind": "GraphQL",
                        "path": "/graphql  (inferred from JS bundle)",
                    })
                    break

            # ── Client-side redirect detection ─────────────────────
            REDIRECT_PATTERNS = [
                (r'window\.location\s*[=.]\s*["\']([^"\']+)["\']',
                 "JS redirect (window.location)"),
                (r'document\.location\s*[=.]\s*["\']([^"\']+)["\']',
                 "JS redirect (document.location)"),
                (r'location\.href\s*=\s*["\']([^"\']+)["\']',
                 "JS redirect (location.href)"),
                (r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
                 "JS redirect (location.replace)"),
                (r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
                 "JS redirect (location.assign)"),
                (r'<meta\s+http-equiv=["\']refresh["\']\s+'
                 r'content=["\'][^"\']*url=([^"\']+)["\']',
                 "Meta refresh redirect"),
                (r'window\.location\.reload\s*\(',
                 "JS page reload (window.location.reload)"),
                (r'document\.write\s*\(\s*["\']<meta\s+http-equiv',
                 "Dynamic meta redirect via document.write"),
                (r'setTimeout\s*\(\s*function\s*\(\)\s*\{[^}]*location',
                 "Delayed JS redirect (setTimeout)"),
                (r'(?:You are being |You should be )'
                 r'<a href=["\']([^"\']+)["\']>redirected</a>',
                 "Framework redirect page (Flask/Rails)"),
                (r'(?:Redirecting to|Redirecting\.\.\.)\s*'
                 r'<a\s+href=["\']([^"\']+)["\']',
                 "Server-side redirect splash page"),
                (r'history\.pushState\s*\([^)]*,\s*[^,]*,\s*["\']([^"\']+)',
                 "JS history.pushState (URL rewrite without reload)"),
                (r'history\.replaceState\s*\([^)]*,\s*[^,]*,\s*["\']([^"\']+)',
                 "JS history.replaceState (URL rewrite without reload)"),
            ]
            found_redirects = []
            for pat, label in REDIRECT_PATTERNS:
                for m in re.finditer(pat, html, re.I | re.S):
                    dest = m.group(1) if m.lastindex else ""
                    found_redirects.append({
                        "type": label,
                        "destination": dest[:200] if dest else "(self)",
                    })
            if found_redirects:
                seen_r2 = set()
                deduped = []
                for r in found_redirects:
                    k = (r["type"], r["destination"])
                    if k not in seen_r2:
                        seen_r2.add(k)
                        deduped.append(r)
                profile["exposures"].append({
                    "path":     "/ (HTML body)",
                    "status":   "client-redirect",
                    "severity": "medium",
                    "note":     (
                        "Client-side redirect detected in HTML — "
                        "the server returns the page but JavaScript or "
                        "a <meta> tag sends the browser elsewhere. "
                        "This is a security issue because:\n"
                        "  • The original page content is still accessible "
                        "(curl/Burp see it, the browser doesn't)\n"
                        "  • Sensitive data, admin panels, or API endpoints "
                        "may be hidden behind the redirect\n"
                        "  • Access control is enforced client-side, not "
                        "server-side — anyone with curl can bypass it\n\n"
                        "HOW TO EXPLOIT:\n"
                        "  1. Use curl (no JS engine) to fetch the page:\n"
                        "       curl -s http://TARGET/\n"
                        "     → You see the REAL content the server sends\n"
                        "  2. In Burp Suite, intercept the response and "
                        "remove/modify the redirect JS\n"
                        "  3. In Firefox: disable JavaScript (about:config → "
                        "javascript.enabled → false), then visit the page\n"
                        "  4. Check if the redirect destination itself has "
                        "useful info (login page? dashboard?)\n\n"
                        "Detected redirects:\n" +
                        "\n".join(
                            f"  • {r['type']} → {r['destination']}"
                            for r in deduped[:10]
                        )
                    ),
                })

        # ── robots.txt parse ────────────────────────────────────────
        robots = self._binary_results.get("robots-body", "") or ""
        if robots:
            disallow = re.findall(
                r"(?im)^\s*Disallow:\s*(\S+)", robots)
            # De-dup and trim.
            seen_r = set()
            for path in disallow:
                if path in seen_r or path in ("/", "", "*"):
                    continue
                seen_r.add(path)
                profile["exposures"].append({
                    "path":     path,
                    "status":   "robots-disallow",
                    "severity": "info",
                    "note":     "Listed as Disallow in robots.txt — "
                                "often hides admin/staging surface.",
                })

        # ── katana endpoints → profile["endpoints"] + auto-classify ─
        kt = self._binary_results.get("katana", "") or ""
        endpoints = []
        for line in kt.splitlines():
            line = line.strip()
            if not line:
                continue
            # katana -json emits one URL per line in a dict or a
            # bare URL depending on version.  Handle both.
            if line.startswith("{"):
                try:
                    d = json.loads(line)
                    ep = d.get("endpoint") or d.get("url") or ""
                except Exception:
                    ep = ""
            else:
                ep = line
            if ep:
                endpoints.append(ep)
        # Dedup, cap at 200 so the profile stays printable.
        profile["endpoints"] = list(dict.fromkeys(endpoints))[:200]

        # Auto-classify obvious API endpoints from katana results.
        for ep in profile["endpoints"]:
            low = ep.lower()
            if "/graphql" in low:
                profile["apis"].append(
                    {"kind": "GraphQL", "path": ep})
            elif re.search(r"/api(/|$|v\d)", low):
                profile["apis"].append({"kind": "REST", "path": ep})
            elif low.endswith(".wsdl") or "soap" in low:
                profile["apis"].append({"kind": "SOAP", "path": ep})
            elif "swagger" in low or "openapi" in low:
                profile["apis"].append(
                    {"kind": "OpenAPI", "path": ep})

        # Dedup APIs by (kind, path).
        seen_a = set()
        uniq_a = []
        for a in profile["apis"]:
            key = (a.get("kind"), a.get("path"))
            if key in seen_a:
                continue
            seen_a.add(key)
            uniq_a.append(a)
        profile["apis"] = uniq_a

        # Dedup tech by lowercase name (+version, if any).
        seen = set()
        uniq = []
        for t in profile["tech"]:
            key = (t["name"].lower(), t.get("version", ""))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(t)
        profile["tech"] = uniq

        return profile

    # ── API Discovery ───────────────────────────────────────────────
    def _run_api_discovery(self, url: str, profile: dict) -> list:
        """Framework-aware API surface discovery.

        Strategy:
          1. Build a baseline by fetching `<url>/<random-uuid>` and
             recording (status, content_length, content_type).  Any
             real probe whose response matches this baseline is a
             SOFT-404 and gets discarded — kills 90% of false positives
             on SPAs that 200 every path.
          2. Probe a framework-agnostic core list (always).
          3. Probe framework-specific lists when the tech stack hints
             at Spring / Flask / Express / ASP.NET / WordPress.
          4. For Swagger/OpenAPI hits, GET the JSON and parse the
             route list into the result.
          5. For GraphQL hits, send the introspection query and grab
             the schema's top-level type names.

        Side effects: every confirmed endpoint is also pushed to
        `app.assault_state` (when reachable) so Bloody Crawl and
        Injection can pick them up.
        """
        import json as _json
        import socket as _socket
        import subprocess as _sp
        import uuid as _uuid

        from urllib.parse import urlparse as _up, urljoin as _urljoin

        # profile["tech"] is a list of dicts ({name, version, source}) —
        # built that way in _build_profile.  The old code did t.lower()
        # treating each entry as a string, which raised AttributeError on
        # the first element and silently killed the entire framework-aware
        # phase (no probes, no swagger/graphql, empty API surface) behind
        # a single warn.  Build the signature from the dict fields.
        # profile["tech"] is a list of dicts ({name, version, source}) —
        # built that way in _build_profile.  The old code did t.lower()
        # treating each entry as a string, which raised AttributeError on
        # the first element and silently killed the entire framework-aware
        # phase (no probes, no swagger/graphql, empty API surface) behind
        # a single warn.  Build the signature from the dict fields.
        tech_lower = " ".join(
            f"{t.get('name', '')} {t.get('version', '')}"
            for t in (profile.get("tech") or [])
            if isinstance(t, dict)
        ).lower()
        framework = self._detect_framework(tech_lower)

        # ── Baseline (soft-404 fingerprint) ─────────────────────
        baseline_path = f"/{_uuid.uuid4().hex}"
        baseline = self._curl_probe(_urljoin(url, baseline_path))
        # Use a fuzzy match: status + ±5% size, content-type match.
        def _is_soft404(probe: dict) -> bool:
            if not baseline:
                return False
            if probe["status"] != baseline["status"]:
                return False
            if probe["content_type"] != baseline["content_type"]:
                return False
            bs = baseline["size"] or 1
            return abs(probe["size"] - bs) / bs < 0.05

        # ── Probe lists ─────────────────────────────────────────
        AGNOSTIC = [
            "/robots.txt", "/sitemap.xml",
            "/.well-known/openid-configuration",
            "/.well-known/security.txt",
            "/server-status", "/server-info",
            "/.git/HEAD", "/.git/config", "/.env", "/.env.local",
            "/graphql", "/graphiql", "/__graphql",
            "/swagger.json", "/swagger-ui/", "/swagger-ui.html",
            "/openapi.json", "/openapi.yaml", "/api-docs",
            "/v2/api-docs", "/v3/api-docs",
            "/api", "/api/v1/", "/api/v2/", "/api/v3/",
            "/api/health", "/api/status",
        ]
        FRAMEWORK_PATHS = {
            "spring": [
                "/actuator", "/actuator/env", "/actuator/health",
                "/actuator/beans", "/actuator/mappings",
                "/actuator/heapdump", "/actuator/threaddump",
                "/actuator/configprops", "/actuator/loggers",
                "/v3/api-docs", "/swagger-ui/", "/swagger-ui.html",
            ],
            "flask": [
                "/graphql", "/graphiql", "/api/docs",
                "/swagger.json", "/openapi.json",
                "/api", "/admin", "/console",
            ],
            "django": [
                "/admin/", "/admin/login/", "/api/", "/swagger/",
                "/redoc/", "/__debug__/", "/api/schema/",
            ],
            "express": [
                "/graphql", "/api-docs", "/swagger.json",
                "/.env", "/api", "/api/v1/",
            ],
            "asp.net": [
                "/elmah.axd", "/trace.axd", "/_blazor",
                "/api/swagger.json", "/swagger/v1/swagger.json",
                "/swagger/", "/Account/Login",
            ],
            "iis": [
                "/elmah.axd", "/trace.axd",
                "/swagger/v1/swagger.json", "/swagger/",
            ],
            "php": [
                "/info.php", "/phpinfo.php", "/admin",
                "/admin/login.php",
            ],
            "wordpress": [
                "/wp-json/", "/wp-json/wp/v2/", "/wp-json/wp/v2/users",
                "/xmlrpc.php", "/wp-admin/", "/wp-login.php",
                "/wp-admin/admin-ajax.php",
            ],
            "node": [
                "/graphql", "/api-docs", "/swagger.json",
            ],
        }

        probes = list(AGNOSTIC)
        if framework and framework in FRAMEWORK_PATHS:
            self._emit(
                f"  [oracle:api] tech hint '{framework}' — adding "
                f"{len(FRAMEWORK_PATHS[framework])} framework probes",
                "oracle", "info")
            for p in FRAMEWORK_PATHS[framework]:
                if p not in probes:
                    probes.append(p)

        # Dedup with normalised paths.
        seen = set()
        ordered = []
        for p in probes:
            if p not in seen:
                seen.add(p)
                ordered.append(p)

        # ── Run probes ──────────────────────────────────────────
        findings = []
        for path in ordered:
            if self._cancelled:
                break
            full = _urljoin(url, path)
            probe = self._curl_probe(full)
            if not probe:
                continue
            if probe["status"] in (0, 404):
                continue
            if _is_soft404(probe):
                continue
            kind = self._classify_api_kind(path, probe)
            entry = {
                "url":       full,
                "path":      path,
                "kind":      kind,
                "status":    probe["status"],
                "size":      probe["size"],
                "content_type": probe["content_type"],
                "framework": framework or "",
            }
            self._emit(
                f"  [oracle:api] [{probe['status']}] {path}  "
                f"({probe['size']}B, {probe['content_type'] or '?'})",
                "oracle", "info")

            # Special handling per kind
            try:
                if kind in ("swagger", "openapi"):
                    routes = self._fetch_swagger_routes(full)
                    if routes:
                        entry["routes"] = routes[:50]
                        self._emit(
                            f"      └─ {len(routes)} routes parsed "
                            f"from spec",
                            "oracle", "success")
                elif kind == "graphql":
                    types = self._graphql_introspection(full)
                    if types:
                        entry["graphql_types"] = types[:30]
                        self._emit(
                            f"      └─ GraphQL introspection "
                            f"OK — {len(types)} types",
                            "oracle", "success")
            except Exception as e:
                self._emit(
                    f"      └─ deep probe failed: {e}",
                    "oracle", "dim")
            findings.append(entry)

        # ── Push to AssaultState (best effort) ──────────────────
        try:
            from utils.assault_state import ApiEndpoint
            # AssaultState lives on the app object; we don't have a
            # direct handle here.  Use a module-level shim by setting
            # a callback if present (the route layer wires it).  If
            # not wired, we silently skip the push — the GUI can read
            # from the profile dict directly.
            push = getattr(self, "_assault_state_push", None)
            if callable(push):
                for f in findings:
                    push(ApiEndpoint(
                        url=f["url"], kind=f["kind"],
                        method="GET", status=f["status"],
                        title=f.get("path", ""),
                        framework=f.get("framework", ""),
                        notes=f.get("content_type", "")))
        except Exception:
            pass

        return findings

    def _detect_framework(self, tech_lower: str) -> str:
        """Map the joined-and-lowercased tech_stack signature to one of
        our framework keys."""
        # Order matters — more specific first (WordPress before PHP).
        for needle, fw in (
            ("wordpress", "wordpress"),
            ("django",    "django"),
            ("flask",     "flask"),
            ("spring",    "spring"),
            ("asp.net",   "asp.net"),
            ("aspnet",    "asp.net"),
            ("iis",       "iis"),
            ("express",   "express"),
            ("node",      "node"),
            ("php",       "php"),
        ):
            if needle in tech_lower:
                return fw
        return ""

    def _curl_probe(self, url: str, timeout: int = 5) -> dict:
        """Single GET probe — returns {status, size, content_type}.

        Uses curl since it's already a HAWK dependency and gives us
        accurate byte-counts via -w.  Skipped silently on errors so
        one bad URL doesn't tank the discovery loop.
        """
        import subprocess as _sp
        try:
            r = _sp.run(
                ["curl", "-s", "-L", "-o", "/dev/null",
                 "-w", "%{http_code}|%{size_download}|%{content_type}",
                 "--max-time", str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 3,
                env=_tool_env())
            parts = (r.stdout or "").strip().split("|")
            if len(parts) >= 3:
                return {
                    "status": int(parts[0]) if parts[0].isdigit() else 0,
                    "size":   int(parts[1]) if parts[1].isdigit() else 0,
                    "content_type": (parts[2] or "").split(";")[0].strip().lower(),
                }
        except Exception:
            pass
        return {}

    def _classify_api_kind(self, path: str, probe: dict) -> str:
        p = path.lower()
        ct = probe.get("content_type", "")
        if "graphql" in p or "graphiql" in p:
            return "graphql"
        if "swagger" in p:
            return "swagger"
        if "openapi" in p or "api-docs" in p:
            return "openapi"
        if "actuator" in p:
            return "actuator"
        if p in ("/.env", "/.env.local"):
            return "envfile"
        if p.startswith(("/.git/", "/git/")):
            return "vcs"
        if "wp-json" in p or "xmlrpc.php" in p:
            return "wordpress"
        if "/api" in p:
            return "rest"
        return "other"

    def _fetch_swagger_routes(self, url: str) -> list:
        """Fetch a swagger.json / openapi.json and extract the path
        list.  Returns [] on parse failure (most likely a swagger-ui
        HTML page rather than the raw spec, in which case we leave
        the route list empty)."""
        import subprocess as _sp
        import json as _json
        try:
            r = _sp.run(
                ["curl", "-s", "-L", "--max-time", "8",
                 "--max-filesize", "1048576", url],
                capture_output=True, text=True, timeout=12,
                env=_tool_env())
            if not r.stdout:
                return []
            data = _json.loads(r.stdout)
            paths = data.get("paths") or {}
            if isinstance(paths, dict):
                return sorted(paths.keys())
        except Exception:
            return []
        return []

    def _graphql_introspection(self, url: str) -> list:
        """Run the standard introspection query against a GraphQL
        endpoint.  Returns the list of top-level type names, or []
        if disabled / blocked / not GraphQL."""
        import subprocess as _sp
        import json as _json
        query = (
            '{"query":"{__schema{types{name fields{name type{name}}}}}"}'
        )
        try:
            r = _sp.run(
                ["curl", "-s", "-L", "--max-time", "8",
                 "-X", "POST", "-H", "Content-Type: application/json",
                 "-d", query, url],
                capture_output=True, text=True, timeout=12,
                env=_tool_env())
            if not r.stdout:
                return []
            data = _json.loads(r.stdout)
            types = data.get("data", {}).get("__schema", {}).get("types") or []
            names = [t.get("name") for t in types
                     if isinstance(t, dict) and t.get("name")]
            return [n for n in names if not n.startswith("__")]
        except Exception:
            return []

    def _recommend(self, profile: dict) -> list:
        """Full recommendations via utils.web_oracle_recommendations.

        The engine also emits regional/stack flags (federation IdPs,
        local CMS concentrations, ERP stacks) — we stash those in
        profile["regional_flags"] so the post-scan dialog can render
        them in a dedicated section, separate from actionable
        recommendations.
        """
        try:
            from utils.web_oracle_recommendations import (
                recommend, regional_flags)
            recs = recommend(profile)
            profile["regional_flags"] = regional_flags(profile)
        except Exception as e:
            print(f"[HAWK] recommendations engine crashed: {e}")
            recs = []
            profile["regional_flags"] = []
        return recs

    # ── UI-thread-safe done dispatch ───────────────────────────────
    def _dispatch_done(self, tool_name, rc, log, profile,
                        recommendations):
        if not self.done_callback:
            return
        def _fire():
            try:
                self.done_callback(tool_name, rc, log,
                                    profile, recommendations)
            except TypeError:
                # Older callers expect (tool_name, rc, log) — fall
                # back so we don't break the generic KillChainCard
                # done handler.
                try:
                    self.done_callback(tool_name, rc, log)
                except Exception as e:
                    print(f"[HAWK] Oracle done_callback failed: {e}")
            except Exception as e:
                print(f"[HAWK] Oracle done_callback failed: {e}")

        if self.ui_dispatcher:
            try:
                self.ui_dispatcher(_fire)
                return
            except Exception:
                pass
        _fire()
