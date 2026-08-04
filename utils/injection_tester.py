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

"""Injection Tester — evidence-first parameter probing.

Tests one (URL, method, parameter) tuple at a time for:
  • REFLECTION  — gates XSS/SSTI; a magic value is sent and we look
    for it back in the response unchanged.
  • SQLi        — error-based + behaviour-diff; aggressive mode adds
    sqlmap.
  • XSS         — light reflected payloads; aggressive adds dalfox.
  • LFI         — /etc/passwd marker check; PHP filter wrapper.
  • CMDi        — `;id`, `|id`, backtick variants; "uid=" marker.
    Aggressive adds commix.
  • SSTI        — `{{7*7}}` and friends; "49" marker.
  • UPLOAD BYPASS — extension/MIME spoof tests on multipart forms.

All Safe-mode probes use plain curl with conservative timeouts and
1 req/s rate limiting (per target).  Aggressive shells out to the
upstream tool but still streams its stdout via the same logger so
the user sees what's happening.

Scope guard: every request URL is checked against `target_host`
before going out.  A param living on `cdn.example.com` is silently
dropped if the bound target is `app.example.com`.

Findings are emitted progressively via `on_finding(dict)` so the GUI
can push them to Target Intel as soon as they're confirmed.  The
final `on_done(stats)` carries totals.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse


# ── Target type ─────────────────────────────────────────────────────

@dataclass
class InjectTarget:
    """One injection target.

    For GET targets, params live in the URL's query string and we
    rebuild the URL with the test payload spliced in for the param
    being tested.

    For POST targets, params are sent as form fields.

    `upload_field` (when set) marks this target as an upload form;
    the upload-bypass test body uses multipart/form-data.
    """
    url:           str
    method:        str = "GET"
    params:        list = field(default_factory=list)
    upload_field:  Optional[str] = None


# ── Markers and payload tables ──────────────────────────────────────

# Reflection canary — the random suffix prevents accidental matches
# in echoed framework banners or static text.
_REFLECT_TAG = "HAWK_R3FL_"
_REFLECT_VAL = lambda: _REFLECT_TAG + uuid.uuid4().hex[:8]

# Safe-mode SQL payloads, ordered cheap → revealing.
SQLI_SAFE_PAYLOADS = [
    ("'",                   "single quote"),
    ('"',                   "double quote"),
    ("')",                  "paren-quote"),
    ("' OR '1'='1",         "OR 1=1"),
    ("' AND '1'='2",        "AND 1=2"),
    ("'-- -",               "comment trail"),
]
SQLI_ERROR_MARKERS = [
    r"you have an error in your sql syntax",
    r"warning.*\bmysqli?_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlite3?\.\w+: ",
    r"sqlstate\[\w+\]",
    r"pg_query\(\)",
    r"npgsql\.",
    r"ora-[0-9]+",
    r"microsoft sql server",
    r"odbc.*\bdriver\b",
    r"syntax error.*at or near",
]

# Reflected XSS — only fired when the param is reflected.  We don't
# *prove* execution from curl alone (that needs a browser); we mark
# MEDIUM if the payload comes back un-encoded.
XSS_SAFE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "javascript:alert(1)",
]

LFI_SAFE_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=index.php",
]
LFI_MARKERS = (r"root:[x*!]:0:0:",
               r"daemon:[x*!]:1:1:")
LFI_PHP_FILTER_MARKER = r"PD9waHA"  # base64("<?php")

CMD_PAYLOADS = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "&& id",
    " || id",
]
CMD_MARKER = r"uid=\d+\("

SSTI_PAYLOADS = [
    ("{{7*7}}",        "Jinja2 / Twig"),
    ("${7*7}",         "Spring SpEL / FreeMarker"),
    ("<%= 7*7 %>",     "ERB"),
    ("#{7*7}",         "Ruby string interp"),
    ("{7*7}",          "Generic"),
]
SSTI_MARKER = "49"

# Upload-bypass — we don't actually keep uploaded shells; we test
# whether the server *accepts* the upload (200/201/302 status).
UPLOAD_TESTS = [
    ("hawk_test.php",   "<?php echo 'hawk'; ?>",
     "application/x-php"),
    ("hawk_test.phtml", "<?php echo 'hawk'; ?>",
     "application/octet-stream"),
    ("hawk_test.php5",  "<?php echo 'hawk'; ?>",
     "application/octet-stream"),
    ("hawk_test.pHp",   "<?php echo 'hawk'; ?>",
     "application/octet-stream"),
    ("hawk_test.php.jpg", "<?php echo 'hawk'; ?>",
     "image/jpeg"),
    ("hawk_test.jpg",   "<?php echo 'hawk'; ?>",
     "image/jpeg"),
]


# ── Curl wrappers ───────────────────────────────────────────────────

def _curl(args, timeout: int = 8) -> tuple[int, str, str]:
    """Run curl, return (status, body, headers).

    We always request `-D -` to capture headers in a separate side-
    channel and `-o -` so the body comes through stdout cleanly.
    """
    full = ["curl", "-s", "-i", "-L", "--max-time", str(timeout)] + args
    try:
        p = subprocess.run(full, capture_output=True, text=True,
                           timeout=timeout + 4)
    except Exception:
        return (0, "", "")
    raw = p.stdout or ""
    head, _sep, body = raw.partition("\r\n\r\n")
    if not _sep:
        # some servers separate by \n\n
        head, _sep, body = raw.partition("\n\n")
    code = 0
    m = re.search(r"^HTTP/[\d\.]+\s+(\d+)", head)
    if m:
        code = int(m.group(1))
    return (code, body, head)


def _splice_get(url: str, param: str, value: str) -> str:
    """Replace `param`'s value in the URL's query string with `value`,
    or append it when missing."""
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    found = False
    new_q = []
    for k, v in q:
        if k == param:
            new_q.append((k, value))
            found = True
        else:
            new_q.append((k, v))
    if not found:
        new_q.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path,
                       p.params, urlencode(new_q, doseq=True),
                       p.fragment))


def _post_body(params: list, focus: str, value: str,
               others_value: str = "1") -> str:
    """Build a urlencoded POST body where `focus` carries the test
    payload and other params get a benign placeholder."""
    fields = []
    seen = set()
    for p in params:
        if p in seen:
            continue
        seen.add(p)
        if p == focus:
            fields.append((p, value))
        else:
            fields.append((p, others_value))
    if focus not in seen:
        fields.append((focus, value))
    return urlencode(fields)


# ── Job ─────────────────────────────────────────────────────────────

class InjectionTesterJob:

    SAFE_RATE_S    = 1.0          # per-request floor, safe mode
    AGGR_RATE_S    = 0.0          # external tools manage their own rate

    def __init__(self,
                 targets: list[InjectTarget],
                 tests: dict,
                 mode: str = "safe",
                 target_host: str = "",
                 cancel_event: Optional[threading.Event] = None,
                 on_log: Optional[Callable[[str, str], None]] = None,
                 on_finding: Optional[Callable[[dict], None]] = None,
                 on_done: Optional[Callable[[dict], None]] = None):
        self.targets      = targets
        self.tests        = tests
        self.mode         = mode
        self.target_host  = (target_host or "").lower()
        self._cancel      = cancel_event or threading.Event()
        self.on_log       = on_log or (lambda *_: None)
        self.on_finding   = on_finding or (lambda *_: None)
        self.on_done      = on_done or (lambda *_: None)
        self._thread      = None
        self._stats       = {"tested": 0, "confirmed": 0, "probable": 0,
                              "skipped": 0, "elapsed": 0.0,
                              "cancelled": False}

    # ── Lifecycle ───────────────────────────────────────────────
    def cancel(self):
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def start(self):
        self._thread = threading.Thread(
            target=self._run, daemon=True,
            name="InjectionTesterJob")
        self._thread.start()

    # ── Scope guard ─────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        if not self.target_host:
            return True
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        return host == self.target_host

    # ── Main loop ───────────────────────────────────────────────
    def _run(self):
        t0 = time.time()
        rate = (self.AGGR_RATE_S if self.mode == "aggressive"
                else self.SAFE_RATE_S)
        try:
            for target in self.targets:
                if self.is_cancelled():
                    break
                if not self._in_scope(target.url):
                    self.on_log(
                        f"  ⊘ scope: skipping out-of-scope target "
                        f"{target.url}", "warn")
                    self._stats["skipped"] += 1
                    continue

                # Upload-only target → only the upload test makes sense.
                if target.upload_field and self.tests.get("upload"):
                    self._test_upload(target)
                    continue

                for param in (target.params or []):
                    if self.is_cancelled():
                        break
                    self.on_log(
                        f"Testing {target.method} "
                        f"{urlparse(target.url).path or '/'}  "
                        f"({param})", "info")
                    self._stats["tested"] += 1

                    is_reflected = self._reflection_probe(target, param)
                    if is_reflected:
                        self.on_log("    [reflect] ✓ reflected in body",
                                    "info")
                    else:
                        self.on_log(
                            "    [reflect] ✗ not reflected (POST or "
                            "encoded)", "dim")

                    if self.tests.get("sqli"):
                        self._test_sqli(target, param, rate)
                    if self.tests.get("xss") and is_reflected:
                        self._test_xss(target, param, rate)
                    if self.tests.get("lfi"):
                        self._test_lfi(target, param, rate)
                    if self.tests.get("cmd"):
                        self._test_cmdi(target, param, rate)
                    if self.tests.get("ssti") and is_reflected:
                        self._test_ssti(target, param, rate)

                # Run upload after the param sweep when both apply.
                if (target.upload_field
                        and self.tests.get("upload")
                        and target.params):
                    self._test_upload(target)

            self._stats["elapsed"] = time.time() - t0
            # Report the abort: a cancelled sweep covered only part of
            # the targets, so "0 confirmed" is not a clean result.
            self._stats["cancelled"] = self.is_cancelled()
            self.on_done(self._stats)
        except Exception as e:
            self.on_log(f"[!] Injection job crashed: {e}", "error")
            self._stats["elapsed"] = time.time() - t0
            self._stats["cancelled"] = self.is_cancelled()
            self.on_done(self._stats)

    # ── Request helpers ─────────────────────────────────────────
    def _send(self, target: InjectTarget, param: str, value: str,
              others_value: str = "1") -> tuple[int, str]:
        """Send one test request — returns (status, body).  Headers
        currently aren't used by the matchers so we drop them."""
        if target.method.upper() == "GET":
            url = _splice_get(target.url, param, value)
            if not self._in_scope(url):
                return (0, "")
            code, body, _ = _curl([url])
            return (code, body)
        # POST
        if not self._in_scope(target.url):
            return (0, "")
        body = _post_body(
            target.params or [param], param, value, others_value)
        code, resp_body, _ = _curl(
            ["-X", "POST", "-H", "Content-Type: application/x-www-form-urlencoded",
             "--data", body, target.url])
        return (code, resp_body)

    def _emit_finding(self, **kw):
        self.on_finding(dict(kw))

    # ── Tests ───────────────────────────────────────────────────
    def _reflection_probe(self, target: InjectTarget, param: str) -> bool:
        canary = _REFLECT_VAL()
        _, body = self._send(target, param, canary)
        return canary in (body or "")

    def _test_sqli(self, target, param, rate):
        # Behaviour-diff samples — collected to detect blind cases.
        sizes = []
        for payload, label in SQLI_SAFE_PAYLOADS:
            if self.is_cancelled():
                return
            code, body = self._send(target, param, payload)
            sizes.append((label, code, len(body or "")))
            for marker in SQLI_ERROR_MARKERS:
                if re.search(marker, body or "", re.I):
                    self.on_log(
                        f"    [sqli] ✓ SQL ERROR — \"{marker}\"",
                        "success")
                    self._stats["confirmed"] += 1
                    self._emit_finding(
                        title=(f"SQL Injection in "
                               f"{urlparse(target.url).path} "
                               f"(parameter: {param})"),
                        severity="high",
                        description=(
                            f"Method: {target.method}\n"
                            f"URL: {target.url}\n"
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Evidence: matched {marker} in response"),
                        impact=("Database access, data exfiltration, "
                                "authentication bypass."),
                        remediation=(
                            "Use parameterized queries / prepared "
                            "statements. Never concatenate user input "
                            "into SQL strings."))
                    return
            time.sleep(rate)

        # Behaviour diff between OR 1=1 and AND 1=2
        try:
            d1 = next(s for lbl, _, s in sizes if lbl == "OR 1=1")
            d2 = next(s for lbl, _, s in sizes if lbl == "AND 1=2")
            if abs(d1 - d2) > 80:
                self.on_log(
                    f"    [sqli] ⚠ behaviour diff "
                    f"(OR 1=1: {d1}B vs AND 1=2: {d2}B) — possible "
                    f"blind SQLi", "warn")
                self._stats["probable"] += 1
                self._emit_finding(
                    title=(f"Possible blind SQL Injection in "
                           f"{urlparse(target.url).path} ({param})"),
                    severity="medium",
                    description=(
                        f"Method: {target.method}\n"
                        f"URL: {target.url}\n"
                        f"Parameter: {param}\n"
                        f"OR 1=1 → {d1}B, AND 1=2 → {d2}B "
                        f"(diff {abs(d1-d2)})"),
                    impact="Possible authentication bypass / data leak.",
                    remediation="Use prepared statements; review "
                                "query branching on user input.")
                # If aggressive, escalate to sqlmap.
                if self.mode == "aggressive":
                    self._aggr_sqlmap(target, param)
                return
        except StopIteration:
            pass
        self.on_log("    [sqli] ✗ not vulnerable (safe payloads)",
                    "dim")
        if self.mode == "aggressive":
            self._aggr_sqlmap(target, param)

    def _test_xss(self, target, param, rate):
        for payload in XSS_SAFE_PAYLOADS:
            if self.is_cancelled():
                return
            _, body = self._send(target, param, payload)
            if payload in (body or ""):
                self.on_log(
                    f"    [xss] ✓ payload reflected un-encoded — "
                    f"{payload[:24]}…", "success")
                self._stats["confirmed"] += 1
                self._emit_finding(
                    title=(f"Reflected XSS in "
                           f"{urlparse(target.url).path} ({param})"),
                    severity="high",
                    description=(
                        f"Method: {target.method}\n"
                        f"URL: {target.url}\n"
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Echoed without HTML encoding."),
                    impact="Session hijack, account takeover, "
                           "phishing in user's browser context.",
                    remediation="Context-aware HTML/JS encoding on "
                                "all reflected user input. CSP "
                                "secondary defence.")
                if self.mode == "aggressive":
                    self._aggr_dalfox(target, param)
                return
            time.sleep(rate)
        self.on_log("    [xss] ✗ not vulnerable (safe payloads)",
                    "dim")
        if self.mode == "aggressive":
            self._aggr_dalfox(target, param)

    def _test_lfi(self, target, param, rate):
        for payload in LFI_SAFE_PAYLOADS:
            if self.is_cancelled():
                return
            _, body = self._send(target, param, payload)
            for marker in LFI_MARKERS:
                if re.search(marker, body or "", re.I):
                    self.on_log(
                        "    [lfi] ✓ /etc/passwd content returned",
                        "success")
                    self._stats["confirmed"] += 1
                    self._emit_finding(
                        title=(f"Local File Inclusion in "
                               f"{urlparse(target.url).path} ({param})"),
                        severity="high",
                        description=(
                            f"Method: {target.method}\n"
                            f"URL: {target.url}\n"
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Evidence: matched {marker}"),
                        impact="Read arbitrary files (config, secrets, "
                               "source code).  Often chains to RCE.",
                        remediation="Whitelist allowed filenames / "
                                    "use opaque IDs that map server-"
                                    "side to a fixed path.")
                    return
            if re.search(LFI_PHP_FILTER_MARKER, body or ""):
                self.on_log(
                    "    [lfi] ✓ php://filter wrapper readable "
                    "(base64 PHP source)", "success")
                self._stats["confirmed"] += 1
                self._emit_finding(
                    title=(f"PHP source disclosure via filter wrapper "
                           f"in {urlparse(target.url).path} ({param})"),
                    severity="high",
                    description=(
                        f"URL: {target.url}\n"
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Body contained base64 PHP signature."),
                    impact="Source code disclosure (DB creds, secrets).",
                    remediation="Disable allow_url_include and url_fopen; "
                                "validate file paths server-side.")
                return
            time.sleep(rate)
        self.on_log("    [lfi] ✗ not vulnerable", "dim")

    def _test_cmdi(self, target, param, rate):
        for payload in CMD_PAYLOADS:
            if self.is_cancelled():
                return
            _, body = self._send(target, param, payload)
            if re.search(CMD_MARKER, body or ""):
                self.on_log(
                    f"    [cmdi] ✓ uid=… returned — {payload}",
                    "success")
                self._stats["confirmed"] += 1
                self._emit_finding(
                    title=(f"Command Injection in "
                           f"{urlparse(target.url).path} ({param})"),
                    severity="critical",
                    description=(
                        f"Method: {target.method}\n"
                        f"URL: {target.url}\n"
                        f"Parameter: {param}\n"
                        f"Payload: {payload}\n"
                        f"Evidence: response contained `uid=…`."),
                    impact="Full RCE in the web app process context.",
                    remediation="Never pass user input into shell. "
                                "Use exec/spawn with array args; "
                                "prefer language-native libraries "
                                "over shelling out.")
                if self.mode == "aggressive":
                    self._aggr_commix(target, param)
                return
            time.sleep(rate)
        self.on_log("    [cmdi] ✗ not vulnerable (safe payloads)", "dim")
        if self.mode == "aggressive":
            self._aggr_commix(target, param)

    def _test_ssti(self, target, param, rate):
        # Baseline first: send the literal "49" canary so we don't get
        # fooled by pages that already contain "49" somewhere static.
        baseline_canary = _REFLECT_VAL()
        _, baseline_body = self._send(target, param, baseline_canary)
        had_49_baseline = re.search(rf"\b{SSTI_MARKER}\b",
                                    baseline_body or "")
        for payload, label in SSTI_PAYLOADS:
            if self.is_cancelled():
                return
            _, body = self._send(target, param, payload)
            now_49 = re.search(rf"\b{SSTI_MARKER}\b", body or "")
            # Only flag SSTI when 49 was NOT present in the baseline
            # response but IS present in the payload response.
            if now_49 and not had_49_baseline:
                # And confirm the literal payload didn't just echo.
                if payload not in (body or ""):
                    self.on_log(
                        f"    [ssti] ✓ {label} — \"{payload}\" "
                        f"evaluated to 49", "success")
                    self._stats["confirmed"] += 1
                    self._emit_finding(
                        title=(f"Server-Side Template Injection "
                               f"({label}) in "
                               f"{urlparse(target.url).path} "
                               f"({param})"),
                        severity="high",
                        description=(
                            f"Method: {target.method}\n"
                            f"URL: {target.url}\n"
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Engine: {label}\n"
                            f"Evidence: \"49\" in response, "
                            f"absent from baseline."),
                        impact="Template engine RCE.  Sandbox bypass "
                               "is well-documented for Jinja2, FreeMarker "
                               "and Twig.",
                        remediation="Never pass user input into a "
                                    "template render context. Use "
                                    "auto-escape and a strict context.")
                    return
            time.sleep(rate)
        self.on_log("    [ssti] ✗ not vulnerable", "dim")

    def _test_upload(self, target: InjectTarget):
        """Upload-bypass — POSTs each test file via multipart/form-
        data and checks the server response.  We only verify "the
        server accepted the file" (200/201/302); confirming code
        execution would need fetching the upload location, which we
        can't reliably guess across apps.  Severity is bumped to
        HIGH if the response body or Location header contains the
        uploaded filename — that strongly suggests the path is
        publicly retrievable.
        """
        if not self._in_scope(target.url):
            return
        self.on_log(
            f"Testing UPLOAD {urlparse(target.url).path or '/'}  "
            f"(file field: {target.upload_field})", "info")
        for fname, body, mime in UPLOAD_TESTS:
            if self.is_cancelled():
                return
            self._stats["tested"] += 1
            try:
                tmp = os.path.join("/tmp",
                                   f"hawk_upload_{uuid.uuid4().hex}_{fname}")
                with open(tmp, "wb") as f:
                    f.write(body.encode("utf-8"))
                args = ["-X", target.method or "POST",
                        "-F", f"{target.upload_field}=@{tmp};"
                              f"type={mime};filename={fname}"]
                # Add benign values for any sibling fields.
                for of in [p for p in (target.params or [])
                           if p != target.upload_field]:
                    args += ["-F", f"{of}=1"]
                args.append(target.url)
                code, resp_body, head = _curl(args)
                if code in (200, 201, 302):
                    confirmed = (fname in (resp_body or "")
                                 or fname in (head or ""))
                    sev = "high" if confirmed else "medium"
                    self.on_log(
                        f"    [upload] {'✓' if confirmed else '◐'} "
                        f"{fname} accepted (HTTP {code})"
                        f"{' — filename echoed' if confirmed else ''}",
                        "success" if confirmed else "warn")
                    self._stats["confirmed" if confirmed else "probable"] += 1
                    self._emit_finding(
                        title=(f"Upload Bypass — {fname} accepted on "
                               f"{urlparse(target.url).path}"),
                        severity=sev,
                        description=(
                            f"URL: {target.url}\n"
                            f"Method: {target.method}\n"
                            f"File field: {target.upload_field}\n"
                            f"Test filename: {fname}\n"
                            f"Test MIME: {mime}\n"
                            f"Status: {code}\n"
                            f"Filename in response: {confirmed}"),
                        impact="Webshell upload → RCE if upload path "
                               "is web-accessible.",
                        remediation="Whitelist extensions server-side, "
                                    "verify Content-Type from magic "
                                    "bytes, store outside the web root, "
                                    "rename to opaque ID.")
                else:
                    self.on_log(
                        f"    [upload] ✗ {fname} rejected (HTTP {code})",
                        "dim")
            finally:
                try: os.unlink(tmp)
                except Exception: pass
            time.sleep(self.SAFE_RATE_S)

    # ── Aggressive shell-outs ───────────────────────────────────
    def _aggr_sqlmap(self, target: InjectTarget, param: str):
        if not shutil.which("sqlmap"):
            self.on_log(
                "    [sqlmap] not installed — apt install -y sqlmap",
                "dim")
            return
        cmd = ["sqlmap", "--batch", "--level=1", "--risk=1",
               "--smart", "--random-agent",
               "-u", target.url, "-p", param]
        if target.method.upper() == "POST":
            cmd += ["--method=POST",
                    "--data", _post_body(
                        target.params or [param], param, "1", "1")]
        self._stream_external("sqlmap", cmd, target, param)

    def _aggr_dalfox(self, target: InjectTarget, param: str):
        if not shutil.which("dalfox"):
            self.on_log(
                "    [dalfox] not installed — go install github.com/"
                "hahwul/dalfox/v2@latest", "dim")
            return
        # Build a URL with `=HAWK_FUZZ` so dalfox knows where to inject.
        if target.method.upper() == "GET":
            test_url = _splice_get(target.url, param, "HAWK_FUZZ")
            cmd = ["dalfox", "url", test_url, "--silence",
                   "--no-color"]
        else:
            cmd = ["dalfox", "url", target.url, "--silence",
                   "--no-color",
                   "--method", "POST",
                   "--data", _post_body(
                       target.params or [param], param,
                       "HAWK_FUZZ", "1")]
        self._stream_external("dalfox", cmd, target, param)

    def _aggr_commix(self, target: InjectTarget, param: str):
        if not shutil.which("commix"):
            self.on_log(
                "    [commix] not installed — apt install -y commix",
                "dim")
            return
        cmd = ["commix", "--batch", "--level=1",
               "-u", target.url]
        if target.method.upper() == "POST":
            cmd += ["--data", _post_body(
                target.params or [param], param, "1", "1")]
        self._stream_external("commix", cmd, target, param)

    def _stream_external(self, tool_name: str, cmd: list,
                          target: InjectTarget, param: str):
        """Stream stdout from an external tool to on_log.  The tool's
        own confirmation logic produces the finding (we don't try to
        re-parse sqlmap's output here — too brittle).  We do
        bookkeeping so the user sees what's happening."""
        self.on_log(f"    [{tool_name}] launching: "
                    f"{' '.join(cmd[:4])}…", "info")
        try:
            p = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 text=True)
        except Exception as e:
            self.on_log(f"    [{tool_name}] spawn failed: {e}", "warn")
            return
        try:
            for line in p.stdout:
                if self.is_cancelled():
                    p.terminate()
                    break
                line = line.rstrip()
                if line:
                    self.on_log(f"    [{tool_name}] {line[:200]}",
                                "dim")
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try: p.kill()
            except Exception: pass
        except Exception as e:
            self.on_log(f"    [{tool_name}] read error: {e}", "warn")
