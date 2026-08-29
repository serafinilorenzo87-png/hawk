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
HAWK — Hydra credential verification.

Hydra is famous for false-positive cascades on poorly-tuned modules:
  * `http-get://target/` against a default IIS welcome page → every
    Basic-Auth attempt returns 200 OK, hydra reports each as success.
  * `http-form-post` with a wrong "F=fail" string → hydra mis-classifies.
  * `mysql` / `postgres` against a non-listening port behind a load
    balancer that always answers OK at TCP level.

This module sits BETWEEN hydra-finished and credential-store-saved:

  1. `parse_hydra_cmd` extracts protocol / host / port / path from
     the actual command line that hydra ran, so we don't have to
     guess.
  2. `detect_false_positive_cascade` does two checks:
       a. Multi-password-same-user heuristic: if hydra reports 2+
          passwords for the SAME user, it's almost always a cascade
          (no real auth — every attempt classified as success).
       b. Counter-check probe: send ONE additional probe with a
          guaranteed-wrong password (`hawk_fp_<random>`).  If the
          response signature matches one of hydra's "successful"
          attempts, the endpoint isn't actually authenticating →
          drop all hydra-reported creds.
  3. Per-protocol verifiers translate "auth attempt" into a single
     network probe and return either True (auth accepted), False
     (auth rejected), or None (couldn't reach the service / no
     verifier available).
  4. `verify_creds` runs 2 then 3 and returns a PER-CREDENTIAL
     verdict, which is what the caller stamps on
     `Credential(verified=...)`.

Tri-state contract, per credential:
  True  → HAWK's own probe authenticated: store it as VERIFIED.
  False → HAWK's own probe was rejected: hydra was wrong, DROP it.
  None  → no verifier for this protocol / probe unreachable: keep the
          cred (the cost of being wrong is one wasted manual try, not
          a deluge of false data) but store it UNVERIFIED and say so
          in the notes, so the operator sees exactly what HAWK did
          and did not prove.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from typing import Optional


# ─── Hydra cmd-line parser ──────────────────────────────────────────

# Hydra's URL syntax: <proto>://<host>[:<port>][/<path>]
# Also recognises: -s <port> as an override before/after the URL.
_HYDRA_URL_RE = re.compile(
    r"\b(?P<proto>[a-z][a-z0-9_-]+)://"
    r"(?P<host>\[[0-9a-fA-F:]+\]|[\w.-]+)"
    r"(?::(?P<port>\d+))?"
    r"(?P<path>/[^\s]*)?",
    re.I,
)
_HYDRA_S_PORT_RE = re.compile(r"\s-s\s+(\d+)")
# Scheme-less web-form shape: the form dialog builds the command as
# "HOST -s PORT http-post-form <triplet>" (no proto://), so _HYDRA_URL_RE
# matches nothing.  Recognise the bare hydra web module and take the host
# token immediately before -s.
_HYDRA_WEBMOD_RE = re.compile(
    r"\b(https?-(?:get|post|head)-form|https?-(?:get|post|head))\b", re.I)
_HYDRA_HOST_BEFORE_S_RE = re.compile(r"(\S+)\s+-s\s+\d+")
_HYDRA_HTTPS_PROTOS = {"https-get", "https-post", "https-head",
                        "https-form-get", "https-form-post"}


@dataclass
class HydraCmdInfo:
    proto: str    = ""    # http-get / ftp / ssh / smb / etc.
    host:  str    = ""
    port:  int    = 0
    path:  str    = "/"   # only meaningful for http-* protocols
    raw:   str    = ""    # original cmd line (for debug)
    is_form: bool = False
    is_http: bool = False
    is_https: bool = False


def parse_hydra_cmd(cmd: str) -> HydraCmdInfo:
    """Best-effort parse of a hydra command line.

    Returns a HydraCmdInfo that's always safe to inspect (empty
    fields if nothing matched).  We don't fail loudly here — the
    caller already has a list of creds hydra returned, the
    verification is a NICE-TO-HAVE on top.
    """
    info = HydraCmdInfo(raw=cmd)
    m = _HYDRA_URL_RE.search(cmd)
    if m:
        info.proto = (m.group("proto") or "").lower()
        info.host  = (m.group("host")  or "")
        info.path  = (m.group("path")  or "/")
        port_str   = m.group("port")
        if port_str:
            try:
                info.port = int(port_str)
            except ValueError:
                pass
    # Fallback for the scheme-less web-form shape (see _HYDRA_WEBMOD_RE):
    # no proto:// means the URL regex found nothing, so without this the
    # cascade counter-check ran against an empty host and printed a
    # nonsensical "://:0" target.  Recover proto (the web module) and host
    # (the token before -s) here.  is_form is derived below and keeps the
    # form off the Basic-Auth GET probe.
    if not info.proto:
        mod_m = _HYDRA_WEBMOD_RE.search(cmd)
        if mod_m:
            info.proto = mod_m.group(1).lower()
            host_m = _HYDRA_HOST_BEFORE_S_RE.search(cmd)
            if host_m:
                info.host = host_m.group(1)
    # -s <port> overrides the inline port if present
    sm = _HYDRA_S_PORT_RE.search(cmd)
    if sm:
        try:
            info.port = int(sm.group(1))
        except ValueError:
            pass
    # Default ports if the user didn't pass one
    if info.port == 0:
        info.port = _DEFAULT_PORTS.get(info.proto, 0)

    info.is_form  = "form" in info.proto
    info.is_https = (info.proto in _HYDRA_HTTPS_PROTOS
                     or info.proto.startswith("https"))
    info.is_http  = (info.proto.startswith("http")
                     or info.proto.startswith("https"))
    return info


_DEFAULT_PORTS = {
    "http-get": 80, "http-post": 80, "http-head": 80,
    "http-form-get": 80, "http-form-post": 80,
    "https-get": 443, "https-post": 443, "https-head": 443,
    "https-form-get": 443, "https-form-post": 443,
    "ftp": 21, "ftps": 990, "sftp": 22,
    "ssh": 22, "ssh2": 22,
    "telnet": 23,
    "smb": 445, "smb2": 445, "smbnt": 445,
    "rdp": 3389,
    "mysql": 3306,
    "mssql": 1433,
    "postgres": 5432,
    "redis": 6379,
    "vnc": 5900,
    "ldap2": 389, "ldap3": 389, "ldap": 389,
    "snmp": 161,
    "imap": 143, "imaps": 993,
    "pop3": 110, "pop3s": 995,
    "smtp": 25,  "smtps": 465,
    "irc": 6667,
}


# ─── Per-protocol verifiers ─────────────────────────────────────────
#
# Each returns one of:
#   True  → auth accepted (server says credential is valid)
#   False → auth rejected (server explicitly said no)
#   None  → couldn't decide (network error, no verifier, timeout)
#
# The "cascade detector" further down compares (real_pass) to
# (fake_pass) signatures.  Equal True means "no real auth — both
# accepted" → cascade.  Different results → genuine auth attempts.

def _verify_http_get(host: str, port: int, path: str,
                      user: str, password: str,
                      use_https: bool = False) -> tuple:
    """Send GET with Basic Auth.  Returns a (status, length,
    snippet_hash) tuple — the cascade detector compares the tuple
    between real_pass and fake_pass."""
    import urllib.request as _ur
    import urllib.error as _ue
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}{path or '/'}"
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = _ur.Request(url, headers={
        "Authorization": f"Basic {auth}",
        "User-Agent":   "Mozilla/5.0 HAWK-fpcheck",
    })
    ctx = None
    if use_https:
        ctx = ssl._create_unverified_context()
    try:
        with _ur.urlopen(req, timeout=8, context=ctx) as resp:
            body = resp.read(4096)
            return (int(resp.status), len(body),
                    _sig(body))
    except _ue.HTTPError as e:
        try:
            body = e.read(4096)
        except Exception:
            body = b""
        return (int(e.code), len(body), _sig(body))
    except Exception:
        return (None, 0, "")


def _verify_ftp(host: str, port: int, user: str,
                  password: str) -> Optional[bool]:
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=8)
        try:
            ftp.login(user, password)
            ok = True
        except ftplib.error_perm:
            ok = False
        try:
            ftp.quit()
        except Exception:
            pass
        return ok
    except Exception:
        return None


def _verify_ssh(host: str, port: int, user: str,
                  password: str) -> Optional[bool]:
    if not shutil.which("sshpass") or not shutil.which("ssh"):
        return None
    try:
        r = subprocess.run([
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PasswordAuthentication=yes",
            "-o", "PubkeyAuthentication=no",
            "-o", "BatchMode=no",
            "-o", "ConnectTimeout=6",
            "-p", str(port or 22),
            f"{user}@{host}", "true",
        ], capture_output=True, timeout=15)
        # exit 0 = login + cmd ran.  Anything else = auth or
        # connection failure; we treat both as "rejected" rather
        # than "unknown" because hydra DID get past whatever it is.
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _verify_smb(host: str, port: int, user: str,
                  password: str) -> Optional[bool]:
    nxc = (shutil.which("netexec") or shutil.which("nxc")
            or shutil.which("crackmapexec"))
    if not nxc:
        return None
    args = [nxc, "smb", host, "-u", user, "-p", password]
    if port and port not in (139, 445):
        args += ["--port", str(port)]
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                            timeout=20)
        out = (r.stdout or "") + (r.stderr or "")
        # netexec marks success with [+] and an "(admin)" or similar
        # tag.  STATUS_LOGON_FAILURE means rejected.  Anything that
        # doesn't say either is "no answer" → unknown.
        if "STATUS_LOGON_FAILURE" in out:
            return False
        if "STATUS_ACCESS_DENIED" in out:
            # SMB authenticated but the test target doesn't allow
            # this user past the auth gate — still counts as a real
            # credential check (auth WAS evaluated).
            return True
        if "[+]" in out:
            return True
        return None
    except Exception:
        return None


def _verify_telnet(host: str, port: int, user: str,
                     password: str) -> Optional[bool]:
    # Telnet auth is application-specific; we don't have a robust
    # verifier here.  Return None so we fall back to the multi-
    # password heuristic.
    return None


def _verify_generic_tcp(host: str, port: int, user: str,
                         password: str) -> Optional[bool]:
    """Last-ditch verifier — just checks the TCP port answers.
    Useful for protocols where a simple connect tells us the
    service is real (vs. a TCP cascade behind a balancer).  Doesn't
    actually authenticate."""
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.close()
        return None  # connect OK but auth not tested
    except Exception:
        return False  # service unreachable


# ─── Cascade detection ──────────────────────────────────────────────

def detect_false_positive_cascade(
        creds: list[tuple[str, str]],
        cmd_info: HydraCmdInfo) -> tuple[
            list[tuple[str, str]], "str | None", bool]:
    """Run the false-positive checks against `creds`.

    Returns (kept_creds, reason_or_None, is_cascade).

    * kept_creds   — the subset of creds we believe are real.  When
                     a cascade is detected, this is empty.
    * reason       — human-readable explanation surfaced to the
                     operator if cascade was detected; None
                     otherwise.
    * is_cascade   — True if we dropped everything.
    """
    if not creds:
        return ([], None, False)

    # Heuristic 1: multi-password-same-user.  Strong signal even
    # without a network probe.  We still run the counter-check
    # because some legit cases exist (account with shared password
    # rotation) but the bar is much higher.
    by_user: dict[str, list[str]] = {}
    for u, p in creds:
        by_user.setdefault(u, []).append(p)
    multi_user = [u for u, pws in by_user.items() if len(pws) >= 2]

    # Heuristic 2: counter-check with a guaranteed-wrong password.
    fake_pass = f"hawk_fp_{secrets.token_hex(10)}"
    sample_user, sample_pass = creds[0]

    proto = cmd_info.proto
    host  = cmd_info.host
    port  = cmd_info.port

    def _http_check() -> bool:
        real = _verify_http_get(
            host, port, cmd_info.path, sample_user, sample_pass,
            use_https=cmd_info.is_https)
        fake = _verify_http_get(
            host, port, cmd_info.path, sample_user, fake_pass,
            use_https=cmd_info.is_https)
        # Cascade if status AND content-length AND body signature
        # all match.  Status alone isn't enough (200 on both could
        # be legit if both pages render the same auth-response
        # template); we require length too.
        return (real == fake and real[0] is not None)

    def _ftp_check() -> bool:
        real = _verify_ftp(host, port, sample_user, sample_pass)
        fake = _verify_ftp(host, port, sample_user, fake_pass)
        return real is True and fake is True

    def _ssh_check() -> bool:
        real = _verify_ssh(host, port, sample_user, sample_pass)
        fake = _verify_ssh(host, port, sample_user, fake_pass)
        return real is True and fake is True

    def _smb_check() -> bool:
        real = _verify_smb(host, port, sample_user, sample_pass)
        fake = _verify_smb(host, port, sample_user, fake_pass)
        return real is True and fake is True

    cascade = False
    try:
        if cmd_info.is_form:
            # Form logins POST a body HAWK can't reconstruct from the
            # command line, so a Basic-Auth GET counter-check is the wrong
            # probe — it would see the same login page for the real and the
            # fake password and falsely flag a cascade.  Fall back to the
            # multi-user heuristic, the only signal that holds without
            # replaying the form POST.
            cascade = bool(multi_user)
        elif cmd_info.is_http:
            cascade = _http_check()
        elif proto in ("ftp", "ftps"):
            cascade = _ftp_check()
        elif proto in ("ssh", "ssh2"):
            cascade = _ssh_check()
        elif proto in ("smb", "smb2", "smbnt"):
            cascade = _smb_check()
        else:
            # No protocol-specific verifier — fall back to the
            # multi-user heuristic alone.
            cascade = bool(multi_user)
    except Exception as e:
        print(f"[HAWK] hydra cascade check failed: {e}")
        cascade = bool(multi_user)

    if cascade:
        # Build a verbose reason — the operator should be able to
        # reproduce the test by hand.
        if multi_user:
            multi_str = ", ".join(
                f"{u}={len(pws)} pws" for u, pws in by_user.items()
                if len(pws) >= 2)
            mu_text = (f"  · same user accepted with multiple "
                        f"passwords ({multi_str}) — strong cascade "
                        f"signal\n")
        else:
            mu_text = ""
        return ([],
                (f"HYDRA false-positive cascade detected on "
                 f"{proto}://{host}:{port}{cmd_info.path}.\n"
                 f"{mu_text}"
                 f"  · counter-check probe with fake password "
                 f"'{fake_pass[:24]}…' produced the SAME response "
                 f"as the 'successful' creds — endpoint is NOT "
                 f"enforcing authentication.\n"
                 f"  · {len(creds)} candidate credential(s) "
                 f"DROPPED by HAWK.\n"
                 f"\n"
                 f"To verify manually:\n"
                 f"  curl -u <user>:totally-fake-pass "
                 f"{('https' if cmd_info.is_https else 'http')}://"
                 f"{host}:{port}{cmd_info.path}  -I"),
                True)

    return (list(creds), None, False)


# ─── Per-credential verification ────────────────────────────────────

# Probing costs one network round-trip per credential and today runs
# on the caller's thread, so cap it.  Creds past the cap are reported
# as unverifiable (None) instead of silently trusted.
MAX_PER_CRED_PROBES = 4


def unverified_note(cmd_info: HydraCmdInfo) -> str:
    """Note stamped on a credential HAWK could not prove itself."""
    return (f"[unverified - no HAWK probe for "
            f"{cmd_info.proto or 'this protocol'}]")


def probe_credential(user: str, password: str,
                     cmd_info: HydraCmdInfo) -> Optional[bool]:
    """Authenticate ONE credential against the service.

    Returns True (accepted), False (rejected) or None (no verifier for
    this protocol, or the probe could not reach a verdict).
    """
    proto = cmd_info.proto
    host  = cmd_info.host
    port  = cmd_info.port
    if not host or not port:
        return None
    try:
        if cmd_info.is_http:
            # Form-based modules post their own body; a Basic-Auth GET
            # tells us nothing about them, so don't pretend it does.
            if cmd_info.is_form:
                return None
            real = _verify_http_get(host, port, cmd_info.path,
                                    user, password,
                                    use_https=cmd_info.is_https)
            if real[0] is None:
                return None
            fake = _verify_http_get(
                host, port, cmd_info.path, user,
                f"hawk_fp_{secrets.token_hex(10)}",
                use_https=cmd_info.is_https)
            if fake[0] is None:
                return None
            # Accepted only when the server answered 2xx/3xx to the
            # real password AND answered differently to a
            # guaranteed-wrong one.  Same answer for both → the
            # endpoint isn't authenticating and the cred proves
            # nothing; a 4xx/5xx → it was rejected outright.
            return bool(200 <= real[0] < 400 and real != fake)
        if proto in ("ftp", "ftps"):
            return _verify_ftp(host, port, user, password)
        if proto in ("ssh", "ssh2"):
            return _verify_ssh(host, port, user, password)
        if proto in ("smb", "smb2", "smbnt"):
            return _verify_smb(host, port, user, password)
    except Exception as e:
        print(f"[HAWK] per-cred probe failed: {e}")
        return None
    return None


def verify_creds(creds: list[tuple[str, str]],
                 cmd_info: HydraCmdInfo,
                 run_cascade: bool = True) -> tuple[
                     list[tuple[str, str, "bool | None"]],
                     list[tuple[str, str]],
                     "str | None", bool]:
    """Cascade check + per-credential probe.

    Returns ``(kept, rejected, reason, is_cascade)`` where

    * kept     — ``[(user, password, probe)]`` with ``probe`` True
                 (HAWK authenticated) or None (unverifiable).
    * rejected — creds whose own probe said False.  hydra reported
                 them, our probe says the password does NOT
                 authenticate, so they never reach the store.
    * reason   — cascade explanation, or None.
    * is_cascade — True when the whole batch was dropped.

    ``run_cascade=False`` skips the batch-level cascade heuristic and
    only runs the per-credential probes (used by callers that already
    scope the cascade check themselves).
    """
    if not creds:
        return ([], [], None, False)

    if run_cascade:
        kept_pairs, reason, is_cascade = detect_false_positive_cascade(
            creds, cmd_info)
        if is_cascade:
            return ([], list(creds), reason, True)
    else:
        kept_pairs, reason, is_cascade = list(creds), None, False

    kept: list[tuple[str, str, "bool | None"]] = []
    rejected: list[tuple[str, str]] = []
    for i, (u, p) in enumerate(kept_pairs):
        verdict = (probe_credential(u, p, cmd_info)
                   if i < MAX_PER_CRED_PROBES else None)
        if verdict is False:
            rejected.append((u, p))
        else:
            kept.append((u, p, verdict))
    return (kept, rejected, reason, is_cascade)


# ─── Helpers ────────────────────────────────────────────────────────

def _sig(body: bytes) -> str:
    """Stable short signature for an HTTP body — first 64 bytes
    hex-encoded.  Used to compare real-pass vs fake-pass responses
    without keeping the full body around."""
    if not body:
        return ""
    return body[:64].hex()
