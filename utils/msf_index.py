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
HAWK — MSF Index
Auto-builds two cross-indexes from the local Metasploit Framework module
tree (``/usr/share/metasploit-framework/modules/``):

  • by_cve   : CVE id  → list of modules referencing that CVE
  • by_path  : module path → metadata (type, default payload, platforms,
                                       arch, suggested payload)

Lifecycle
---------
• ``start_background_build()`` is called once at HAWK startup from app.py.
  It spawns a daemon thread — the UI is never blocked.
• The thread checks the JSON cache (``hawkc/cache/msf_index.json``).
    – If the cache is missing, older than 24 h, the MSF modules dir is
      newer than the cache, OR the cache version is below the current
      schema version → full rebuild from .rb files.
    – Otherwise the existing cache is loaded directly (fast path).
• Once the thread finishes, ``is_ready()`` returns True and all calls to
  ``lookup(cve_id)`` / ``lookup_module(path)`` return results.  Before
  that, both functions return safe empty values.

Public API
----------
* ``is_ready()``                — bool: index loaded
* ``lookup(cve_id)``            → list of {path, name, label}   (CVE-keyed)
* ``lookup_module(module_path)`` → dict or None  (path-keyed metadata)
* ``start_background_build()``  — kick off the background build thread

Cache schema versioning
-----------------------
Old caches (v1, no ``version`` field, no ``by_path``) are detected at
load time and trigger a full rebuild — preserves backward compatibility
without forcing the user to delete the file manually.
"""

import os
import re
import json
import time
import threading
import logging
from pathlib import Path
from utils.config import CACHE_DIR

log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
MSF_MODULES_DIR = "/usr/share/metasploit-framework/modules"
_HAWK_DIR   = Path(CACHE_DIR)
_CACHE_FILE = _HAWK_DIR / "msf_index.json"

# Rebuild when the cache is older than this (seconds). 24 h.
_CACHE_MAX_AGE = 86_400

# Schema version — bump when the cache format changes so old caches get
# rebuilt automatically.
_SCHEMA_VERSION = 3

# ── Module-type prefix mapping ────────────────────────────────────────────────
# MSF uses-path: exploit/X/Y/Z — but the filesystem is exploits/X/Y/Z.rb
_TYPE_MAP = {
    "exploits":  "exploit",
    "auxiliary": "auxiliary",
    "post":      "post",
    "payloads":  "payload",
    "encoders":  "encoder",
    "nops":      "nop",
    "evasion":   "evasion",
}

# ── Compiled regexes ──────────────────────────────────────────────────────────
_CVE_RE = re.compile(
    r"""\[\s*['"]CVE['"]\s*,\s*['"](\d{4}-\d+)['"]\s*\]""",
    re.I,
)
_NAME_RE  = re.compile(r"'Name'\s*=>\s*'([^']{3,120})'")
_NAME_RE2 = re.compile(r'"Name"\s*=>\s*"([^"]{3,120})"')

# 'Platform' value parsing — handles all common shapes:
#   'Platform' => 'unix'
#   'Platform' => ['unix', 'linux']
#   'Platform' => %w(unix linux)
_PLATFORM_RE = re.compile(
    r"['\"]Platform['\"]\s*=>\s*"
    r"(?:"
    r"['\"]([^'\"]+)['\"]"                # single string
    r"|\[([^\]]+)\]"                       # array
    r"|%w[\(\[]([^\)\]]+)[\)\]]"           # %w() literal array
    r")",
    re.IGNORECASE,
)

# 'Arch' value parsing — ARCH_X86 / ARCH_X64 / ARCH_CMD / ARCH_PHP / etc.
_ARCH_RE = re.compile(
    r"['\"]Arch['\"]\s*=>\s*"
    r"(?:"
    r"(ARCH_[A-Z0-9_]+)"                   # single ARCH_XXX
    r"|\[([^\]]+)\]"                       # array of ARCH_XXX
    r")",
    re.IGNORECASE,
)

# DefaultOptions hash — capture the whole '{ ... }' block (one level deep).
# Matches across newlines (Ruby formats this multi-line very often).
_DEFAULT_OPTS_RE = re.compile(
    r"['\"]DefaultOptions['\"]\s*=>\s*\{([^{}]*)\}",
    re.IGNORECASE | re.DOTALL,
)
# Inside that block we look for the PAYLOAD entry.
_DEFAULT_PAYLOAD_RE = re.compile(
    r"['\"]PAYLOAD['\"]\s*=>\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

# ── Global state ──────────────────────────────────────────────────────────────
# Two separate dicts so each lookup type is O(1) and we never confuse
# CVE keys with module-path keys.
_BY_CVE:  dict      = {}     # { "2011-2523": [{path, name, label}, …] }
_BY_PATH: dict      = {}     # { "exploit/.../foo": {meta…} }
_READY:   bool      = False
_BUILD_THREAD       = None
_LOCK               = threading.Lock()


# ── Public API ────────────────────────────────────────────────────────────────

def is_ready() -> bool:
    """True once the index has been loaded (from cache or freshly built)."""
    return _READY


def lookup(cve_id: str) -> list:
    """Return a list of ``{path, name, label}`` dicts for the given CVE.

    ``cve_id`` is accepted in any of these forms:
        ``"CVE-2011-2523"``  |  ``"cve-2011-2523"``  |  ``"2011-2523"``

    Returns ``[]`` when:
    • The index is not ready yet (background build still running).
    • No Metasploit module references this CVE.

    Thread-safe — reads the immutable global index populated by the
    background builder thread.

    .. note::
        API unchanged from v1 — existing callers in
        ``target_intel_widget._get_exploits_for_vuln`` keep working.
    """
    if not _READY:
        return []
    key = cve_id.upper()
    if key.startswith("CVE-"):
        key = key[4:]          # normalise to "2011-2523"
    with _LOCK:
        raw = _BY_CVE.get(key, [])
        return [m for m in raw
                if "/fileformat/" not in m.get("path", "")
                and "/docgen/" not in m.get("path", "")]


def lookup_module(module_path: str) -> "dict | None":
    """Return metadata for an MSF module path, or None if unknown.

    Result schema::

        {
            "module_type":       "exploit" | "auxiliary" | "post" | "payload" | …,
            "name":              human module name,
            "default_payload":   str  (from DefaultOptions, "" if absent),
            "platforms":         ["unix", "linux", …]  (lowercase, deduped),
            "archs":             ["ARCH_X86", "ARCH_X64", …]  (uppercase),
            "suggested_payload": str  (best-guess payload, "" for non-exploits),
            "needs_lhost_lport": bool (True for exploit+reverse-payload),
        }

    Designed for the MSF launch dialog: the dialog can pre-fill the
    PAYLOAD field with ``suggested_payload`` and skip LHOST/LPORT setup
    entirely when ``module_type == "auxiliary"`` or
    ``needs_lhost_lport == False``.
    """
    if not _READY or not module_path:
        return None
    with _LOCK:
        meta = _BY_PATH.get(module_path)
        return dict(meta) if meta else None


def search_by_keywords(keywords: list, max_results: int = 10) -> list:
    """Search MSF modules by keywords in path and name fields.

    Returns list of {path, name, label} dicts where ALL keywords match
    (case-insensitive) against the combined path + name string.
    Only returns exploit and auxiliary modules."""
    if not is_ready() or not keywords:
        return []
    keywords_lower = [k.lower() for k in keywords if k]
    if not keywords_lower:
        return []
    results = []
    with _LOCK:
        for path, meta in _BY_PATH.items():
            if not path.startswith(("exploit/", "auxiliary/")):
                continue
            if "/fileformat/" in path or "/docgen/" in path:
                continue
            haystack = (path + " " + (meta.get("name") or "")).lower()
            if all(kw in haystack for kw in keywords_lower):
                results.append({
                    "path": path,
                    "name": meta.get("name", ""),
                    "label": meta.get("name") or path.rsplit("/", 1)[-1],
                })
                if len(results) >= max_results:
                    break
    return results


# ── Internal helpers ──────────────────────────────────────────────────────────

def _module_path_from_file(rb_path: str) -> str:
    """Convert an absolute .rb path to the MSF ``use`` path.

    Example::

        /usr/share/metasploit-framework/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
        →  exploit/unix/ftp/vsftpd_234_backdoor
    """
    try:
        rel   = os.path.relpath(rb_path, MSF_MODULES_DIR)
        parts = Path(rel).parts
        if not parts:
            return ""
        type_dir = parts[0]
        prefix   = _TYPE_MAP.get(type_dir, type_dir)
        rest     = "/".join(parts[1:])
        if rest.endswith(".rb"):
            rest = rest[:-3]
        return f"{prefix}/{rest}"
    except ValueError:
        return ""


def _module_type_from_path(module_path: str) -> str:
    """Extract the leading type segment ('exploit', 'auxiliary', …)."""
    if not module_path:
        return ""
    return module_path.split("/", 1)[0]


def _parse_rb(rb_path: str) -> dict:
    """Extract all interesting metadata from a .rb file in one pass.

    Reads only the first 320 lines — Ruby module metadata always lives at
    the top of the file (Module class init), so we avoid scanning long
    payload bodies / CmdShell stagers / ERB blocks.

    Returns a dict::

        {
            "name":            module name (str, "" if missing),
            "cves":            list of CVE keys ("2011-2523" form),
            "default_payload": "cmd/unix/reverse_perl" (or "" if not declared),
            "platforms":       ["unix", "linux", …] lowercase,
            "archs":           ["ARCH_X86", "ARCH_X64", …] uppercase,
        }

    Empty / on-error → all fields empty (caller can still record the
    module path with no metadata if it wants to).
    """
    out = {
        "name": "",
        "cves": [],
        "default_payload": "",
        "platforms": [],
        "archs": [],
    }
    try:
        with open(rb_path, "r", encoding="utf-8", errors="replace") as fh:
            buf_lines = []
            for i, line in enumerate(fh):
                if i > 320:
                    break
                buf_lines.append(line)
            buf = "".join(buf_lines)
    except OSError:
        return out

    # CVE references — capture the year-num part ("2011-2523")
    cve_seen = set()
    for m in _CVE_RE.finditer(buf):
        ck = m.group(1)
        if ck not in cve_seen:
            cve_seen.add(ck)
            out["cves"].append(ck)

    # Module name (first match wins)
    nm = _NAME_RE.search(buf) or _NAME_RE2.search(buf)
    if nm:
        out["name"] = nm.group(1).strip()

    # Platforms — handle string / array / %w() forms
    pm = _PLATFORM_RE.search(buf)
    if pm:
        plats_raw = (pm.group(1) or pm.group(2) or pm.group(3) or "").strip()
        # Tokenise — split on quotes, commas, whitespace
        toks = re.findall(r"[A-Za-z][A-Za-z0-9_-]*", plats_raw)
        seen = set()
        for t in toks:
            tl = t.lower()
            if tl and tl not in seen:
                seen.add(tl)
                out["platforms"].append(tl)

    # Architectures
    am = _ARCH_RE.search(buf)
    if am:
        archs_raw = (am.group(1) or am.group(2) or "").strip()
        toks = re.findall(r"ARCH_[A-Z0-9_]+", archs_raw, re.I)
        seen = set()
        for t in toks:
            tu = t.upper()
            if tu not in seen:
                seen.add(tu)
                out["archs"].append(tu)

    # DefaultOptions → PAYLOAD (if declared)
    do_m = _DEFAULT_OPTS_RE.search(buf)
    if do_m:
        body = do_m.group(1)
        pm2 = _DEFAULT_PAYLOAD_RE.search(body)
        if pm2:
            out["default_payload"] = pm2.group(1).strip()

    # Detect backdoor / bind exploits that don't use a reverse handler.
    # These modules connect to a pre-existing bindshell or trigger a
    # backdoor listener — they need cmd/unix/interact (or similar),
    # NOT a reverse payload.
    is_bind = False
    buf_low = buf.lower()
    if "backdoor" in rb_path.lower():
        is_bind = True
    elif re.search(r"handler_disabled\s*=>\s*true", buf_low):
        is_bind = True
    elif re.search(r"disablepayloadhandler.*true", buf_low):
        is_bind = True
    elif re.search(r"['\"]handlerdisable['\"]", buf_low):
        is_bind = True
    elif "cmd/unix/interact" in buf_low:
        is_bind = True
    out["is_bind"] = is_bind

    return out


# ── Suggested-payload inference ──────────────────────────────────────────────

# Ordered list of (platform_token, arch_token, payload).  arch_token may
# be "" to mean "any arch / no arch declared".  First match wins.  Used
# only when the module's DefaultOptions don't declare a payload — a
# pragmatic fallback so the launch dialog has SOMETHING to pre-fill with.
_PAYLOAD_INFERENCE = [
    # Unix-cmd family — fits any unix shell-injection exploit
    ("unix",    "ARCH_CMD",  "cmd/unix/reverse_perl"),
    ("unix",    "",          "cmd/unix/reverse_perl"),
    # Linux x64 modern default
    ("linux",   "ARCH_X64",  "linux/x64/meterpreter/reverse_tcp"),
    ("linux",   "ARCH_X86",  "linux/x86/meterpreter/reverse_tcp"),
    ("linux",   "",          "linux/x64/meterpreter/reverse_tcp"),
    # Windows — MSF uses 'win' as the canonical token; 'windows' also
    # appears occasionally in older modules.  Both alias to the same
    # x64-default meterpreter.
    ("win",     "ARCH_X64",  "windows/x64/meterpreter/reverse_tcp"),
    ("win",     "ARCH_X86",  "windows/meterpreter/reverse_tcp"),
    ("win",     "",          "windows/x64/meterpreter/reverse_tcp"),
    ("windows", "ARCH_X64",  "windows/x64/meterpreter/reverse_tcp"),
    ("windows", "ARCH_X86",  "windows/meterpreter/reverse_tcp"),
    ("windows", "",          "windows/x64/meterpreter/reverse_tcp"),
    # Interpreter / VM payloads
    ("java",    "",          "java/meterpreter/reverse_tcp"),
    ("php",     "",          "php/meterpreter/reverse_tcp"),
    ("python",  "",          "python/meterpreter/reverse_tcp"),
    ("ruby",    "",          "ruby/shell/reverse_tcp"),
    ("nodejs",  "",          "nodejs/shell_reverse_tcp"),
    # Multi — caller decides at runtime based on target OS
    ("multi",   "",          "linux/x64/meterpreter/reverse_tcp"),
    # OSX / Apple silicon — both 'osx' and 'mac' show up as platform tokens
    ("osx",     "ARCH_X64",  "osx/x64/meterpreter/reverse_tcp"),
    ("osx",     "",          "osx/x64/meterpreter/reverse_tcp"),
    ("mac",     "",          "osx/x64/meterpreter/reverse_tcp"),
    # BSD family
    ("bsd",     "",          "bsd/x64/shell_reverse_tcp"),
    ("freebsd", "",          "bsd/x64/shell_reverse_tcp"),
    # Android / iOS (rare, but exploits exist)
    ("android", "",          "android/meterpreter/reverse_tcp"),
    ("apple_ios", "",        "apple_ios/meterpreter/reverse_tcp"),
]


def _infer_suggested_payload(module_type: str, default_payload: str,
                              platforms: list, archs: list,
                              is_bind: bool = False) -> str:
    """Compute the best payload to pre-fill in the MSF launch dialog.

    Logic:
      1. If the module declares a ``DefaultOptions => PAYLOAD => ...`` it
         is always returned (developer's explicit choice — never override).
      2. Auxiliary / post / encoder / nop / payload / evasion modules
         don't take a payload at all → return "".
      3. Backdoor / bind exploits → ``cmd/unix/interact`` (they connect
         to a pre-existing listener, not a reverse handler).
      4. For exploits, walk the inference table; first (platform, arch)
         match wins.  Empty arch entries are wildcards — they fire when
         no arch was declared OR the declared arch wasn't in the table.
      5. Fall through → return "" (the launch dialog will leave the
         field empty for the user to fill in).
    """
    if default_payload:
        return default_payload

    if module_type and module_type != "exploit":
        return ""

    if is_bind:
        return "cmd/unix/interact"

    # Build a quick set for arch matching
    arch_set = {a.upper() for a in (archs or [])}
    plat_set = {p.lower() for p in (platforms or [])}

    # Pass 1: exact (platform, arch) match
    for plat, arch, payload in _PAYLOAD_INFERENCE:
        if plat in plat_set and arch and arch in arch_set:
            return payload

    # Pass 2: platform match with arch wildcard
    for plat, arch, payload in _PAYLOAD_INFERENCE:
        if plat in plat_set and not arch:
            return payload

    return ""


def _needs_lhost_lport(module_type: str, suggested_payload: str) -> bool:
    """True when the launch dialog should expose LHOST/LPORT fields.

    Auxiliary / post don't take payloads.  Some exploits have payloads
    that don't need LHOST/LPORT (cmd/unix/generic, bind shells), but
    the common case for the launch dialog is "reverse" payloads.
    """
    if module_type != "exploit":
        return False
    if not suggested_payload:
        return False
    # Bind shells, generic command-execution payloads, and
    # find_shell-class payloads don't take LHOST/LPORT.
    if "reverse" not in suggested_payload.lower():
        return False
    return True


# ── Index build ──────────────────────────────────────────────────────────────

def _build_index() -> tuple:
    """Walk the MSF modules directory and build BOTH cross-indexes.

    Returns ``(by_cve_dict, by_path_dict)``.  Caller is responsible for
    swapping them into the global state.
    """
    by_cve:  dict = {}
    by_path: dict = {}

    msf_root = Path(MSF_MODULES_DIR)
    if not msf_root.is_dir():
        log.warning("[MSF index] MSF modules dir not found: %s",
                    MSF_MODULES_DIR)
        return by_cve, by_path

    all_rb = list(msf_root.rglob("*.rb"))
    log.info("[MSF index] Scanning %d .rb files …", len(all_rb))
    t0 = time.time()
    n_with_cve  = 0
    n_with_meta = 0

    for rb in all_rb:
        mod_path = _module_path_from_file(str(rb))
        if not mod_path:
            continue

        meta = _parse_rb(str(rb))
        mtype = _module_type_from_path(mod_path)

        # Build by_path entry — even modules without CVEs go here so
        # the launch dialog can look up payload metadata for any module.
        suggested = _infer_suggested_payload(
            mtype, meta["default_payload"],
            meta["platforms"], meta["archs"],
            is_bind=meta.get("is_bind", False))
        by_path_entry = {
            "module_type":       mtype,
            "name":              meta["name"],
            "default_payload":   meta["default_payload"],
            "platforms":         meta["platforms"],
            "archs":             meta["archs"],
            "suggested_payload": suggested,
            "needs_lhost_lport": _needs_lhost_lport(mtype, suggested),
        }
        by_path[mod_path] = by_path_entry
        if (meta["default_payload"] or meta["platforms"] or meta["archs"]):
            n_with_meta += 1

        # Build by_cve entries — only for modules that declare CVEs.
        if meta["cves"]:
            n_with_cve += 1
            label = meta["name"] or mod_path.rsplit("/", 1)[-1]
            cve_entry = {
                "path":  mod_path,
                "name":  meta["name"],
                "label": label,
            }
            for cve_key in meta["cves"]:
                by_cve.setdefault(cve_key, []).append(cve_entry)

    elapsed = time.time() - t0
    log.info(
        "[MSF index] Built %d total modules, %d with CVE refs, %d with "
        "platform/payload metadata, in %.1f s (%d CVE keys)",
        len(by_path), n_with_cve, n_with_meta, elapsed, len(by_cve),
    )
    return by_cve, by_path


# ── Cache I/O ────────────────────────────────────────────────────────────────

def _should_rebuild() -> bool:
    """True when the cache is absent, too old, MSF tree is newer, OR the
    cached schema version is below the current ``_SCHEMA_VERSION``."""
    if not _CACHE_FILE.exists():
        return True
    try:
        cache_mtime = _CACHE_FILE.stat().st_mtime
    except OSError:
        return True

    # Age threshold
    if (time.time() - cache_mtime) > _CACHE_MAX_AGE:
        return True

    # MSF directory newer than cache → new modules were installed
    msf_root = Path(MSF_MODULES_DIR)
    if msf_root.is_dir():
        try:
            if msf_root.stat().st_mtime > cache_mtime:
                return True
        except OSError:
            pass

    # Cache schema version check — old caches (v1 or unversioned) get
    # rebuilt automatically so payload metadata becomes available.
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        cached_version = int(data.get("version", 1))
        if cached_version < _SCHEMA_VERSION:
            log.info("[MSF index] Cache schema v%d < current v%d — rebuild.",
                     cached_version, _SCHEMA_VERSION)
            return True
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return True

    return False


def _save_cache(by_cve: dict, by_path: dict) -> None:
    try:
        _HAWK_DIR.mkdir(parents=True, exist_ok=True)
        tmp = _CACHE_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({
                "ts":      time.time(),
                "version": _SCHEMA_VERSION,
                "by_cve":  by_cve,
                "by_path": by_path,
            }, fh, separators=(",", ":"))
        tmp.replace(_CACHE_FILE)
        log.info(
            "[MSF index] Cache saved: %s  (%d CVE keys, %d modules)",
            _CACHE_FILE, len(by_cve), len(by_path),
        )
    except OSError as exc:
        log.warning("[MSF index] Could not write cache: %s", exc)


def _load_cache() -> "tuple | None":
    """Return ``(by_cve, by_path)`` from the cached file, or None on error.

    Validates schema version — refuses to load v1 caches so the worker
    falls back to a rebuild and the user gets the new metadata.
    """
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if int(data.get("version", 1)) < _SCHEMA_VERSION:
            return None
        by_cve  = data.get("by_cve")
        by_path = data.get("by_path")
        if not isinstance(by_cve, dict) or not isinstance(by_path, dict):
            return None
        return by_cve, by_path
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


# ── Worker / startup ─────────────────────────────────────────────────────────

def _worker() -> None:
    """Background thread body — load or rebuild both indexes."""
    global _BY_CVE, _BY_PATH, _READY
    try:
        if _should_rebuild():
            log.info("[MSF index] Building fresh index …")
            by_cve, by_path = _build_index()
            if by_path:
                _save_cache(by_cve, by_path)
        else:
            log.info("[MSF index] Loading from cache: %s", _CACHE_FILE)
            loaded = _load_cache()
            if loaded is None:
                log.info("[MSF index] Cache invalid — rebuilding …")
                by_cve, by_path = _build_index()
                if by_path:
                    _save_cache(by_cve, by_path)
            else:
                by_cve, by_path = loaded

        with _LOCK:
            _BY_CVE  = by_cve  or {}
            _BY_PATH = by_path or {}
            _READY   = True

        log.info("[MSF index] Ready — %d CVE keys, %d modules indexed.",
                 len(_BY_CVE), len(_BY_PATH))

    except Exception as exc:          # noqa: BLE001
        log.exception("[MSF index] Builder thread failed: %s", exc)
        with _LOCK:
            # Mark ready anyway so callers don't block forever; empty
            # indexes mean lookup() / lookup_module() return safe defaults.
            _READY = True


def start_background_build() -> None:
    """Kick off the background index-builder thread.

    Safe to call multiple times — subsequent calls are no-ops if the
    thread is already running or the index is already ready.  Designed
    to be called from ``HawkApp.__init__`` right after the UI is built so
    the scan runs while the user is still reading the splash / api-key
    dialog.
    """
    global _BUILD_THREAD
    if _READY:
        return
    if _BUILD_THREAD is not None and _BUILD_THREAD.is_alive():
        return
    t = threading.Thread(
        target=_worker,
        name="hawk-msf-index-builder",
        daemon=True,
    )
    _BUILD_THREAD = t
    t.start()
    log.info("[MSF index] Background build thread started.")
