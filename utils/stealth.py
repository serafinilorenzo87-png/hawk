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
HAWK — Stealth Mode helpers.

When Stealth Mode is ON, every artefact written to the TARGET machine
is renamed and relocated so routine forensic review / SIEM keyword
scans can't pattern-match on "winpeas", "linpeas", "privesccheck",
explicit IP-in-filename, or the usual `/tmp/*.out` / `C:\\Windows\\Temp\\*.out`
paths that every blue-team rule watches.

What it does NOT do: behavioural EDR evasion, AMSI bypass, LOLBAS
living-off-the-land translation, or anti-forensics cleanup.  Those
are future work (see v2.0 ARGUS teaser).

Coverage:
  * Level 1 — random 8-char hex filename, plausible Windows / Linux
    extension (.tmp / .log / .dat on Win; naked or dot-prefixed on Linux).
  * Level 3 — random pick among low-watched paths (C:\\Users\\Public\\*
    on Windows, /dev/shm on Linux) instead of the classic Temp dirs.
  * Level 4 — light binary scrambling: appends random bytes to .exe /
    .dll (PE format tolerates trailing garbage), prepends a random
    comment line to .ps1 / .bat / .sh.  Changes SHA-256 by construction
    so signature-only AV rules miss.

Kali-side filenames stay DESCRIPTIVE on purpose — the user has to
read their own output files, so "winpeas-exe-<ip>-<ts>.out" wins
there.  Stealth only applies to what lands on the target.
"""

from __future__ import annotations

import os
import random
import secrets
from dataclasses import dataclass, field
from typing import Optional


# ─── Plausible paths ────────────────────────────────────────────────
#
# Windows picks (all writable without local-admin on a default Win10+
# install; all NOT in the top-tier watched list of most EDR defaults):
#   C:\Users\Public\Videos      — low-interest user-profile folder
#   C:\Users\Public\Music       — same
#   C:\Users\Public\Documents   — same
#   C:\Users\Public\Downloads   — same
#   %TEMP% / %APPDATA%\Local\Temp\  — per-user temp, less monitored
#                                     than the C:\Windows\Temp global
#
# NOTE on extensions: we KEEP the original extension (.exe / .bat /
# .ps1) on the binary because Windows honours file extension at exec
# time — renaming winpeas.exe to a3f2b8e1.tmp would simply NOT run
# on the target.  Stealth here is in the random-hex STEM, not the
# extension.  For the output file (text-only) we use .log / .tmp /
# .dat because any extension works for a text blob.
_WIN_STEALTH_PATHS: list[str] = [
    # All concrete absolute paths — we deliberately AVOID %TEMP%
    # and %APPDATA% even though those would be per-user quieter,
    # because cmd.exe expands %VAR% but PowerShell uses $env:VAR,
    # and our transfer/execute templates mix both shells.  Keeping
    # paths literal means the commands work identically in cmd and
    # PS without env-expansion gymnastics.
    "C:\\Users\\Public\\Videos",
    "C:\\Users\\Public\\Music",
    "C:\\Users\\Public\\Documents",
    "C:\\Users\\Public\\Downloads",
]

# Extensions used ONLY for the output file (the one the tool writes).
# Since the output is plain text, any extension works.  Rotating
# between these makes the file blend with normal system noise.
_WIN_OUT_EXTS: tuple[str, ...] = ("log", "tmp", "dat")

# Linux picks:
#   /dev/shm       — RAM-backed tmpfs, ZERO disk trace after reboot
#   /var/tmp       — persists reboot but less watched than /tmp
#   /tmp           — classic, dot-prefix for ls visibility hiding
#   ~/.cache       — per-user, plausible application cache
#
# Tuple: (path, filename_prefix).  Prefix "." makes the file hidden
# from a default `ls` (not `ls -a`).
_LINUX_STEALTH_PATHS: list[tuple[str, str]] = [
    ("/dev/shm",        "."),   # RAM-only, forensic-proof on reboot
    ("/var/tmp",        "."),
    ("/tmp",            "."),
    ("$HOME/.cache",    ""),    # dotdir already hidden, no prefix
]


# ─── StealthContext ─────────────────────────────────────────────────

@dataclass
class StealthContext:
    """Everything the PEAS workflow dialog needs to drive a stealth
    transfer + execute.  Populated by `generate_stealth_context` once
    per dialog open; passed into the dialog so the same ctx drives
    Step 1 (host), Step 2 (transfer), Step 3 (execute) and the
    mapping banner shown to the user.

    The original tool binary on Kali stays untouched; a scrambled
    COPY is written to `scrambled_src` with filename
    `scrambled_name` and that copy is what the target downloads.
    """
    enabled:          bool = False
    real_tool:        str  = ""     # "winpeas.exe" / "linpeas.sh" ...
    random_name:      str  = ""     # "a3f2b8e1"
    random_ext:       str  = ""     # "tmp" / "log" / ""  (no dot)
    out_random_name:  str  = ""
    out_random_ext:   str  = ""     # "tmp" / ""
    remote_dir:       str  = ""     # "C:\\Users\\Public\\Videos"
    remote_bin_path:  str  = ""     # "C:\\Users\\Public\\Videos\\a3f2b8e1.tmp"
    remote_out_path:  str  = ""     # "C:\\Users\\Public\\Videos\\5c8d2f4a.tmp"
    scrambled_src:    str  = ""     # local path on Kali (served via HTTP)
    scrambled_name:   str  = ""     # "a3f2b8e1.tmp" — URL/download name
    original_sha256:  str  = ""     # for the mapping banner
    scrambled_sha256: str  = ""     # for the mapping banner


# ─── Public API ─────────────────────────────────────────────────────

def generate_stealth_context(real_tool_name: str,
                              ext: str,
                              os_type: str,
                              local_binary_path: str,
                              dicts_dir: str) -> StealthContext:
    """Build a fresh stealth context for one PEAS workflow run.

    * `real_tool_name` — "winpeas.exe" / "linpeas.sh" / ...
    * `ext` — file extension lowered, no dot ("exe", "bat", "ps1", "sh")
    * `os_type` — "windows" or "linux"
    * `local_binary_path` — where the original binary sits on Kali
    * `dicts_dir` — where HAWK puts the scrambled copy (served via HTTP)

    Side effects: writes `dicts_dir/<random>.<ext>` (the scrambled
    copy).  Returns the ctx — caller does the rest (feeding names
    into the dialog's transfer / execute command templates).
    """
    ctx               = StealthContext()
    ctx.enabled       = True
    ctx.real_tool     = real_tool_name
    ctx.random_name   = secrets.token_hex(4)   # 8 hex chars
    ctx.out_random_name = secrets.token_hex(4)

    if os_type == "windows":
        path = random.choice(_WIN_STEALTH_PATHS)
        # Keep ORIGINAL binary extension — Windows refuses to
        # execute PE files whose extension isn't in PATHEXT.
        # Stealth is in the random stem, not the extension.
        ctx.random_ext     = ext.lower().lstrip(".")
        ctx.out_random_ext = random.choice(_WIN_OUT_EXTS)
        ctx.remote_dir     = path
        ctx.remote_bin_path = (
            f"{path}\\{ctx.random_name}.{ctx.random_ext}")
        ctx.remote_out_path = (
            f"{path}\\{ctx.out_random_name}."
            f"{ctx.out_random_ext}")
    else:
        # Linux — extension doesn't matter for execution (shebang
        # handles interpreter selection for scripts, chmod+x +
        # direct invoke works for binaries).  Use dot-prefix to
        # hide from default `ls`.
        path, prefix = random.choice(_LINUX_STEALTH_PATHS)
        ctx.random_ext     = ""
        ctx.out_random_ext = ""
        ctx.remote_dir     = path
        ctx.remote_bin_path = f"{path}/{prefix}{ctx.random_name}"
        ctx.remote_out_path = (
            f"{path}/{prefix}{ctx.out_random_name}")

    # Scrambled copy on Kali — this is what the target downloads.
    # Filename matches remote so the transfer URL is obvious.
    if ctx.random_ext:
        ctx.scrambled_name = f"{ctx.random_name}.{ctx.random_ext}"
    else:
        # Linux — preserve leading dot if the remote path uses it,
        # so the file is hidden on Kali's HTTP server dir too
        # (cosmetic; the operator can still see it with ls -a).
        ctx.scrambled_name = ctx.random_name
    ctx.scrambled_src = os.path.join(dicts_dir, ctx.scrambled_name)

    # Actually scramble.  Compute hashes for the mapping banner.
    try:
        orig_h, new_h = scramble_binary(
            local_binary_path, ctx.scrambled_src, ext)
        ctx.original_sha256  = orig_h
        ctx.scrambled_sha256 = new_h
    except Exception as e:
        print(f"[HAWK] stealth: scramble failed: {e}")
        # Fall back to a plain copy so at least the transfer works
        # without the hash evasion.
        try:
            import shutil as _shutil
            _shutil.copy2(local_binary_path, ctx.scrambled_src)
        except Exception:
            pass

    return ctx


def scramble_binary(src_path: str, dst_path: str,
                     ext: str) -> tuple[str, str]:
    """Write a byte-scrambled copy of `src_path` to `dst_path`.

    PE binaries (.exe, .dll): append 1-4 KB of random bytes after
    the last section.  PE format is explicit that anything past the
    last section's virtual-end is ignored at load time, so the
    binary still runs identically.

    Text scripts (.ps1, .bat, .cmd, .sh): prepend a random-hex
    comment line using the script language's native comment char
    (`#` for PowerShell / shell, `REM ` for batch).  Hash changes,
    behaviour unchanged.

    Unknown extensions: append random bytes (best-effort — may
    break some formats; extend this function as needed).

    Returns (sha256_original, sha256_scrambled).
    """
    import hashlib

    ext = (ext or "").lower().lstrip(".")

    with open(src_path, "rb") as fh:
        data = fh.read()
    orig_sha = hashlib.sha256(data).hexdigest()

    if ext in ("exe", "dll"):
        # PE trailing-bytes trick.  Random size between 1 KB and 4 KB.
        pad = secrets.token_bytes(random.randint(1024, 4096))
        out = data + pad
    elif ext in ("ps1", "sh"):
        # Single-line random comment on top.
        rnd = secrets.token_hex(16)
        prefix = f"# {rnd}\n".encode("utf-8")
        out = prefix + data
    elif ext in ("bat", "cmd"):
        rnd = secrets.token_hex(16)
        prefix = f"REM {rnd}\r\n".encode("utf-8")
        out = prefix + data
    else:
        # Fallback — append random bytes.  Safe for most opaque
        # blobs, may break strict-format parsers.
        out = data + secrets.token_bytes(random.randint(512, 2048))

    with open(dst_path, "wb") as fh:
        fh.write(out)
    new_sha = hashlib.sha256(out).hexdigest()
    return (orig_sha, new_sha)


def short_hash(h: str, n: int = 12) -> str:
    """Truncate a SHA-256 for display in the mapping banner."""
    if not h:
        return ""
    return h[:n] + "…" if len(h) > n else h
