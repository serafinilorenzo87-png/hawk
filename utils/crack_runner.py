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
HAWK — Crack runner.

Unified multi-strategy cracker that wraps john / hashcat so the GUI
doesn't have to.  Exposes one public method per supported strategy
(`run_fast`, `run_rule_based`, `run_hybrid`, `run_target`, `run_mask`,
`run_full_stack`) and a shared `detect_devices()` helper for the UI
to show a GPU/CPU banner.

Design constraints specific to HAWK's environment:

  · Kali VM with NO real GPU is the common case.  Hashcat needs an
    OpenCL device or it exits instantly ("[-] No devices found/left")
    — that's the bug the user was hitting.  We force
    `--opencl-device-types 1` (CPU OpenCL) when no GPU is detected,
    so hashcat falls back to the CPU kernel rather than bailing.
  · John is kept as the fast lane — it auto-uses SSE on CPU, no
    OpenCL dance.
  · Strategies stream progress lines to an output callback (terminal
    widget) and dispatch a final `done_callback(strategy_name, rc,
    cracked_pass_or_none)` on the UI thread.
  · Stop-on-hit: `run_full_stack` chains strategies and aborts the
    sequence the moment any one of them produces a cracked password.

Hash format support is limited to what the Credential Store already
handles (NTLM / NetNTLMv2 / MD5 / SHA1 / SHA256 / bcrypt / md5crypt /
sha512crypt).  Extending to new types means adding rows to
`_JOHN_FORMAT` and `_HASHCAT_MODE`.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
import subprocess
from typing import Optional
from utils.config import CACHE_DIR, CONFIGS_DIR, TMP_DIR


# ─── Hash format tables ──────────────────────────────────────────────

# Hash type → john --format string (None = john cannot handle it).
_JOHN_FORMAT = {
    "NTLM":         "NT",
    "NetNTLMv2":    "netntlmv2",
    "NetNTLMv1":    "netntlm",
    "MD5":          "raw-md5",
    "SHA1":         "raw-sha1",
    "SHA256":       "raw-sha256",
    "bcrypt":       "bcrypt",
    "md5crypt":     "md5crypt",
    "sha512crypt":  "sha512crypt",
    "sha256crypt":  "sha256crypt",
    "LM":           "LM",
}

# Hash type → hashcat -m mode number (None = not in hashcat).
_HASHCAT_MODE = {
    "NTLM":         1000,
    "NetNTLMv2":    5600,
    "NetNTLMv1":    5500,
    "MD5":          0,
    "SHA1":         100,
    "SHA256":       1400,
    "bcrypt":       3200,
    "md5crypt":     500,
    "sha512crypt":  1800,
    "sha256crypt":  7400,
    "LM":           3000,
}


# ─── Path resolution ─────────────────────────────────────────────────

_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
_TOP_100K = ("/usr/share/seclists/Passwords/Common-Credentials/"
             "10-million-password-list-top-100000.txt")
_TOP_10K = ("/usr/share/seclists/Passwords/Common-Credentials/"
            "10-million-password-list-top-10000.txt")

# hashcat ships rules in different paths across distros — on rolling
# Kali they're usually in /usr/share/hashcat/rules, but docker-minimal
# and hashcat-utils splits ship them elsewhere.  We probe each path in
# order at runtime so a missing default doesn't silently break the
# RULE-BASED strategy.
_BEST64_RULES = [
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/doc/hashcat/examples/rules/best64.rule",
    "/usr/share/doc/hashcat-data/rules/best64.rule",
    "/usr/share/hashcat-utils/rules/best64.rule",
    "/opt/hashcat/rules/best64.rule",
    os.path.expanduser(
        "~/.local/share/hashcat/rules/best64.rule"),
]
_ONE_RULES = [
    "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
    "/usr/share/doc/hashcat/examples/rules/OneRuleToRuleThemAll.rule",
    "/opt/hashcat/rules/OneRuleToRuleThemAll.rule",
]
_T0XLC_RULES = [
    "/usr/share/hashcat/rules/T0XlC.rule",
    "/usr/share/doc/hashcat/examples/rules/T0XlC.rule",
]


# Inline fallback rule set — written to /tmp when NO system rule file
# is found (typical on docker-slim Kali or minimal installs without the
# `hashcat-data` package).  It's a hand-picked subset of the high-value
# transformations from best64.rule / OneRuleToRuleThemAll — enough to
# crack the common "Dictionary + decoration" patterns (Password123,
# Admin! , Welcome2024, P@ssw0rd, etc.) without depending on the user
# fixing their hashcat install.
#
# Keep this LIST SHORT (~30 rules): hashcat multiplies candidates by
# rules-count, so a 100-rule fallback on a 14M rockyou balloons to
# 1.4B candidates and turns rule-based from "fast hybrid" into "slow
# heat-the-CPU".  30 well-chosen rules is the sweet spot.
_HAWK_FALLBACK_RULE_TEXT = """\
:
l
u
c
C
t
r
d
$!
$1
$2
$3
$7
$0 $1
$1 $2 $3
$!
$? $!
$@
$#
$2 $0 $2 $3
$2 $0 $2 $4
$2 $0 $2 $5
$2 $0 $2 $6
$2 $0 $1 $9
so0
se3
sa@
ss$
si1
c $1
c $!
c $1 $2 $3
c $! $!
u $1
l $!
l $1 $2 $3
^1
^!
$1 $2 $3 $4
$0 $0 $7
"""


def _ensure_fallback_rule(name: str = "hawk_fallback") -> str:
    """Write the HAWK fallback rule to /tmp and return its path.

    Idempotent: once written the file stays put across runs.  Name is
    parametrised so different callers can use the same text under
    different filenames (cosmetic — the logs show the .rule basename
    in the hashcat invocation line)."""
    os.makedirs(TMP_DIR, exist_ok=True)
    path = os.path.join(TMP_DIR, f"{name}.rule")
    try:
        # Only rewrite if missing or stale (shorter than our text —
        # protects against a zero-byte file left by a crashed write).
        if (not os.path.isfile(path)
                or os.path.getsize(path)
                < len(_HAWK_FALLBACK_RULE_TEXT) // 2):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_HAWK_FALLBACK_RULE_TEXT)
        return path
    except Exception:
        return ""


def _first_existing(paths, fallback: str = "") -> str:
    """Accept either a string or a list.  Returns the first path that
    exists on disk, or `fallback` when none of them do."""
    if isinstance(paths, str):
        paths = [paths]
    for p in paths or []:
        if p and os.path.isfile(p):
            return p
    return fallback


# ─── hashcat session isolation ───────────────────────────────────────
#
# Hashcat reuses the same session name ("hashcat") for every invocation
# unless you pass `--session=<NAME>`.  The session name maps to a
# lockfile — so a crashed / still-running / killed-mid-flight hashcat
# process poisons the lock and every subsequent run errors out with
#     "Already an instance '/usr/bin/hashcat' running on pid NNN"
# even though the actual pid NNN may no longer exist.  Stale locks in
# `~/.local/share/hashcat/sessions/hashcat/` require manual cleanup.
#
# Fix (mirrors what we already do for john's per-run recovery file):
# generate a unique session name per run and pass it + --restore-disable
# so each invocation is fully isolated and leaves no state behind.

import uuid as _uuid_mod


def _hashcat_session_args() -> tuple[list, str]:
    """Return (extra_argv, session_name) for a fresh isolated run.

    Caller should append `extra_argv` to its hashcat invocation and
    pass `session_name` to `_cleanup_hashcat_session()` in its finally
    block."""
    name = f"hawk_{_uuid_mod.uuid4().hex[:10]}"
    return (["--session", name, "--restore-disable"], name)


def _cleanup_hashcat_session(session_name: str) -> None:
    """Best-effort cleanup of any state files hashcat wrote under the
    given session name.  Safe to call even if nothing exists — a
    crashed hashcat leaves different files in different locations and
    we only try the well-known spots."""
    candidates = [
        os.path.join(CACHE_DIR, "xdg-data", "hashcat",
                     "sessions", session_name),
        os.path.join(CACHE_DIR, "hashcat", "sessions", session_name),
    ]
    # Each candidate is a directory containing .log / .pid / .restore.
    # Remove the whole dir if it exists.
    import shutil as _shutil
    for d in candidates:
        try:
            if os.path.isdir(d):
                _shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass


# ─── Device detection ────────────────────────────────────────────────

def _crack_env() -> dict:
    """Environment for john/hashcat that keeps XDG/temp state in hawkc."""
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


def detect_devices() -> dict:
    """Probe hashcat -I once and classify what we have.

    Returns:
        {
          "has_hashcat": bool,
          "has_john":    bool,
          "has_gpu":     bool,     # real OpenCL/CUDA GPU found
          "has_cpu_ocl": bool,     # CPU OpenCL device found
          "devices":     [dict],   # parsed device list
          "summary":     str,      # human-readable 1-line banner
          "force_cpu_flag": list,  # extra argv HAWK should pass hashcat
        }
    """
    out = {
        "has_hashcat":    shutil.which("hashcat") is not None,
        "has_john":       shutil.which("john") is not None,
        "has_gpu":        False,
        "has_cpu_ocl":    False,
        "devices":        [],
        "summary":        "",
        "force_cpu_flag": [],
    }

    if not out["has_hashcat"]:
        out["summary"] = ("hashcat NOT installed — only FAST (john) "
                          "works.  Install: sudo apt install hashcat")
        return out

    try:
        r = subprocess.run(
            ["hashcat", "-I"],
            capture_output=True, text=True, timeout=10,
            errors="replace", env=_crack_env())
        blob = r.stdout + "\n" + r.stderr
    except Exception as e:
        out["summary"] = f"hashcat -I failed: {e}"
        return out

    # Parse device blocks.  Each block looks like:
    #   Backend Device ID #1
    #     Type...........: GPU
    #     Vendor.........: NVIDIA
    #     Name...........: NVIDIA GeForce GTX 1650
    dev_blocks = re.findall(
        r"(Backend Device ID [^\n]+\n(?:[ \t]+[^\n]+\n)+)", blob)
    for blk in dev_blocks:
        dev = {}
        for key in ("Type", "Vendor", "Name"):
            m = re.search(rf"{key}\.+:\s*(\S.*)", blk)
            if m:
                dev[key.lower()] = m.group(1).strip()
        if not dev:
            continue
        out["devices"].append(dev)
        dtype = (dev.get("type") or "").upper()
        if dtype == "GPU":
            out["has_gpu"] = True
        elif dtype == "CPU":
            out["has_cpu_ocl"] = True

    # Build summary banner + CPU-fallback flag.
    if out["has_gpu"]:
        gpu_name = next((d.get("name", "GPU")
                         for d in out["devices"]
                         if (d.get("type") or "").upper() == "GPU"),
                        "GPU")
        out["summary"] = (f"✅  GPU accel ON ({gpu_name}) — all "
                          "estimates 10-50× faster than CPU-only.")
    elif out["has_cpu_ocl"]:
        out["summary"] = (
            "⚠  CPU-only (no GPU device).  Hashcat routed through CPU "
            "OpenCL — usable but slow.  Budget times as estimated.")
        out["force_cpu_flag"] = ["--opencl-device-types", "1"]
    else:
        out["summary"] = (
            "⚠  No OpenCL device found — hashcat would exit instantly. "
            "HAWK forces --opencl-device-types 1 (pure-CPU fallback). "
            "Consider CRACK ONLINE for anything beyond FAST on this VM.")
        out["force_cpu_flag"] = ["--opencl-device-types", "1"]

    return out


# ─── Strategy runner ────────────────────────────────────────────────

class CrackRunner:
    """Sequencer + subprocess wrapper for all crack strategies.

    Lifecycle (single strategy):

        r = CrackRunner(output_callback=..., done_callback=...,
                         ui_dispatcher=...)
        r.run_rule_based(hash_str, hash_type)

    Lifecycle (FULL STACK):

        r.run_full_stack(hash_str, hash_type,
                          target_dict_path=None,
                          stages=None)       # None = default list

    done_callback signature:
        (strategy: str, rc: int, cracked: Optional[str])
    """

    def __init__(self, output_callback=None, done_callback=None,
                 ui_dispatcher=None):
        self.output_callback = output_callback
        self.done_callback   = done_callback
        self.ui_dispatcher   = ui_dispatcher

        self._proc = None
        self._cancelled = False
        self._devices = detect_devices()

    # ── public device query ───────────────────────────────────────────
    @property
    def devices(self) -> dict:
        return self._devices

    def kill(self):
        """SIGTERM → wait 2s → SIGKILL escalation.

        john in particular ignores SIGTERM when its .rec recovery file
        is locked (classic "it was responding after all" scenario for
        users staring at the 'stopping…' label in the progress dialog
        for minutes).  We always schedule the SIGKILL fallback in a
        daemon thread so kill() returns instantly to the UI.
        """
        self._cancelled = True
        p = self._proc
        if not p:
            return
        try:
            p.terminate()
        except Exception:
            pass

        def _escalate(proc=p):
            import time as _time
            _time.sleep(2.0)
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass
        threading.Thread(target=_escalate, daemon=True).start()

    # ── Strategy dispatchers ──────────────────────────────────────────
    # Every run_* is thread-wrapped so the UI thread doesn't block.

    def run_fast(self, hash_str: str, hash_type: str):
        """john --wordlist=rockyou.txt.  Fastest, smallest coverage."""
        threading.Thread(
            target=self._run_fast_impl,
            args=(hash_str, hash_type),
            daemon=True).start()

    def run_rule_based(self, hash_str: str, hash_type: str,
                        rule: str = "best64"):
        """hashcat -a 0 with a rule file on rockyou."""
        threading.Thread(
            target=self._run_rule_based_impl,
            args=(hash_str, hash_type, rule),
            daemon=True).start()

    def run_hybrid(self, hash_str: str, hash_type: str,
                    mask: str = "?d?d?s"):
        """hashcat -a 6 with a short suffix mask on top-100k."""
        threading.Thread(
            target=self._run_hybrid_impl,
            args=(hash_str, hash_type, mask),
            daemon=True).start()

    def run_target(self, hash_str: str, hash_type: str,
                    dict_path: str):
        """hashcat -a 0 with a custom target-profile dict + best64."""
        threading.Thread(
            target=self._run_target_impl,
            args=(hash_str, hash_type, dict_path),
            daemon=True).start()

    def run_mask(self, hash_str: str, hash_type: str, mask: str):
        """hashcat -a 3 pure mask attack."""
        threading.Thread(
            target=self._run_mask_impl,
            args=(hash_str, hash_type, mask),
            daemon=True).start()

    def run_full_stack(self, hash_str: str, hash_type: str,
                        target_dict_path: Optional[str] = None):
        """Run FAST → RULE-BASED → HYBRID → TARGET, stop on hit."""
        threading.Thread(
            target=self._run_full_stack_impl,
            args=(hash_str, hash_type, target_dict_path),
            daemon=True).start()

    # ── Implementations ───────────────────────────────────────────────
    def _emit(self, line: str, level: str = "info"):
        if self.output_callback:
            try:
                if self.ui_dispatcher:
                    self.ui_dispatcher(
                        self.output_callback, line,
                        "crack", level)
                else:
                    self.output_callback(line, "crack", level)
            except Exception:
                pass

    def _done(self, strategy: str, rc: int,
               cracked: Optional[str]):
        if not self.done_callback:
            return
        try:
            if self.ui_dispatcher:
                self.ui_dispatcher(self.done_callback,
                                    strategy, rc, cracked)
            else:
                self.done_callback(strategy, rc, cracked)
        except Exception as e:
            print(f"[HAWK] crack done_callback: {e}")

    # --- shared: write hash to a temp file, return path ---------------
    def _hash_file(self, hash_str: str) -> str:
        os.makedirs(TMP_DIR, exist_ok=True)
        fd, path = tempfile.mkstemp(
            prefix="hawk_crack_", suffix=".hash", dir=TMP_DIR)
        try:
            os.write(fd, hash_str.encode() + b"\n")
        finally:
            os.close(fd)
        return path

    # --- shared: stream a subprocess, write progress, return
    # --- (returncode, full_stdout) --------------------------
    def _stream(self, argv: list, tag: str,
                 timeout: int = 3600) -> tuple:
        self._emit(f"  [{tag}] $ {' '.join(argv)}", "cmd")
        try:
            self._proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1, errors="replace",
                env=_crack_env())
        except Exception as e:
            self._emit(f"  [{tag}] spawn failed: {e}", "error")
            return (-1, "")
        buf = []
        try:
            for line in self._proc.stdout:
                if self._cancelled:
                    try:
                        self._proc.terminate()
                    except Exception:
                        pass
                    break
                line = line.rstrip()
                buf.append(line)
                # Suppress hashcat status noise but keep meaningful
                # lines (Cracked, Exhausted, Found, progress bumps).
                low = line.lower()
                if (line.startswith("Status...........: ")
                        or line.startswith("Speed.#")
                        or line.startswith("Progress.........: ")
                        or line.startswith("Rejected.........: ")
                        or line.startswith("Restore.Point")
                        or line.startswith("Candidate.Engine")
                        or line.startswith("Hardware.Mon")
                        or not line):
                    continue
                self._emit(f"  [{tag}] {line}", "info")
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._emit(f"  [{tag}] timeout — killing.", "warn")
            try:
                self._proc.kill()
            except Exception:
                pass
        rc = self._proc.returncode if self._proc else -1
        self._proc = None
        return (rc, "\n".join(buf))

    # --- shared: read cracked password from a per-run outfile ---------
    def _read_cracked_from_outfile(
            self, outfile_path: str) -> Optional[str]:
        """Read the plaintext password hashcat / john wrote to their
        per-run --outfile (hashcat) or --pot (john) path.

        Why per-run outfile instead of `hashcat --show` against a
        shared potfile:

        The shared-potfile approach short-circuits the ATTACK itself:
        hashcat reads a shared potfile at startup, sees the target
        hash already cracked from an earlier HAWK run, prints
            INFO: All hashes found as potfile and/or empty entries!
        and exits in 1s without ever testing whether the CURRENT
        strategy (RULE-BASED / HYBRID / MASK / TARGET) would have found
        it on its own.  That makes HAWK useless as a learning tool —
        the user can never answer "is this hash crackable by rule-based
        alone?".  Per-run outfile + --potfile-disable keeps every run
        honest: the strategy actually runs end-to-end every time.

        Format: hashcat with --outfile-format 2 writes one plaintext
        password per line.  john's --pot file is legacy format
        (hash:pass) so we use rsplit(":", 1) as a compromise."""
        try:
            with open(outfile_path, "r", encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    # Accept both formats: "password" (hashcat format 2)
                    # and "hash:password" (john pot).  We can tell them
                    # apart by whether a colon is present, but for
                    # robustness always take the last field after the
                    # last colon if one exists.
                    if ":" in line:
                        return line.rsplit(":", 1)[-1]
                    return line
        except FileNotFoundError:
            # The crack completed but nothing was found — no outfile
            # was written, so no match.
            return None
        except Exception as e:
            print(f"[HAWK] outfile read failed ({outfile_path}): {e}")
        return None

    def _read_cracked_john(self, hash_file: str,
                             fmt: str) -> Optional[str]:
        # NOTE: UNUSED since the FAST strategy switched to a per-run
        # --pot file read via _read_cracked_from_outfile.  Kept here as
        # a reference helper in case some future flow wants to query
        # john's DEFAULT john.pot (which we deliberately
        # bypass to avoid attack short-circuits — see FAST for why).
        try:
            r = subprocess.run(
                ["john", f"--format={fmt}", "--show", hash_file],
                capture_output=True, text=True, timeout=30,
                errors="replace", env=_crack_env())
            # john --show: "user:password:other:fields"
            for line in (r.stdout or "").splitlines():
                if ":" in line and not line.startswith("0 password"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1]:
                        return parts[1]
        except Exception as e:
            print(f"[HAWK] john --show failed: {e}")
        return None

    # --- FAST (john) --------------------------------------------------
    def _run_fast_impl(self, hash_str: str, hash_type: str):
        fmt = _JOHN_FORMAT.get(hash_type)
        if not fmt:
            self._emit(f"  [FAST] john doesn't support {hash_type} — "
                       "skipping.", "warn")
            self._done("FAST", -1, None)
            return
        wl = _first_existing([_ROCKYOU])
        if not wl:
            self._emit("  [FAST] rockyou.txt not found "
                       "(sudo gunzip /usr/share/wordlists/"
                       "rockyou.txt.gz).", "error")
            self._done("FAST", -1, None)
            return

        hf = self._hash_file(hash_str)
        # Unique session name per run → john never collides with a
        # locked john.rec from a prior crashed/stopped run.
        # Without this, STOP on a running john leaves a lock that
        # blocks every subsequent crack with:
        #   "Crash recovery file is locked: /home/kali/.john/john.rec"
        import uuid as _uuid
        sess_id = _uuid.uuid4().hex[:8]
        sess_dir = os.path.join(TMP_DIR, "john")
        try:
            os.makedirs(sess_dir, exist_ok=True)
        except Exception:
            pass
        sess_path = os.path.join(sess_dir, f"hawk_{sess_id}")
        # Per-run pot file — same rationale as hashcat's
        # --potfile-disable/--outfile pattern: the default
        # john's default john.pot would short-circuit the attack when a prior
        # FAST run already cracked the hash, exiting instantly and
        # leaving the user unable to tell whether rockyou+john would
        # actually find it.  A fresh pot per run forces john to truly
        # run the dictionary attack every time.
        pot_path = sess_path + ".pot"

        self._emit(f"  [FAST] john --format={fmt} + rockyou "
                   f"(14M candidates)...", "info")
        try:
            # NOTE: no `--nolog` — that's a hashcat flag, john has no
            # equivalent.  Log file lands at `<session>.log` and is
            # cleaned up in the finally block along with the .rec.
            rc, _ = self._stream(
                ["john", f"--format={fmt}",
                 f"--session={sess_path}",
                 f"--pot={pot_path}",
                 f"--wordlist={wl}", hf],
                tag="FAST", timeout=1800)
            # Read directly from the per-run pot file — avoids having
            # to invoke `john --show` (which itself reads the pot, but
            # now we have a clean isolated one so the direct read is
            # simpler and identical in outcome).
            cracked = self._read_cracked_from_outfile(pot_path)
        finally:
            # Hash file + any leftover john state files (.rec, .log,
            # .pot).
            try:
                os.unlink(hf)
            except Exception:
                pass
            for ext in (".rec", ".log", ".pot"):
                try:
                    os.unlink(sess_path + ext)
                except Exception:
                    pass
        self._done("FAST", rc, cracked)

    # --- RULE-BASED (hashcat -a 0 + rule file) ------------------------
    def _run_rule_based_impl(self, hash_str: str, hash_type: str,
                               rule_name: str):
        mode = _HASHCAT_MODE.get(hash_type)
        if mode is None:
            self._emit(f"  [RULE-BASED] hashcat mode unknown for "
                       f"{hash_type} — skipping.", "warn")
            self._done("RULE-BASED", -1, None)
            return
        wl = _first_existing([_ROCKYOU])
        # Resolve the rule file across the 6 common install layouts
        # we probe in _BEST64_RULES etc.  Different Kali packages
        # drop these in different directories.
        rule_lists = {
            "best64":  _BEST64_RULES,
            "t0xlc":   _T0XLC_RULES,
            "onerule": _ONE_RULES,
        }
        rule_path = _first_existing(
            rule_lists.get(rule_name, _BEST64_RULES))

        # Wordlist is a hard requirement — without rockyou the strategy
        # is dead in the water.  Bail with a clear message.
        if not wl:
            self._emit(
                "  [RULE-BASED] rockyou.txt not found — install with "
                "`sudo apt install wordlists && sudo gunzip "
                "/usr/share/wordlists/rockyou.txt.gz`.",
                "error")
            self._done("RULE-BASED", -1, None)
            return

        # Rule file is NICE-to-have.  If the system install is missing
        # the rules subdir (common on docker-slim / minimal-kali), fall
        # back to our inline rule set so the user gets *something*
        # instead of an abort.  The original system-fix hint is still
        # emitted so the user can upgrade to the real best64 later.
        if not rule_path:
            rule_path = _ensure_fallback_rule(f"hawk_{rule_name}")
            if rule_path:
                self._emit(
                    f"  [RULE-BASED] system {rule_name}.rule not "
                    f"found — using HAWK inline fallback "
                    f"({rule_path}).\n"
                    "        For the real thing: `sudo apt install "
                    "hashcat-data` or `git clone "
                    "github.com/hashcat/hashcat /tmp/hc && sudo cp "
                    "-r /tmp/hc/rules /usr/share/hashcat/`.",
                    "warn")
            else:
                self._emit(
                    f"  [RULE-BASED] {rule_name}.rule missing AND "
                    "fallback write failed (check /tmp perms).",
                    "error")
                self._done("RULE-BASED", -1, None)
                return

        hf = self._hash_file(hash_str)
        out_path = hf + ".out"
        sess_args, sess_name = _hashcat_session_args()
        self._emit(
            f"  [RULE-BASED] hashcat -m {mode} -a 0 -r "
            f"{os.path.basename(rule_path)} + rockyou  (-w 1 keeps "
            f"the host UI responsive)...", "info")
        try:
            # -w 1 = Low workload profile.  Crucial on Kali running
            # inside a VM: without it hashcat pegs every core and
            # the desktop freezes until the job finishes.  Low-
            # workload is ~20% slower but keeps the GUI clickable.
            #
            # --potfile-disable + --outfile → every run actually runs
            # the attack (no short-circuit on cached hits), and the
            # cracked password lands in the per-run outfile that we
            # read after the process exits.  See
            # _read_cracked_from_outfile for the full story.
            argv = ["hashcat", "-m", str(mode), "-a", "0",
                    hf, wl, "-r", rule_path,
                    "-w", "1",
                    "--status", "--status-timer", "10",
                    "--self-test-disable",
                    "--potfile-disable",
                    "--outfile", out_path,
                    "--outfile-format", "2"]
            argv += sess_args
            argv += self._devices.get("force_cpu_flag", [])
            rc, _ = self._stream(argv, tag="RULE-BASED",
                                  timeout=7200)
            cracked = self._read_cracked_from_outfile(out_path)
        finally:
            for p in (hf, out_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass
            _cleanup_hashcat_session(sess_name)
        self._done("RULE-BASED", rc, cracked)

    # --- HYBRID (hashcat -a 6, top-100k + short suffix mask) ----------
    def _run_hybrid_impl(self, hash_str: str, hash_type: str,
                           mask: str):
        mode = _HASHCAT_MODE.get(hash_type)
        if mode is None:
            self._emit(f"  [HYBRID] hashcat mode unknown for "
                       f"{hash_type} — skipping.", "warn")
            self._done("HYBRID", -1, None)
            return
        wl = _first_existing([_TOP_100K, _TOP_10K, _ROCKYOU])
        if not wl:
            self._emit(
                "  [HYBRID] no wordlist available.", "error")
            self._done("HYBRID", -1, None)
            return

        hf = self._hash_file(hash_str)
        out_path = hf + ".out"
        sess_args, sess_name = _hashcat_session_args()
        self._emit(
            f"  [HYBRID] hashcat -m {mode} -a 6 "
            f"{os.path.basename(wl)} + '{mask}'  (-w 1 keeps the "
            f"host UI responsive)...", "info")
        try:
            # -w 1 low workload → Kali stays clickable even at full
            # crack throttle (see RULE-BASED for the full story).
            argv = ["hashcat", "-m", str(mode), "-a", "6",
                    hf, wl, mask,
                    "-w", "1",
                    "--status", "--status-timer", "10",
                    "--self-test-disable",
                    "--potfile-disable",
                    "--outfile", out_path,
                    "--outfile-format", "2"]
            argv += sess_args
            argv += self._devices.get("force_cpu_flag", [])
            rc, _ = self._stream(argv, tag="HYBRID",
                                  timeout=3600)
            cracked = self._read_cracked_from_outfile(out_path)
        finally:
            for p in (hf, out_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass
            _cleanup_hashcat_session(sess_name)
        self._done("HYBRID", rc, cracked)

    # --- TARGET (custom dict + best64) --------------------------------
    def _run_target_impl(self, hash_str: str, hash_type: str,
                          dict_path: str):
        mode = _HASHCAT_MODE.get(hash_type)
        if mode is None:
            self._done("TARGET", -1, None)
            return
        if not dict_path or not os.path.isfile(dict_path):
            self._emit(
                f"  [TARGET] dict not found: {dict_path}", "error")
            self._done("TARGET", -1, None)
            return
        # Best effort: use system best64 if present, else the HAWK
        # inline fallback.  Target-dict cracks with no rules at all
        # are almost always worse than with decoration rules, so we
        # go out of our way to provide *something*.
        rule_path = _first_existing(_BEST64_RULES)
        using_fallback = False
        if not rule_path:
            rule_path = _ensure_fallback_rule("hawk_best64")
            using_fallback = bool(rule_path)

        hf = self._hash_file(hash_str)
        self._emit(
            f"  [TARGET] hashcat -m {mode} -a 0 "
            f"{os.path.basename(dict_path)}"
            + (f" + {'HAWK-fallback' if using_fallback else 'best64'} "
               f"rule" if rule_path else "")
            + "  (-w 1 keeps the host UI responsive)...", "info")
        out_path = hf + ".out"
        sess_args, sess_name = _hashcat_session_args()
        try:
            argv = ["hashcat", "-m", str(mode), "-a", "0",
                    hf, dict_path]
            if rule_path:
                argv += ["-r", rule_path]
            argv += ["-w", "1",
                     "--status", "--status-timer", "10",
                     "--self-test-disable",
                     "--potfile-disable",
                     "--outfile", out_path,
                     "--outfile-format", "2"]
            argv += sess_args
            argv += self._devices.get("force_cpu_flag", [])
            rc, _ = self._stream(argv, tag="TARGET",
                                  timeout=1800)
            cracked = self._read_cracked_from_outfile(out_path)
        finally:
            for p in (hf, out_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass
            _cleanup_hashcat_session(sess_name)
        self._done("TARGET", rc, cracked)

    # --- MASK (hashcat -a 3 pure structural) --------------------------
    def _run_mask_impl(self, hash_str: str, hash_type: str,
                        mask: str):
        mode = _HASHCAT_MODE.get(hash_type)
        if mode is None:
            self._done("MASK", -1, None)
            return
        hf = self._hash_file(hash_str)
        out_path = hf + ".out"
        sess_args, sess_name = _hashcat_session_args()
        self._emit(
            f"  [MASK] hashcat -m {mode} -a 3 mask='{mask}'  "
            f"(-w 1 keeps the host UI responsive)...", "info")
        try:
            argv = ["hashcat", "-m", str(mode), "-a", "3",
                    hf, mask,
                    "-w", "1",
                    "--status", "--status-timer", "10",
                    "--self-test-disable",
                    "--potfile-disable",
                    "--outfile", out_path,
                    "--outfile-format", "2"]
            argv += sess_args
            argv += self._devices.get("force_cpu_flag", [])
            rc, _ = self._stream(argv, tag="MASK",
                                  timeout=86400)
            cracked = self._read_cracked_from_outfile(out_path)
        finally:
            for p in (hf, out_path):
                try:
                    os.unlink(p)
                except Exception:
                    pass
            _cleanup_hashcat_session(sess_name)
        self._done("MASK", rc, cracked)

    # --- FULL STACK (chained, stop-on-hit) ----------------------------
    def _run_full_stack_impl(self, hash_str: str, hash_type: str,
                               target_dict_path: Optional[str]):
        """Chain: FAST → RULE-BASED → HYBRID → TARGET (if dict
        available).  Stops the moment any stage produces a password."""
        captured: dict = {"cracked": None, "stage": None, "rc": -1}

        original_done = self.done_callback

        def _stage_done(stage, rc, cracked):
            if cracked:
                captured["cracked"] = cracked
                captured["stage"] = stage
                captured["rc"] = rc
            # Don't invoke the outer callback here — we do it ONCE
            # at the end of the whole stack.
            captured["_stage_rc"] = rc

        # Swap the callback temporarily.
        self.done_callback = _stage_done

        try:
            self._emit("  [FULL STACK] starting multi-stage crack...",
                       "info")

            stages = [
                ("FAST",        lambda: self._run_fast_impl(
                                   hash_str, hash_type)),
                ("RULE-BASED",  lambda: self._run_rule_based_impl(
                                   hash_str, hash_type, "best64")),
                ("HYBRID",      lambda: self._run_hybrid_impl(
                                   hash_str, hash_type, "?d?d?s")),
            ]
            if target_dict_path:
                stages.append(
                    ("TARGET",
                     lambda: self._run_target_impl(
                         hash_str, hash_type, target_dict_path)))

            for name, fn in stages:
                if self._cancelled:
                    break
                self._emit(f"  [FULL STACK] → stage: {name}",
                           "info")
                fn()   # blocks: each _impl method waits for its
                        # subprocess to finish before returning
                if captured["cracked"]:
                    self._emit(
                        f"  [FULL STACK] ✓ cracked at stage "
                        f"{captured['stage']} — "
                        f"password: {captured['cracked']}",
                        "success")
                    break
            else:
                self._emit("  [FULL STACK] exhausted all stages "
                           "without a hit.", "warn")
        finally:
            self.done_callback = original_done

        # Single final dispatch.
        self._done("FULL STACK",
                    0 if captured["cracked"] else 1,
                    captured["cracked"])
