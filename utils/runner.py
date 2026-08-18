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
HAWK - Runner v1.0
MSF resource script: after exploit, interacts with session automatically.
Ping -Pn: only adds -Pn flag, no extra scan parameters.
"""

import ipaddress
import subprocess, threading, shutil, os, re, signal, time
from datetime import datetime
from utils.config import CACHE_DIR, CONFIGS_DIR, TMP_DIR, resolve_tool_tmpdir


import socket


# ─── Extended PATH for all HAWK subprocesses ────────────────────────────────
# Tools like kerbrute, nuclei, rustscan, certipy etc. are often installed
# outside $PATH (~/go/bin, ~/.cargo/bin, /opt/tools, ~/kerbrute ...).
# Instead of resolving each binary individually in every routing function,
# we extend the PATH once and pass it to every Popen call.  This way ANY
# command HAWK runs will automatically find binaries in pentester locations.
#
# The cache is built lazily on first use and reused for the entire session.

_hawk_env_cache = None

def _hawk_env():
    """Return a copy of os.environ with PATH extended to include all
    pentester-relevant directories from modules.base._EXTRA_BIN_DIRS,
    plus common bare-file download locations (~/kerbrute, ~/chisel, …).
    Directories that don't exist on disk are silently skipped."""
    global _hawk_env_cache
    if _hawk_env_cache is not None:
        return _hawk_env_cache

    env = os.environ.copy()
    current_path = env.get("PATH", "")

    try:
        from modules.base import _EXTRA_BIN_DIRS
        extra_dirs = list(_EXTRA_BIN_DIRS)
    except ImportError:
        extra_dirs = []

    # Also search the user's home directory itself — many people just
    # download a binary straight into ~/ (e.g. ~/kerbrute, ~/chisel).
    for home in [os.path.expanduser("~"), "/root"]:
        if home not in extra_dirs:
            extra_dirs.append(home)

    # Filter to directories that actually exist, then prepend them so
    # they take priority over system PATH (pipx before apt, etc.).
    existing = [d for d in extra_dirs if os.path.isdir(d)]
    extended = os.pathsep.join(existing)
    env["PATH"] = extended + os.pathsep + current_path if extended else current_path
    xdg_data = os.path.join(CACHE_DIR, "xdg-data")
    for d in (CONFIGS_DIR, CACHE_DIR, xdg_data, TMP_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
    env["XDG_CONFIG_HOME"] = CONFIGS_DIR
    env["XDG_CACHE_HOME"] = CACHE_DIR
    env["XDG_DATA_HOME"] = xdg_data
    # TMP_DIR by default; a real local temp only when BASE_DIR is on a
    # shared/network filesystem whose temp I/O hangs tools (nuclei).
    env["TMPDIR"] = resolve_tool_tmpdir()

    _hawk_env_cache = env
    return env

def is_port_free(port: int) -> bool:
    """Check if a TCP port is available for binding."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", int(port)))
            return True
    except OSError:
        return False


def find_free_port(start: int = 4444) -> int:
    """Find first free port starting from start."""
    for p in range(start, start + 200):
        if is_port_free(p):
            return p
    return start

_ANSI = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
def strip_ansi(t): return _ANSI.sub('', t)


# ─── Raw-socket capabilities detection ────────────────────────────────────────
# If the user has run setup_nmap_caps.sh (or equivalent setcap), nmap/masscan
# can do SYN scans without sudo.  Running without sudo means:
#   • no sudo credential-cache problems (no password prompts mid-scan)
#   • no sudo pty-relay buffering of --stats-every progress lines
#   • real-time progress bar updates
#
# We probe once per binary per process and cache the result — `getcap` is a
# tiny syscall but there's no point in running it on every scan.
_CAPS_CACHE = {}      # binary_name → True/False
_CAPS_TOOLS  = ("nmap", "masscan")    # tools we know how to un-sudo

def has_raw_caps(binary: str) -> bool:
    """Return True if *binary* is on PATH and carries cap_net_raw.

    Cached for the lifetime of the process.  Safe to call from any thread.
    """
    if binary in _CAPS_CACHE:
        return _CAPS_CACHE[binary]
    ok = False
    try:
        path = shutil.which(binary)
        if path and shutil.which("getcap"):
            # `getcap BINARY` prints e.g. `/usr/bin/nmap cap_net_raw=eip` when
            # caps are set, or nothing at all otherwise.
            r = subprocess.run(["getcap", path],
                               capture_output=True, text=True, timeout=3)
            ok = "cap_net_raw" in r.stdout
    except Exception:
        ok = False
    _CAPS_CACHE[binary] = ok
    return ok


def _strip_sudo_if_caps(command: str) -> str:
    """Drop the `sudo ` prefix from commands that only needed it for raw
    sockets — when the tool has cap_net_raw set, sudo is pure overhead that
    also breaks real-time progress output."""
    if not command.startswith("sudo "):
        return command
    rest = command[5:].lstrip()
    # Peek at the first non-option token (skip `-X` flags that belong to sudo)
    parts = rest.split()
    first = ""
    for tok in parts:
        if tok.startswith("-"):
            continue
        first = os.path.basename(tok)
        break
    if first in _CAPS_TOOLS and has_raw_caps(first):
        return rest
    return command


# ─── netexec (nxc) schema-mismatch diagnostic ─────────────────────────────
# Background: netexec keeps a sqlite DB per protocol under
# ~/.nxc/workspaces/<ws>/<proto>.db.  When the installed netexec version
# is upgraded but those DBs were created by an older version, every nxc
# run aborts with:
#     [-] Schema mismatch detected for table '...' in protocol '...'
#     [-] This is probably because a newer version of nxc is being run
#         on an old DB schema.
# and exits without doing anything — the user sees the HAWK card
# "complete" in a fraction of a second with zero results.
#
# HAWK does NOT touch NetExec's home database. We only remember the
# observed nxc version in hawkc/cache and log a diagnostic if it changes,
# so the portable app never deletes or rewrites user-owned NetExec state
# outside the folder.

_NXC_PROTOCOLS = {
    "smb", "ldap", "winrm", "mssql", "rdp", "ssh", "ftp", "wmi",
    "nfs", "vnc",
}
_NXC_CMD_RE = re.compile(r"^(?:sudo\s+(?:-\S+\s+)*)?(?:nxc|netexec|crackmapexec|cme)\s+(\w+)", re.I)
_nxc_preflight_done = False


def _nxc_current_version() -> str:
    """Return the netexec version string, or '' if nxc isn't installed
    or doesn't respond in time.  Cheap: runs once per HAWK process."""
    if not shutil.which("nxc"):
        return ""
    try:
        r = subprocess.run(["nxc", "--version"],
                           capture_output=True, text=True, timeout=4)
        return (r.stdout or r.stderr or "").strip().splitlines()[0] if (
            r.stdout or r.stderr) else ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _preflight_nxc(command: str) -> None:
    """If `command` is an nxc invocation and we haven't checked yet this
    HAWK session, compare the installed nxc version against the marker
    file under hawkc/cache.  On mismatch, emit a diagnostic only.
    Writes the new version back to the marker.

    Safe no-op when nxc isn't installed, when command isn't an nxc run,
    or when the version hasn't changed.
    """
    global _nxc_preflight_done
    if _nxc_preflight_done:
        return
    m = _NXC_CMD_RE.match(command.strip())
    if not m:
        return
    proto = m.group(1).lower()
    if proto not in _NXC_PROTOCOLS:
        return  # first token after nxc isn't a protocol (e.g. --help)

    _nxc_preflight_done = True   # attempt only once per process

    current = _nxc_current_version()
    if not current:
        return  # nxc not installed or version probe failed — leave alone

    marker_dir = os.path.join(CACHE_DIR, "nxc")
    marker = os.path.join(marker_dir, "nxc_schema_version")
    stored = ""
    try:
        with open(marker, "r", encoding="utf-8") as fh:
            stored = fh.read().strip()
    except OSError:
        stored = ""

    if stored == current:
        return  # same version as last time — DBs match, nothing to do

    # Version changed (or first run). Older HAWK builds modified NetExec
    # workspace DBs here to repair schema mismatches. That violates the
    # portable-folder policy, so we only record the observed version and
    # let NetExec handle its own home-state.
    changed = bool(stored and stored != current)

    # Persist the new version so we only warn once for this upgrade.
    try:
        os.makedirs(marker_dir, exist_ok=True)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(current)
    except OSError:
        pass

    if os.environ.get("HAWK_DBG_PROGRESS", "1") == "1" and changed:
        print(f"[HAWK] nxc upgrade detected ({current!r}) — "
              f"not touching NetExec DBs; fix manually if schema mismatch appears.",
              flush=True)


def _pty_pair():
    """Create a pseudo-terminal pair (master_fd, slave_fd).

    The slave side is given to the child process as stdin/stdout/stderr
    so it sees a real tty — tools like nmap then use line-buffered
    output and flush --stats-every progress lines immediately.

    We disable echo and output post-processing on the slave so that:
      • no input is echoed back
      • \\n is NOT converted to \\r\\n (we handle both delimiters ourselves)
      • window size is set to 80x24 — a brand-new pty defaults to 0x0 which
        can confuse tools that probe TIOCGWINSZ (nmap was silent otherwise).
    """
    import pty, termios, fcntl, struct
    master_fd, slave_fd = pty.openpty()
    try:
        attrs = termios.tcgetattr(slave_fd)
        attrs[1] &= ~termios.OPOST   # no \n → \r\n conversion
        attrs[3] &= ~termios.ECHO    # no echo
        termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
    except Exception:
        pass
    try:
        # rows=24, cols=80, xpixels=0, ypixels=0
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ,
                    struct.pack('HHHH', 24, 80, 0, 0))
    except Exception:
        pass
    return master_fd, slave_fd


def find_wordlist(paths):
    for p in paths:
        if os.path.isfile(p): return p
    return ""

def _parse_ip_addr_output(text: str):
    """Yield (iface, ipv4) pairs from both `ip -o` and normal `ip addr`."""
    current_iface = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        header = re.match(r"^\d+:\s+([^:]+):", line)
        if header:
            current_iface = header.group(1).split("@", 1)[0].strip()

        inline = re.match(
            r"^\d+:\s+([^\s:]+).*?\binet\s+(\d+\.\d+\.\d+\.\d+)/",
            line,
        )
        if inline:
            yield inline.group(1).split("@", 1)[0].strip(), inline.group(2)
            continue

        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", line)
        if m and current_iface:
            yield current_iface, m.group(1)


def _usable_lhost_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.version == 4
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_unspecified
    )


def _iface_rank(iface: str) -> int:
    name = (iface or "").lower()
    if name.startswith(("tun", "tap", "wg", "tailscale", "zt")):
        return 0  # VPN / overlay networks: HTB, THM, WireGuard, Tailscale.
    if name.startswith(("eth", "ens", "enp", "eno")):
        return 1  # Common VM NICs: VirtualBox, VMware, Hyper-V, ESXi.
    if name.startswith(("wlan", "wl")):
        return 2
    if name.startswith(("vboxnet", "vmnet", "virbr", "docker", "br-", "cni", "podman")):
        return 4  # Local bridges are often not reachable by the target.
    return 3


def _candidate_sort_key(candidate):
    try:
        addr = ipaddress.ip_address(candidate["ip"])
        ip_penalty = 0 if (addr.is_private or candidate["iface"].lower().startswith(
            ("tun", "tap", "wg", "tailscale", "zt")
        )) else 1
    except ValueError:
        ip_penalty = 2
    return (
        _iface_rank(candidate["iface"]),
        ip_penalty,
        candidate["order"],
        candidate["iface"],
    )


def lhost_candidates():
    """Return usable local IPv4 candidates ordered for reverse callbacks."""
    commands = [
        ["ip", "-o", "-4", "addr", "show", "up", "scope", "global"],
        ["ip", "-o", "-4", "addr", "show", "scope", "global"],
        ["ip", "-o", "-4", "addr", "show"],
        ["ip", "addr"],
    ]
    candidates, seen, order = [], set(), 0
    for cmd in commands:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        for iface, ip in _parse_ip_addr_output(r.stdout):
            if not iface or not _usable_lhost_ip(ip):
                continue
            key = (iface, ip)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"iface": iface, "ip": ip, "order": order})
            order += 1

    if not candidates:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 80))
                ip = s.getsockname()[0]
            if _usable_lhost_ip(ip):
                candidates.append({"iface": "default-route", "ip": ip, "order": order})
        except OSError:
            pass

    return sorted(candidates, key=_candidate_sort_key)


def lhost_detect():
    candidates = lhost_candidates()
    return candidates[0]["ip"] if candidates else ""


def lhost_iface():
    candidates = lhost_candidates()
    return candidates[0]["iface"] if candidates else "unknown"


def route_to_target(target_ip: str) -> dict:
    """How the kernel actually reaches ``target_ip`` — the authoritative
    answer on a multi-homed host.

    Returns ``{"iface", "src", "gateway", "on_link"}`` (keys present only
    when parsed).  On a box with several interfaces the default route is
    NOT necessarily the one that reaches the target: transfer URLs and
    reachability checks built from the default-route IP point at the wrong
    NIC (OBS-2 / MSF2 #13).  ``ip route get <ip>`` asks the kernel which
    source address and gateway it would use, e.g.

        192.168.176.173 via 192.168.176.1 dev eth1 src 192.168.176.172 ...
        10.10.10.5 dev tun0 src 10.10.14.9 ...           (on-link, no gw)

    Returns ``{}`` when the target is not a usable IPv4 or ``ip`` is
    unavailable/fails — callers then fall back to the ranked global lhost.
    """
    if not target_ip:
        return {}
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return {}
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "get", target_ip],
            capture_output=True, text=True, timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {}
    text = r.stdout or ""
    out = {}
    dev = re.search(r"\bdev\s+(\S+)", text)
    if dev:
        out["iface"] = dev.group(1)
    src = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", text)
    if src and _usable_lhost_ip(src.group(1)):
        out["src"] = src.group(1)
    via = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", text)
    if via:
        out["gateway"] = via.group(1)
        out["on_link"] = False
    elif out:
        # A parsed route with no "via" hop is on-link (same L2 segment).
        out["on_link"] = True
    return out


def lhost_for_target(target_ip: str) -> str:
    """The local source IP the kernel uses to reach ``target_ip``.

    Prefers the route lookup (correct on multi-homed hosts); falls back to
    the ranked global lhost when the route can't be resolved."""
    src = route_to_target(target_ip).get("src")
    return src or lhost_detect()


def _open_terminal(title, cmd, return_proc=False):
    """Open a new terminal window running `cmd` (a bash script string).

    Returns True on success, False if no terminal emulator is available.
    When `return_proc=True`, returns the Popen object instead of True so
    callers can poll for xterm-window close (used by the CONNECT feedback
    loop to detect failures and offer a retry with compat flags).

    Logs failures to stderr so they surface during debugging.

    Prefers Kali's native terminals (qterminal → xfce4-terminal → gnome →
    konsole) and falls back to xterm. This matches the user's desktop
    environment instead of always showing a grey/white xterm.

    All terminal subprocesses inherit the extended PATH from _hawk_env()
    so tools installed in non-standard locations (~/go/bin, ~/.cargo/bin,
    /opt/tools, etc.) are found automatically.
    """
    import sys
    env = _hawk_env()

    # Default size: HAWK launches a lot of long-running tools (gvm-start,
    # msfconsole, hydra) where 80x24 is painful — bump everywhere we can.
    # Font size is set per-terminal because each emulator has its own knob.
    GEO_COLS, GEO_ROWS = 160, 44
    FONT_SIZE = 14
    FONT_FAMILY = "Monospace"

    def _done(proc):
        return proc if return_proc else True

    # Write the bash script to a tempfile and have the terminal run
    # `bash <file>`.  This sidesteps every shell-quoting trap — qterminal
    # in particular only accepts ONE command-string after -e, and Qt's
    # command splitter doesn't always understand bash-style escaping
    # (`'"'"'` round-trips), so passing a complex inline `bash -c '...'`
    # made qterminal exit instantly.  A tempfile is bullet-proof
    # regardless of the terminal's flag-parsing quirks.
    import tempfile as _tempfile
    import stat as _stat
    script_path = None
    try:
        os.makedirs(TMP_DIR, exist_ok=True)
        fd, script_path = _tempfile.mkstemp(
            suffix=".sh", prefix="hawk_term_", dir=TMP_DIR)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n")
            # Self-delete on exit so /tmp doesn't slowly fill up.  Wrapped
            # in a trap so it fires regardless of how the script ends
            # (rc=0, error, signal).
            f.write(f"trap 'rm -f {script_path}' EXIT\n")
            f.write(cmd)
            f.write("\n")
        os.chmod(script_path,
                 _stat.S_IRUSR | _stat.S_IWUSR | _stat.S_IXUSR)
    except Exception as e:
        print(f"[hawk] terminal tempfile write failed: {e}", file=sys.stderr)
        script_path = None

    # Liveness check: Popen returns immediately on fork/exec success, but
    # the spawned terminal can die milliseconds later if CLI flags are
    # wrong.  Wait briefly and poll — if already exited, the launch
    # failed and we fall through to the next emulator.
    import time as _time
    def _spawn(args):
        try:
            p = subprocess.Popen(args, env=env)
        except Exception as e:
            print(f"[hawk] {args[0]} launch failed: {e}", file=sys.stderr)
            return None
        # Brief settle window — most flag-parsing failures kill the
        # process within ~50 ms.  300 ms is conservative.
        _time.sleep(0.3)
        if p.poll() is not None:
            print(f"[hawk] {args[0]} died immediately "
                  f"(rc={p.returncode}) — trying next emulator",
                  file=sys.stderr)
            return None
        return p

    # Build the per-emulator launch arg list.  When the tempfile write
    # succeeded (the normal path) we use it everywhere — robust against
    # quote/escape issues.  If the tempfile write failed (extremely
    # rare — disk full, permissions), we fall back to inline `bash -c`
    # which works for most terminals but can break qterminal on
    # complex scripts.
    if script_path:
        run_argv = ["bash", script_path]
    else:
        run_argv = ["bash", "-c", cmd]

    # Priority: native Kali terminals first.  qterminal is the default
    # on current Kali Linux (XFCE), gnome-terminal on Kali GNOME,
    # xfce4-terminal on legacy XFCE setups, konsole on Kali KDE.
    # xterm only as last resort — it looks alien against the modern
    # Kali desktop.

    # Window-geometry hints.  qterminal has no native columns/rows
    # flag, but as a Qt app it honours the standard `-qwindowgeometry`
    # which takes WxH in PIXELS (not cell counts).  ~10 px per cell
    # at 14 pt so 160 cols × 44 rows ≈ 1600 × 700.  We pad for the
    # menu bar / scrollbar.
    QT_GEOM_PX = "1600x800"

    # qterminal (default terminal on Kali Linux XFCE).  -e accepts a
    # single command string; with the tempfile approach we pass
    # "bash /path/script.sh" which Qt's splitCommand parses correctly
    # into argv.
    if shutil.which("qterminal"):
        if script_path:
            qcmd = f"bash {script_path}"
        else:
            import shlex as _shlex
            qcmd = f"bash -c {_shlex.quote(cmd)}"
        p = _spawn(["qterminal",
                    "-qwindowgeometry", QT_GEOM_PX,
                    "--title", title, "-e", qcmd])
        if p:
            return _done(p)

    if shutil.which("xfce4-terminal"):
        p = _spawn(["xfce4-terminal", f"--title={title}",
                    f"--geometry={GEO_COLS}x{GEO_ROWS}",
                    "-x", *run_argv])
        if p:
            return _done(p)

    if shutil.which("gnome-terminal"):
        p = _spawn(["gnome-terminal", f"--title={title}",
                    f"--geometry={GEO_COLS}x{GEO_ROWS}",
                    "--", *run_argv])
        if p:
            return _done(p)

    if shutil.which("konsole"):
        p = _spawn(["konsole", "-p", f"tabtitle={title}",
                    "-p", f"TerminalColumns={GEO_COLS}",
                    "-p", f"TerminalRows={GEO_ROWS}",
                    "-e", *run_argv])
        if p:
            return _done(p)

    if shutil.which("xterm"):
        p = _spawn(["xterm", "-title", title,
                    "-geometry", f"{GEO_COLS}x{GEO_ROWS}",
                    "-fa", FONT_FAMILY, "-fs", str(FONT_SIZE),
                    "-e", *run_argv])
        if p:
            return _done(p)

    # No emulator launched — clean up the unused tempfile.
    if script_path:
        try:
            os.unlink(script_path)
        except OSError:
            pass
    return None if return_proc else False


def open_native_shell_captured(title: str, initial_cmd: str,
                                on_exit_callback=None,
                                on_line_callback=None,
                                auto_close: bool = False) -> bool:
    """Same as open_native_shell, but tees the interactive session output
    to a temp file and — when the terminal window closes — invokes
    `on_exit_callback(lines:list[str], rc:int)` on a background thread.

    Used by the CONNECT feedback loop: after the user closes the xterm,
    HAWK inspects the captured output for legacy-rescuable failure
    signatures (TLS handshake mismatches, host-key rejections, SMB
    protocol negotiation errors, ...) and offers an automatic retry
    with compat flags + the per-port override flipped to "legacy".

    Fallback: if no terminal returns a Popen (i.e. all emulators failed
    to launch) we return False and the callback never fires — caller
    should have a fallback path.
    """
    if not initial_cmd:
        return False

    import tempfile, threading as _t, os as _os, shlex as _shlex
    # Temp file that the wrapper tees into. It lives under hawkc/tmp so
    # portable runs do not scatter helper logs into the user's system tmp.
    _os.makedirs(TMP_DIR, exist_ok=True)
    fd, logpath = tempfile.mkstemp(
        prefix="hawk_connect_", suffix=".log", dir=TMP_DIR)
    _os.close(fd)

    # Wrapper:  echo-the-cmd → run-with-tee → drop-to-shell.  We tee
    # BOTH stdout and stderr (2>&1) so TLS-handshake-from-stderr errors
    # like psql's "SSL error: unsupported protocol" are captured.  The
    # trailing "; echo [HAWK]__CONNECT_RC=$?" lets us read the command's
    # real exit code from the log after the shell closes.
    #
    # IMPORTANT — quoting:
    # The pretty echo that prints `$ <cmd>` to the terminal used to wrap
    # initial_cmd inside echo's single quotes.  That broke any command
    # that already contained single quotes (e.g. the FTP anonymous
    # auto-login pipe `{ printf 'user anonymous anonymous@\n...'; ... }`):
    # the inner `'` closed echo's quoting → `\n` ended up unquoted →
    # bash rendered it as literal `n` → the command we ACTUALLY ran
    # was garbage.  Fix: pass the command as a positional arg to printf
    # with `%s`, shlex-quoted so any embedded quote is preserved
    # verbatim.  No interpretation happens on the format arg.
    cmd_quoted = _shlex.quote(initial_cmd)
    # `auto_close=True` is used for GUI-launcher commands (xfreerdp,
    # vncviewer) where the user interacts with the spawned GUI window,
    # not the terminal — keeping the xterm open after the command
    # exits is just noise.  For rc=0 we close the xterm immediately.
    # For rc≠0 we keep it open so the user can read the error before
    # it vanishes (otherwise a quick-fail "Connection refused" is
    # gone before they can see it).  CLI tools (ssh, ftp, mysql,
    # psql prompts) always drop to bash so the user can inspect /
    # retry inside the same terminal.
    if auto_close:
        tail = (
            f"rc=${{PIPESTATUS[0]}}; "
            f"echo \"[HAWK]__CONNECT_RC=$rc\" >> {logpath}; "
            f"if [ $rc -eq 0 ]; then "
            f"    printf '\\e[32m[HAWK] Command exited cleanly — "
            f"closing xterm in 2 s. Ctrl-C to keep it open.\\e[0m\\n'; "
            f"    sleep 2 || exec bash; "
            f"else "
            f"    printf '\\e[31m[HAWK] Command failed (rc=%s). "
            f"Drop to shell so you can read the error. "
            f"Ctrl-D to close.\\e[0m\\n' $rc; "
            f"    exec bash; "
            f"fi"
        )
    else:
        tail = (
            f"echo '[HAWK]__CONNECT_RC='${{PIPESTATUS[0]}} >> {logpath}; "
            f"echo ''; "
            f"printf '\\e[33m[HAWK] Drop to shell — Ctrl-D to close.\\e[0m\\n'; "
            f"exec bash"
        )
    # Pretty echo of the command was removed (HAWK 2026-04-29) per user
    # request — on SSH and similar tools with long legacy compat flags
    # the echo line was longer than the visible terminal width and made
    # the password prompt hard to read.  The full command is still
    # visible in the dialog preview before LAUNCH and in the HAWK
    # terminal's own log, so removing the in-xterm echo loses no info.
    script = (
        f"( {initial_cmd} ) 2>&1 | tee {logpath}; "
        + tail
    )
    proc = _open_terminal(title, script, return_proc=True)
    if not proc:
        try:
            _os.unlink(logpath)
        except OSError:
            pass
        return False

    # Live-tail thread: while the spawned terminal is alive, stream new
    # lines from the tee'd logfile to ``on_line_callback`` so the caller
    # (e.g. HAWK's connect dispatcher) can mirror the session into its
    # own UI in real time.  Stops when the terminal exits — the final
    # flush is handled in _watch() before on_exit_callback fires.
    tail_stop = _t.Event()
    if on_line_callback:
        def _tail():
            import time
            pos = 0
            while not tail_stop.is_set():
                try:
                    if _os.path.exists(logpath):
                        with open(logpath, "r", encoding="utf-8",
                                    errors="replace") as f:
                            f.seek(pos)
                            data = f.read()
                            pos = f.tell()
                        if data:
                            for line in data.splitlines():
                                if (line and
                                        "[HAWK]__CONNECT_RC=" not in line):
                                    try:
                                        on_line_callback(line)
                                    except Exception:
                                        pass
                except Exception:
                    pass
                time.sleep(0.15)
        _t.Thread(target=_tail, daemon=True).start()

    def _watch():
        try:
            proc.wait()
        except Exception:
            pass
        # Stop the live-tail thread before the final read so we don't
        # double-emit the last chunk.
        tail_stop.set()
        # Give the shell a moment to flush the tee before we read.
        import time
        time.sleep(0.3)
        try:
            with open(logpath, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
        except Exception:
            data = ""
        finally:
            try:
                _os.unlink(logpath)
            except OSError:
                pass
        # Extract the embedded exit code; default to 0 if absent.
        rc = 0
        import re as _re
        m = _re.search(r"\[HAWK\]__CONNECT_RC=(\d+)", data)
        if m:
            rc = int(m.group(1))
            data = data[:m.start()]   # strip marker from what we hand back
        lines = data.splitlines()
        if on_exit_callback:
            try:
                on_exit_callback(lines, rc)
            except Exception as e:
                import sys as _s
                print(f"[hawk] on_exit_callback error: {e}", file=_s.stderr)

    _t.Thread(target=_watch, daemon=True).start()
    return True


def open_native_shell(title: str = "HAWK — shell", initial_cmd: str = "",
                       auto_close: bool = False) -> bool:
    """Open a native terminal emulator with an interactive shell.

    If initial_cmd is provided, run it and then decide what to do:
      * auto_close=False (default)  → drop to bash so the user can
        continue typing / inspect output / retry.  Closes on Ctrl-D.
      * auto_close=True             → close automatically on rc=0
        (GUI launchers like xfreerdp / vncviewer don't need a
        lingering terminal).  On rc≠0 we still drop to bash so the
        user can read the error message before it vanishes.
    """
    if initial_cmd:
        import shlex as _shlex
        q = _shlex.quote(initial_cmd)
        if auto_close:
            tail = (
                "rc=$?; "
                "if [ $rc -eq 0 ]; then "
                "    printf '\\e[32m[HAWK] Command exited cleanly — "
                "closing xterm in 2 s. Ctrl-C to keep it open.\\e[0m\\n'; "
                "    sleep 2 || exec bash; "
                "else "
                "    printf '\\e[31m[HAWK] Command failed (rc=%s). "
                "Drop to shell. Ctrl-D to close.\\e[0m\\n' $rc; "
                "    exec bash; "
                "fi"
            )
        else:
            tail = (
                "echo ''; "
                "printf '\\e[33m[HAWK] Drop to shell — Ctrl-D to close."
                "\\e[0m\\n'; "
                "exec bash"
            )
        # Pretty echo removed (HAWK 2026-04-29) — see open_native_shell_captured
        # for the rationale.  The shlex-quoted variable `q` is kept above
        # in case future code needs it (e.g. reintroducing an opt-in
        # verbose mode).
        _ = q  # silence unused-var linters
        script = (
            f"{initial_cmd}; "
            + tail
        )
    else:
        script = "exec bash"
    return _open_terminal(title, script)

def _dispatch(ui_dispatcher, callback, *args, **kwargs):
    """Dispatch callback on tkinter main thread when dispatcher is available."""
    if callback is None:
        return
    if ui_dispatcher is None:
        callback(*args, **kwargs)
        return
    ui_dispatcher(callback, *args, **kwargs)



class BruteForceEstimator:
    APS = {"ssh":8,"ftp":15,"http":50,"http-get":50,"smb":10,"rdp":5,"default":10}

    @staticmethod
    def estimate(wordlist_path, protocol="default", threads=4, usernames=1):
        try:
            lines = sum(1 for _ in open(wordlist_path,"rb")) if os.path.isfile(wordlist_path) else 14_000_000
        except: lines = 14_000_000
        aps = BruteForceEstimator.APS.get(protocol.lower(), BruteForceEstimator.APS["default"]) * threads
        total = lines * usernames; secs = total / aps
        h = int(secs//3600); m = int((secs%3600)//60)
        human = f"~{h}h {m:02d}min" if h>0 else f"~{m} minutes" if m>0 else "< 1 minute"
        return {"total_attempts":total,"estimated_secs":int(secs),"human":human,"wordlist_lines":lines}


class _SpawnAborted(Exception):
    """STOP arrived before the child process existed — see
    ToolRunner.kill() / the guard right before Popen."""


class ToolRunner:
    # Hard cap on the retained output buffer.  Every line also goes to
    # the terminal widget and, from there, into the session JSON, so an
    # unbounded `-p-` verbose scan used to grow RAM and the snapshot
    # without limit.  When the cap is hit the OLDEST lines are dropped
    # and the operator is told once — silent truncation would be the
    # same lie as a silent failure.
    _LOG_CAP = 20000
    # Hard cap on a single line.  A binary blob read from a pty has no
    # newline for megabytes.
    _LINE_CAP = 16384

    def __init__(self, output_callback=None, done_callback=None,
                 ui_dispatcher=None):
        self.output_callback = output_callback or (lambda *a: None)
        self.done_callback   = done_callback   or (lambda *a: None)
        self.ui_dispatcher   = ui_dispatcher
        self.process = None; self.running = False; self._log = []
        # Set by kill() so a STOP issued in the window between run()
        # and Popen aborts the spawn instead of doing nothing (H4).
        self._kill_requested = False
        self._log_truncated = False

    def run(self, command, tool_name="tool", cwd=None, timeout=None):
        """Start `command`.

        `timeout` is seconds; None means no limit.  Callers pass
        `Tool.timeout` (declared in modules/base.py and, until now,
        never read) so a hung tool no longer holds the reader thread
        for the lifetime of the process.
        """
        if self.running: return
        self._log = []
        self._kill_requested = False
        self._log_truncated = False
        # Set synchronously, not inside the worker: otherwise a STOP
        # landing between run() and the thread's first statement sees
        # running=False and reports "nothing to stop" — while the
        # _kill_requested guard does abort the spawn.
        self.running = True
        threading.Thread(target=self._run_process,
                         args=(command, tool_name, cwd, timeout),
                         daemon=True).start()

    def kill(self):
        """Stop the running process.  Never blocks the caller — if the
        TERM path takes too long we escalate to KILL in a background
        thread.  Returns immediately so the UI thread can continue
        flipping the STOP → RUN button and updating the dot colour.

        Returns True when a stop was really initiated, False when there
        was nothing to stop — callers must not report a successful STOP
        on a False.

        User-reported bug: clicking STOP on a stuck impacket run (pty
        blocked inside sudo wrapper) froze HAWK until xkill.  Root
        cause was the original kill() called killpg once with SIGTERM
        and set running=False synchronously, while the reader thread
        stayed blocked on read() from a pty that sudo hadn't fully
        closed.  The new path sends SIGTERM, waits 2 s in a thread,
        escalates to SIGKILL on the whole group, and finally falls
        back to Popen.kill() on the direct PID — guaranteed to
        terminate in <3 s no matter how deep the pipe is."""
        # Record the request unconditionally: between run() and the
        # Popen at the bottom of _run_process there is a window of
        # seconds (_strip_sudo_if_caps, _preflight_nxc — both do I/O)
        # in which self.process is still None.  STOP used to be a
        # silent no-op there: the button went back to RUN and the tool
        # started anyway a moment later.
        self._kill_requested = True
        if not self.process:
            # Pre-flight: the spawn is aborted at the Popen guard.
            return bool(self.running)
        if not self.running:
            return False
        # Flip the flag FIRST so concurrent readers stop feeding the
        # output callback while the escalation runs.
        self.running = False
        proc = self.process

        def _escalate():
            import time
            pgid = None
            try:
                pgid = os.getpgid(proc.pid)
            except (ProcessLookupError, PermissionError, OSError):
                pgid = None
            # 1. SIGTERM to the process group (most tools respect this)
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            # 2. Give the child 2 s to exit gracefully
            for _ in range(20):
                if proc.poll() is not None:
                    return
                time.sleep(0.1)
            # 3. Still alive → SIGKILL the group
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            # 4. Final fallback — direct kill on the PID
            for _ in range(10):
                if proc.poll() is not None:
                    return
                time.sleep(0.1)
            try:
                proc.kill()
            except Exception:
                pass
            # 5. Verify.  Under `sudo` the real worker is a root-owned
            #    child of a process group we don't own: killpg from a
            #    non-root process returns EPERM, which every branch
            #    above swallows.  HAWK would then mark the tool DONE
            #    while nmap kept scanning the target.  Probe the group
            #    with signal 0 and, if it is still there, say so —
            #    with the exact command to finish the job.
            time.sleep(0.5)
            if pgid is None:
                return
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return                      # group is gone: really stopped
            except (PermissionError, OSError):
                pass                        # exists but not ours → survived
            self._emit(
                f"[!] STOP could not kill the tool: process group {pgid} "
                f"is still alive (root-owned child under sudo). "
                f"HAWK is NOT stopping it — kill it manually:  "
                f"sudo pkill -g {pgid}",
                "tool", "error")

        threading.Thread(target=_escalate, daemon=True).start()
        return True

    def get_log(self): return list(self._log)

    def _run_process(self, command, tool_name, cwd, timeout=None):
        self.running = True
        master_fd = slave_fd = None
        using_pty = False
        deadline = (time.monotonic() + timeout) if timeout else None

        # ── Drop sudo when caps are set ────────────────────────────────
        # If nmap/masscan has cap_net_raw (via setup_nmap_caps.sh), we can
        # skip sudo entirely — no pty-relay buffering, no credential
        # prompts, real-time progress.
        original = command
        command = _strip_sudo_if_caps(command)

        # ── nxc schema diagnostic ──────────────────────────────────────
        # If nxc was upgraded since the last HAWK session, NetExec's
        # own DBs may be stale. HAWK records the version change but does
        # not mutate external NetExec state, preserving the self-contained
        # policy.
        try:
            _preflight_nxc(command)
        except Exception as e:
            if os.environ.get("HAWK_DBG_PROGRESS", "1") == "1":
                print(f"[HAWK] nxc preflight failed (ignored): {e}",
                      flush=True)

        # ── Fallback: defeat stdio buffering inside sudo ───────────────
        # If sudo is still there (caps not set), inject `stdbuf -oL -eL`
        # after sudo so nmap's libc flushes per-line.  This doesn't fully
        # solve sudo's pty-relay bundling but it helps.  The real fix is
        # running setup_nmap_caps.sh once.
        if command.startswith("sudo ") and "stdbuf" not in command.split()[:4]:
            command = "sudo stdbuf -oL -eL " + command[5:]

        # DEBUG: one-line summary of what we're actually running, so we can
        # prove whether sudo was stripped and see raw output flow.
        if os.environ.get("HAWK_DBG_PROGRESS", "1") == "1":
            print(f"[HAWK] FINAL CMD: {command}", flush=True)
            if original != command:
                print(f"[HAWK]   (was: {original})", flush=True)

        try:
            # Spawn the child with a pseudo-terminal on stdout/stderr so
            # it sees a real tty.  This makes nmap (and other tools) use
            # line-buffered output and flush --stats-every progress lines
            # immediately instead of holding them in a 4-8 KB pipe buffer.
            #
            # stdin is inherited from the parent process — critical for
            # sudo's tty-cached credentials.  If we gave it the pty as
            # stdin, sudo would see a brand-new tty with no cached
            # credentials and block forever.
            try:
                master_fd, slave_fd = _pty_pair()
                using_pty = True
            except Exception:
                master_fd = slave_fd = None

            # Last gate before the child exists.  Everything above this
            # point (_strip_sudo_if_caps, _preflight_nxc, pty creation)
            # can take seconds, and a STOP issued in that window used to
            # do nothing at all: the button flipped back to RUN and nmap
            # started anyway.  Abort the spawn instead.
            if self._kill_requested:
                self._emit("[*] Aborted before launch — STOP was pressed "
                           "while the tool was still starting up.",
                           tool_name, "warn")
                raise _SpawnAborted()

            if using_pty:
                self.process = subprocess.Popen(
                    command, shell=True,
                    stdout=slave_fd, stderr=slave_fd,
                    preexec_fn=os.setsid, cwd=cwd, close_fds=True,
                    env=_hawk_env())
                os.close(slave_fd); slave_fd = None
            else:
                # Fallback: plain pipe (progress bars won't update live
                # but the scan itself still works).
                self.process = subprocess.Popen(
                    command, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    preexec_fn=os.setsid, cwd=cwd,
                    env=_hawk_env())
                master_fd = self.process.stdout.fileno()

            # Deadline watchdog.  `Tool.timeout` has been declared in
            # modules/base.py since day one and never read, so a tool
            # that hung held the reader thread for the lifetime of the
            # process.  The watchdog reuses kill() — same SIGTERM →
            # SIGKILL escalation, same honest survival check.
            if deadline is not None:
                proc = self.process

                def _watchdog():
                    while self.running and proc.poll() is None:
                        if time.monotonic() >= deadline:
                            self._emit(
                                f"[!] Timeout: no exit after {timeout}s — "
                                f"stopping {tool_name}. Output above is "
                                f"everything the tool produced.",
                                tool_name, "error")
                            self.kill()
                            return
                        time.sleep(0.5)

                threading.Thread(target=_watchdog, daemon=True).start()

            buf = b""
            while True:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:         # EIO when child exits (pty)
                    break
                if not chunk:
                    break
                buf += chunk
                # Flush all complete lines (terminated by \n or \r)
                while True:
                    idx_n = buf.find(b'\n')
                    idx_r = buf.find(b'\r')
                    if idx_n == -1 and idx_r == -1:
                        break
                    if idx_n == -1:
                        idx = idx_r
                    elif idx_r == -1:
                        idx = idx_n
                    else:
                        idx = min(idx_n, idx_r)
                    raw_line = buf[:idx]
                    buf = buf[idx + 1:]
                    try:
                        line = strip_ansi(
                            raw_line.decode('utf-8', errors='replace').strip())
                    except Exception:
                        continue
                    if line:
                        # DEBUG: show progress-candidate lines so we can see
                        # whether nmap is actually emitting stats at all.
                        if (os.environ.get("HAWK_DBG_PROGRESS", "1") == "1"
                                and ("% done" in line or "Timing:" in line
                                     or line.startswith("Stats:")
                                     or line.startswith("Initiating ")
                                     or line.startswith("Completed "))):
                            print(f"[HAWK] nmap: {line}", flush=True)
                        self._emit(line, tool_name, self._classify(line))
            # Flush remaining partial line
            if buf:
                try:
                    line = strip_ansi(
                        buf.decode('utf-8', errors='replace').strip())
                    if line:
                        self._emit(line, tool_name, self._classify(line))
                except Exception:
                    pass
            self.process.wait(); rc = self.process.returncode
        except _SpawnAborted:
            rc = -1
        except FileNotFoundError:
            self._emit(f"[!] Not found: {command.split()[0]}", tool_name, "error"); rc = 127
        except Exception as e:
            self._emit(f"[!] Error: {e}", tool_name, "error"); rc = -1
        finally:
            # Close pty fds (slave_fd is already None if Popen succeeded).
            # In pipe-fallback mode master_fd belongs to subprocess — don't
            # close it here, Popen manages the lifetime.
            if slave_fd is not None:
                try: os.close(slave_fd)
                except OSError: pass
            if using_pty and master_fd is not None:
                try: os.close(master_fd)
                except OSError: pass
            self.running = False
            _dispatch(self.ui_dispatcher, self.done_callback, tool_name, rc, self.get_log())

    def _emit(self, line, tool_name, level="info"):
        if len(line) > self._LINE_CAP:
            line = (line[:self._LINE_CAP]
                    + f"  … [HAWK truncated this line at "
                      f"{self._LINE_CAP} chars]")
        self._log.append((level, line))
        if len(self._log) > self._LOG_CAP:
            # Drop the oldest half in one go rather than one line per
            # append, and say it once.  The lines are still on screen
            # and in the log file; what is capped is what HAWK keeps in
            # RAM and copies into the session JSON.
            drop = len(self._log) - self._LOG_CAP // 2
            del self._log[:drop]
            note = (f"[!] Retained output capped at {self._LOG_CAP} "
                    f"lines — older lines were dropped from the "
                    f"session record. The full stream is still in "
                    f"the terminal.")
            # Re-pin the notice after every trim: it lives at index 0 and
            # would otherwise be the first thing dropped, leaving a
            # truncated log that looks complete.
            self._log.insert(0, ("warn", note))
            if not self._log_truncated:
                self._log_truncated = True
                _dispatch(self.ui_dispatcher, self.output_callback,
                          note, tool_name, "warn")
        _dispatch(self.ui_dispatcher, self.output_callback, line, tool_name, level)

    def _classify(self, line):
        low = line.lower()
        if any(k in low for k in ["error","failed","denied","refused","[!]"]): return "error"
        if any(k in low for k in ["warning","warn","[-]"]): return "warn"
        if any(k in low for k in ["open","found","success","[+]","discovered","vuln","vulnerable"]): return "success"
        return "info"


class MsfScannerRunner:
    EXPLOIT_SCANNER_MAP = {
        "ms17_010":"auxiliary/scanner/smb/smb_ms17_010",
        "eternalblue":"auxiliary/scanner/smb/smb_ms17_010",
        "ms08_067":"auxiliary/scanner/smb/smb_ms08_067",
        "ms09_050":"auxiliary/scanner/smb/smb_ms09_050",
        "ms10_061":"auxiliary/scanner/smb/smb_ms10_061",
        "ms12_020":"auxiliary/scanner/rdp/ms12_020_maxchannelids",
        "bluekeep":"auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
        "heartbleed":"auxiliary/scanner/ssl/openssl_heartbleed",
        "shellshock":"auxiliary/scanner/http/apache_mod_cgi_bash_env",
        "tomcat":"auxiliary/scanner/http/tomcat_mgr_login",
        "jenkins":"auxiliary/scanner/http/jenkins_enum",
        "mssql":"auxiliary/scanner/mssql/mssql_login",
        "mysql":"auxiliary/scanner/mysql/mysql_login",
        "smb_login":"auxiliary/scanner/smb/smb_login",
        "ssh_login":"auxiliary/scanner/ssh/ssh_login",
        "ftp_login":"auxiliary/scanner/ftp/ftp_login",
        "vnc":"auxiliary/scanner/vnc/vnc_login",
        "rdp":"auxiliary/scanner/rdp/rdp_scanner",
        "winrm":"auxiliary/scanner/winrm/winrm_auth_bypass",
        "struts":"auxiliary/scanner/http/struts_dmi_exec",
        "redis":"auxiliary/scanner/redis/redis_server",
        "mongodb":"auxiliary/scanner/mongodb/mongodb_login",
    }

    # A scanner module that hasn't finished in this long is hung.
    _DEFAULT_TIMEOUT = 900

    def __init__(self, output_callback=None, done_callback=None, ui_dispatcher=None):
        self.output_callback = output_callback or (lambda *a: None)
        self.done_callback   = done_callback   or (lambda *a: None)
        self.ui_dispatcher   = ui_dispatcher
        self._log = []; self.running = False
        self.process = None
        self._stop = threading.Event()

    def kill(self):
        """Stop the msfconsole scanner.  Returns True when a stop was
        really initiated.  Was absent entirely: the scan could not be
        cancelled and, if the read loop raised, msfconsole was left
        orphaned."""
        self._stop.set()
        proc = self.process
        if not (proc and self.running):
            return False
        self.running = False
        try:
            proc.terminate()
        except Exception:
            pass

        def _escalate():
            for _ in range(20):
                if proc.poll() is not None:
                    return
                time.sleep(0.1)
            try:
                proc.kill()
            except Exception:
                pass

        threading.Thread(target=_escalate, daemon=True).start()
        return True

    @classmethod
    def find_scanner(cls, exploit_name):
        low = exploit_name.lower()
        for key, scanner in cls.EXPLOIT_SCANNER_MAP.items():
            if key in low: return scanner
        try:
            parts = exploit_name.split("/"); term = parts[-1] if parts else exploit_name
            r = subprocess.run(["msfconsole","-q","-x",f"search type:auxiliary name:{term}; exit"],
                               capture_output=True, text=True, timeout=30)
            m = re.search(r'(auxiliary/\S+)', strip_ansi(r.stdout))
            if m: return m.group(1)
        except: pass
        return ""

    def run_scanner(self, scanner, target, extra_opts=None, timeout=None):
        self._log=[]; self.running=True; self._stop.clear()
        threading.Thread(target=self._run,
                         args=(scanner, target, extra_opts or {},
                               timeout or self._DEFAULT_TIMEOUT),
                         daemon=True).start()

    def _run(self, scanner, target, extra_opts, timeout):
        opts = [f"set {k} {v}" for k,v in extra_opts.items()]
        cmds = [f"use {scanner}", f"set RHOSTS {target}", "set THREADS 4"] + opts + ["run","exit -y"]
        vulnerable = False
        proc = None
        try:
            proc = subprocess.Popen(["msfconsole","-q","-x",";".join(cmds)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                    env=_hawk_env())
            self.process = proc
            deadline = time.monotonic() + timeout

            def _watchdog():
                while self.running and proc.poll() is None:
                    if time.monotonic() >= deadline:
                        _dispatch(self.ui_dispatcher, self.output_callback,
                                  f"[!] Scanner timeout after {timeout}s — "
                                  f"stopping msfconsole.",
                                  "scanner", "error")
                        self.kill()
                        return
                    time.sleep(0.5)

            threading.Thread(target=_watchdog, daemon=True).start()

            for raw in proc.stdout:
                if self._stop.is_set():
                    break
                line = strip_ansi(raw.rstrip())
                level = "success" if "[+]" in line else "error" if "[-]" in line else "info"
                self._log.append((level,line)); _dispatch(self.ui_dispatcher, self.output_callback, line, "scanner", level)
                if any(k in line.lower() for k in ["is vulnerable","vulnerable!","likely vulnerable","target is vulnerable"]):
                    vulnerable = True
            proc.wait(); rc = proc.returncode
        except Exception as e:
            _dispatch(self.ui_dispatcher, self.output_callback, f"[!] Scanner error: {e}", "scanner", "error"); rc=-1
        finally:
            # Never leave msfconsole orphaned: if the read loop raised or
            # was cancelled, the child is still there holding the socket.
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
            self.running=False; self.process=None
            _dispatch(self.ui_dispatcher, self.done_callback, scanner, rc, self._log, vulnerable)


class MetasploitRunner:
    """
    Writes MSF resource script (.rc) and opens in xterm.
    After exploit, automatically interacts with the session (sessions -i 1).
    Background thread captures output in HAWK terminal.
    """

    def __init__(self, output_callback=None, done_callback=None, shell_callback=None, ui_dispatcher=None):
        self.output_callback = output_callback or (lambda *a: None)
        self.done_callback   = done_callback   or (lambda *a: None)
        self.shell_callback  = shell_callback  or (lambda *a: None)
        self.ui_dispatcher   = ui_dispatcher
        self._started=False; self._log=[]
        # The run has TWO threads that used to each fire done_callback:
        # the xterm-exit hook (authoritative — the exploit really ended)
        # and the read-only background capture (finishes ~2 s after
        # launch).  The card therefore printed "completed" while the
        # exploit was still running in the xterm, then printed it again
        # much later.  One shot only, guarded across threads.
        self._done_lock = threading.Lock()
        self._done_fired = False

    def _fire_done(self, tool_name, rc, log):
        with self._done_lock:
            if self._done_fired:
                return
            self._done_fired = True
        _dispatch(self.ui_dispatcher, self.done_callback, tool_name, rc, log)

    def run(self, commands, target, lhost="", lport="4444"):
        # Auto-check LPORT — find free port if occupied
        try:
            lport_int = int(str(lport).strip())
            if not is_port_free(lport_int):
                lport_int = find_free_port(lport_int + 1)
                lport = str(lport_int)
                print(f"[HAWK] LPORT {lport} was busy — using {lport_int}")
        except Exception:
            pass
        if self._started: return
        self._started = True
        effective_lhost = lhost or lhost_detect()

        resolved = [c.replace("{target}",target)
                     .replace("{lhost}",effective_lhost)
                     .replace("{lport}",lport)
                    for c in commands]

        # Exploits that manage their own handler internally
        SELF_HANDLER_EXPLOITS = [
            "ms17_010_eternalblue", "ms08_067_netapi", "ms10_061_spoolss",
            "cve_2019_0708_bluekeep", "doublepulsar", "eternalromance",
            "eternalsynergy", "ms17_010_psexec",
        ]
        # Detect both full-RCE exploits and auxiliary/scanner modules —
        # the latter don't take a payload/LHOST/LPORT and don't spawn
        # sessions, so we must skip the handler block entirely and the
        # post-run `sessions -i 1 / sysinfo / getuid` lines.
        exploit_name = next((c.split(None,1)[-1].strip() for c in resolved
                             if c.strip().lower().startswith("use exploit/")), "")
        auxiliary_name = next((c.split(None,1)[-1].strip() for c in resolved
                               if c.strip().lower().startswith("use auxiliary/")), "")
        is_auxiliary  = bool(auxiliary_name) and not exploit_name
        is_self_handler = any(k in exploit_name.lower()
                               for k in SELF_HANDLER_EXPLOITS)

        # ── HTTP-staging payload detection ──────────────────────────────
        # Modern Metasploit (post-2024) sets `cmd/<os>/(http|https)/...`
        # as the DefaultOptions PAYLOAD on several classic exploits
        # (vsftpd_234_backdoor, samba/usermap, distcc, irc/unreal, …).
        # These payloads bootstrap an HTTP server INSIDE the exploit
        # module to serve the meterpreter binary — adding HAWK's usual
        # `multi/handler` block separately would make BOTH register the
        # same FETCH_URIPATH, causing the run to abort with:
        #     [-] Exploit failed: RuntimeError unknown: Failed to add
        #         resource bad-config: Resource collision detected.
        #         Set FETCH_URIPATH to a different value to continue.
        # When we detect such a payload we simply SKIP the multi/handler
        # block — the exploit handles staging + listener internally.
        is_http_stager = any(
            re.search(r"\bcmd/(linux|windows|unix|osx|bsd)/https?/",
                       c.lower())
            for c in resolved
        )

        # Needs a handler only when (a) we're running an exploit (not
        # auxiliary) AND (b) the exploit doesn't auto-handle its own
        # reverse shell AND (c) the command list references a reverse
        # payload AND (d) the payload isn't a self-staging cmd/<os>/http
        # variant that would clash with multi/handler.
        needs_handler = ((not is_auxiliary)
                         and (not is_self_handler)
                         and (not is_http_stager)
                         and any(
                             ("reverse_tcp" in c.lower() or
                              "reverse_http" in c.lower() or
                              "meterpreter" in c.lower())
                             for c in resolved))

        payload = "windows/x64/meterpreter/reverse_tcp"
        for c in resolved:
            if c.strip().lower().startswith("set payload"):
                payload = c.split(None,2)[-1].strip(); break

        lines = []
        if needs_handler:
            lines += [
                "use exploit/multi/handler",
                f"set PAYLOAD {payload}",
                f"set LHOST {effective_lhost}",
                f"set LPORT {lport}",
                "set ExitOnSession false",
                "exploit -j -z",
                "",
            ]

        # Track whether we've injected DisablePayloadHandler for the
        # current exploit module.  When we have our own multi/handler
        # listening on LPORT (job 0), the exploit module would by
        # default ALSO try to start a handler on the same port — that's
        # the "Rex::BindFailed: address already in use" the user kept
        # hitting on java_rmi_server.  Setting `DisablePayloadHandler
        # true` on the exploit makes it use the external handler we
        # already spawned, no self-conflict.
        disable_handler_set = False

        for c in resolved:
            low = c.strip().lower()
            if needs_handler and any(k in low for k in ["multi/handler","exitonsession"]): continue
            # When the new `use exploit/...` line goes through, inject
            # DisablePayloadHandler immediately after — must be set
            # AFTER the use (it's a module datastore option, scoped to
            # the currently-loaded module).  Only fires once per script
            # (defensive for scripts with multiple `use` lines).
            if (needs_handler and not disable_handler_set
                    and low.startswith("use exploit/")
                    and "multi/handler" not in low):
                lines.append(c)
                lines.append("set DisablePayloadHandler true")
                disable_handler_set = True
                continue
            # Use 'exploit' (not -j) so session is interactive
            if low == "run" or low == "exploit -j":
                lines.append("exploit")
            else:
                lines.append(c)

        # After exploit — DON'T append sessions -i / sysinfo / getuid.
        # `exploit` (without -j) is blocking: MSF drops the user
        # directly into the opened session.  Appending resource-script
        # lines after it would only execute AFTER the session ends,
        # and sysinfo/getuid are Meterpreter-only (fail on cmd shells
        # like cmd/unix/reverse_perl with "Unknown command").

        ts = int(time.time())
        os.makedirs(TMP_DIR, exist_ok=True)
        script_path = os.path.join(TMP_DIR, f"hawk_msf_{ts}.rc")
        try:
            with open(script_path, "w") as f:
                f.write("\n".join(lines) + "\n")
        except Exception as e:
            _dispatch(self.ui_dispatcher, self.output_callback, f"[!] Cannot write MSF script: {e}", "msfconsole", "error"); return

        exploit_name = next((c.split(None,1)[-1].strip() for c in resolved
                             if c.strip().lower().startswith("use exploit/")), "")
        title = (f"HAWK — MSF: {exploit_name.split('/')[-1]} → {target}"
                 if exploit_name else f"HAWK — MSF → {target}")

        # ── Preventive hint when LPORT is involved ──────────────────────
        # MSF jobs spawned with `exploit -j -z` keep the handler alive
        # AFTER the user closes msfconsole's main prompt.  When the user
        # then launches a SECOND MSF exploit on the same LPORT, the new
        # `multi/handler` (or the exploit's own listener) fails to bind
        # with `Rex::BindFailed`.  Surface a one-liner now so the user
        # knows what to do if their next launch fails.
        if needs_handler:
            _dispatch(self.ui_dispatcher, self.output_callback,
                f"  [*] MSF tip: if your NEXT exploit fails to bind "
                f"LPORT {lport}, run `pkill -f msfconsole` first to clear "
                f"stale handlers.",
                "msfconsole", "dim")

        keep_open = (
            f"msfconsole -q -r {script_path}; "
            f"rm -f {script_path}; "
            f"echo ''; echo '=== MSF session ended. Type exit or press Ctrl+C. ==='; "
            f"read -p 'Press ENTER to close...'"
        )

        # ── Captured-output mode for post-mortem error detection ────────
        # We run msfconsole inside the captured-shell wrapper so HAWK can
        # scan the session log AFTER xterm closes and surface specific
        # MSF errors directly to the HAWK terminal (the user often closes
        # the xterm without reading the failure, then asks "perché non
        # funziona?").  Falls back to the plain xterm path when the
        # captured wrapper isn't available (older HAWK builds).
        callback = self.output_callback
        dispatcher = self.ui_dispatcher
        done_cb = self.done_callback

        def _on_msf_exit(lines, rc):
            """Post-mortem scan of the msfconsole session log.  Detects
            the most common MSF launch failures and prints actionable
            hints to the HAWK terminal."""
            try:
                text = "\n".join(lines)
            except Exception:
                text = ""

            # Resource collision (HTTP stager + multi/handler clash)
            if ("Resource collision detected" in text or
                    "FETCH_URIPATH" in text):
                _dispatch(
                    dispatcher, callback,
                    "  [!] MSF resource collision detected — the chosen "
                    "payload uses an HTTP stager and clashed with another "
                    "active handler. Fix:\n"
                    "      • Close all open msfconsole xterms before "
                    "retrying\n"
                    "      • Or change LPORT in the launch dialog\n"
                    "      • Or pick a non-HTTP payload (cmd/unix/"
                    "reverse_perl) for cmd/* exploits",
                    "msfconsole", "warn")

            # LPORT bind failure
            if ("Rex::BindFailed" in text or
                    "Handler failed to bind" in text or
                    "address is already in use" in text.lower()):
                _dispatch(
                    dispatcher, callback,
                    "  [!] MSF LPORT bind failed — port is already in "
                    "use on Kali. Fix:\n"
                    "      • Close all xterms running msfconsole "
                    "(stale background handlers persist)\n"
                    "      • Run: pgrep -af msfconsole; pkill -f "
                    "msfconsole\n"
                    "      • Or pick a different LPORT in the launch "
                    "dialog and retry",
                    "msfconsole", "warn")

            # Payload incompatible (the user's earlier issue with
            # java_rmi + linux/x64 meterpreter)
            if "is not a compatible payload" in text:
                _dispatch(
                    dispatcher, callback,
                    "  [!] MSF payload incompatible with the exploit. "
                    "Fix: open the launch dialog again, edit the "
                    "Payload field to a compatible class (java/* for "
                    "Java RMI, cmd/unix/* for unix webapps, "
                    "windows/* for Windows exploits).",
                    "msfconsole", "warn")

            if ("value specified for PAYLOAD is not valid" in text
                    or "a payload has not been selected" in text.lower()):
                _dispatch(
                    dispatcher, callback,
                    "  [!] MSF rejected the payload (BadChars or "
                    "incompatible). Fix: clear the Payload field in "
                    "the launch dialog and retry — MSF will auto-pick "
                    "a compatible payload for this module.",
                    "msfconsole", "warn")

            # Notify the original done_callback so the rest of HAWK
            # (timeline tracking, cleanup, etc.) sees the run as done.
            # This is the AUTHORITATIVE completion: the xterm closed, so
            # the exploit really has ended.
            try:
                self._fire_done("msfconsole",
                                rc if rc is not None else 0, lines)
            except Exception:
                pass

        ok = open_native_shell_captured(
            title, keep_open, on_exit_callback=_on_msf_exit,
            auto_close=False)
        if not ok:
            _dispatch(self.ui_dispatcher, self.output_callback,
                "[!] No terminal emulator (xterm/gnome-terminal).\n"
                f"    Install: sudo apt install xterm\n"
                f"    Then: msfconsole -q -r {script_path}",
                "msfconsole", "error")
            self._fire_done("msfconsole", -1, []); return

        # Background capture for HAWK terminal
        threading.Thread(target=self._bg_capture,
                         args=(script_path, target, payload, effective_lhost, lport),
                         daemon=True).start()

    def _bg_capture(self, script_path, target, payload, lhost, lport):
        """
        Background msfconsole used ONLY to mirror the setup output into the
        HAWK terminal. Historically this ran the full RC script (same as the
        xterm instance) which caused two msfconsole processes to race for
        the handler LPORT → 'Rex::BindFailed: address already in use'.

        Now we strip everything that would actually bind a socket, launch
        the exploit, or drive post-exploit commands — the xterm instance
        owns the exploit.  We keep only harmless informational lines so
        the user still sees 'use exploit/...', 'set PAYLOAD', etc. in the
        HAWK terminal for context.
        """
        time.sleep(0.8)
        tool_name = "msfconsole"; shell_found = False
        bg_path = script_path.replace(".rc", "_bg.rc")

        # Commands that (a) bind a port, (b) launch the exploit, or
        # (c) drive the resulting session. Any of these in the bg script
        # would collide with the xterm msfconsole on LPORT.
        def _is_stripped(ln: str) -> bool:
            s = ln.strip().lower()
            if not s:
                return False
            # handler block
            if s.startswith("use exploit/multi/handler"): return True
            if s == "set exitonsession false":             return True
            # exploit verbs
            if s in ("exploit", "run", "check"):           return True
            if s.startswith("exploit ") or s.startswith("run "): return True
            # post-exploit / session interaction
            if s.startswith("sessions"):                   return True
            if s in ("sysinfo", "getuid", "hashdump",
                     "shell", "background", "bg"):        return True
            return False

        try:
            with open(script_path) as f:
                content = f.read()
            kept = [ln for ln in content.splitlines()
                    if not _is_stripped(ln)]
            kept.append("# bg capture — exploit is running in xterm, "
                        "this process is read-only.")
            kept.append("exit -y")
            bg_content = "\n".join(kept) + "\n"
            with open(bg_path, "w") as f:
                f.write(bg_content)
        except Exception:
            bg_path = None

        if not bg_path:
            return

        try:
            proc = subprocess.Popen(
                ["msfconsole","-q","-r",bg_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=_hawk_env())
            for raw in proc.stdout:
                line  = strip_ansi(raw.rstrip())
                level = ("success" if "[+]" in line else
                         "error"   if "[-]" in line or "[!]" in line
                         else "info")
                self._log.append((level,line))
                _dispatch(self.ui_dispatcher, self.output_callback,
                          line, tool_name, level)
                # Only trigger on real session open, not on error messages
                low = line.lower()
                if any(p in low for p in [
                    "meterpreter session", "command shell session",
                    "session opened", "opened a shell"
                ]) and "invalid" not in low and "no active" not in low:
                    shell_found = True
            proc.wait(); rc = proc.returncode
        except Exception as e:
            _dispatch(self.ui_dispatcher, self.output_callback,
                      f"[!] Capture error: {e}", tool_name, "error")
            rc = -1
        finally:
            try: os.remove(bg_path)
            except: pass
            if shell_found: self.shell_callback(target)
            # Do NOT report the run as done here.  This process only
            # mirrors the setup lines into the HAWK terminal and exits
            # ~2 s after launch; the exploit itself lives in the xterm
            # and finishes whenever the operator is finished with it.
            _dispatch(self.ui_dispatcher, self.output_callback,
                      "  [*] Setup mirror finished — the exploit is still "
                      "running in the xterm. HAWK will report completion "
                      "when that window closes.",
                      tool_name, "dim")

    def kill(self):
        """The exploit runs inside an xterm HAWK does not own — there is
        no process here to signal.  Return False so callers report the
        truth instead of flipping the button back to RUN and calling it
        stopped."""
        return False

    def get_log(self): return list(self._log)


def _greenbone_creds():
    """Load Greenbone credentials from env or hawkc/configs/greenbone.json."""
    user = os.environ.get("HAWK_GVM_USER", "").strip()
    password = os.environ.get("HAWK_GVM_PASSWORD", "")
    cfg_path = os.path.join(CONFIGS_DIR, "greenbone.json")
    if (not user or not password) and os.path.isfile(cfg_path):
        try:
            import json
            with open(cfg_path, encoding="utf-8") as f:
                cfg = json.load(f)
            if isinstance(cfg, dict):
                user = user or str(cfg.get("username") or "").strip()
                password = password or str(cfg.get("password") or "")
        except Exception:
            pass
    # Preserve the previous Kali lab default when the user has not opted
    # into explicit credentials, but keep the literals in one place.
    return (user or "admin", password or "admin")


class GreenBoneRunner:
    # A GVM scan that hasn't reported Done in this long is not coming
    # back — the poll loop used to be `while True: sleep(30)` with no
    # exit other than a status string, so a stuck task pinned a thread
    # for the lifetime of the process.
    _MAX_POLL_SECS = 4 * 3600
    _POLL_INTERVAL = 30

    def __init__(self, output_callback=None, done_callback=None, ui_dispatcher=None):
        self.output_callback=output_callback or (lambda *a:None)
        self.done_callback=done_callback or (lambda *a:None)
        self.ui_dispatcher=ui_dispatcher
        self.process=None; self.running=False; self._log=[]
        self._stop = threading.Event()
        self._task_id = None

    @staticmethod
    def is_available(): return shutil.which("gvm-cli") is not None

    @staticmethod
    def is_running():
        try:
            user, password = _greenbone_creds()
            r=subprocess.run(["gvm-cli","--gmp-username",user,"--gmp-password",password,
                              "socket","--xml","<get_version/>"],
                             capture_output=True,text=True,timeout=5)
            return r.returncode==0
        except: return False

    def run(self, target, scan_config="Full and fast"):
        self._log=[]; self.running=True; self._stop.clear()
        threading.Thread(target=self._run_scan,args=(target,scan_config),daemon=True).start()

    def kill(self):
        """Stop the scan.  `self.process` is never assigned on this
        runner (every gvm-cli call is a short-lived subprocess.run), so
        the old guard `if self.process and self.running` made kill() a
        permanent no-op that didn't even clear `running`.  The poll loop
        watches the Event instead, and the task is stopped server-side
        so the scan doesn't keep running inside gvmd."""
        if not self.running:
            return False
        self._stop.set()
        self.running = False
        task_id = self._task_id
        if task_id:
            def _stop_task():
                try:
                    self._gvm(f"<stop_task task_id='{task_id}'/>")
                except Exception as e:
                    _dispatch(self.ui_dispatcher, self.output_callback,
                              f"[!] Could not stop the GVM task "
                              f"server-side ({e}) — the scan may still be "
                              f"running in gvmd. Stop it from the "
                              f"Greenbone web UI.", "greenbone", "error")
            threading.Thread(target=_stop_task, daemon=True).start()
        return True

    def _run_scan(self, target, scan_config):
        tn="greenbone"
        try:
            self._emit(f"[*] Creating target {target}...",tn,"info")
            # GMP element is <name>.  A mass rename left `<n>` here (and
            # `</r>` in _parse_results): gvmd rejected create_target, the
            # config lookup never matched and no scan ever started.
            # Restored, but NOT verifiable headless — needs a Kali box
            # with gvmd running to validate end to end.
            res=self._gvm(f"<create_target><name>HAWK-{target}</name><hosts>{target}</hosts></create_target>")
            m=re.search(r'id="([^"]+)"',res)
            if not m: self._emit("[!] Target creation failed.",tn,"error"); _dispatch(self.ui_dispatcher, self.done_callback, tn,1,self.get_log()); return
            tid=m.group(1); cfgs=self._gvm("<get_configs/>")
            cm=re.search(r'<config id="([^"]+)"[^>]*>.*?<name>'+re.escape(scan_config),cfgs,re.DOTALL)
            cid=cm.group(1) if cm else "daba56c8-73ec-11df-a475-002264764cea"
            tx=self._gvm(f"<create_task><name>HAWK-{target}</name><config id='{cid}'/><target id='{tid}'/></create_task>")
            tm=re.search(r'id="([^"]+)"',tx)
            if not tm: self._emit("[!] Task creation failed.",tn,"error"); _dispatch(self.ui_dispatcher, self.done_callback, tn,1,self.get_log()); return
            task_id=tm.group(1); self._task_id=task_id
            self._gvm(f"<start_task task_id='{task_id}'/>")
            self._emit(f"[+] Scan started. Polling every "
                       f"{self._POLL_INTERVAL}s...",tn,"success")
            deadline = time.monotonic() + self._MAX_POLL_SECS
            while True:
                # Event-based sleep so STOP interrupts the wait instead
                # of leaving the operator up to 30 s of "did it work?".
                if self._stop.wait(self._POLL_INTERVAL):
                    self._emit("[*] Scan stopped by operator.",tn,"warn")
                    break
                if time.monotonic() >= deadline:
                    self._emit(
                        f"[!] Giving up after "
                        f"{self._MAX_POLL_SECS // 3600}h without a Done "
                        f"status. HAWK stopped polling — the task may "
                        f"still be running in gvmd; check the Greenbone "
                        f"web UI.", tn, "error")
                    break
                sx=self._gvm(f"<get_tasks task_id='{task_id}'/>")
                if "<status>Done</status>" in sx: self._emit("[+] Done.",tn,"success"); break
                if "<status>Stopped</status>" in sx: break
                pm=re.search(r"<progress>(\d+)</progress>",sx)
                if pm: self._emit(f"[*] Progress: {pm.group(1)}%",tn,"info")
            self._parse_results(self._gvm(f"<get_results filter='task_id={task_id}' details='1'/>"),tn)
            _dispatch(self.ui_dispatcher, self.done_callback, tn,0,self.get_log())
        except Exception as e:
            self._emit(f"[!] Error: {e}",tn,"error"); _dispatch(self.ui_dispatcher, self.done_callback, tn,1,self.get_log())
        finally: self.running=False

    def _gvm(self, xml):
        user, password = _greenbone_creds()
        r=subprocess.run(["gvm-cli","--gmp-username",user,"--gmp-password",password,"socket","--xml",xml],
                         capture_output=True,text=True,timeout=60)
        return r.stdout

    def _parse_results(self, xml, tn):
        results=re.findall(r"<result[^>]*>.*?<name>(.*?)</name>.*?<severity>(.*?)</severity>.*?<description>(.*?)</description>.*?</result>",xml,re.DOTALL)
        if not results: self._emit("  — No vulnerabilities found.",tn,"info"); return
        for name,sev,desc in results:
            try: sv=float(sev)
            except: sv=0
            lvl="error" if sv>=7 else "warn" if sv>=4 else "info"
            self._emit(f"  [{sev}]  {name.strip()}",tn,lvl)
            self._emit(f"         {desc.strip()[:120]}",tn,"dim")

    def _emit(self, line, tn, level="info"):
        self._log.append((level,line)); _dispatch(self.ui_dispatcher, self.output_callback, line, tn, level)
    def get_log(self): return list(self._log)


# Module-level singleton state for the Greenbone browser-open helper.
# Two distinct UI paths (the START button and the AUTOFIX button on
# the Greenbone dialog) both call `open_greenbone_when_ready`, and
# previously each fired its own poll thread + browser.open.  When the
# user closed the freshly-opened browser tab, the second polling
# thread would re-detect the web UI as ready and reopen the browser
# ~3 seconds later — looking like an "auto-respawn" bug.  Guarding
# with a lock + already-opened flag collapses any number of concurrent
# calls into a single browser open per HAWK process.
import threading as _gb_threading
_GB_LOCK = _gb_threading.Lock()
_GB_POLL_THREAD = None
_GB_OPENED = False


def open_greenbone_when_ready(url: str = "https://127.0.0.1:9392",
                              timeout: float = 180.0,
                              poll_interval: float = 2.0,
                              on_status=None):
    """Poll the Greenbone Web UI on `url` and open the browser only once the
    HTTPS endpoint actually answers (gvmd ready + NVTs reload finished).

    Replaces the previous fixed `threading.Timer(8s/15s, webbrowser.open)`
    behaviour, which raced gvm-start: the page loaded while ospd-openvas
    was still reloading NVTs and the user had to F5.

    `on_status(msg)` is an optional callback used to surface progress in
    the HAWK terminal ("Greenbone web UI ready", "still waiting…", etc).
    Falls through to webbrowser.open after `timeout` so the user is never
    stranded — but logs a warning so they know readiness wasn't confirmed.

    De-duplication: at most one polling thread runs per HAWK process,
    and at most one webbrowser.open() fires.  Repeat calls (e.g. user
    clicks START then AUTOFIX, or START twice) are no-ops — they log
    a 'skipping duplicate call' line and return immediately.  Manual
    re-opens still work via the Access Panel's button, which calls
    webbrowser.open directly and does not go through this helper.
    """
    global _GB_POLL_THREAD, _GB_OPENED

    import socket, ssl, webbrowser, threading, time
    from urllib.parse import urlsplit
    p = urlsplit(url)
    host = p.hostname or "127.0.0.1"
    port = p.port or (443 if p.scheme == "https" else 80)

    def _say(msg):
        if on_status:
            try: on_status(msg)
            except Exception: pass

    # Singleton guard — collapse duplicate triggers from concurrent
    # UI paths.  Must happen BEFORE we spawn the polling thread.
    with _GB_LOCK:
        if _GB_OPENED:
            _say("Greenbone browser already opened in this session — "
                 "skipping duplicate call.")
            return
        if _GB_POLL_THREAD is not None and _GB_POLL_THREAD.is_alive():
            _say("Greenbone browser-open already pending — "
                 "skipping duplicate call.")
            return

    def _tcp_open():
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            return False

    def _https_answers():
        # gvmd uses a self-signed cert.  We don't care about validation —
        # we only want a TLS handshake + HTTP response (any status).
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    s.sendall(
                        f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    data = s.recv(64)
                    return data.startswith(b"HTTP/")
        except Exception:
            return False

    def _mark_opened():
        global _GB_OPENED
        with _GB_LOCK:
            _GB_OPENED = True

    def _wait_and_open():
        deadline = time.time() + timeout
        seen_tcp = False
        while time.time() < deadline:
            # Re-check the singleton each loop so a concurrent signal
            # (e.g. user clicked Access Panel → opened manually) lets
            # us bail out without doubling up.
            with _GB_LOCK:
                if _GB_OPENED:
                    return
            if not seen_tcp:
                if _tcp_open():
                    seen_tcp = True
                    _say("Greenbone TCP up — waiting for web UI to answer…")
            else:
                if _https_answers():
                    _say("Greenbone web UI ready — opening browser.")
                    _mark_opened()
                    try: webbrowser.open(url)
                    except Exception: pass
                    return
            time.sleep(poll_interval)
        _say("Greenbone readiness timeout — opening browser anyway "
             "(reload the page if it errors).")
        _mark_opened()
        try: webbrowser.open(url)
        except Exception: pass

    with _GB_LOCK:
        _GB_POLL_THREAD = threading.Thread(
            target=_wait_and_open, daemon=True)
        _GB_POLL_THREAD.start()


def _reset_greenbone_open_state():
    """Test hook — clear the singleton flags so a fresh smoke test
    can exercise `open_greenbone_when_ready` without restarting the
    interpreter.  Not called from production code paths."""
    global _GB_POLL_THREAD, _GB_OPENED
    with _GB_LOCK:
        _GB_POLL_THREAD = None
        _GB_OPENED = False


class GreenBoneInstaller:
    def __init__(self, output_callback=None, step_callback=None, done_callback=None):
        self.output_callback=output_callback or (lambda *a:None)

    def install_in_xterm(self):
        script = (
            "echo '=== HAWK: Installing Greenbone/GVM ===' && "
            "sudo apt-get update && "
            "sudo apt-get install -y gvm && "
            "sudo gvm-setup && "
            "sudo gvm-start && "
            "sudo gvm-check-setup && "
            "echo '' && "
            "echo '=== Done! Return to HAWK and click RUN again. ===' && "
            "read -p 'Press ENTER to close...'"
        )
        return _open_terminal("HAWK — Installing Greenbone/GVM", script)


class MultiRunner:
    def __init__(self, output_callback=None, all_done_callback=None, ui_dispatcher=None):
        self.output_callback=output_callback or (lambda *a:None)
        self.all_done_callback=all_done_callback or (lambda *a:None)
        self.ui_dispatcher=ui_dispatcher
        self._queue=[]; self._results=[]; self._running=False; self._current=None; self._lock=threading.Lock()

    def run_sequence(self, commands):
        with self._lock:
            if self._running: return
            self._queue=list(commands); self._results=[]; self._running=True
        self._run_next()

    def _run_next(self):
        with self._lock:
            if not self._queue:
                self._running=False; results=list(self._results)
                _dispatch(self.ui_dispatcher, self.all_done_callback, results); return
            cmd,name=self._queue.pop(0)
        def done(n,rc,log):
            with self._lock: self._results.append((n,rc))
            self._run_next()
        r=ToolRunner(output_callback=self.output_callback,done_callback=done, ui_dispatcher=self.ui_dispatcher)
        with self._lock: self._current=r
        r.run(cmd,name)

    def kill(self):
        """Drop the queue and stop the command in flight.  Returns what
        the inner runner reported, so a caller can't claim a successful
        STOP when nothing was actually stopped."""
        with self._lock: self._queue=[]; self._running=False; current=self._current
        if not current:
            return False
        return current.kill() is not False
