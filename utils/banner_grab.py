"""Universal banner-grab helper for HAWK.

Replaces the legacy `bash + /dev/tcp + head -c N` and `bash read -t -N`
approaches, both of which had silent-failure modes:
  • bash `read` builtin on a /dev/tcp file descriptor sometimes
    times out without consuming any bytes even when the server has
    sent the banner (kernel/bash interaction, observed live on
    Kali 2025 bash 5.3 against a healthy SSH server).
  • C-stdio buffering inside `head -c N` lost the captured bytes
    when the outer `timeout` killed the parent bash subshell.

Python's socket module bypasses both:
  • No shell-level quoting / FD-passing fragility.
  • Predictable behaviour across Linux distros (Python 3 is on
    every modern Kali, Debian, Ubuntu, Arch, Alpine, RHEL).
  • Distinguishes "server closed connection without banner"
    (MaxStartups exhausted, TCP wrappers, sshd hung) from
    "timeout waiting for banner" — gives the operator an
    actionable diagnostic instead of a silent empty output.

The helper is invoked from HAWK's tool dispatcher and emits one
line of output: either the raw banner string (decoded latin-1
because banners are 8-bit clean and we never want to crash on
non-UTF-8 bytes) OR a `[HAWK: ...]` diagnostic line that the
parser recognises and surfaces as an info-level finding.

Usage:
    python3 banner_grab.py HOST PORT [TIMEOUT_SECONDS]

TIMEOUT_SECONDS defaults to 3.  Exit code is always 0 — the
parser distinguishes success from diagnostic via output content,
not via rc (the legacy nc-based parser already handled that).
"""
import socket
import sys


def grab(host: str, port: int,
         timeout: float = 3.0,
         max_bytes: int = 256) -> str:
    """Open a TCP connection and read up to ``max_bytes`` bytes.

    Returns the decoded banner string on success, or a
    ``[HAWK: ...]`` diagnostic on any expected error condition.
    Never raises — exceptions become diagnostic strings.
    """
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        data = s.recv(max_bytes)
        if data:
            return data.decode("latin-1", "replace").rstrip()
        # recv returning b"" means the remote closed the
        # connection cleanly without sending any data.  On SSH
        # 4.x targets this is usually MaxStartups exhausted; on
        # MySQL/Postgres it's often TLS-mode mismatch; on HTTP
        # it can be an immediate close before any header.
        return ("[HAWK: connection closed by remote, "
                "no banner sent]")
    except socket.timeout:
        # Connected (or in connect()) but no data within timeout.
        return "[HAWK: timeout waiting for banner]"
    except ConnectionRefusedError:
        return "[HAWK: connection refused]"
    except OSError as e:
        # All other low-level errors (host unreachable, network
        # down, route problems, etc.).  Format the errno text so
        # the operator gets something useful.
        return f"[HAWK: error: {e}]"
    finally:
        try:
            s.close()
        except Exception:
            pass


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(
            "usage: banner_grab.py HOST PORT [TIMEOUT_SECONDS]\n")
        return 2
    host = argv[1]
    try:
        port = int(argv[2])
    except ValueError:
        sys.stderr.write(f"invalid port: {argv[2]!r}\n")
        return 2
    timeout = 3.0
    if len(argv) > 3:
        try:
            timeout = float(argv[3])
        except ValueError:
            sys.stderr.write(f"invalid timeout: {argv[3]!r}\n")
            return 2
    print(grab(host, port, timeout))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
