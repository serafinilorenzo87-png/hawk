r"""The Web Oracle's _stream_cmd must not orphan a hung tool.

web_oracle._stream_cmd reads a tool's stdout line by line.  A tool that
hangs in shutdown (nuclei stalling on shared-folder temp I/O) keeps
stdout open and emits nothing more, so the read loop used to block
forever and the process was left running in the background (observed
live: a nuclei from a past Oracle run alive for >1 day).  A watchdog now
kills the whole process group on cancel or after `timeout`, and
_kill_proc_group escalates SIGTERM -> SIGKILL so a signal-ignoring tool
still dies.
"""

import os
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import utils.web_oracle as wo


class _StubRunner:
    """Minimal stand-in carrying only what _stream_cmd touches."""

    def __init__(self):
        self._cancelled = False
        self._results_lock = threading.Lock()
        self._binary_results = {}

    def _emit(self, *a, **k):
        pass


_StubRunner._stream_cmd = wo.WebOracleRunner._stream_cmd

_HANG = [sys.executable, "-c", "import time; time.sleep(60)"]


class OracleWatchdogTests(unittest.TestCase):
    def test_hung_tool_killed_by_timeout(self):
        r = _StubRunner()
        start = time.monotonic()
        r._stream_cmd(_HANG, "t", "probe", timeout=2)
        elapsed = time.monotonic() - start
        self.assertLess(
            elapsed, 15,
            "the watchdog must kill a hung tool near `timeout`, not block "
            "forever on its still-open stdout")

    def test_cancel_kills_promptly(self):
        r = _StubRunner()

        def _cancel_soon():
            time.sleep(1.0)
            r._cancelled = True

        threading.Thread(target=_cancel_soon, daemon=True).start()
        start = time.monotonic()
        r._stream_cmd(_HANG, "t", "probe", timeout=120)
        elapsed = time.monotonic() - start
        self.assertLess(
            elapsed, 15,
            "cancel must tear the tool down, not wait for `timeout`")


@unittest.skipUnless(os.name == "posix", "process groups are POSIX-only")
class KillProcGroupTests(unittest.TestCase):
    def test_kill_group_terminates(self):
        import subprocess
        p = subprocess.Popen(["sh", "-c", "sleep 60"],
                             preexec_fn=os.setsid)
        wo._kill_proc_group(p)
        for _ in range(30):
            if p.poll() is not None:
                break
            time.sleep(0.1)
        self.assertIsNotNone(p.poll(), "the process group must be dead")


if __name__ == "__main__":
    unittest.main()
