"""DB Fingerprint must not brute-force the full probe battery serially.

Regression for the live hang: run against a DC's 34 open ports (none of
them databases), the tool sat for 17+ minutes because ``main`` walked the
ports one at a time and each non-DB port burned ~30s working through all
nine probes' individual socket timeouts.

Two defences are asserted here:
  * ``_port_open`` is a cheap TCP pre-gate so a closed/filtered port is
    dismissed in one connect instead of the whole battery, and
    ``fingerprint_port`` short-circuits on it (no probe ever fires).
  * ``main`` fans the ports out across a thread pool, so wall-clock is
    ~max(per-port) not sum(per-port), while output stays in port order.
"""

import io
import os
import socket
import sys
import time
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils import db_fingerprint as dbf  # noqa: E402


class PortGateTests(unittest.TestCase):
    def test_open_port_detected(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(dbf._port_open("127.0.0.1", port, timeout=2.0))
        finally:
            srv.close()

    def test_closed_port_rejected_fast(self):
        # Bind, grab the port, then close so nothing is listening.
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()
        t0 = time.monotonic()
        # A closed port must be dismissed within a single connect timeout
        # (the whole point of the pre-gate) — never the ~30s full battery.
        # Whether the OS returns an immediate refusal or waits out the
        # timeout is platform-dependent; only the bound matters here.
        self.assertFalse(dbf._port_open("127.0.0.1", port, timeout=0.5))
        self.assertLess(time.monotonic() - t0, 5.0)

    def test_fingerprint_port_short_circuits_on_closed(self):
        """No probe may fire on a port the pre-gate says is closed."""
        calls = []

        def _boom(host, port):
            calls.append(port)
            raise AssertionError("probe fired on a closed port")

        orig = dict(dbf._PROBES)
        orig_open = dbf._port_open
        try:
            dbf._port_open = lambda h, p, timeout=2.0: False
            for k in dbf._PROBES:
                dbf._PROBES[k] = _boom
            self.assertIsNone(dbf.fingerprint_port("127.0.0.1", 445))
        finally:
            dbf._PROBES.clear()
            dbf._PROBES.update(orig)
            dbf._port_open = orig_open
        self.assertEqual(calls, [])


class ParallelMainTests(unittest.TestCase):
    def test_main_preserves_order_and_only_prints_hits(self):
        ports = [53, 445, 6379, 88, 27017]
        # Deterministic stand-in for the network layer: two "DBs" found.
        found = {
            6379: ("redis", "7.2.4", "high"),
            27017: ("mongodb", "", "high"),
        }
        orig = dbf.fingerprint_port
        try:
            dbf.fingerprint_port = lambda h, p: found.get(p)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = dbf.main(["db_fingerprint.py", "10.0.0.1",
                               ",".join(str(p) for p in ports)])
        finally:
            dbf.fingerprint_port = orig

        self.assertEqual(rc, 0)
        out = buf.getvalue().splitlines()
        self.assertEqual(
            out[0], "[HAWK_DB_DIAG: scanning 5 port(s) on 10.0.0.1]")
        self.assertEqual(out[-1], "[HAWK_DB_DIAG: done]")
        hits = [ln for ln in out if ln.startswith("[HAWK_DB port=")]
        # Only the two hits, and in the original port order (6379 < 27017).
        self.assertEqual(
            hits,
            ["[HAWK_DB port=6379 svc=redis version=7.2.4 confidence=high]",
             "[HAWK_DB port=27017 svc=mongodb version=? confidence=high]"])

    def test_scan_one_swallows_probe_exceptions(self):
        orig = dbf.fingerprint_port
        try:
            def _raise(h, p):
                raise RuntimeError("boom")
            dbf.fingerprint_port = _raise
            line = dbf._scan_one("10.0.0.1", 445)
        finally:
            dbf.fingerprint_port = orig
        self.assertEqual(line, "[HAWK_DB_DIAG: port=445 error: boom]")


if __name__ == "__main__":
    unittest.main()
