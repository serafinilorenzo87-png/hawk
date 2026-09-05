r"""End-to-end regression for the proxychains_scan ramo.

Bug shipped in 51ed43e and fixed in the follow-up: the ramo passed a
list of (ts, line) tuples to target_intel.update_from_nmap().  That
call routes into OSFingerprint.from_nmap_output, which does
`line.strip()` on every element — tuples don't have .strip(), so the
call raised AttributeError, silently swallowed by the except.  Net
effect: the Ports panel was NEVER populated from a proxychains-nmap
run, even though the finding text looked complete.

These tests lock the contract by exercising the RAMO (not the parser
in isolation).  The ramo lives in a module-level helper
`_proxychains_scan_dispatch` extracted from CardRuntimeMixin._on_done
specifically so this test can invoke it without importing
customtkinter-heavy modules.

Coverage:
  1. Ramo end-to-end: hand it (ts, line) tuples with [proxychains]
     noise + nmap output → verify open_ports is populated with EVERY
     port and update_from_nmap received a list of STRINGS.
  2. Ramo strips [proxychains] noise → parse_output_to_intel receives
     a clean_log with no "[proxychains]"-prefixed lines.
  3. Documentary: feeding tuples DIRECTLY to from_nmap_output crashes
     — this is the trap the fix protects against.
  4. Failure surfaces to the terminal at "warn": if update_from_nmap
     raises, the terminal receives a warn (silent-swallow was what
     masked the tuple/strings bug in production).
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# Realistic raw log the ToolRunner would hand the _on_done callback:
# (ts, line) tuples, some [proxychains]-prefixed, some pure nmap.
_RAW_LOG = [
    ("out", "[proxychains] config file found: /etc/proxychains4.conf"),
    ("out", "[proxychains] preloading /usr/lib/.../libproxychains.so.4"),
    ("out", "[proxychains] DLL init: proxychains-ng 4.17"),
    ("out", "Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-04"),
    ("out", "Nmap scan report for 10.10.10.5"),
    ("out", "Host is up (0.0049s latency)."),
    ("out", "PORT     STATE SERVICE"),
    ("out", "21/tcp   open  ftp"),
    ("out", "22/tcp   open  ssh"),
    ("out", "80/tcp   open  http"),
    ("out", "445/tcp  open  microsoft-ds"),
    ("out", "3306/tcp open  mysql"),
    ("out", "8180/tcp open  unknown"),
    ("out", "Nmap done: 1 IP address (1 host up) scanned in 0.98s"),
]

_EXPECTED_PORTS = {21, 22, 80, 445, 3306, 8180}


class _FakeIntel:
    """Stand-in for gui.widgets.target_intel_widget.TargetIntel that
    just calls the real OSFingerprint parser and stores its result.

    Records what update_from_nmap received (type + reference) so tests
    can assert the ramo unpacks tuples correctly.
    """
    def __init__(self, raising=False):
        self.received = None
        self.received_type_of_item = None
        self.open_ports = set()
        self._raising = raising

    def update_from_nmap(self, arg):
        self.received = arg
        if self._raising:
            raise RuntimeError("simulated parser failure")
        self.received_type_of_item = (
            type(arg[0]).__name__ if arg else "empty")
        from modules.exploit_suggester import OSFingerprint
        fp = OSFingerprint.from_nmap_output(arg)
        self.open_ports = {p for p, *_ in fp.open_ports}


class _FakeTerminal:
    def __init__(self):
        self.writes = []          # list of (msg, level)

    def write(self, msg, level="info"):
        self.writes.append((msg, level))


def _load_dispatch():
    """Load the ramo helper from card_runtime.py.  Uses the
    test_custom_route_exec_record customtkinter stub pattern so the
    module can be imported without a real Tk display."""
    # Reuse the stub installer from the sibling test file — same
    # _DummyCtk class the rest of the suite uses.
    import test_custom_route_exec_record as _stub
    _stub._install_customtkinter_stub()
    from gui.widgets.card_runtime import _proxychains_scan_dispatch
    return _proxychains_scan_dispatch


class ProxychainsRamoEndToEndTests(unittest.TestCase):
    """Invoke the actual ramo with the actual runner-shaped input."""

    @classmethod
    def setUpClass(cls):
        cls.dispatch = staticmethod(_load_dispatch())

    def _tool(self):
        return MagicMock(id="proxychains_scan", name="PROXYCHAINS NMAP",
                          binary="proxychains4")

    def test_ramo_extracts_strings_and_populates_open_ports(self):
        """Feed tuples in, get every port out.  This is the exact
        regression: the ramo MUST unpack tuples before handing them
        to update_from_nmap or the parser silently blanks out."""
        intel = _FakeIntel()
        parse_cb = MagicMock()
        self.dispatch(_RAW_LOG, intel, parse_cb, self._tool(),
                      terminal=None)
        self.assertEqual(
            intel.received_type_of_item, "str",
            f"ramo handed {intel.received_type_of_item!r} to "
            f"update_from_nmap — must be str (fix: "
            f"`[line for _, line in clean_log]`)")
        missing = _EXPECTED_PORTS - intel.open_ports
        self.assertFalse(
            missing,
            f"open_ports missing {sorted(missing)} — the ramo failed "
            f"to populate the Ports panel end-to-end.  Got: "
            f"{sorted(intel.open_ports)}")

    def test_ramo_strips_proxychains_noise_before_finding_push(self):
        """The clean_log fed to _parse_output_to_intel must have zero
        [proxychains]-prefixed lines (that noise was polluting the
        auto_finding description text in prod)."""
        intel = _FakeIntel()
        parse_cb = MagicMock()
        self.dispatch(_RAW_LOG, intel, parse_cb, self._tool())
        parse_cb.assert_called_once()
        _tool_arg, clean_log_arg = parse_cb.call_args.args
        self.assertTrue(
            all(not line.startswith("[proxychains]")
                for _ts, line in clean_log_arg),
            "clean_log fed to parse_output_to_intel still contains "
            "[proxychains] lines — the noise filter is broken")
        # And the nmap payload survived the filter.
        self.assertTrue(
            any("21/tcp" in line for _ts, line in clean_log_arg),
            "nmap open-port lines were stripped along with the "
            "[proxychains] noise")

    def test_parser_failure_surfaces_to_terminal_as_warn(self):
        """If update_from_nmap raises, the terminal must see a warn.
        Silent swallow was exactly what let the tuple/strings bug live
        in production undetected."""
        intel = _FakeIntel(raising=True)
        term = _FakeTerminal()
        parse_cb = MagicMock()
        self.dispatch(_RAW_LOG, intel, parse_cb, self._tool(),
                      terminal=term)
        warns = [(msg, level) for msg, level in term.writes
                 if level == "warn"]
        self.assertTrue(
            warns,
            "parser failure produced no warn — the silent swallow that "
            "hid the original tuple bug is back")
        self.assertIn(
            "proxychains", warns[0][0].lower(),
            "warn message should identify the source (proxychains)")


class ParserDocumentaryTests(unittest.TestCase):
    """Locks the invariant that motivated the fix: from_nmap_output
    does NOT tolerate (ts, line) tuples — the caller MUST extract the
    string half first.  If a future refactor makes the parser
    tuple-tolerant, this test needs to be revisited alongside the
    ramo's extraction step."""

    def test_tuples_do_not_populate_open_ports(self):
        from modules.exploit_suggester import OSFingerprint
        tuples = [("out", "21/tcp open ftp"),
                  ("out", "22/tcp open ssh")]
        # Either crashes with AttributeError or returns fp with no
        # ports — both outcomes leave the Ports panel empty.  Assert
        # that the ports we care about are NOT populated.
        try:
            fp = OSFingerprint.from_nmap_output(tuples)
            got = {p for p, *_ in fp.open_ports}
        except AttributeError:
            got = set()
        self.assertNotEqual(
            got, {21, 22},
            "from_nmap_output populated open_ports from a list of "
            "tuples — the ramo's string extraction may no longer be "
            "necessary, revisit the fix comment in card_runtime.py")


if __name__ == "__main__":
    unittest.main()
