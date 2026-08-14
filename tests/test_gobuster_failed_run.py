"""A failed dir-buster run must not be reported as a clean empty scan.

When gobuster/ffuf/dirb abort (e.g. "connect: no route to host", wildcard
bail-out, missing wordlist) they exit non-zero and print zero path rows.
The parser's empty-result branch used to fire regardless of exit code and
emit a reassuring "0 paths found — target really has no content" info
finding, selling a failure as a successful-but-empty scan.  A non-zero
exit with no hits must instead be surfaced as a failure and add no
finding.  (STOP and stale-session runs are short-circuited upstream, so a
non-zero code reaching the parser is a genuine tool failure.)
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class _DummyCtk:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, _n):
        return _DummyCtk

    def __call__(self, *a, **k):
        return _DummyCtk()


def _install_customtkinter_stub():
    module = types.ModuleType("customtkinter")
    for name in (
        "CTkFrame", "CTkFont", "CTkButton", "CTkLabel", "CTkEntry",
        "CTkTextbox", "CTkToplevel", "CTkScrollableFrame", "CTkOptionMenu",
        "CTkCheckBox", "CTkRadioButton", "CTkProgressBar", "CTkTabview",
        "CTkSwitch", "StringVar", "BooleanVar", "IntVar",
    ):
        setattr(module, name, _DummyCtk)
    sys.modules["customtkinter"] = module


# Real Metasploitable2 gobuster output when the box had already dropped:
# every request fails at L3, zero path rows, fatal error, exit 1.
_GOBUSTER_FAIL = [
    ("info", "==============================================================="),
    ("info", "Gobuster v3.8.2"),
    ("info", "[+] Url:                     http://192.168.177.134:80"),
    ("info", "[+] Threads:                 10"),
    ("info", "[+] Wordlist:                /usr/share/wordlists/dirb/common.txt"),
    ("info", "Starting gobuster in directory enumeration mode"),
    ("info", "Progress: 0 / 1 (0.00%)"),
    ("error",
     '2026/08/13 10:27:00 error on running gobuster on '
     'http://192.168.177.134:80/: unable to connect to '
     'http://192.168.177.134:80/: Get "http://192.168.177.134:80/": '
     'dial tcp 192.168.177.134:80: connect: no route to host'),
]

# A clean run that genuinely found nothing: it completed, exit 0.
_GOBUSTER_EMPTY_OK = [
    ("info", "[+] Url:                     http://192.168.177.134:80"),
    ("info", "[+] Threads:                 10"),
    ("info", "Starting gobuster in directory enumeration mode"),
    ("info", "Progress: 4614 / 4614 (100.00%)"),
    ("info", "Finished"),
]


class _Terminal:
    def __init__(self):
        self.messages = []

    def write(self, msg, style=None):
        self.messages.append((msg, style))

    def section(self, title):
        self.messages.append((title, "section"))


class _DummyIntel:
    def __init__(self):
        self.findings = []

    def add_auto_finding(self, **kw):
        self.findings.append(kw)


def _build_web_parser():
    from gui.widgets.card_parsers_web import CardWebParserMixin

    class Host(CardWebParserMixin):
        def __init__(self):
            self.app = types.SimpleNamespace(
                terminal=_Terminal(),
                target_intel=_DummyIntel(),
                session_manager=types.SimpleNamespace(current=None),
                # run scheduled callbacks synchronously
                after=lambda _delay, fn: fn())

        def _get_target(self):
            return "192.168.177.134"

        def _strip_ansi(self, s):
            return s

        def _extract_web_target_label(self, tool):
            return "http://192.168.177.134:80/"

    return Host()


def _tool():
    return types.SimpleNamespace(
        name="GOBUSTER Dir", binary="gobuster", id="gobuster_dir")


class GobusterFailedRunTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_failed_run_adds_no_finding(self):
        host = _build_web_parser()
        host._parse_gobuster_to_intel(_tool(), _GOBUSTER_FAIL, 1)
        self.assertEqual(
            host.app.target_intel.findings, [],
            "a failed dir-buster run must not add an empty-result finding")

    def test_failed_run_reports_the_failure(self):
        host = _build_web_parser()
        host._parse_gobuster_to_intel(_tool(), _GOBUSTER_FAIL, 1)
        blob = " ".join(m for m, _ in host.app.terminal.messages).lower()
        self.assertIn("failed", blob)
        self.assertNotIn("no paths matched", blob)

    def test_clean_empty_run_still_reports_zero_paths(self):
        """The fix must not swallow a legitimate empty (exit 0) scan."""
        host = _build_web_parser()
        host._parse_gobuster_to_intel(_tool(), _GOBUSTER_EMPTY_OK, 0)
        self.assertEqual(len(host.app.target_intel.findings), 1,
                         host.app.target_intel.findings)
        f = host.app.target_intel.findings[0]
        self.assertEqual(f["severity"], "info")
        self.assertIn("0 paths found", f["description"])


if __name__ == "__main__":
    unittest.main()
