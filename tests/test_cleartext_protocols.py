r"""Cleartext-protocol detection must not fire on TLS variants.

`_check_cleartext_protocols` classified services with a SUBSTRING match
(`key in svc`), so "ftps"/"smtps"/"imaps"/"pop3s" matched "ftp"/"smtp"/
"imap"/"pop3" and were reported as "Cleartext Protocols" — a false
finding on services that are in fact encrypted.  The match is now exact
per service name, with the TLS variants (and tftp, which has no
credentials) excluded up front, including on a cleartext default port.
"""

import os
import re
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


class _Terminal:
    def write(self, *a, **k):
        pass

    def section(self, *a, **k):
        pass


def _port_line(port, proto, svc):
    return f"{port}/{proto}  open  {svc}"


def _run(lines):
    """Drive the parser and return the list of add_auto_finding kwargs."""
    from gui.widgets.card_parsers_post import CardPostParserMixin
    findings = []

    class Host:
        def __init__(self):
            self.app = types.SimpleNamespace(
                after=lambda _delay, fn: fn(),
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                terminal=_Terminal())

        def _get_target(self):
            return "192.168.177.134"

    CardPostParserMixin._check_cleartext_protocols(Host(), list(lines))
    return findings


def _detected_count(findings):
    """The single combined card's title carries the count of hits."""
    if not findings:
        return 0
    m = re.search(r"—\s*(\d+)\s+on", findings[0]["title"])
    return int(m.group(1)) if m else -1


class CleartextTlsVariantTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_tls_variants_on_their_own_ports_are_not_flagged(self):
        for port, svc in (
            (990, "ftps"), (989, "ftps-data"), (465, "smtps"),
            (993, "imaps"), (995, "pop3s"), (992, "telnets"),
        ):
            findings = _run([_port_line(port, "tcp", svc)])
            self.assertEqual(
                findings, [],
                f"{svc}/{port} is encrypted and must not be flagged")

    def test_tls_variant_on_a_cleartext_default_port_is_not_flagged(self):
        # ftps sitting on 21 must NOT be caught by the default-port fallback.
        self.assertEqual(_run([_port_line(21, "tcp", "ftps")]), [])
        self.assertEqual(_run([_port_line(25, "tcp", "smtps")]), [])

    def test_ssl_tunnelled_service_is_not_flagged(self):
        # nmap prints tunnelled services as "ssl/<svc>"; these are encrypted.
        self.assertEqual(_run([_port_line(21, "tcp", "ssl/ftp")]), [])

    def test_tftp_is_not_flagged(self):
        # tftp is unauthenticated: there are no credentials to sniff.
        self.assertEqual(_run([_port_line(69, "udp", "tftp")]), [])

    def test_true_cleartext_protocols_are_still_flagged(self):
        for port, svc in (
            (21, "ftp"), (23, "telnet"), (25, "smtp"),
            (110, "pop3"), (143, "imap"),
        ):
            findings = _run([_port_line(port, "tcp", svc)])
            self.assertEqual(
                len(findings), 1,
                f"{svc}/{port} is cleartext and must be flagged")
            self.assertEqual(findings[0]["severity"], "medium")

    def test_mixed_log_counts_only_the_cleartext_service(self):
        # ftp (cleartext) + ftps (TLS) on the same host -> one hit, the ftp.
        findings = _run([
            _port_line(21, "tcp", "ftp"),
            _port_line(990, "tcp", "ftps"),
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(_detected_count(findings), 1)


if __name__ == "__main__":
    unittest.main()
