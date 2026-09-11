"""TICKETER (Golden Ticket) parser.

Live regression: a successful forge was filed by the generic fallback
as a low 'info' finding with a truncated impacket log dump — no mention
of who was impersonated, where the .ccache landed, how to use it, or how
to remediate.  A Golden Ticket is full domain-wide persistence, so the
dedicated parser must raise a CRITICAL finding whose result block names
the concrete forge (user + ccache) and whose usage commands are a
reusable pass-the-ticket runbook with <DC-IP>/<DOMAIN>/<DC-FQDN>
placeholders.  A run that saved no ticket must fall through to the
generic fallback.
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


class _Terminal:
    def __init__(self):
        self.messages = []

    def write(self, msg, style=None):
        self.messages.append((msg, style))

    def section(self, title):
        self.messages.append((title, "section"))


# Exact shape of a successful impacket-ticketer run against the lab DC.
_FORGE_OK = [
    "Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies",
    "[*] Creating basic skeleton ticket and PAC Infos",
    "[*] Customizing ticket for prova.prova.com/Administrator",
    "[*] \tPAC_LOGON_INFO",
    "[*] \tEncTicketPart",
    "[*] Signing/Encrypting final ticket",
    "[*] \tPAC_SERVER_CHECKSUM",
    "[*] Saving ticket in Administrator.ccache",
]

# No 'Customizing' line — user must be derived from the ccache name.
_FORGE_NO_CUST = [
    "Impacket v0.13.0",
    "[*] Signing/Encrypting final ticket",
    "[*] Saving ticket in bob.ccache",
]

# A failed / aborted run never saves a ticket.
_FORGE_FAIL = [
    "Impacket v0.13.0",
    "[*] Creating basic skeleton ticket and PAC Infos",
    "[-] Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP",
]


def _run(log):
    from gui.widgets.card_parsers_ad import CardADParserMixin

    findings = []

    class Host(CardADParserMixin):
        def __init__(self):
            self.phase_id = "ad_pentesting"
            self.app = types.SimpleNamespace(
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                terminal=_Terminal(),
                after=lambda _d, fn: fn())

        def _get_target(self):
            return "192.0.2.10"

        def _strip_ansi(self, s):
            return s

    tool = types.SimpleNamespace(
        name="TICKETER (Golden Ticket)", binary="impacket-ticketer",
        id="ticketer_golden")
    claimed = Host()._parse_ticketer_to_intel(
        tool, [("out", ln) for ln in log])
    return claimed, findings


class TicketerParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_successful_forge_is_critical(self):
        claimed, findings = _run(_FORGE_OK)
        self.assertTrue(claimed, "parser must CLAIM a successful forge, "
                        "not fall through to the generic info dump")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        # A Golden Ticket is domain-wide persistence → critical.
        self.assertEqual(f["severity"], "critical")
        self.assertIn("Administrator", f["title"])
        self.assertIn("prova.prova.com", f["title"])
        self.assertTrue(f["linked_run_id"])

    def test_result_block_keeps_real_forge_values(self):
        _, findings = _run(_FORGE_OK)
        d = findings[0]["description"]
        # What was actually forged, in real values.
        self.assertIn("Administrator@prova.prova.com", d)
        self.assertIn("Administrator.ccache", d)
        self.assertIn("krbtgt", d)
        self.assertIn("New-KrbtgtKeys", d)

    def test_usage_is_a_pass_the_ticket_runbook_with_placeholders(self):
        _, findings = _run(_FORGE_OK)
        d = findings[0]["description"]
        # The four numbered steps I want the operator to follow.
        self.assertIn("ls -l Administrator.ccache", d)
        self.assertIn("/etc/hosts", d)
        self.assertIn("export KRB5CCNAME=Administrator.ccache", d)
        self.assertIn("klist", d)
        # Target-specific values are placeholders, never the lab IP.
        self.assertIn("<DC-IP>", d)
        self.assertIn("<DOMAIN>", d)
        self.assertIn("<DC-FQDN>", d)
        self.assertNotIn("192.0.2.10", d)
        # The impersonated user stays real inside the template command.
        self.assertIn(
            "impacket-psexec -k -no-pass -dc-ip <DC-IP> "
            "<DOMAIN>/Administrator@<DC-FQDN>", d)
        # And the reasons are explained, not just the raw commands.
        self.assertIn("bound to the DC hostname, not its IP", d)
        self.assertIn("KRB_AP_ERR_SKEW", d)

    def test_user_derived_from_ccache_when_no_customizing_line(self):
        claimed, findings = _run(_FORGE_NO_CUST)
        self.assertTrue(claimed)
        self.assertIn("bob", findings[0]["title"])

    def test_no_saved_ticket_falls_through_to_fallback(self):
        claimed, findings = _run(_FORGE_FAIL)
        self.assertFalse(claimed, "a run that saved no ticket must let "
                         "the generic fallback handle it")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
