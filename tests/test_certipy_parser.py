"""CERTIPY find/quick parser — classification correctness.

Two regressions this guards:
- "0 certificate authorities" (no Enterprise CA registered) must be
  reported as "no Enterprise CA", NOT "AD CS ... (no ESC vulns found)".
  The old Path A matched the bare "Certificate Authorities" header even
  when the line said "Could not find any CAs".
- An LDAPS handshake reset (certipy v5 defaults to LDAPS; legacy DCs
  reset it) must point the operator at the plain-LDAP retry
  (-ldap-scheme ldap), not flatly conclude the DC has no AD CS role.
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


# certipy v5 over plain LDAP, no Enterprise CA registered in the domain.
_ZERO_CAS = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[*] Finding certificate authorities",
    "[*] Found 0 certificate authorities",
    "[*] Enumeration output:",
    "Certificate Authorities   : [!] Could not find any CAs",
    "Certificate Templates     : [!] Could not find any certificate templates",
]
# certipy v5 default LDAPS against a legacy DC -> TLS handshake reset.
_LDAPS_RESET = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[-] Got error: socket ssl wrapping error: [Errno 104] "
    "Connection reset by peer",
]
# certipy -vulnerable with a CA-level ESC11 and an ESC1 template (plus a
# "[*] Remarks" section whose ESC15/ESC2/ESC3 lines must NOT be counted).
_ESC1 = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[*] Enumeration output:",
    "Certificate Authorities",
    "  0",
    "    CA Name                             : prova-VAGRANT-2008R2-CA",
    "    DNS Name                            : vagrant-2008R2.prova.prova.com",
    "    [!] Vulnerabilities",
    "      ESC11                             : Encryption is not enforced "
    "for ICPR (RPC) requests.",
    "Certificate Templates",
    "  0",
    "    Template Name                       : User",
    "    Enabled                             : True",
    "    Client Authentication               : True",
    "    Enrollee Supplies Subject           : True",
    "    [!] Vulnerabilities",
    "      ESC1                              : Enrollee supplies subject "
    "and template allows client authentication.",
    "      ESC15                             : Enrollee supplies subject "
    "and schema version is 1.",
    "      ESC4                              : User has dangerous "
    "permissions.",
    "    [*] Remarks",
    "      ESC15                             : Only applicable if the "
    "environment has not been patched. See CVE-2024-49019 or the wiki.",
    "      ESC2 Target Template              : Template can be targeted "
    "as part of ESC2 exploitation.",
    "      ESC3 Target Template              : Template can be targeted "
    "as part of ESC3 exploitation.",
]


# certipy req: an ESC1 cert minted for Administrator.
_REQ_OK = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[!] DNS resolution failed: The DNS query name does not exist: "
    "PROVA.PROVA.COM.",
    "[*] Requesting certificate via RPC",
    "[*] Request ID is 3",
    "[*] Successfully requested certificate",
    "[*] Got certificate with UPN 'Administrator@prova.prova.com'",
    "[*] Certificate has no object SID",
    "[*] Wrote certificate and private key to 'esc1.pfx'",
]
_REQ_FAIL = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[-] Got error: some RPC failure",
]


def _run_req(log):
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
        name="CERTIPY — request cert (ESC1)", binary="certipy",
        id="certipy_req")
    claimed = Host()._parse_certipy_req_to_intel(
        tool, [("out", ln) for ln in log])
    return claimed, findings


# certipy auth: PKINIT with the ESC1 cert -> TGT + UnPAC'd NT hash.
_AUTH_HASH = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[*] Using principal: 'administrator@prova.prova.com'",
    "[*] Trying to get TGT...",
    "[*] Got TGT",
    "[*] Saving credential cache to 'administrator.ccache'",
    "[*] Wrote credential cache to 'administrator.ccache'",
    "[*] Trying to retrieve NT hash for 'administrator'",
    "[*] Got hash for 'administrator@prova.prova.com': "
    "aad3b435b51404eeaad3b435b51404ee:62ab5460e57f01fb5540f5897538e8fa",
]
# auth against an account whose password expired -> no TGT, no hash.
_AUTH_FAIL = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[*] Trying to get TGT...",
    "[-] Got error while trying to request TGT: Kerberos SessionError: "
    "KDC_ERR_KEY_EXPIRED(Password has expired; change password to reset)",
]
# auth run with -no-save (HAWK's default): TGT + hash, but no ccache line.
_AUTH_NOSAVE = [
    "Certipy v5.0.3 - by Oliver Lyak (ly4k)",
    "[*] Using principal: 'administrator@prova.prova.com'",
    "[*] Trying to get TGT...",
    "[*] Got TGT",
    "[*] Trying to retrieve NT hash for 'administrator'",
    "[*] Got hash for 'administrator@prova.prova.com': "
    "aad3b435b51404eeaad3b435b51404ee:62ab5460e57f01fb5540f5897538e8fa",
]


def _run_auth(log):
    from gui.widgets.card_parsers_ad import CardADParserMixin

    findings, creds = [], []

    class Host(CardADParserMixin):
        def __init__(self):
            self.phase_id = "ad_pentesting"
            self.app = types.SimpleNamespace(
                cred_store=types.SimpleNamespace(
                    add_credential=lambda c: creds.append(c)),
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                terminal=_Terminal(),
                after=lambda _d, fn: fn())

        def _get_target(self):
            return "192.0.2.10"

        def _strip_ansi(self, s):
            return s

    tool = types.SimpleNamespace(
        name="CERTIPY — auth with cert", binary="certipy",
        id="certipy_auth")
    claimed = Host()._parse_certipy_auth_to_intel(
        tool, [("out", ln) for ln in log])
    return claimed, findings, creds


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
        name="CERTIPY — quick (vuln-only)", binary="certipy",
        id="certipy_quick")
    claimed = Host()._parse_certipy_find_to_intel(
        tool, [("out", ln) for ln in log])
    return claimed, findings


class CertipyParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_zero_cas_reported_as_no_enterprise_ca(self):
        claimed, findings = _run(_ZERO_CAS)
        self.assertTrue(claimed)
        self.assertEqual(len(findings), 1)
        title = findings[0]["title"]
        self.assertIn("no Enterprise CA", title)
        # The old mis-classification we are guarding against.
        self.assertNotIn("no ESC vulns", title)

    def test_ldaps_reset_points_to_plain_ldap(self):
        claimed, findings = _run(_LDAPS_RESET)
        self.assertTrue(claimed)
        self.assertEqual(len(findings), 1)
        desc = findings[0]["description"]
        self.assertIn("-ldap-scheme ldap", desc)
        # Must NOT flatly conclude the DC has no AD CS role.
        self.assertIn("does NOT", desc)

    def test_esc1_finding_is_critical_and_actionable(self):
        claimed, findings = _run(_ESC1)
        self.assertTrue(claimed)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "critical")
        d = f["description"]
        # CA-level ESC11 is captured, not only template ESCs.
        self.assertIn("ESC11", f["title"])
        self.assertIn("ESC1", f["title"])
        # 4 real misconfigs (CA ESC11 + User ESC1/ESC15/ESC4); the
        # "[*] Remarks" ESC15/ESC2/ESC3 lines are NOT double-counted.
        self.assertIn("4 AD CS misconfiguration", d)
        self.assertEqual(d.count("ESC15"), 1)
        # The real template is pre-baked into the certipy-req command.
        self.assertIn("-template 'User'", d)
        self.assertNotIn("<template>", d)

    def test_finding_feeds_certipy_req_prefill(self):
        # The certipy_req dialog reads CA name + template back OUT of the
        # certipy_find finding to pre-fill its <CA_NAME>/<TEMPLATE> fields.
        # This locks the parser<->extractor contract (the finding's list
        # format the extractor regex depends on).
        _, findings = _run(_ESC1)
        desc = findings[0]["description"]
        from gui.widgets.card_ad_routes import CardADRoutesMixin

        # A no-vulns finding whose prose ("no exploitable ESC1-ESC11
        # misconfiguration") must NOT leak "misconfiguration" as a
        # template (regression: the extractor once matched that phrase).
        prose = ("Certipy enumerated AD CS on 192.0.2.10 but found no "
                 "exploitable ESC1–ESC11 misconfiguration.  CA name: "
                 "prova-VAGRANT-2008R2-CA")

        class RouteHost(CardADRoutesMixin):
            def __init__(self):
                self.app = types.SimpleNamespace(
                    target_intel=types.SimpleNamespace(
                        _auto_findings=[
                            {"source": "CERTIPY — quick (vuln-only)",
                             "description": prose},
                            {"source": "CERTIPY — quick (vuln-only)",
                             "description": desc}]))

        ca, templates = RouteHost()._extract_certipy_find_results()
        self.assertEqual(ca, "prova-VAGRANT-2008R2-CA")
        # Only the real ESC1 template — no CA subject, no prose noise.
        self.assertEqual(templates, ["User"])

    def test_req_cert_is_high_and_actionable(self):
        claimed, findings = _run_req(_REQ_OK)
        self.assertTrue(claimed, "a minted cert must CLAIM the finding, "
                        "not fall through to the generic info dump")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("Administrator@prova.prova.com", f["title"])
        d = f["description"]
        self.assertIn("esc1.pfx", d)        # the REAL path certipy wrote
        self.assertIn("certipy auth", d)    # next step
        self.assertIn("-sid", d)            # the no-object-SID caveat

    def test_req_failure_falls_through(self):
        claimed, findings = _run_req(_REQ_FAIL)
        self.assertFalse(claimed)
        self.assertEqual(findings, [])

    def test_auth_recovers_hash_as_critical_credential(self):
        claimed, findings, creds = _run_auth(_AUTH_HASH)
        self.assertTrue(claimed)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")
        d = findings[0]["description"]
        self.assertIn("62ab5460e57f01fb5540f5897538e8fa", d)
        self.assertIn("secretsdump", d)          # DCSync runbook
        # The recovered hash is captured as a credential (verified=False).
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0].username, "administrator")
        self.assertIn("62ab5460", creds[0].hash_val)
        self.assertFalse(creds[0].verified)

    def test_auth_failure_falls_through(self):
        claimed, findings, creds = _run_auth(_AUTH_FAIL)
        self.assertFalse(claimed)
        self.assertEqual(findings, [])
        self.assertEqual(creds, [])

    def test_auth_no_save_still_captures_hash(self):
        # With -no-save there is no ccache line, but the hash is still
        # captured and the runbook notes the missing ticket.
        claimed, findings, creds = _run_auth(_AUTH_NOSAVE)
        self.assertTrue(claimed)
        self.assertEqual(len(creds), 1)
        self.assertIn("62ab5460", creds[0].hash_val)
        d = findings[0]["description"]
        self.assertIn("62ab5460e57f01fb5540f5897538e8fa", d)
        self.assertIn("no-save", d)


if __name__ == "__main__":
    unittest.main()
