"""GetUserSPNs / KERBEROAST parser.

Live regression: run against a DC that DID have SPN accounts, the finding
came out as a generic low-severity "KERBEROAST (GetUserSPNs) on <t>" card
with nobody listed.  Cause: the row regex assumed the sAMAccountName was
the FIRST column, but GetUserSPNs prints the ServicePrincipalName first
(it contains '/' and ':'), so the regex matched no users and the parser
returned False → generic fallback.  A kerberoastable service account is a
high-value foothold, so the finding must be severity 'high' and name the
accounts, even when the TGS request itself failed on clock skew.
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


class _Store:
    def __init__(self):
        self.added = []

    def add_credential(self, cred):
        self.added.append(cred)


# GetUserSPNs stdout — SPN is the FIRST column.  This is the exact shape
# the live DC produced (two seeded SPN accounts), ending on a clock-skew
# error so no hash was retrieved.
_SPN_TABLE_SKEW = [
    "Impacket v0.13.0 - Copyright Fortra, LLC",
    "ServicePrincipalName                          Name       MemberOf              PasswordLastSet             LastLogon  Delegation",
    "--------------------------------------------  ---------  --------------------  --------------------------  ---------  ----------",
    "MSSQLSvc/vagrant-2008r2.prova.prova.com:1433  svc_sql    CN=HAWK_Team,CN=Users 2026-09-11 02:07:16.047286  <never>",
    "HTTP/svc-deleg.prova.prova.com                svc_deleg  CN=HAWK_Team,CN=Users 2026-09-11 02:16:13.873830  <never>",
    "[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)",
]

_HASH = ("$krb5tgs$23$*svc_sql$PROVA.PROVA.COM$"
         "MSSQLSvc/vagrant-2008r2.prova.prova.com:1433*$"
         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

_SPN_TABLE_HASH = [
    "Impacket v0.13.0 - Copyright Fortra, LLC",
    "ServicePrincipalName                          Name       MemberOf   PasswordLastSet             LastLogon  Delegation",
    "--------------------------------------------  ---------  ---------  --------------------------  ---------  ----------",
    "MSSQLSvc/vagrant-2008r2.prova.prova.com:1433  svc_sql    -          2026-09-11 02:07:16         <never>",
    _HASH,
]

_NO_ENTRIES = [
    "Impacket v0.13.0 - Copyright Fortra, LLC",
    "No entries found!",
]


def _run(log):
    from gui.widgets.card_parsers_ad import CardADParserMixin

    findings = []
    store = _Store()

    class Host(CardADParserMixin):
        def __init__(self):
            self.phase_id = "ad_pentesting"
            self.app = types.SimpleNamespace(
                cred_store=store,
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                terminal=_Terminal(),
                # after(delay, fn) → run fn immediately (no Tk loop).
                after=lambda _d, fn: fn())

        def _get_target(self):
            return "192.0.2.10"

        def _strip_ansi(self, s):
            return s

    tool = types.SimpleNamespace(
        name="KERBEROAST (GetUserSPNs)", binary="impacket-GetUserSPNs",
        id="getuserspns")
    claimed = Host()._parse_kerberoast_to_intel(
        tool, [("out", ln) for ln in log])
    return claimed, findings, store


class KerberoastParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_spn_table_extracts_users_high_severity_even_on_skew(self):
        claimed, findings, store = _run(_SPN_TABLE_SKEW)
        self.assertTrue(claimed, "parser must CLAIM the result, not fall "
                        "through to the generic fallback")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        # Both seeded SPN accounts extracted from the SPN-first table.
        self.assertIn("svc_sql", f["description"])
        self.assertIn("svc_deleg", f["description"])
        self.assertIn("2 SPN user(s)", f["title"])
        # Kerberoastable accounts are high-value → 'high', not info/low.
        self.assertEqual(f["severity"], "high")
        # No hash retrieved (skew) → no cred, but a clock-skew hint.
        self.assertEqual(store.added, [])
        self.assertIn("KRB_AP_ERR_SKEW", f["description"])
        self.assertIn("ntpdate", f["description"])

    def test_tgs_hash_saved_as_cred(self):
        claimed, findings, store = _run(_SPN_TABLE_HASH)
        self.assertTrue(claimed)
        self.assertEqual(len(store.added), 1)
        cred = store.added[0]
        self.assertEqual(cred.username, "svc_sql")
        self.assertEqual(cred.hash_type, "Kerberos TGS")
        self.assertFalse(cred.verified)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("TGS hash(es)", f["title"])

    def test_no_entries_is_info_not_high(self):
        claimed, findings, store = _run(_NO_ENTRIES)
        self.assertTrue(claimed)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertIn("no SPN users", findings[0]["title"])
        self.assertEqual(store.added, [])


_ASREP_LOG = [
    "Impacket v0.13.0 - Copyright Fortra, LLC",
    "Name       MemberOf      PasswordLastSet       LastLogon   UAC",
    "---------  ------------  --------------------  ----------  --------",
    "svc_asrep  CN=HAWK_Team  2026-09-11 02:07:16   <never>     0x410200",
    ("$krb5asrep$23$svc_asrep@PROVA.PROVA.COM:"
     "8ede90a9b9e01d2fb88e0a748fe3eb1f$21bec405087a375be8b8098ba3d5cfe7"),
]


def _run_asrep(log):
    from gui.widgets.card_parsers_ad import CardADParserMixin

    findings = []
    store = _Store()

    class Host(CardADParserMixin):
        def __init__(self):
            self.phase_id = "ad_pentesting"
            self.app = types.SimpleNamespace(
                cred_store=store,
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                terminal=_Terminal(),
                after=lambda _d, fn: fn())

        def _get_target(self):
            return "192.0.2.10"

        def _strip_ansi(self, s):
            return s

    tool = types.SimpleNamespace(
        name="AS-REP ROAST (GetNPUsers)", binary="impacket-GetNPUsers",
        id="getnpusers")
    Host()._parse_asrep_to_intel(tool, [("out", ln) for ln in log])
    return findings, store


class AsrepParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_finding_names_the_roasted_users_and_saves_cred(self):
        findings, store = _run_asrep(_ASREP_LOG)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        # The finding must NAME the roastable account, not just count it.
        self.assertIn("AS-REP roastable users:", f["description"])
        self.assertIn("svc_asrep", f["description"])
        # And the hash lands in the store as a Kerberos AS-REP cred.
        self.assertEqual(len(store.added), 1)
        self.assertEqual(store.added[0].username, "svc_asrep")
        self.assertEqual(store.added[0].hash_type, "Kerberos AS-REP")


_FINDELEG_LOG = [
    "Impacket v0.13.0 - Copyright Fortra, LLC",
    "AccountName      AccountType  DelegationType                       "
    "DelegationRightsTo                   SPN Exists",
    "---------------  -----------  -----------------------------------  "
    "-----------------------------------  ----------",
    "VAGRANT-2008R2$  Computer     Unconstrained                        "
    "N/A                                  Yes",
    "svc_deleg        Person       Constrained w/o Protocol Transition  "
    "CIFS/vagrant-2008r2.prova.prova.com  No",
]


def _run_findeleg(log):
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
        name="FIND DELEGATION", binary="impacket-findDelegation",
        id="findDelegation")
    claimed = Host()._parse_findelegation_to_intel(
        tool, [("out", ln) for ln in log])
    return claimed, findings


class FindDelegationParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_structured_high_finding_with_types_and_targets(self):
        claimed, findings = _run_findeleg(_FINDELEG_LOG)
        self.assertTrue(claimed, "parser must claim the result, not fall "
                        "through to the generic dump")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        # Delegation is a real privesc vector → high, not the generic info.
        self.assertEqual(f["severity"], "high")
        self.assertIn("2 delegated", f["title"])
        d = f["description"]
        # Both accounts, their types, and the constrained target SPN.
        self.assertIn("VAGRANT-2008R2$", d)
        self.assertIn("Unconstrained", d)
        self.assertIn("svc_deleg", d)
        self.assertIn("CIFS/vagrant-2008r2.prova.prova.com", d)
        # The multi-word DelegationType column parsed whole.
        self.assertIn("Constrained w/o Protocol Transition", d)

    def test_no_delegation_is_info(self):
        claimed, findings = _run_findeleg([
            "Impacket v0.13.0",
            "AccountName  AccountType  DelegationType  DelegationRightsTo"
            "  SPN Exists",
            "No entries found!",
        ])
        self.assertTrue(claimed)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertIn("none on", findings[0]["title"])


if __name__ == "__main__":
    unittest.main()
