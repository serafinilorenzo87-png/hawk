"""BloodHound stat extraction — the counting rules behind the Target
Intel finding + post-collect summary dialog.

Regressions this guards:
  * krbtgt is NOT a kerberoast target.  It always carries an SPN
    (kadmin/changepw) and is disabled, so BloodHound's `hasspn` flag
    marks it — but the KDC won't issue a roastable TGS for a disabled
    account.  A live run against the lab DC surfaced krbtgt as the one
    "kerberoastable" user and told the operator to "run KERBEROAST next",
    which is wrong.  krbtgt (and any disabled SPN account) must be
    excluded.
  * Domain/Enterprise Admins members must be resolved to display names
    (BloodHound stores them as ObjectIdentifier SIDs) and deduped (a
    principal in both groups is counted once) so the finding names the
    crown-jewel accounts instead of dropping them or printing raw SIDs.
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


def _u(sid, name, sam, **props):
    p = {"name": name, "samaccountname": sam}
    p.update(props)
    return {"ObjectIdentifier": sid, "Properties": p}


class BloodhoundExtractStatsTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.card_parsers_ad import _bloodhound_extract_stats
        self._extract = _bloodhound_extract_stats

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    # ── The full lab-shaped fixture ─────────────────────────────────────
    def _fixture(self):
        users = [
            _u("S-1-5-21-A-500", "ADMINISTRATOR@PROVA.PROVA.COM",
               "Administrator", hasspn=False, enabled=True),
            _u("S-1-5-21-A-1000", "VAGRANT@PROVA.PROVA.COM",
               "vagrant", hasspn=False, enabled=True),
            _u("S-1-5-21-A-502", "KRBTGT@PROVA.PROVA.COM",
               "krbtgt", hasspn=True, enabled=False),
            _u("S-1-5-21-A-1105", "SQLSVC@PROVA.PROVA.COM",
               "sqlsvc", hasspn=True, enabled=True),
            _u("S-1-5-21-A-1106", "OLDSVC@PROVA.PROVA.COM",
               "oldsvc", hasspn=True, enabled=False),     # disabled SPN
            _u("S-1-5-21-A-1107", "ASREP@PROVA.PROVA.COM",
               "asrep", hasspn=False, dontreqpreauth=True, enabled=True),
        ]
        computers = [
            {"ObjectIdentifier": "S-1-5-21-A-1001",
             "Properties": {"name": "VAGRANT-2008R2.PROVA.PROVA.COM",
                            "unconstraineddelegation": True}},
            {"ObjectIdentifier": "S-1-5-21-A-1002",
             "Properties": {"name": "WS01.PROVA.PROVA.COM",
                            "unconstraineddelegation": False}},
        ]
        groups = [
            {"ObjectIdentifier": "S-1-5-21-A-512",
             "Properties": {"name": "DOMAIN ADMINS@PROVA.PROVA.COM"},
             "Members": [{"ObjectIdentifier": "S-1-5-21-A-500"},
                         {"ObjectIdentifier": "S-1-5-21-A-1000"}]},
            {"ObjectIdentifier": "S-1-5-21-A-519",
             "Properties": {"name": "ENTERPRISE ADMINS@PROVA.PROVA.COM"},
             # Administrator again -> must be deduped.
             "Members": [{"ObjectIdentifier": "S-1-5-21-A-500"}]},
            {"ObjectIdentifier": "S-1-5-21-A-513",
             "Properties": {"name": "DOMAIN USERS@PROVA.PROVA.COM"},
             "Members": []},
        ]
        return users, computers, groups

    def test_krbtgt_and_disabled_spn_excluded_from_kerberoast(self):
        s = self._extract(*self._fixture())
        # Only the enabled, non-krbtgt SPN user survives.
        self.assertEqual(s["kerberoastable"], ["SQLSVC@PROVA.PROVA.COM"])
        self.assertNotIn("KRBTGT@PROVA.PROVA.COM", s["kerberoastable"])
        self.assertNotIn("OLDSVC@PROVA.PROVA.COM", s["kerberoastable"])

    def test_asrepable_and_unconstrained(self):
        s = self._extract(*self._fixture())
        self.assertEqual(s["asrepable"], ["ASREP@PROVA.PROVA.COM"])
        self.assertEqual(s["unconstrained_pcs"],
                         ["VAGRANT-2008R2.PROVA.PROVA.COM"])

    def test_da_members_resolved_to_names_and_deduped(self):
        s = self._extract(*self._fixture())
        # SIDs resolved to names; Administrator (in both DA and EA) once.
        self.assertEqual(
            s["da_members"],
            ["ADMINISTRATOR@PROVA.PROVA.COM", "VAGRANT@PROVA.PROVA.COM"])

    def test_all_user_names_collected(self):
        # user_names is the raw session inventory: it keeps every user
        # (krbtgt included) — the krbtgt filter applies only to the
        # kerberoast list, not to who was discovered.
        s = self._extract(*self._fixture())
        self.assertEqual(len(s["user_names"]), 6)
        self.assertIn("KRBTGT@PROVA.PROVA.COM", s["user_names"])

    def test_lab_case_only_krbtgt_has_spn_yields_zero_kerberoastable(self):
        """The exact live case: on this DC krbtgt is the ONLY hasspn
        user, so after excluding it the roastable count is 0 — the finding
        must NOT recommend KERBEROAST against krbtgt."""
        users = [
            _u("S-1-5-21-A-500", "ADMINISTRATOR@PROVA.PROVA.COM",
               "Administrator", hasspn=False, enabled=True),
            _u("S-1-5-21-A-502", "KRBTGT@PROVA.PROVA.COM",
               "krbtgt", hasspn=True, enabled=False),
        ]
        s = self._extract(users, [], [])
        self.assertEqual(s["kerberoastable"], [])

    def test_missing_enabled_key_still_counts_spn_user(self):
        """Older BloodHound JSON may omit `enabled`; an SPN user without
        it (and not krbtgt) must still be treated as kerberoastable."""
        users = [
            _u("S-1-5-21-A-1105", "SVC@PROVA.PROVA.COM", "svc",
               hasspn=True),   # no 'enabled' key
        ]
        s = self._extract(users, [], [])
        self.assertEqual(s["kerberoastable"], ["SVC@PROVA.PROVA.COM"])

    def test_empty_inputs_are_safe(self):
        s = self._extract(None, None, None)
        self.assertEqual(s["kerberoastable"], [])
        self.assertEqual(s["da_members"], [])
        self.assertEqual(s["user_names"], [])


if __name__ == "__main__":
    unittest.main()
