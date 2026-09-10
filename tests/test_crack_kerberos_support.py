"""Roasted Kerberos hashes must be crackable from the Credential Store.

Live regression: after KERBEROAST pushed svc_sql's TGS hash to the store,
clicking CRACK -> FAST printed "john doesn't support Kerberos TGS -
skipping".  Cause: neither crack map (_JOHN_FORMAT for FAST/john,
_HASHCAT_MODE for the rule/hybrid/mask strategies) had a key for the
"Kerberos TGS" / "Kerberos AS-REP" hash_type that the GetUserSPNs /
GetNPUsers parsers set — so every strategy skipped.  detect_hash_type
also returned "Unknown" for a pasted $krb5*$ hash, breaking the same path
for manual imports.

The keys here MUST stay byte-identical to the hash_type strings the
parsers assign, or the maps silently miss again.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class CrackMapTests(unittest.TestCase):
    def test_maps_cover_both_kerberos_types(self):
        from utils.crack_runner import _JOHN_FORMAT, _HASHCAT_MODE
        self.assertEqual(_JOHN_FORMAT.get("Kerberos TGS"), "krb5tgs")
        self.assertEqual(_JOHN_FORMAT.get("Kerberos AS-REP"), "krb5asrep")
        self.assertEqual(_HASHCAT_MODE.get("Kerberos TGS"), 13100)
        self.assertEqual(_HASHCAT_MODE.get("Kerberos AS-REP"), 18200)

    def test_dcc2_covered(self):
        from utils.crack_runner import _JOHN_FORMAT, _HASHCAT_MODE
        self.assertEqual(_JOHN_FORMAT.get("DCC2"), "mscash2")
        self.assertEqual(_HASHCAT_MODE.get("DCC2"), 2100)

    def test_every_produced_hash_type_is_crackable(self):
        """Coverage contract: EVERY hash_type string a HAWK parser assigns
        to a stored credential must resolve in BOTH crack maps, or CRACK
        silently skips it (the "john doesn't support …" bug).  This is the
        guard that would have caught Kerberos TGS/AS-REP and DCC2 up front.

        Keep this set in sync with the `hash_type=` assignments in the
        parsers (grep: `hash_type="`).
        """
        from utils.crack_runner import _JOHN_FORMAT, _HASHCAT_MODE
        produced = {"NTLM", "NetNTLMv2", "Kerberos TGS",
                    "Kerberos AS-REP", "DCC2"}
        for ht in produced:
            self.assertIn(ht, _JOHN_FORMAT,
                          f"{ht} is produced by a parser but missing from "
                          f"_JOHN_FORMAT — CRACK/FAST will skip it")
            self.assertIn(ht, _HASHCAT_MODE,
                          f"{ht} is produced by a parser but missing from "
                          f"_HASHCAT_MODE — the hashcat strategies skip it")


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


class DetectHashTypeTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_detects_krb5tgs_and_krb5asrep(self):
        from gui.widgets.credential_store_widget import detect_hash_type
        tgs = ("$krb5tgs$23$*svc_sql$PROVA.PROVA.COM$"
               "MSSQLSvc/host:1433*$aabbccdd")
        asrep = "$krb5asrep$23$svc_asrep@PROVA.PROVA.COM:aabb$ccdd"
        self.assertEqual(detect_hash_type(tgs), "Kerberos TGS")
        self.assertEqual(detect_hash_type(asrep), "Kerberos AS-REP")
        # And those detected types resolve in the crack maps.
        from utils.crack_runner import _JOHN_FORMAT, _HASHCAT_MODE
        self.assertIn(detect_hash_type(tgs), _JOHN_FORMAT)
        self.assertIn(detect_hash_type(asrep), _HASHCAT_MODE)


if __name__ == "__main__":
    unittest.main()
