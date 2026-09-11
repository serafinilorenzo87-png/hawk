"""GPP-DECRYPT parser.

A decrypted SYSVOL GPP cpassword is a high-value credential: it is almost
always a LOCAL-admin password pushed identically to every machine by the
same GPO (MS14-025), i.e. domain-wide lateral-movement fuel.  The parser
must therefore push it to the Credential Store AND raise a HIGH finding
instead of leaving it in the terminal for the generic low-info fallback.
The optional account name comes from the dialog (it is not in
gpp-decrypt's output).  A malformed blob that yields no plaintext must
fall through to the generic fallback.
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


# gpp-decrypt prints just the cleartext password after the command echo.
_OK = [
    "$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhUoDPE",
    "Local*P4ssword!",
]
# A malformed blob yields no usable plaintext.
_BAD = [
    "$ gpp-decrypt notarealblob",
    "Traceback (most recent call last):",
    "ValueError: Invalid base64-encoded string",
]


def _run(log, username=""):
    from gui.widgets.card_parsers_ad import CardADParserMixin

    findings, creds = [], []

    class Host(CardADParserMixin):
        def __init__(self):
            self.phase_id = "ad_pentesting"
            self._gpp_username = username
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
        name="GPP-DECRYPT (Groups.xml)", binary="gpp-decrypt",
        id="gpp_decrypt")
    claimed = Host()._parse_gpp_decrypt_to_intel(
        tool, [("out", ln) for ln in log])
    return claimed, findings, creds


class GppDecryptParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_recovered_password_is_high_finding_and_credential(self):
        claimed, findings, creds = _run(_OK, username="Administrator")
        self.assertTrue(claimed, "parser must CLAIM a decrypted cpassword, "
                        "not fall through to the generic info dump")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("Administrator", f["title"])
        self.assertIn("Local*P4ssword!", f["description"])
        self.assertIn("--local-auth", f["description"])   # spray runbook
        self.assertTrue(f["linked_run_id"])
        # Credential captured with the supplied account name.
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0].username, "Administrator")
        self.assertEqual(creds[0].password, "Local*P4ssword!")

    def test_blank_username_still_captures_the_secret(self):
        claimed, findings, creds = _run(_OK, username="")
        self.assertTrue(claimed)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0].password, "Local*P4ssword!")
        # Finding <-> credential linkage stays intact for the CRED button.
        self.assertEqual(findings[0]["linked_run_id"],
                         creds[0].linked_run_id)

    def test_malformed_blob_falls_through_to_fallback(self):
        claimed, findings, creds = _run(_BAD)
        self.assertFalse(claimed, "a blob that yields no plaintext must let "
                         "the generic fallback handle it")
        self.assertEqual(findings, [])
        self.assertEqual(creds, [])


if __name__ == "__main__":
    unittest.main()
