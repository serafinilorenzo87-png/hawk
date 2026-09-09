r"""Kerbrute output parser (_parse_kerbrute_to_intel).

A kerbrute `userenum` VALID USERNAME line proves an account EXISTS — it
carries no password and no hash.  The parser used to push each such
username into the Credential Store as an empty cleartext stub, cluttering
the store with credentials that had nothing to spray or crack.  Those
belong in Target Intel (discovered users), not the store.

A `passwordspray` / `bruteuser` VALID LOGIN line, by contrast, IS a real
secret (Kerberos pre-auth succeeded with that password) and correctly
lands in the store, verified.

These tests lock that split.
"""

import os
import sys
import types
import unittest
import tempfile
from contextlib import contextmanager
from unittest.mock import patch

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


class _Recorder:
    def __init__(self):
        self.added = []

    def add_credential(self, cred):
        self.added.append(cred)

    def refresh(self):
        pass


_USERENUM_LOG = [
    ("out", "2026/09/09 19:57:58 >  Using KDC(s):"),
    ("out", "2026/09/09 19:57:58 >  [+] VALID USERNAME:\t "
            "administrator@prova.prova.com"),
    ("out", "2026/09/09 19:57:58 >  [+] VALID USERNAME:\t "
            "vagrant@prova.prova.com"),
    ("out", "2026/09/09 19:57:59 >  Done! Tested 6 usernames (2 valid)"),
]

_SPRAY_LOG = [
    ("out", "2026/09/09 20:01:00 >  [+] VALID LOGIN:\t "
            "svc_test@prova.prova.com:Summer2026!"),
]


class KerbruteParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    @contextmanager
    def _parser(self, mode="userenum"):
        from utils.session import Session
        from gui.widgets.card_parsers_service import CardServiceParserMixin

        class _Parser(CardServiceParserMixin):
            phase_id = "enumeration"

            def _get_target(self):
                return "192.168.176.177"

            def _strip_ansi(self, s):
                return s

        with tempfile.TemporaryDirectory() as d:
            with patch("utils.session.is_within_base", return_value=True), \
                 patch("utils.config.is_within_base", return_value=True):
                sess = Session("192.168.176.177")
                sess.file_path = os.path.join(d, "sess.json")
                findings = []
                parser = _Parser()
                parser._kerbrute_ctx = {
                    "realm": "prova.prova.com",
                    "dc": "192.168.176.177", "mode": mode}
                parser.app = types.SimpleNamespace(
                    session_manager=types.SimpleNamespace(current=sess),
                    cred_store=_Recorder(),
                    target_intel=types.SimpleNamespace(
                        add_auto_finding=lambda **k: findings.append(k)),
                    terminal=types.SimpleNamespace(
                        write=lambda *a, **k: None),
                    after=lambda _delay, fn: fn())
                yield parser, sess, parser.app.cred_store, findings

    def test_userenum_records_users_not_credentials(self):
        with self._parser("userenum") as (parser, sess, store, findings):
            tool = types.SimpleNamespace(id="kerbrute_userenum",
                                         name="KERBRUTE Users",
                                         binary="kerbrute")
            parser._parse_kerbrute_to_intel(tool, _USERENUM_LOG)

            # Users landed in Target Intel / session, as discovered users.
            users = [u.lower() for u in sess.discovered_users]
            self.assertIn("administrator", users)
            self.assertIn("vagrant", users)

            # NOTHING was pushed to the Credential Store — a VALID USERNAME
            # has no password/hash, so an empty stub would be useless.
            self.assertEqual(
                [], store.added,
                "userenum must not push empty username stubs to the store")

            # A finding summarises the run.
            self.assertEqual(1, len(findings))
            self.assertIn("2 users", findings[0]["title"])
            self.assertIn("0 logins", findings[0]["title"])

    def test_valid_login_still_lands_in_the_store_verified(self):
        with self._parser("passwordspray") as (parser, sess, store, findings):
            tool = types.SimpleNamespace(id="kerbrute_userenum",
                                         name="KERBRUTE Users",
                                         binary="kerbrute")
            parser._parse_kerbrute_to_intel(tool, _SPRAY_LOG)

            self.assertEqual(1, len(store.added),
                             "a VALID LOGIN must be stored as a credential")
            cred = store.added[0]
            self.assertEqual("svc_test", cred.username)
            self.assertEqual("Summer2026!", cred.password)
            self.assertTrue(cred.verified,
                            "a kerbrute VALID LOGIN is a proven password")


if __name__ == "__main__":
    unittest.main()
