r"""ldapsearch LDIF parser (_parse_ldapsearch_to_intel).

The parser classified each LDIF record by its objectClass — but the
preset queries don't request objectClass ("All Users" asks only for
sAMAccountName/mail/displayName/memberOf), so every record fell through
unclassified, `total` was 0, and the parser returned without producing
ANY Target Intel finding: a successful "All Users" run showed nothing.

The parser now infers the record type from the attributes actually
present (sAMAccountName -> user, a trailing '$' or dNSHostName ->
computer, a bare cn -> group) and splits records on `dn:` (some servers
separate entries with only a `# comment`, not a blank line).  The
summary finding also uses a stable title so re-runs update one finding.
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


# The real MS3 "All Users" output: no objectClass requested, records
# separated by "# comment" lines rather than blank lines.
_LDIF_ALLUSERS = [("out", ln) for ln in [
    "# extended LDIF",
    "#",
    "# base <DC=prova,DC=prova,DC=com> with scope subtree",
    "# filter: (objectClass=user)",
    "# requesting: sAMAccountName mail displayName memberOf",
    "#",
    "# Administrator, Users, prova.prova.com",
    "dn: CN=Administrator,CN=Users,DC=prova,DC=prova,DC=com",
    "memberOf: CN=Domain Admins,CN=Users,DC=prova,DC=prova,DC=com",
    "sAMAccountName: Administrator",
    "# Guest, Users, prova.prova.com",
    "dn: CN=Guest,CN=Users,DC=prova,DC=prova,DC=com",
    "memberOf: CN=Guests,CN=Builtin,DC=prova,DC=prova,DC=com",
    "sAMAccountName: Guest",
    "# vagrant, Users, prova.prova.com",
    "dn: CN=vagrant,CN=Users,DC=prova,DC=prova,DC=com",
    "displayName: vagrant",
    "sAMAccountName: vagrant",
    "# VAGRANT-2008R2, Domain Controllers, prova.prova.com",
    "dn: CN=VAGRANT-2008R2,OU=Domain Controllers,DC=prova,DC=prova,DC=com",
    "sAMAccountName: VAGRANT-2008R2$",
    "# krbtgt, Users, prova.prova.com",
    "dn: CN=krbtgt,CN=Users,DC=prova,DC=prova,DC=com",
    "sAMAccountName: krbtgt",
    "# search result",
    "search: 2",
    "result: 0 Success",
]]


class LdapsearchParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    @contextmanager
    def _parser(self):
        from utils.session import Session
        from gui.widgets.card_parsers_ad import CardADParserMixin

        class _Parser(CardADParserMixin):
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
                parser.app = types.SimpleNamespace(
                    session_manager=types.SimpleNamespace(current=sess),
                    target_intel=types.SimpleNamespace(
                        add_auto_finding=lambda **k: findings.append(k)),
                    terminal=types.SimpleNamespace(write=lambda *a, **k: None),
                    after=lambda _delay, fn: fn())
                yield parser, sess, findings

    def test_all_users_without_objectclass_produces_a_finding(self):
        with self._parser() as (parser, sess, findings):
            ok = parser._parse_ldapsearch_to_intel(
                types.SimpleNamespace(id="ldapsearch", name="LDAPSEARCH",
                                      binary="ldapsearch"),
                _LDIF_ALLUSERS)
            self.assertTrue(ok, "parser returned False on valid All Users LDIF")
            main = [f for f in findings
                    if f["title"].startswith("LDAP Enumeration")]
            self.assertEqual(1, len(main),
                             "no LDAP enumeration finding was produced")
            desc = main[0]["description"]
            # The four real users are classified as users...
            for u in ("Administrator", "Guest", "vagrant", "krbtgt"):
                self.assertIn(u, desc)
            # ...and the machine account is a computer, not a user.
            self.assertIn("VAGRANT-2008R2$", desc)

    def test_summary_finding_title_is_stable(self):
        with self._parser() as (parser, sess, findings):
            parser._parse_ldapsearch_to_intel(
                types.SimpleNamespace(id="ldapsearch", name="LDAPSEARCH",
                                      binary="ldapsearch"),
                _LDIF_ALLUSERS)
            main = [f for f in findings
                    if f["title"].startswith("LDAP Enumeration")][0]
            # Stable title (target only) + replace so re-runs badge.
            self.assertIn("192.168.176.177", main["title"])
            self.assertNotIn("objects", main["title"])
            self.assertTrue(main.get("replace"))


if __name__ == "__main__":
    unittest.main()
