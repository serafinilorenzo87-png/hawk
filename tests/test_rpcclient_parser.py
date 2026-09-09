r"""rpcclient batch output through the shared enum4linux/rpcclient parser
(_parse_enum4linux_to_intel).

The parser's regexes were written for enum4linux-ng output, so an
authenticated `rpcclient -c 'srvinfo;enumdomusers;enumdomgroups;
netshareenumall;getdompwinfo;...'` run had its users parsed but its
GROUPS (group:[name] rid:[..]), SHARES (netname:/remark:) and PASSWORD
POLICY (min_password_length:) silently dropped — the finding showed only
the SID + users, and discovered_shares/groups stayed empty.  The srvinfo
"os version : 6.1" line was also mis-captured as os_info="version : 6.1".

These tests feed the real MS3 rpcclient batch and lock the full parse.
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


_RPC_LOG = [("out", ln) for ln in [
    "192.168.176.177Wk Sv PDC Tim NT",
    "platform_id     :\t500",
    "os version      :\t6.1",
    "server type     :\t0x280102b",
    "Domain Name: PROVA",
    "Domain Sid: S-1-5-21-1142370083-1635491856-2103976639",
    "min_password_length: 7",
    "password_properties: 0x00000001",
    "DOMAIN_PASSWORD_COMPLEX",
    "user:[Administrator] rid:[0x1f4]",
    "user:[Guest] rid:[0x1f5]",
    "user:[krbtgt] rid:[0x1f6]",
    "user:[vagrant] rid:[0x3e8]",
    "group:[Domain Admins] rid:[0x200]",
    "group:[Enterprise Admins] rid:[0x207]",
    "group:[Group Policy Creator Owners] rid:[0x208]",
    "group:[Print Operators] rid:[0x226]",
    "netname: ADMIN$",
    "remark:\tRemote Admin",
    "path:\tC:\\Windows",
    "password:\t(null)",
    "netname: CertEnroll",
    "remark:\tActive Directory Certificate Services share",
    "path:\tC:\\Windows\\system32\\CertSrv\\CertEnroll",
    "password:\t(null)",
    "netname: SYSVOL",
    "remark:\tLogon server share",
    "password:\t(null)",
    "found 34 privileges",
    "SeImpersonatePrivilege \t\t0:29 (0x0:0x1d)",
]]


class RpcclientBatchParserTests(unittest.TestCase):
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
        from gui.widgets.card_parsers_service import CardServiceParserMixin

        class _Parser(CardServiceParserMixin):
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
                        add_auto_finding=lambda **k: findings.append(k),
                        remove_auto_findings_by_source=lambda *a, **k: 0),
                    terminal=types.SimpleNamespace(write=lambda *a, **k: None),
                    after=lambda _delay, fn: fn())
                yield parser, sess, findings

    def _tool(self):
        return types.SimpleNamespace(id="rpcclient", name="RPCCLIENT",
                                     binary="rpcclient")

    def test_users_groups_shares_all_captured(self):
        with self._parser() as (parser, sess, findings):
            self.assertTrue(parser._parse_enum4linux_to_intel(
                self._tool(), _RPC_LOG))
            users = {u.lower() for u in sess.discovered_users}
            for u in ("administrator", "guest", "krbtgt", "vagrant"):
                self.assertIn(u, users)
            groups = set(sess.discovered_groups)
            for g in ("Domain Admins", "Enterprise Admins",
                      "Group Policy Creator Owners", "Print Operators"):
                self.assertIn(g, groups)
            shares = {s.lower() for s in sess.discovered_shares}
            for s in ("admin$", "certenroll", "sysvol"):
                self.assertIn(s, shares)

    def test_finding_has_groups_shares_policy_and_no_priv_misattribution(self):
        with self._parser() as (parser, sess, findings):
            parser._parse_enum4linux_to_intel(self._tool(), _RPC_LOG)
            self.assertEqual(1, len(findings))
            f = findings[0]
            self.assertTrue(f["title"].startswith("RPCCLIENT on"))
            desc = f["description"]
            self.assertIn("Domain Admins", desc)          # groups section
            self.assertIn("ADMIN$", desc)                 # shares section
            self.assertIn("CertEnroll", desc)
            self.assertIn("min length 7", desc)           # password policy
            # The 34 enumprivs are the domain's SUPPORTED privileges, not
            # vagrant's — they must NOT be attributed to the user.
            self.assertNotIn("SeImpersonate", desc)
            # srvinfo "os version : 6.1" must not leak as a mangled OS line.
            self.assertNotIn("version :", desc)


if __name__ == "__main__":
    unittest.main()
