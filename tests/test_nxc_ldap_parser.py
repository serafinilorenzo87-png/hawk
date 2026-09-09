r"""NetExec `nxc ldap --users --groups` output parser.

nxc >= 1.x prints users and groups as space-aligned TABLES with a dashed
header (`-Username- ...` / `-Group- ...`), not the older bare-name /
"name members: N" form.  The parser had no state for these tables, so
the group-table header (which starts with "-") was skipped and every
group ROW leaked its first token into the USER bucket: a DC with 4 users
and ~50 groups was reported as "39 users, 0 groups", and group names
("Administrators", "Print", "Domain", ...) polluted discovered_users.

The fix switches state on the table headers and parses each row's first
column (multi-word group names kept whole).  These tests lock the real
MS3 (Server 2008 R2 DC) output to the correct split.
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


def _p(payload):
    """Wrap a payload string in nxc's `LDAP <ip> <port> <host>  ` prefix."""
    return ("info",
            f"LDAP        192.168.176.177 389    VAGRANT-2008R2   {payload}")


# The real MS3 output (trimmed to a representative set of the ~50 groups,
# keeping the multi-word ones that exercise the name column).
_NXC_LDAP_LOG = [
    _p("[*] Windows 7 / Server 2008 R2 Build 7601 (name:VAGRANT-2008R2) "
       "(domain:prova.prova.com) (signing:None)"),
    _p(r"[+] prova.prova.com\vagrant:vagrant"),
    _p("VAGRANT-2008R2$"),
    _p("Administrator"),
    _p("vagrant"),
    _p("krbtgt"),
    _p("[*] Enumerated 4 domain users: prova.prova.com"),
    _p("-Username-                    -Last PW Set-       -BadPW-  -Description-"),
    _p("Administrator                 2026-02-21 00:58:16 3        Built-in account for administering the computer/domain"),
    _p("Guest                         <never>             2        Built-in account for guest access to the computer/domain"),
    _p("vagrant                       2026-02-21 00:58:16 0        Vagrant User"),
    _p("krbtgt                        2026-04-13 21:04:28 0        Key Distribution Center Service Account"),
    _p("-Group-                                  -Members- -Description-"),
    _p("Administrators                           4         Administrators have complete and unrestricted access"),
    _p("Users                                    4         Users are prevented from making accidental changes"),
    _p("Print Operators                          0         Members can administer domain printers"),
    _p("Backup Operators                         0         Backup Operators can override security restrictions"),
    _p("Schema Admins                            1         Designated administrators of the schema"),
    _p("Enterprise Admins                        1         Designated administrators of the enterprise"),
    _p("Domain Admins                            1         Designated administrators of the domain"),
    _p("Domain Users                             0         All domain users"),
    _p("Group Policy Creator Owners              1         Members in this group can modify group policy"),
    _p("Pre-Windows 2000 Compatible Access       1         A backward compatibility group which allows read access"),
    _p("Denied RODC Password Replication Group   8         Members in this group cannot have their passwords replicated"),
    _p("DnsAdmins                                0         DNS Administrators Group"),
]

_EXPECTED_USERS = {"VAGRANT-2008R2$", "Administrator", "vagrant",
                   "krbtgt", "Guest"}
_EXPECTED_GROUPS = {
    "Administrators", "Users", "Print Operators", "Backup Operators",
    "Schema Admins", "Enterprise Admins", "Domain Admins", "Domain Users",
    "Group Policy Creator Owners", "Pre-Windows 2000 Compatible Access",
    "Denied RODC Password Replication Group", "DnsAdmins",
}


class NxcLdapTableParserTests(unittest.TestCase):
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
                    cred_store=types.SimpleNamespace(refresh=lambda: None,
                                                     add_credential=lambda c: None),
                    target_intel=types.SimpleNamespace(
                        add_auto_finding=lambda **k: findings.append(k),
                        remove_auto_findings_by_source=lambda *a, **k: 0),
                    terminal=types.SimpleNamespace(
                        write=lambda *a, **k: None,
                        section=lambda *a, **k: None),
                    after=lambda _delay, fn: fn())
                yield parser, sess, findings

    def test_groups_are_not_bucketed_as_users(self):
        with self._parser() as (parser, sess, _):
            parser._parse_nxc_ldap_to_intel(
                types.SimpleNamespace(id="nxc_ldap", name="NETEXEC LDAP"),
                _NXC_LDAP_LOG)
            users = set(sess.discovered_users)
            # The five real principals, and ONLY those.
            self.assertEqual(_EXPECTED_USERS, users,
                             f"user bucket polluted / incomplete: {users}")
            # None of the group names leaked in as users.
            for leaked in ("Administrators", "Print", "Domain",
                           "Schema", "Enterprise", "DnsAdmins"):
                self.assertNotIn(leaked, users,
                                 f"group name '{leaked}' leaked into users")

    def test_groups_are_parsed_with_multiword_names(self):
        with self._parser() as (parser, sess, _):
            parser._parse_nxc_ldap_to_intel(
                types.SimpleNamespace(id="nxc_ldap", name="NETEXEC LDAP"),
                _NXC_LDAP_LOG)
            groups = set(sess.discovered_groups)
            self.assertEqual(_EXPECTED_GROUPS, groups,
                             f"groups mis-parsed: {groups}")
            # Multi-word names kept whole, not split at the first space.
            self.assertIn("Print Operators", groups)
            self.assertIn("Pre-Windows 2000 Compatible Access", groups)

    def test_finding_has_stable_title_and_counts_in_description(self):
        with self._parser() as (parser, sess, findings):
            parser._parse_nxc_ldap_to_intel(
                types.SimpleNamespace(id="nxc_ldap", name="NETEXEC LDAP"),
                _NXC_LDAP_LOG)
            self.assertEqual(1, len(findings))
            f = findings[0]
            # Title is STABLE (target only, no counts) + replace=True so
            # re-runs merge into one badge-counted finding instead of
            # spawning a new one whenever the counts change.
            self.assertTrue(f["title"].startswith("NXC LDAP"))
            self.assertIn("192.168.176.177", f["title"])
            self.assertNotIn("users", f["title"])
            self.assertTrue(f.get("replace"))
            # Counts moved to the description.
            self.assertIn("5", f["description"])
            self.assertIn("12", f["description"])

    def test_finding_lists_all_users_beyond_the_old_20_cap(self):
        """The finding must show the WHOLE enumeration (it is expandable),
        not a 20-line teaser: on a real DC the operator needs every
        account, not just the first 20."""
        log = [
            _p("[*] Windows 7 / Server 2008 R2 (domain:prova.prova.com)"),
            _p(r"[+] prova.prova.com\vagrant:vagrant"),
        ] + [_p(f"user{i:02d}") for i in range(1, 26)]
        with self._parser() as (parser, sess, findings):
            parser._parse_nxc_ldap_to_intel(
                types.SimpleNamespace(id="nxc_ldap", name="NETEXEC LDAP"),
                log)
            self.assertEqual(25, len(sess.discovered_users))
            desc = findings[0]["description"]
            # user25 was hidden by the old cap of 20; it must show now.
            self.assertIn("user25", desc)
            self.assertIn("user01", desc)


if __name__ == "__main__":
    unittest.main()
