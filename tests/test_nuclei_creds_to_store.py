r"""nuclei default-login / weak-cred matches must reach the Credential Store.

nuclei confirms a working login via its template extractors (e.g.
postgres-default-logins -> postgres:postgres on :5432), but those creds
only ever landed in a Target Intel card — never in the Credential Store,
so Hydra/Connect pickers and the report never saw them.  The nuclei
parser now mirrors the JWT analyzer: it extracts the login from the
match text and pushes a verified credential, linked to the finding.

Extractor text varies per template, so extraction is exercised across
the shapes nuclei actually prints.
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
    def write(self, *a, **k):
        pass

    def section(self, *a, **k):
        pass


class _CredRec:
    def __init__(self):
        self.added = []

    def add_credential(self, cred):
        self.added.append(cred)


def _mixin():
    from gui.widgets.card_parsers_web import CardWebParserMixin
    return CardWebParserMixin


def _run(log_lines):
    """Drive _parse_nuclei_to_intel with a stub host; return (store, findings)."""
    CardWebParserMixin = _mixin()
    store = _CredRec()
    findings = []

    class Host(CardWebParserMixin):
        def __init__(self):
            self.phase_id = "web_recon"
            self.app = types.SimpleNamespace(
                after=lambda _delay, fn: fn(),
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                cred_store=store,
                terminal=_Terminal())

        # Helpers that live on sibling mixins in the real app.
        def _get_target(self):
            return "192.168.177.134"

        def _extract_web_target_label(self, tool):
            return "http://192.168.177.134"

        def _is_ascii_banner_line(self, line):
            return False

    tool = types.SimpleNamespace(name="nuclei")
    log = [(None, ln) for ln in log_lines]
    ok = CardWebParserMixin._parse_nuclei_to_intel(Host(), tool, log)
    return ok, store, findings


class NucleiExtractorTests(unittest.TestCase):
    """The pure extractor, across the formats nuclei prints."""

    def setUp(self):
        self._old = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        self.ex = _mixin()._extract_nuclei_creds

    def tearDown(self):
        if self._old is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old

    def test_quoted_key_value_pairs(self):
        c = self.ex("postgres-default-logins", "js",
                    "192.168.177.134:5432",
                    'usernames="postgres",passwords="postgres"')
        self.assertEqual(c, [{"username": "postgres", "password": "postgres",
                              "service": "PostgreSQL", "port": 5432,
                              "db": ""}])

    def test_unquoted_comma_key_value_pairs(self):
        c = self.ex("postgres-default-logins", "js",
                    "192.168.177.134:5432",
                    "database=postgres,password=postgres,usernames=postgres")
        self.assertEqual(len(c), 1)
        self.assertEqual((c[0]["username"], c[0]["password"]),
                         ("postgres", "postgres"))
        self.assertEqual(c[0]["db"], "postgres")   # database=... captured

    def test_bare_user_pass_pair_for_cred_template(self):
        c = self.ex("mysql-default-login", "network",
                    "192.168.177.134:3306", "root:root")
        self.assertEqual(c, [{"username": "root", "password": "root",
                              "service": "MySQL", "port": 3306, "db": ""}])

    def test_password_only_falls_back_to_service_default_user(self):
        # No port in the URL -> service default (5432); no user -> postgres.
        c = self.ex("postgres-default-logins", "js",
                    "http://192.168.177.134", 'passwords="postgres"')
        self.assertEqual(c, [{"username": "postgres", "password": "postgres",
                              "service": "PostgreSQL", "port": 5432,
                              "db": ""}])

    def test_url_port_overrides_service_default(self):
        c = self.ex("postgres-default-logins", "js",
                    "postgres://192.168.177.134:6543",
                    "usernames=postgres,passwords=postgres")
        self.assertEqual(c[0]["port"], 6543)

    def test_multiple_pairs_zip_index_wise(self):
        c = self.ex("mysql-default-login", "network", "h:3306",
                    'usernames="admin,root",passwords="admin,toor"')
        self.assertEqual(
            [(x["username"], x["password"]) for x in c],
            [("admin", "admin"), ("root", "toor")])

    def test_version_noise_is_not_a_credential(self):
        # tech-detect is not a cred template; "nginx:1.18" must not parse.
        self.assertEqual(
            self.ex("tech-detect", "http", "http://h/", "nginx:1.18"), [])

    def test_non_cred_key_value_is_ignored(self):
        self.assertEqual(
            self.ex("some-detect", "http", "http://h/", "version=1.2.3"), [])

    def test_no_match_text_yields_nothing(self):
        self.assertEqual(
            self.ex("exposed-git", "http", "http://h/.git/config", ""), [])


class NucleiCredStorePushTests(unittest.TestCase):
    """End-to-end: a default-login line pushes a verified, linked cred."""

    def setUp(self):
        self._old = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old

    def test_postgres_default_login_reaches_store_as_verified(self):
        line = ('[postgres-default-logins] [js] [high] '
                '192.168.177.134:5432 '
                '[usernames="postgres",passwords="postgres"]')
        ok, store, findings = _run([line])
        self.assertTrue(ok)
        self.assertEqual(len(store.added), 1)
        c = store.added[0]
        self.assertEqual(c.username, "postgres")
        self.assertEqual(c.password, "postgres")
        self.assertEqual(c.cred_type, "cleartext")
        self.assertIn("PostgreSQL", c.services)
        self.assertEqual(c.host, "192.168.177.134")
        self.assertTrue(c.verified)
        self.assertTrue(c.linked_run_id)

    def test_credential_is_linked_to_the_finding(self):
        line = ('[postgres-default-logins] [js] [high] '
                '192.168.177.134:5432 [postgres:postgres]')
        _, store, findings = _run([line])
        self.assertEqual(len(store.added), 1)
        self.assertTrue(findings, "expected a Target Intel card")
        rid = store.added[0].linked_run_id
        self.assertEqual(findings[0].get("linked_run_id"), rid)

    def test_non_cred_findings_push_no_credentials(self):
        line = "[tech-detect:nginx] [http] [info] http://192.168.177.134/ [nginx]"
        _, store, findings = _run([line])
        self.assertEqual(store.added, [])
        self.assertTrue(findings)
        self.assertEqual(findings[0].get("linked_run_id"), "")

    def test_same_credential_seen_twice_pushes_once(self):
        lines = [
            '[postgres-default-logins] [js] [high] 192.168.177.134:5432 '
            '[postgres:postgres]',
            '[postgres-default-logins] [js] [high] 192.168.177.134:5432 '
            '[usernames="postgres",passwords="postgres"]',
        ]
        _, store, _ = _run(lines)
        self.assertEqual(len(store.added), 1, "in-run dedup by identity")


if __name__ == "__main__":
    unittest.main()
