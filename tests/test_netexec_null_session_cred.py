r"""netexec's default null session (`-u '' -p ''`) must be treated as
anonymous, NOT as an authenticated run for a user literally named ''.

The auth-mode sniffer read the username off the command line with a
`-u` regex whose quoted branches required >=1 char (`'([^']+)'`), so the
empty `''` fell through to the `(\S+)` fallback and captured the literal
two-char token "''".  That misfiled the anonymous bind as an
authenticated run: it pushed a bogus `''` credential (verified=False) to
the session and raised a "SMB Authenticated Access -- ''@host" finding,
duplicating the real anonymous access already in the store.

Fix: the `-u` regex now uses `*` inside the quotes (mirroring `-p`), so
`-u ''` matches with an empty capture -> auth_user="" -> anonymous path.
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


class _Recorder:
    """Stub that records the credentials it is asked to add."""
    def __init__(self):
        self.added = []
        self.credentials = []

    def add_credential(self, cred):
        self.added.append(cred)

    def get_credentials(self):
        return []

    def refresh(self):
        pass

    def save(self):
        pass

    def _touch(self):
        pass


# netexec smb ... --shares over a real null session: the [+] domain line
# then a share table netexec prints as "SMB <ip> 445 <host> <share> READ".
# No "Pwn3d!" and no "Anonymous login successful" marker.
_NXC_NULL_LOG = [
    ("info", "SMB  192.168.177.134  445  METASPLOITABLE  [+] localdomain\\:"),
    ("info", "SMB  192.168.177.134  445  METASPLOITABLE  [*] Enumerated shares"),
    ("info", "SMB  192.168.177.134  445  METASPLOITABLE  Share  Permissions  Remark"),
    ("info", "SMB  192.168.177.134  445  METASPLOITABLE  -----  -----------  ------"),
    ("info", "SMB  192.168.177.134  445  METASPLOITABLE  tmp    READ         oh noes!"),
]

_NXC_AUTH_LOG = [
    ("info", "SMB  192.168.177.134  445  METASPLOITABLE  [+] localdomain\\msfadmin:msfadmin (Pwn3d!)"),
    ("info", "SMB  192.168.177.134  445  METASPLOITABLE  tmp    READ,WRITE   oh noes!"),
]


def _run(cmd, log):
    """Drive _parse_smb_output for a netexec run and return the host stub."""
    from gui.widgets.card_parsers_post import CardPostParserMixin

    findings = []
    sess = _Recorder()
    store = _Recorder()

    class Host(CardPostParserMixin):
        def __init__(self):
            self.phase_id = "enumeration"
            self._tool_widgets = {"netexec": {"_last_cmd": cmd}}
            self.app = types.SimpleNamespace(
                session_manager=types.SimpleNamespace(current=sess),
                cred_store=store,
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k),
                    remove_auto_findings_by_source=lambda *a, **k: 0),
                terminal=_Terminal())

        def _get_target(self):
            return "192.168.177.134"

        def _strip_ansi(self, s):
            return s

    tool = types.SimpleNamespace(
        name="NETEXEC (CME)", binary="netexec", id="netexec")
    Host()._parse_smb_output(tool, log)
    return sess, store, findings


class NetexecNullSessionTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_null_session_is_not_a_literal_quote_username(self):
        sess, store, _ = _run(
            "netexec smb 192.168.177.134 --port 445 -u '' -p '' --shares",
            _NXC_NULL_LOG)
        bogus = [c for c in (sess.added + store.added)
                 if (c.username or "").strip() in ("''", '""', "'", '"')]
        self.assertEqual(
            bogus, [],
            "null session must not create a credential whose username is "
            "the literal quote token")

    def test_null_session_routes_to_anonymous(self):
        _, store, findings = _run(
            "netexec smb 192.168.177.134 --port 445 -u '' -p '' --shares",
            _NXC_NULL_LOG)
        anon = [c for c in store.added
                if (c.username or "").lower() == "anonymous"]
        self.assertTrue(
            anon, "null session with a share listing must push the "
            "anonymous credential through the store")
        titles = [f.get("title", "") for f in findings]
        self.assertFalse(
            any(t.startswith("SMB Authenticated Access") for t in titles),
            "null session must not raise an 'SMB Authenticated Access' "
            f"finding; got {titles}")

    def test_real_authenticated_run_still_harvests_the_cred(self):
        # Regression guard: a genuine -u user -p pass run must still be
        # recognised as authenticated and harvest that user's credential.
        # It is routed through the credential STORE (so a new cred blinks
        # and no "pushed" line prints on a dedup no-op), not
        # sess.add_credential.
        sess, store, findings = _run(
            "netexec smb 192.168.177.134 --port 445 -u msfadmin "
            "-p msfadmin --shares",
            _NXC_AUTH_LOG)
        harvested = [c for c in store.added
                     if (c.username or "") == "msfadmin"]
        self.assertTrue(
            harvested,
            "an authenticated netexec run must push its credential "
            "through the store")
        self.assertTrue(harvested[0].verified,
                        "a Pwn3d! login must be stored verified")
        titles = [f.get("title", "") for f in findings]
        self.assertTrue(
            any(t.startswith("SMB Authenticated Access") for t in titles),
            f"authenticated run must raise the auth finding; got {titles}")


if __name__ == "__main__":
    unittest.main()
