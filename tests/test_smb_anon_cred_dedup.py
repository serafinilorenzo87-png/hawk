"""The anonymous SMB credential must be added through the Credential
Store (which normalises password ""→"anonymous" and dedups), NOT via a
bare Session.add_credential.

The "Step 4b" placeholder path used sess.add_credential with password="",
which never matched the store-normalised "anonymous/anonymous" row — so
re-running SMBCLIENT List stacked a duplicate anonymous credential on
every pass.  Both anon-cred write paths must now route through
cred_store.add_credential.
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


# Real Metasploitable2 anonymous smbclient -L output.
_SMB_ANON_LOG = [
    ("info", "Anonymous login successful"),
    ("info", "Sharename       Type      Comment"),
    ("info", "---------       ----      -------"),
    ("info", "print$          Disk      Printer Drivers"),
    ("info", "tmp             Disk      oh noes!"),
    ("info", "opt             Disk"),
    ("info", "IPC$            IPC       IPC Service"),
    ("info", "ADMIN$          IPC       IPC Service"),
]


class SmbAnonCredRoutingTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _run(self):
        from gui.widgets.card_parsers_post import CardPostParserMixin

        sess = _Recorder()
        store = _Recorder()

        class Host(CardPostParserMixin):
            def __init__(self):
                self.phase_id = "enumeration"
                self._tool_widgets = {
                    "smbclient_list": {
                        "_last_cmd":
                        "smbclient -L //192.168.177.134 -p 445 -N"}}
                self.app = types.SimpleNamespace(
                    session_manager=types.SimpleNamespace(current=sess),
                    cred_store=store,
                    target_intel=types.SimpleNamespace(
                        add_auto_finding=lambda **k: None,
                        remove_auto_findings_by_source=lambda *a, **k: 0),
                    terminal=_Terminal())

            def _get_target(self):
                return "192.168.177.134"

            def _strip_ansi(self, s):
                return s

        tool = types.SimpleNamespace(
            name="SMBCLIENT List", binary="smbclient", id="smbclient_list")
        Host()._parse_smb_output(tool, _SMB_ANON_LOG)
        return sess, store

    def test_anon_cred_goes_through_store_not_session(self):
        sess, store = self._run()
        anon_in_store = [c for c in store.added
                         if (c.username or "").lower() == "anonymous"]
        anon_in_sess = [c for c in sess.added
                        if (c.username or "").lower() == "anonymous"]
        self.assertTrue(anon_in_store,
                        "anon cred must go through the Credential Store")
        self.assertEqual(anon_in_sess, [],
                         "anon cred must NOT bypass the store via "
                         "sess.add_credential (that stacked duplicates)")


if __name__ == "__main__":
    unittest.main()
