"""Import + construct smoke test for HAWK's dialogs.

Four of the audit's criticals were a single undefined symbol on a normal
path — `_btn(border=...)`, `self._autosize`, `_BHCE_SETUP_STEPS`,
`anon_access`.  None of them is visible by re-reading the code, and each
one killed a feature the moment the operator clicked it.  What they have
in common is that simply *building* the widget tree raises.

So: build every dialog we can reach with a cheap fake app, and assert
nothing raises.  The dialogs are never shown — the root is withdrawn and
destroyed in tearDown.

Not covered here (needs a live session, a running tool or network I/O,
not a fake parent): the Greenbone family, the BloodHound graph window,
the crack-progress/strategy dialogs, and the privesc guides.  Those keep
their own coverage elsewhere; this file is about construction crashes.
"""

import os
import sys
import types
import unittest

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Headless environments have no customtkinter / no display: skip the
# module instead of aborting collection for the whole suite.
ctk = pytest.importorskip("customtkinter")


class _Terminal:
    def __init__(self):
        self.lines = []

    def write(self, message, style=None):
        self.lines.append((message, style))


class _CredStore:
    def __init__(self):
        self.added = []

    def add_credential(self, cred):
        self.added.append(cred)

    def refresh(self):
        pass


class _TargetIntel:
    def __init__(self):
        self.findings = []

    def add_auto_finding(self, title, description, severity=None,
                         source=None, **kw):
        self.findings.append((title, severity, source))


def _fake_app(session=None):
    return types.SimpleNamespace(
        terminal=_Terminal(),
        session_manager=types.SimpleNamespace(current=session),
        cred_store=_CredStore(),
        target_intel=_TargetIntel(),
    )


def _a_tool(tool_id=None):
    """A real Tool out of the registry — dialogs read .name/.desc/
    .cmd_template and call .build_command()."""
    from modules.post_exploit import PostExploitModule
    from modules.lateral import LateralModule
    for mod in (PostExploitModule, LateralModule):
        for tool in mod.TOOLS:
            if tool_id is None or tool.id == tool_id:
                return tool
    raise AssertionError(f"tool {tool_id!r} not in the registry")


class _TkTestCase(unittest.TestCase):
    def setUp(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        self.root = ctk.CTk()
        self.root.withdraw()
        self.app = _fake_app()

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass


class DialogConstructionTests(_TkTestCase):
    """Each case builds one dialog and asserts it comes up."""

    def _cases(self):
        from gui import dialogs_core as dc
        from gui import dialogs_ops as do
        from gui import dialogs_bloodhound as db
        from gui.payload_dialog import PayloadSelectorDialog
        from utils.session import Credential

        parent = self.root
        tool = _a_tool()
        cred = Credential(username="admin", password="pass",
                          cred_type="cleartext", host="10.10.10.10")

        return [
            # X3 — the payload selector could not open at all.
            ("PayloadSelectorDialog",
             lambda: PayloadSelectorDialog(parent)),
            ("PayloadSelectorDialog(compatible)",
             lambda: PayloadSelectorDialog(
                 parent, compatible_payloads=[
                     "windows/x64/meterpreter/reverse_tcp"],
                 exploit_name="exploit/windows/smb/ms17_010_eternalblue")),
            # X4 — the BH CE setup guide raised NameError on every open.
            ("show_bloodhound_ce_setup_dialog",
             lambda: db.show_bloodhound_ce_setup_dialog(parent)),
            ("_show_graph_missing_deps",
             lambda: db._show_graph_missing_deps(parent, "no networkx")),
            ("_show_graph_empty",
             lambda: db._show_graph_empty(parent)),
            # The rest of the family, same construction risk.
            ("LhostDialog",
             lambda: dc.LhostDialog(parent)),
            ("NonStandardPortDialog",
             lambda: dc.NonStandardPortDialog(
                 parent, "http", 8080, "10.10.10.10", self.app)),
            ("OsAmbiguousDialog",
             lambda: dc.OsAmbiguousDialog(
                 parent,
                 types.SimpleNamespace(
                     os_candidates=["Windows Server 2008 R2", "Windows 7"],
                     confidence=42),
                 "10.10.10.10")),
            ("AccessGateDialog",
             lambda: dc.AccessGateDialog(parent, "Exploitation")),
            ("PermissionDialog",
             lambda: dc.PermissionDialog(parent, tool, {"name": "Recon"})),
            ("NmapCustomDialog",
             lambda: dc.NmapCustomDialog(parent, tool)),
            ("RustscanCustomDialog",
             lambda: dc.RustscanCustomDialog(parent, tool)),
            ("ApiKeyManagerDialog",
             lambda: dc.ApiKeyManagerDialog(parent)),
            ("MetasploitDialog",
             lambda: dc.MetasploitDialog(parent, tool)),
            ("BruteForceDialog",
             lambda: dc.BruteForceDialog(parent, tool)),
            ("WAFEvasionDialog",
             lambda: dc.WAFEvasionDialog(parent, "10.10.10.10", self.app)),
            ("WordlistCheckDialog",
             lambda: dc.WordlistCheckDialog(parent, "/usr/share/x.txt")),
            ("DomainSuggestionDialog",
             lambda: dc.DomainSuggestionDialog(
                 parent, "corp.local", "nmap", 80, "smb-os-discovery")),
            ("HashCrackDialog",
             lambda: do.HashCrackDialog(parent, cred, 0)),
            ("NoPortsFoundDialog",
             lambda: do.NoPortsFoundDialog(parent, "nmap", "10.10.10.10")),
            ("QuickServiceProbeDialog",
             lambda: do.QuickServiceProbeDialog(
                 parent, "10.10.10.10", 445, "smb")),
            ("BackgroundJobDialog",
             lambda: do.BackgroundJobDialog(parent, "nmap", "running")),
            ("show_proxychains_config_dialog",
             lambda: do.show_proxychains_config_dialog(parent, self.app)),
        ]

    def test_every_dialog_constructs(self):
        for label, build in self._cases():
            with self.subTest(dialog=label):
                try:
                    build()
                except Exception as exc:                 # noqa: BLE001
                    self.fail(f"{label} raised "
                              f"{type(exc).__name__}: {exc}")
                self.root.update_idletasks()


class TargetCommandDialogTests(_TkTestCase):
    """X1 — the COPY button was built with kwargs `_btn` does not take,
    so the dialog came up with no COPY and no CLOSE.  Both twins here."""

    def _card(self, mixin):
        class _Card(ctk.CTkFrame, mixin):
            pass
        card = _Card(self.root)
        card.app = self.app
        return card

    def test_show_target_command_dialog(self):
        from gui.widgets.card_runtime import CardRuntimeMixin
        card = self._card(CardRuntimeMixin)
        card._show_target_command_dialog(_a_tool("rdp_enable"))
        self.root.update_idletasks()

    def test_route_netsh_portfwd(self):
        from gui.widgets.card_ad_routes import CardADRoutesMixin
        card = self._card(CardADRoutesMixin)
        card._route_netsh_portfwd(_a_tool("netsh_portfwd"))
        self.root.update_idletasks()


class DialogCloseCallbackTests(_TkTestCase):
    """The X button must take the same route as the CLOSE button.

    Tk's default for WM_DELETE_WINDOW is a bare destroy(), so a dialog
    dismissed with the X skipped whatever callback the caller was
    waiting for — most visibly at startup, where the API-key dialog owns
    the withdrawn root and HAWK stayed alive and invisible.
    """

    def test_make_win_installs_a_handler(self):
        from gui.dialogs_common import _make_win
        win = _make_win(self.root, "smoke", 520, 300)
        self.assertTrue(win.protocol("WM_DELETE_WINDOW"))

    def test_make_win_runs_the_close_callback(self):
        from gui.dialogs_common import _make_win
        seen = []
        win = _make_win(self.root, "smoke", 520, 300,
                        on_close=lambda: seen.append(True))
        # Invoke the registered handler the way the window manager does.
        win.tk.call(win.protocol("WM_DELETE_WINDOW"))
        self.assertEqual(seen, [True])
        self.assertFalse(win.winfo_exists(),
                         "the X left the dialog on screen")

    def test_api_key_dialog_x_takes_the_skip_path(self):
        from gui.api_key_dialog import ApiKeyDialog
        seen = []
        dlg = ApiKeyDialog(self.root, on_done=lambda k: seen.append(k))
        self.root.update_idletasks()
        dlg.tk.call(dlg.protocol("WM_DELETE_WINDOW"))
        self.assertEqual(seen, [""])


class SmbAnonymousParserTests(_TkTestCase):
    """X5 — not a dialog, same bug class.

    `anon_access` was read and never assigned, so every anonymous SMB
    share listing raised NameError and aborted the rest of `_on_done`:
    no credential persisted, no finding, no card update.  Kept next to
    the dialog smokes because it is the same "undefined symbol on the
    normal path" failure the batch exists to close.
    """

    _ANON_LOG = [
        ("out", "Anonymous login successful"),
        ("out", "\tADMIN$           Disk      Remote Admin"),
        ("out", "\tC$               Disk      Default share"),
        ("out", "\tIPC$             IPC       Remote IPC"),
    ]

    def _parser(self, session):
        from gui.widgets.card_parsers_post import CardPostParserMixin

        class _Card(CardPostParserMixin):
            phase_id = "post_exploit"

            def __init__(self, app):
                self.app = app
                self._tool_widgets = {
                    "smbclient_list": {
                        "_last_cmd": "smbclient -L //10.10.10.10 -N"}}

            def _get_target(self):
                return "10.10.10.10"

            @staticmethod
            def _strip_ansi(s):
                return s

        return _Card(_fake_app(session))

    def _session(self):
        from utils.session import Session
        return Session(target_ip="10.10.10.10")

    def test_anonymous_listing_does_not_raise(self):
        sess = self._session()
        card = self._parser(sess)
        tool = types.SimpleNamespace(id="smbclient_list", name="SMBCLIENT")
        card._parse_smb_output(tool, self._ANON_LOG)

        # The whole tail of the parser has to run: finding + credential.
        self.assertTrue(
            any("Anonymous" in title
                for title, _sev, _src in card.app.target_intel.findings),
            "no anonymous-SMB finding was produced")
        self.assertTrue(card.app.cred_store.added,
                        "the connect-hint credential never reached the store")

    def test_authenticated_listing_is_not_reported_anonymous(self):
        sess = self._session()
        card = self._parser(sess)
        card._tool_widgets["smbclient_list"]["_last_cmd"] = (
            "smbclient -L //10.10.10.10 -U 'admin%Passw0rd'")
        tool = types.SimpleNamespace(id="smbclient_list", name="SMBCLIENT")
        card._parse_smb_output(tool, self._ANON_LOG[1:])

        titles = [t for t, _s, _src in card.app.target_intel.findings]
        self.assertTrue(titles, "no finding at all for an authenticated run")
        self.assertFalse([t for t in titles if "Anonymous" in t],
                         f"authenticated run reported as anonymous: {titles}")


if __name__ == "__main__":
    unittest.main()
