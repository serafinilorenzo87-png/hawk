"""The anonymous SMB connect hint must not point at an admin share.

When SMBCLIENT List logs in anonymously, HAWK suggests an
`smbclient //target/<share> -N` connect command.  The old picker put
C$ / ADMIN$ first in its preference list, so on Metasploitable2 (which
exposes ADMIN$ as a share) the hint became `//target/ADMIN$ -N` — an
administrative share that -N can never reach (NT_STATUS_ACCESS_DENIED).
The picker must prefer a real readable Disk share (e.g. tmp) and never
choose C$ / ADMIN$ / IPC$.
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


class PickAnonShareTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _pick(self, shares):
        from gui.widgets.card_parsers_post import _pick_anon_connect_share
        return _pick_anon_connect_share(shares)

    def test_metasploitable2_picks_tmp_not_admin(self):
        self.assertEqual(
            self._pick(["print$", "tmp", "opt", "IPC$", "ADMIN$"]), "tmp")

    def test_never_picks_admin_shares(self):
        for shares in (
            ["C$", "ADMIN$", "IPC$", "Users"],
            ["ADMIN$", "IPC$", "opt"],
        ):
            self.assertNotIn(self._pick(shares), ("C$", "ADMIN$", "IPC$"))

    def test_only_admin_shares_returns_empty(self):
        self.assertEqual(self._pick(["C$", "ADMIN$", "IPC$"]), "")

    def test_falls_back_to_first_non_admin_share(self):
        # print$ isn't in the preference list but is a valid non-admin
        # fallback over ADMIN$/IPC$.
        self.assertEqual(self._pick(["ADMIN$", "IPC$", "print$"]), "print$")

    def test_match_is_case_insensitive(self):
        self.assertEqual(self._pick(["ADMIN$", "TMP"]), "TMP")


if __name__ == "__main__":
    unittest.main()
