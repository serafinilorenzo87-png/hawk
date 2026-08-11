# HAWK — Hostile Assessment War-Kit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0
#
# Attribution "Created by Lorenzo Serafini" must be preserved in all
# redistributed and Derivative Works — see NOTICE for details.

"""New-credential row highlight (MSF3 B4.4).

A freshly captured credential (e.g. a Responder NetNTLMv2 hash) must be
marked NEW so its ROW is highlighted, not just the tab counter.  The
identity used to key "new" rows has to survive a store refresh, and viewing
the tab (_blink_stop) must clear it.  Runs headless via a customtkinter stub.
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


class CredIdentityTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.credential_store_widget import cred_identity
        from utils.session import Credential
        self.cred_identity = cred_identity
        self.Credential = Credential

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_domain_prefix_is_stripped_and_lowercased(self):
        a = self.cred_identity(self.Credential(
            username="PROVA\\Administrator", host="DC01",
            hash_val="aad3b", cred_type="NetNTLMv2"))
        b = self.cred_identity(self.Credential(
            username="administrator", host="dc01",
            hash_val="aad3b", cred_type="NetNTLMv2"))
        self.assertEqual(a, b)

    def test_forward_slash_domain_is_stripped(self):
        a = self.cred_identity(self.Credential(
            username="metasploitable.lab/admin", password="p"))
        self.assertEqual(a[0], "admin")

    def test_different_secret_is_a_different_identity(self):
        a = self.cred_identity(self.Credential(
            username="u", password="p1"))
        b = self.cred_identity(self.Credential(
            username="u", password="p2"))
        self.assertNotEqual(a, b)


class NewKeyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets import credential_store_widget as mod
        from utils.session import Credential
        self._mod = mod
        self.Credential = Credential

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _widget(self):
        w = self._mod.CredentialStoreWidget.__new__(
            self._mod.CredentialStoreWidget)
        w._new_cred_keys = set()
        w._tab_label = None            # _blink_start is a no-op without it
        w._new_findings = 0
        w._blink_active = False
        w._blink_count = 0
        w.refreshed = 0
        w.refresh = lambda: setattr(w, "refreshed", w.refreshed + 1)
        return w

    def test_mark_captured_registers_identity_and_refreshes(self):
        w = self._widget()
        cred = self.Credential(username="svc", host="dc01",
                               hash_val="deadbeef", cred_type="NetNTLMv2")
        w.mark_captured(cred)
        self.assertIn(self._mod.cred_identity(cred), w._new_cred_keys)
        self.assertEqual(w.refreshed, 1)

    def test_viewing_the_tab_clears_the_new_set(self):
        w = self._widget()
        w._new_cred_keys.add(("svc", "dc01", "netntlmv2", "deadbeef"))
        w._blink_stop()
        self.assertEqual(w._new_cred_keys, set())


if __name__ == "__main__":
    unittest.main()
