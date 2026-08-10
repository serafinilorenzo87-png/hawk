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

"""Contract for the smbclient share-list command (W-05).

The smbclient route hand-rolled `smbclient -L //<t> -N -p <p>`, dropping
the -I / min-protocol / lanman flags legacy Windows (Server 2008 R2)
needs → NT_STATUS_RESOURCE_NAME_NOT_FOUND.  The same pattern hit the
CONNECT path (the Target Intel CONNECT dialog + the non-standard-port
verify hint).

These guards pin every SMB share-list command HAWK builds to the module's
single source of compat flags (modules.enumeration.SMBCLIENT_COMPAT_FLAGS
for the route, TargetIntelWidget._COMPAT_FLAGS["smb"] for CONNECT).  They
run headless via a customtkinter stub installed per-test (restored in
tearDown so it can't leak into other modules' importorskip).
"""

import os
import sys
import types
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class _DummyCtk:
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, _name):
        return _DummyCtk

    def __call__(self, *args, **kwargs):
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


class _CtkStub:
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        super().setUp()

    def tearDown(self):
        super().tearDown()
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk


def _src(*parts):
    with open(os.path.join(ROOT, *parts), "r", encoding="utf-8") as fh:
        return fh.read()


class SmbclientCommandTests(_CtkStub, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from gui.widgets.card_routes_network import build_smbclient_list_cmd
        self.build = build_smbclient_list_cmd

    def test_anonymous_carries_legacy_windows_flags(self):
        cmd = self.build("10.0.0.5", 445, "", "")
        self.assertIn("-I 10.0.0.5", cmd)
        self.assertIn("client min protocol=NT1", cmd)
        self.assertIn("client lanman auth=yes", cmd)
        self.assertIn("-N", cmd)
        self.assertTrue(cmd.startswith("smbclient -L //10.0.0.5 -p 445"))

    def test_authenticated_keeps_flags_and_drops_N(self):
        cmd = self.build("10.0.0.5", 139, "bob", "hunter2")
        self.assertIn("-U 'bob%hunter2'", cmd)
        self.assertIn("-I 10.0.0.5", cmd)
        self.assertNotIn(" -N", cmd)

    def test_password_single_quote_is_escaped(self):
        cmd = self.build("10.0.0.5", 445, "bob", "o'brien")
        # The raw `o'brien'` must not appear unescaped in the command.
        self.assertNotIn("%o'brien'", cmd)


class SmbclientRouteSourceContractTests(_CtkStub, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.src = _src("gui", "widgets", "card_routes_network.py")

    def test_route_does_not_hand_roll_bare_N(self):
        # The pre-fix route built `smbclient -L //{target} -N -p {p}`.
        self.assertNotIn("-N -p", self.src)

    def test_route_sources_compat_flags_from_module(self):
        self.assertIn(
            "from modules.enumeration import SMBCLIENT_COMPAT_FLAGS",
            self.src)


class SmbConnectPathTests(_CtkStub, unittest.TestCase):
    def test_service_profile_smbclient_actions_route_through_compat(self):
        from gui.widgets.target_intel_widget import TargetIntelWidget
        actions = TargetIntelWidget._SERVICE_PROFILES["smb"]["actions"]
        smbclient_tpls = [a["tpl"] for a in actions
                          if a["tpl"].startswith("smbclient")]
        self.assertTrue(smbclient_tpls, "no smbclient CONNECT actions found")
        for tpl in smbclient_tpls:
            self.assertIn("{compat}", tpl,
                          f"CONNECT action drops the legacy flags: {tpl}")

    def test_compat_flags_single_source_has_legacy_windows_flags(self):
        from gui.widgets.target_intel_widget import TargetIntelWidget
        smb = TargetIntelWidget._COMPAT_FLAGS["smb"]
        self.assertIn("-I {host}", smb)
        self.assertIn("client min protocol=NT1", smb)
        self.assertIn("client lanman auth=yes", smb)

    def test_nonstandard_port_verify_cmd_has_legacy_flags(self):
        from gui.dialogs_common import SERVICE_VERIFY_COMMANDS
        cmds = dict(SERVICE_VERIFY_COMMANDS["smb"]["commands"])
        smbclient = cmds["smbclient list"]
        self.assertIn("-I {target}", smbclient)
        self.assertIn("client min protocol=NT1", smbclient)
        self.assertIn("client lanman auth=yes", smbclient)


class SmbclientModuleTemplateTests(unittest.TestCase):
    def setUp(self):
        import modules.enumeration as en
        self.en = en
        self.tools = {t.id: t for t in en.EnumerationModule.TOOLS}

    def test_compat_flags_constant_and_template(self):
        flags = self.en.SMBCLIENT_COMPAT_FLAGS
        self.assertIn("-I {target}", flags)
        self.assertIn("client min protocol=NT1", flags)
        self.assertIn("client lanman auth=yes", flags)
        tpl = self.tools["smbclient_list"].cmd_template
        self.assertIn("-I {target}", tpl)
        self.assertIn("client min protocol=NT1", tpl)
        self.assertIn("client lanman auth=yes", tpl)


if __name__ == "__main__":
    unittest.main()
