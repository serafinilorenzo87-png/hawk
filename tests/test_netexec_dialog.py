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

"""Contract for the netexec (SMB) network-route dialog.

The dialog used to BUILD its command by hand, so it drifted from the
netexec 1.5.1 CLI the module cmd_template targets:

  * W-02  — stale `--sessions` (renamed `--smb-sessions`) → argparse
            aborts and the whole enum is zeroed.
  * W-02b — `--users` / `--groups` moved to the `ldap` protocol → they
            are no-ops when offered under `smb`.
  * W-03  — the "Anonymous" option dropped the `-u '' -p ''` null-session
            bind legacy Windows (Server 2008 R2) needs.

These guards pin the built command to the module's single source of
flags (modules.enumeration.NXC_NULL_SESSION_AUTH + the option table).
They run headless via a customtkinter stub — same pattern as
tests/test_intel_nmap_findings.py.
"""

import os
import re
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
    """Install the customtkinter stub for the duration of a test and
    restore sys.modules afterwards.  Installing at run time (not import
    time) keeps the stub from leaking into other modules' collection-time
    `pytest.importorskip("customtkinter")` — same discipline as
    tests/test_intel_nmap_findings.py."""

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


def _cred(cred_type, username, password=None, hash_val=None):
    return types.SimpleNamespace(
        cred_type=cred_type, username=username,
        password=password, hash_val=hash_val)


def _src(*parts):
    with open(os.path.join(ROOT, *parts), "r", encoding="utf-8") as fh:
        return fh.read()


class NetexecCommandTests(_CtkStub, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from gui.widgets.card_routes_network import build_netexec_smb_cmd
        self.build = build_netexec_smb_cmd

    def test_anonymous_uses_null_session_bind(self):
        """W-03: Anonymous must emit `-u '' -p ''` (from the module)."""
        cmd = self.build("10.0.0.5", 445, ["--shares"], cred=None)
        self.assertIn("-u '' -p ''", cmd)
        self.assertTrue(cmd.startswith("netexec smb 10.0.0.5 --port 445"))

    def test_sessions_flag_is_smb_sessions(self):
        """W-02: the flag is `--smb-sessions`, never the stale
        `--sessions` netexec 1.5.1's argparse rejects."""
        cmd = self.build("10.0.0.5", 445, ["--shares", "--smb-sessions"],
                         cred=None)
        self.assertIn("--smb-sessions", cmd)
        self.assertEqual(
            re.findall(r"(?<![\w-])--sessions(?![\w-])", cmd), [])

    def test_cleartext_cred_replaces_anonymous(self):
        cred = _cred("cleartext", "admin", password="Passw0rd")
        cmd = self.build("10.0.0.5", 445, ["--shares"], cred=cred)
        self.assertIn("-u 'admin' -p 'Passw0rd'", cmd)
        self.assertNotIn("-u '' -p ''", cmd)

    def test_hash_cred_uses_pass_the_hash(self):
        cred = _cred("hash", "admin",
                     hash_val="aad3b435b51404ee:31d6cfe0d16ae931")
        cmd = self.build("10.0.0.5", 445, ["--shares"], cred=cred)
        self.assertIn("-H 'aad3b435b51404ee:31d6cfe0d16ae931'", cmd)
        self.assertIn("-u 'admin'", cmd)

    def test_no_double_spaces(self):
        cmd = self.build("10.0.0.5", 445, [], cred=None)
        self.assertNotIn("  ", cmd)


class NetexecOptionTableContractTests(_CtkStub, unittest.TestCase):
    """The dialog's option table is the single source of the offered
    flags — pin it to the netexec 1.5.1 spelling."""

    def setUp(self):
        super().setUp()
        from gui.widgets.card_routes_network import NXC_SMB_OPTIONS
        self.flags = [flag for _k, flag, _label in NXC_SMB_OPTIONS]

    def test_sessions_flag_is_smb_sessions(self):
        # W-02: `--smb-sessions`, never the stale `--sessions` / `--rid`.
        self.assertIn("--smb-sessions", self.flags)
        self.assertNotIn("--sessions", self.flags)
        self.assertNotIn("--rid", self.flags)
        self.assertIn("--rid-brute", self.flags)

    def test_users_groups_not_offered_under_smb(self):
        # W-02b: they moved to the ldap protocol → no-ops under smb.
        self.assertNotIn("--users", self.flags)
        self.assertNotIn("--groups", self.flags)

    def test_dialog_sources_null_session_from_module(self):
        # W-03: the null-session bind is imported from the module, not
        # hand-rolled in the dialog.
        src = _src("gui", "widgets", "card_routes_network.py")
        self.assertIn(
            "from modules.enumeration import NXC_NULL_SESSION_AUTH", src)


class NetexecModuleTemplateTests(unittest.TestCase):
    def setUp(self):
        import modules.enumeration as en
        self.en = en
        self.tools = {t.id: t for t in en.EnumerationModule.TOOLS}

    def test_null_session_constant_and_template(self):
        self.assertEqual(self.en.NXC_NULL_SESSION_AUTH, "-u '' -p ''")
        self.assertIn("-u '' -p ''", self.tools["netexec"].cmd_template)


if __name__ == "__main__":
    unittest.main()
