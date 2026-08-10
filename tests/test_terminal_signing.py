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

"""SMB-signing terminal annotation (W-01).

The terminal annotated every SMB message-signing line "vulnerable to
NTLM relay", even when signing is REQUIRED — the secure, NON-relayable
case.  The annotation must now depend on whether signing is required.

Runs headless via a customtkinter stub installed per-test (restored in
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


class SmbSigningAnnotationTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.terminal_widget import _explain
        self.explain = _explain

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_signing_required_is_not_relayable(self):
        # Signing required is SECURE: the note must say so (blocked) and
        # must NOT call the host relay-vulnerable.
        for line in ("|   Message signing enabled and required",
                     "|_  message_signing: required"):
            note = self.explain(line).lower()
            self.assertTrue(note, f"no annotation at all for {line!r}")
            self.assertIn("blocked", note,
                          f"signing REQUIRED not marked safe: {line!r}")
            self.assertNotIn("vulnerable", note,
                             f"signing REQUIRED wrongly called vulnerable: "
                             f"{line!r}")

    def test_signing_not_required_is_relayable(self):
        for line in ("|   Message signing enabled but not required",
                     "|_  message_signing: disabled (dangerous, but default)",
                     "|_  message_signing: supported"):
            note = self.explain(line).lower()
            self.assertIn("vulnerable", note,
                          f"signing NOT required missed the relay note: "
                          f"{line!r}")


if __name__ == "__main__":
    unittest.main()
