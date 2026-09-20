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

"""RBCD dialog must warn, up front, when the DC cannot support RBCD.

RBCD writes msDS-AllowedToActOnBehalfOfOtherIdentity — a Server 2012
schema attribute.  Against the 2008 R2 lab DC the write returns
"invalid attribute type" and the attack is impossible, confirmed live.
The card should say so before the run (honest signal, same as the
ADDCOMPUTER method advisory), keyed on the reliable SMB/NTLM product
version so a wrong nmap -O guess can't flip it, and WITHOUT dragging
2012/2012 R2 (which DO support RBCD) into the warning.
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


def _install_ctk_stub():
    m = types.ModuleType("customtkinter")
    for name in ("CTk", "CTkFrame", "CTkFont", "CTkButton", "CTkLabel",
                 "CTkEntry", "CTkTextbox", "CTkToplevel", "CTkScrollableFrame",
                 "CTkOptionMenu", "CTkCheckBox", "CTkComboBox",
                 "CTkSegmentedButton", "CTkScrollbar", "CTkTabview",
                 "CTkSwitch", "CTkRadioButton", "CTkProgressBar", "CTkSlider",
                 "StringVar", "BooleanVar", "IntVar", "DoubleVar"):
        setattr(m, name, _DummyCtk)
    m.set_appearance_mode = lambda *a, **k: None
    m.set_default_color_theme = lambda *a, **k: None
    sys.modules["customtkinter"] = m


_install_ctk_stub()

from gui.widgets.card_ad_routes import CardADRoutesMixin        # noqa: E402
from utils.config import COLORS                                 # noqa: E402


def _fp(ntlm="", version="", platform="windows"):
    return types.SimpleNamespace(ntlm_product_version=ntlm, version=version,
                                 platform=platform)


class _FakeSelf:
    # _rbcd_schema_advisory calls self._dc_predates_rbcd(...); expose the
    # real staticmethod so the advisory can run on a lightweight fake.
    _dc_predates_rbcd = staticmethod(CardADRoutesMixin._dc_predates_rbcd)

    def __init__(self, fp):
        self.app = types.SimpleNamespace(
            target_intel=types.SimpleNamespace(_fp=fp))


def _advisory(fp):
    return CardADRoutesMixin._rbcd_schema_advisory(_FakeSelf(fp))


class DcPredatesRbcdTests(unittest.TestCase):

    def test_2008r2_dc_predates_rbcd(self):
        # the live lab DC: 6.1.7601, os_raw was a wrong -O guess
        self.assertIs(CardADRoutesMixin._dc_predates_rbcd(
            _fp(ntlm="6.1.7601", version="2008 R2 SP1")), True)

    def test_older_windows_predate_rbcd(self):
        for pv in ("5.1.2600", "5.2.3790", "6.0.6002"):
            self.assertIs(CardADRoutesMixin._dc_predates_rbcd(_fp(ntlm=pv)),
                          True, pv)

    def test_2012_and_newer_support_rbcd(self):
        for pv in ("6.2.9200", "6.3.9600", "10.0.17763"):
            self.assertIs(CardADRoutesMixin._dc_predates_rbcd(_fp(ntlm=pv)),
                          False, pv)

    def test_version_string_fallback(self):
        self.assertIs(CardADRoutesMixin._dc_predates_rbcd(
            _fp(version="2008 R2 SP1")), True)
        self.assertIs(CardADRoutesMixin._dc_predates_rbcd(
            _fp(version="2012 R2")), False)

    def test_unknown_is_none(self):
        self.assertIsNone(CardADRoutesMixin._dc_predates_rbcd(_fp()))
        self.assertIsNone(CardADRoutesMixin._dc_predates_rbcd(None))


class RbcdAdvisoryTests(unittest.TestCase):

    def test_pre_2012_dc_gets_a_red_impossible_warning(self):
        text, color = _advisory(_fp(ntlm="6.1.7601", version="2008 R2 SP1"))
        self.assertIn("PRE-2012", text)
        self.assertIn("CANNOT work", text)
        self.assertIn("constrained delegation", text)
        self.assertEqual(color, COLORS["text_red"])

    def test_2012_dc_is_not_warned_off(self):
        text, color = _advisory(_fp(ntlm="6.3.9600", version="2012 R2"))
        self.assertIn("2012+", text)
        self.assertNotEqual(color, COLORS["text_red"])

    def test_unknown_dc_gives_a_neutral_hint(self):
        text, color = _advisory(_fp())
        self.assertIn("not fingerprinted", text)
        self.assertNotEqual(color, COLORS["text_red"])


if __name__ == "__main__":
    unittest.main()
