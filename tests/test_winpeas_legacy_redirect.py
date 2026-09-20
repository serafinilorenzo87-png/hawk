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

"""winPEAS.exe variant picker must redirect legacy (pre-.NET-4) targets to
winPEAS.bat, driven by the reliable SMB/NTLM product version rather than
the ``nmap -O`` os_raw guess.

The bug: the 2008 R2 DC mis-IDs under ``-O`` as "Embedded Standard 7 /
Windows Phone", so the os_raw/version keyword scan missed it and the
picker recommended a .exe variant — which on a pre-.NET-4 box loads
silently and writes a 0-byte file.  The fix reads ``ntlm_product_version``
(6.1.7601, negotiated over SMB and immune to the wrong -O guess) and only
falls back to the noisy os_raw scan when no reliable signal exists.
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
                 "CTkEntry", "CTkTextbox", "CTkToplevel",
                 "CTkScrollableFrame", "CTkOptionMenu", "CTkCheckBox",
                 "CTkComboBox", "CTkSegmentedButton",
                 "StringVar", "BooleanVar", "IntVar"):
        setattr(m, name, _DummyCtk)
    m.set_appearance_mode = lambda *a, **k: None
    m.set_default_color_theme = lambda *a, **k: None
    sys.modules["customtkinter"] = m


_install_ctk_stub()

from gui.dialogs_privesc import (                            # noqa: E402
    _recommend_winpeas_exe_variant, _is_pre_dotnet4_windows)


class _FP:
    """Minimal fingerprint: only the attributes the picker reads."""

    def __init__(self, os_raw="", version="", ntlm_product_version="",
                 arch=None, platform="windows"):
        self.os_raw = os_raw
        self.version = version
        self.ntlm_product_version = ntlm_product_version
        self.arch = arch
        self.platform = platform


def _redirects(fp):
    _id, _reason, redirect_bat = _recommend_winpeas_exe_variant(fp, [])
    return redirect_bat


class LegacyRedirectTests(unittest.TestCase):

    def test_2008r2_dc_with_wrong_os_guess_redirects_to_bat(self):
        """The exact .177 session shape: -O guessed 'Embedded Standard 7 /
        Windows Phone', but SMB negotiated 6.1.7601 → pre-.NET-4 → .bat."""
        fp = _FP(os_raw=("Microsoft Windows Embedded Standard 7, "
                         "Microsoft Windows Phone 7.5 or 8.0"),
                 version="2008 R2 SP1",
                 ntlm_product_version="6.1.7601")
        self.assertTrue(_redirects(fp))

    def test_xp_via_ntlm_version_redirects(self):
        self.assertTrue(_redirects(_FP(ntlm_product_version="5.1.2600")))

    def test_modern_win10_is_not_redirected(self):
        fp = _FP(version="10", ntlm_product_version="10.0.19041")
        self.assertFalse(_redirects(fp))

    def test_2012r2_is_dotnet4_capable_and_keeps_the_exe(self):
        """8/8.1/2012/2012R2 are 'legacy' to classify_generation() but
        ship .NET 4.5 — winPEAS.exe runs, so they must NOT be redirected."""
        fp = _FP(version="2012 R2", ntlm_product_version="6.3.9600")
        self.assertFalse(_redirects(fp))

    def test_reliable_ntlm_vetoes_a_wrong_os_raw_keyword_hit(self):
        """A modern box mis-guessed by -O as literally 'Windows 7' in
        os_raw must still get the .exe when SMB says 10.0."""
        fp = _FP(os_raw="Microsoft Windows 7 or Windows Server 2008 R2",
                 ntlm_product_version="10.0.19041")
        self.assertFalse(_redirects(fp))

    def test_os_raw_keyword_scan_is_the_fallback_when_no_reliable_signal(self):
        """No ntlm/version at all, only an os_raw hint → conservative .bat."""
        fp = _FP(os_raw="Microsoft Windows XP Professional")
        self.assertTrue(_redirects(fp))

    def test_no_signal_at_all_does_not_redirect(self):
        self.assertFalse(_redirects(_FP()))


class PreDotnet4TriStateTests(unittest.TestCase):

    def test_ntlm_pre_net4_is_true(self):
        for pv in ("5.1.2600", "5.2.3790", "6.0.6002", "6.1.7601"):
            self.assertIs(_is_pre_dotnet4_windows(_FP(ntlm_product_version=pv)),
                          True, pv)

    def test_ntlm_dotnet4_ready_is_false(self):
        for pv in ("6.2.9200", "6.3.9600", "10.0.19041"):
            self.assertIs(_is_pre_dotnet4_windows(_FP(ntlm_product_version=pv)),
                          False, pv)

    def test_version_fallback(self):
        self.assertIs(_is_pre_dotnet4_windows(_FP(version="2008 R2 SP1")), True)
        self.assertIs(_is_pre_dotnet4_windows(_FP(version="2019")), False)

    def test_unknown_is_none(self):
        self.assertIsNone(_is_pre_dotnet4_windows(_FP()))
        self.assertIsNone(_is_pre_dotnet4_windows(None))


if __name__ == "__main__":
    unittest.main()
