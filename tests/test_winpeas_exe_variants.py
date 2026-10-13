"""Regression guard for the winPEAS.exe smart preflight picker.

show_winpeas_exe_preflight_dialog() iterated over a module global
``_WINPEAS_EXE_VARIANTS`` that was never defined, so opening the picker
raised NameError.  These checks assert the catalogue now exists with the
shape the dialog and the card handler read, and that every id
``_recommend_winpeas_exe_variant`` can return maps to a real variant.

Headless-safe: no Tk root / display is needed — we only read the
module-level data and exercise key lookups.
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
    _WINPEAS_EXE_VARIANTS, _recommend_winpeas_exe_variant)

_REQUIRED_KEYS = {
    "id", "name", "runtime", "arch", "obfuscated",
    "desc", "url", "local_name", "script_name",
}

_REC_IDS = ("any", "any_ofs", "x64", "x64_ofs", "x86", "x86_ofs")


class WinpeasExeVariantCatalogueTests(unittest.TestCase):

    def test_catalogue_is_non_empty_list_of_dicts(self):
        self.assertIsInstance(_WINPEAS_EXE_VARIANTS, list)
        self.assertGreaterEqual(len(_WINPEAS_EXE_VARIANTS), 1)
        for v in _WINPEAS_EXE_VARIANTS:
            self.assertIsInstance(v, dict)

    def test_every_variant_has_required_keys(self):
        for v in _WINPEAS_EXE_VARIANTS:
            missing = _REQUIRED_KEYS - set(v)
            self.assertFalse(
                missing,
                f"variant {v.get('id')!r} missing keys: {missing}")

    def test_obfuscated_is_bool(self):
        for v in _WINPEAS_EXE_VARIANTS:
            self.assertIsInstance(
                v["obfuscated"], bool,
                f"variant {v['id']!r}: obfuscated must be bool")

    def test_rec_ids_all_present(self):
        ids = {v["id"] for v in _WINPEAS_EXE_VARIANTS}
        for need in _REC_IDS:
            self.assertIn(
                need, ids,
                f"_recommend_winpeas_exe_variant can return {need!r} "
                f"but no variant has that id")

    def test_urls_point_to_peass_ng_releases(self):
        for v in _WINPEAS_EXE_VARIANTS:
            self.assertTrue(
                v["url"].startswith(
                    "https://github.com/peass-ng/PEASS-ng/releases/"),
                f"{v['id']}: url must be a PEASS-ng release asset")

    def test_recommend_returns_known_id_or_none(self):
        ids = {v["id"] for v in _WINPEAS_EXE_VARIANTS}
        rec_id, _reason, redirect = _recommend_winpeas_exe_variant(
            None, [])
        if not redirect:
            self.assertIn(rec_id, ids)


if __name__ == "__main__":
    unittest.main()
