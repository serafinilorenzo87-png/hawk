"""Regression guard for the POTATO privilege-escalation picker.

show_potato_picker_dialog() referenced a module global `_POTATO_VARIANTS`
that was never defined (and `from gui.dialogs_common import *` can't carry
an underscore name), so opening the picker raised NameError on the first
`for v in _POTATO_VARIANTS` line.  These checks assert the catalogue now
exists with the shape the dialog reads, so that path can't regress.

Headless-safe: the dialog is never constructed (no Tk root / display is
needed) — we only read the module-level data and exercise the exact
`.format()` call the preview builder makes, which is where a bad
brace-escape in a cmd_template would blow up.
"""

import os
import sys
import unittest

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Importing gui.dialogs_privesc pulls in customtkinter (import only — no
# widget is built here).  Skip on environments without it, same as the
# other dialog tests, instead of failing collection.
pytest.importorskip("customtkinter")

from gui import dialogs_privesc as dp   # noqa: E402


# The ids _auto_pick() can return; variant_var defaults to one of these,
# so each MUST map to a real variant or the default selection falls
# through to _POTATO_VARIANTS[0].
_AUTO_PICK_IDS = ("juicy", "printspoofer", "godpotato")

# Keys show_potato_picker_dialog() reads off every variant dict.
_REQUIRED_KEYS = {"id", "name", "compat", "notes",
                  "binary_name", "url", "cmd_template"}


class PotatoVariantCatalogueTests(unittest.TestCase):

    def test_catalogue_is_non_empty_indexable(self):
        # _current_variant() falls back to _POTATO_VARIANTS[0], so the
        # list must exist and be indexable at 0.
        self.assertTrue(hasattr(dp, "_POTATO_VARIANTS"))
        self.assertIsInstance(dp._POTATO_VARIANTS, list)
        self.assertGreaterEqual(len(dp._POTATO_VARIANTS), 1)
        self.assertIsInstance(dp._POTATO_VARIANTS[0], dict)

    def test_every_variant_has_the_keys_the_dialog_reads(self):
        for v in dp._POTATO_VARIANTS:
            missing = _REQUIRED_KEYS - set(v)
            self.assertFalse(
                missing, f"variant {v.get('id')!r} missing keys: {missing}")

    def test_auto_pick_ids_all_present(self):
        ids = {v["id"] for v in dp._POTATO_VARIANTS}
        for need in _AUTO_PICK_IDS:
            self.assertIn(
                need, ids,
                f"_auto_pick() can return {need!r} but no variant has it")

    def test_cmd_templates_format_like_the_preview_builder(self):
        # Mirror _update_preview(): bin=C:\Windows\Temp\<name>, plus
        # lhost/lport.  A stray single brace in a template would raise
        # KeyError / ValueError here.
        for v in dp._POTATO_VARIANTS:
            remote_bin = "C:\\Windows\\Temp\\" + v["binary_name"]
            cmd = v["cmd_template"].format(
                bin=remote_bin, lhost="10.10.14.9", lport="4444")
            self.assertIn(remote_bin, cmd, v["id"])
            self.assertIn("10.10.14.9", cmd, v["id"])
            self.assertIn("4444", cmd, v["id"])
            # No format placeholder should survive the substitution.
            for tok in ("{bin}", "{lhost}", "{lport}"):
                self.assertNotIn(tok, cmd, v["id"])

    def test_download_urls_are_direct_release_assets(self):
        # The DOWNLOAD button does `curl -L --fail -o <binary_name> <url>`,
        # so each url must be a direct asset ending in that binary name.
        for v in dp._POTATO_VARIANTS:
            self.assertTrue(
                v["url"].startswith("https://github.com/"), v["id"])
            self.assertTrue(
                v["url"].endswith(v["binary_name"]),
                f"{v['id']}: url does not end in {v['binary_name']}")


if __name__ == "__main__":
    unittest.main()
