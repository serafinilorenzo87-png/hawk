"""Clipboard unification tests (finding F-01).

The COPY action must survive the close of the transient dialog it was
triggered from.  xclip does this natively; when xclip is absent the Tk
fallback must own the selection on the ROOT window (which lives for the
whole session) rather than on the dialog's Toplevel — otherwise closing
the dialog drops the clipboard.
"""

import os
import sys
import types
import unittest
from unittest.mock import patch, MagicMock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Headless CI has no customtkinter; clipboard.py imports it at module top
# only for isinstance() checks that these tests never reach.  A minimal
# stub lets the module import so we can exercise clipboard_copy/paste.
# The stub is removed from sys.modules right after import so it never
# masks a real absence for other test modules (which importorskip it).
_injected_ctk = "customtkinter" not in sys.modules
if _injected_ctk:
    _ctk = types.ModuleType("customtkinter")
    _ctk.CTkEntry = type("CTkEntry", (), {})
    _ctk.CTkTextbox = type("CTkTextbox", (), {})
    sys.modules["customtkinter"] = _ctk

from utils import clipboard  # noqa: E402

if _injected_ctk:
    del sys.modules["customtkinter"]


class ClipboardCopyTests(unittest.TestCase):
    def test_copy_uses_xclip_when_available(self):
        with patch.object(clipboard, "_xclip_available", return_value=True), \
             patch.object(clipboard.subprocess, "run") as run:
            self.assertTrue(clipboard.clipboard_copy("hello"))
            run.assert_called_once()
            args, kwargs = run.call_args
            self.assertIn("xclip", args[0])
            self.assertEqual(kwargs.get("input"), b"hello")

    def test_copy_falls_back_to_root_window_when_no_xclip(self):
        root = MagicMock()
        with patch.object(clipboard, "_xclip_available", return_value=False), \
             patch.object(clipboard.tk, "_default_root", root, create=True):
            self.assertTrue(clipboard.clipboard_copy("secret"))
        # The selection must be bound to the root window, not to a Toplevel.
        root.clipboard_clear.assert_called_once()
        root.clipboard_append.assert_called_once_with("secret")

    def test_copy_returns_false_without_xclip_or_root(self):
        with patch.object(clipboard, "_xclip_available", return_value=False), \
             patch.object(clipboard.tk, "_default_root", None, create=True):
            self.assertFalse(clipboard.clipboard_copy("x"))

    def test_empty_text_is_noop(self):
        with patch.object(clipboard, "_xclip_available", return_value=True), \
             patch.object(clipboard.subprocess, "run") as run:
            self.assertFalse(clipboard.clipboard_copy(""))
            run.assert_not_called()


class ClipboardPasteTests(unittest.TestCase):
    def test_paste_uses_xclip_when_available(self):
        proc = MagicMock()
        proc.stdout = b"clip"
        with patch.object(clipboard, "_xclip_available", return_value=True), \
             patch.object(clipboard.subprocess, "run", return_value=proc):
            self.assertEqual(clipboard.clipboard_paste(), "clip")

    def test_paste_falls_back_to_root_window_when_no_xclip(self):
        root = MagicMock()
        root.clipboard_get.return_value = "fromtk"
        with patch.object(clipboard, "_xclip_available", return_value=False), \
             patch.object(clipboard.tk, "_default_root", root, create=True):
            self.assertEqual(clipboard.clipboard_paste(), "fromtk")


if __name__ == "__main__":
    unittest.main()
