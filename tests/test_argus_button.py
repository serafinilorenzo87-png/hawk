"""Smoke tests for the ARGUS state-aware button (M1.5).

Mocks the plugin loader so we can verify visual state per PluginState
without manipulating the real ~/.hawk/ directory.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import customtkinter as ctk

from utils.plugin_loader import PluginState
from utils.config import COLORS


class _FakeLoader:
    def __init__(self, state, error=None):
        self.state = state
        self.error = error
        self.plugin = None
        self.license = None
    def mount(self, *a, **kw): return True
    def unmount(self): pass


def _find_descendants(widget, of_type):
    """Walk Tk children recursively."""
    out = []
    for c in widget.winfo_children():
        if isinstance(c, of_type):
            out.append(c)
        out.extend(_find_descendants(c, of_type))
    return out


class ArgusButtonStateTests(unittest.TestCase):
    def setUp(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        self.root = ctk.CTk()
        self.root.geometry("1+1+9999+9999")  # off-screen
        self.parent = ctk.CTkFrame(self.root)
        self.parent.pack()

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass

    def _build_with_state(self, state, error=None):
        """Construct just the ARGUS button portion, mocking discover_argus."""
        from gui.widgets.target_bar import TargetBar
        # Bypass full TargetBar wiring — instantiate a minimal subclass that
        # exposes only the ARGUS button helpers without other UI.
        bar = ctk.CTkFrame(self.parent)
        bar.pack()
        # Bind the ARGUS helpers from TargetBar onto the bar instance via type.
        bar.app = self.root
        bar._teaser_title_labels = []
        bar._make_argus_button = TargetBar._make_argus_button.__get__(bar)
        bar._make_argus_active_button = TargetBar._make_argus_active_button.__get__(bar)
        bar._make_coming_soon_button = TargetBar._make_coming_soon_button.__get__(bar)
        bar._show_coming_soon_dialog = TargetBar._show_coming_soon_dialog.__get__(bar)
        bar._open_argus_window = TargetBar._open_argus_window.__get__(bar)
        bar._build_hawk_api = TargetBar._build_hawk_api.__get__(bar)

        with patch("utils.plugin_loader.discover_argus",
                   return_value=_FakeLoader(state, error)):
            bar._make_argus_button(bar)
        self.root.update_idletasks()
        return bar

    def test_not_installed_uses_default_grey_lock(self):
        bar = self._build_with_state(PluginState.NOT_INSTALLED)
        labels = _find_descendants(bar, ctk.CTkLabel)
        texts = [str(lb.cget("text")) for lb in labels]
        # Title and lock icon are rendered as separate CTkLabels.
        self.assertIn("ARGUS", texts)
        self.assertTrue(any("🔒" in t for t in texts), texts)

    def test_no_license_uses_amber_accent(self):
        bar = self._build_with_state(
            PluginState.NO_LICENSE, error="license file not found")
        # The shell frame is the first CTkFrame child of `bar`.
        shell = next(c for c in bar.winfo_children()
                     if isinstance(c, ctk.CTkFrame))
        self.assertEqual(str(shell.cget("border_color")),
                         COLORS["text_yellow"])
        labels = _find_descendants(bar, ctk.CTkLabel)
        texts = [str(lb.cget("text")) for lb in labels]
        self.assertTrue(any("license required" in t for t in texts), texts)

    def test_expired_uses_amber_clock_icon(self):
        bar = self._build_with_state(
            PluginState.EXPIRED, error="license expired on 2024-01-01")
        shell = next(c for c in bar.winfo_children()
                     if isinstance(c, ctk.CTkFrame))
        self.assertEqual(str(shell.cget("border_color")),
                         COLORS["text_yellow"])
        labels = _find_descendants(bar, ctk.CTkLabel)
        texts = [str(lb.cget("text")) for lb in labels]
        self.assertTrue(any("⏰" in t for t in texts), texts)
        self.assertTrue(any("expired" in t for t in texts), texts)

    def test_incompatible_uses_red_warning_icon(self):
        bar = self._build_with_state(
            PluginState.INCOMPATIBLE,
            error="incompatible version: plugin needs 2.0.0, host is 1.0.0")
        shell = next(c for c in bar.winfo_children()
                     if isinstance(c, ctk.CTkFrame))
        self.assertEqual(str(shell.cget("border_color")),
                         COLORS["text_red"])

    def test_import_error_uses_red_warning_icon(self):
        bar = self._build_with_state(
            PluginState.IMPORT_ERROR, error="boom")
        shell = next(c for c in bar.winfo_children()
                     if isinstance(c, ctk.CTkFrame))
        self.assertEqual(str(shell.cget("border_color")),
                         COLORS["text_red"])

    def test_active_uses_cyan_no_lock(self):
        bar = self._build_with_state(PluginState.ACTIVE)
        shell = next(c for c in bar.winfo_children()
                     if isinstance(c, ctk.CTkFrame))
        self.assertEqual(str(shell.cget("border_color")),
                         COLORS["text_cyan"])
        labels = _find_descendants(bar, ctk.CTkLabel)
        texts = [str(lb.cget("text")) for lb in labels]
        # Active button has NO lock or warning icon.
        self.assertFalse(any(c in t for c in ("🔒", "⏰", "⚠")
                             for t in texts), texts)
        self.assertIn("ARGUS", texts)


if __name__ == "__main__":
    unittest.main()
