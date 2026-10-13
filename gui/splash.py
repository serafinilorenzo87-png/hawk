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

"""
HAWK - Splash Screen
Animated terminal-style intro: shows a header image + typewriter
banner + loading messages, then transitions to the main window.
"""

import os
import customtkinter as ctk
from utils.config import (BANNER, BANNER_SUBTITLE, BANNER_LINE,
                          SPLASH_MESSAGES, COLORS, APP_VERSION)


# Path to the header image shown above the banner.  Drop a PNG (with
# transparent background recommended) at `assets/hawk.png` inside the
# project root and it will be picked up automatically.  Any image
# format Pillow can open works (.png / .jpg / .gif / .webp).
_HAWK_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IMAGE_CANDIDATES = [
    os.path.join(_HAWK_ROOT, "assets", "hawk.png"),
    os.path.join(_HAWK_ROOT, "assets", "hawk.jpg"),
    os.path.join(_HAWK_ROOT, "assets", "hawk.jpeg"),
    os.path.join(_HAWK_ROOT, "assets", "hawk.gif"),
    os.path.join(_HAWK_ROOT, "assets", "hawk.webp"),
]


class SplashScreen(ctk.CTkToplevel):
    """
    Modal splash window with a typewriter animation.
    Calls on_done() when animation completes.
    """

    TYPING_SPEED_MS = 4    # ms between banner characters
    MSG_DELAY_MS    = 220  # ms between loading messages
    FINISH_DELAY_MS = 600  # ms before closing

    # Max image display size inside the splash (width, height) in px.
    # The source image is scaled down — NEVER up — preserving aspect.
    IMAGE_MAX_SIZE = (180, 180)

    def __init__(self, parent, on_done):
        super().__init__(parent)
        self._on_done = on_done

        # Window setup
        self.title("HAWK")
        self.geometry("680x500")    # taller now — eyes + banner
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg_primary"])
        self.after(100, lambda: self.grab_set())

        # Remove default window decorations attempt (for aesthetics)
        try:
            self.overrideredirect(True)
        except Exception:
            pass

        # Center on screen
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - 680) // 2
        y  = (sh - 500) // 2
        self.geometry(f"680x500+{x}+{y}")

        self._skipped = False
        self._build_ui()
        self._start_animation()

        # Skip on ESC or click
        self.bind("<Escape>", lambda e: self._skip())
        self.bind("<Button-1>", lambda e: self._skip())

    def _build_ui(self):
        # Outer border frame
        border = ctk.CTkFrame(
            self,
            fg_color     = COLORS["bg_primary"],
            border_color = COLORS["border_green"],
            border_width = 2,
            corner_radius = 6,
        )
        border.pack(fill="both", expand=True, padx=4, pady=4)

        # Header image (if available).  We look for a hawk logo at
        # assets/hawk.png and show it centered above the banner.  If
        # no image is present — or Pillow isn't installed — we skip
        # this silently so nothing breaks.
        image = self._load_header_image()
        if image is not None:
            self._img_lbl = ctk.CTkLabel(border, text="", image=image,
                                         anchor="center")
            self._img_lbl.pack(pady=(16, 6))
            # Keep a reference on the instance so the image isn't
            # garbage-collected by Tk (CTkImage holds its own ref but
            # PhotoImage doesn't — belt and suspenders).
            self._header_image = image

        # Banner text area
        self._banner_lbl = ctk.CTkLabel(
            border,
            text="",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color=COLORS["text_green"],
            justify="left",
            anchor="w",
        )
        self._banner_lbl.pack(padx=24, pady=(4, 4), anchor="w")

        # Subtitle
        self._sub_lbl = ctk.CTkLabel(
            border,
            text="",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=COLORS["text_dim"],
            justify="left",
            anchor="w",
        )
        self._sub_lbl.pack(padx=24, pady=(0, 2), anchor="w")

        # Separator line
        self._sep_lbl = ctk.CTkLabel(
            border,
            text="",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=COLORS["text_muted"],
            justify="left",
            anchor="w",
        )
        self._sep_lbl.pack(padx=24, pady=(0, 12), anchor="w")

        # Loading messages area
        self._msg_lbl = ctk.CTkLabel(
            border,
            text="",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color=COLORS["text_green"],
            justify="left",
            anchor="w",
        )
        self._msg_lbl.pack(padx=24, pady=(4, 0), anchor="w")

        # Progress bar
        self._progress = ctk.CTkProgressBar(
            border,
            width=580, height=4,
            fg_color     = COLORS["bg_secondary"],
            progress_color = COLORS["border_green"],
            corner_radius = 2,
        )
        self._progress.pack(padx=24, pady=(20, 8))
        self._progress.set(0)

        # Version line
        ctk.CTkLabel(
            border,
            text=f"  v{APP_VERSION} — Open Source — Kali Linux — Created by Lorenzo Serafini",
            font=ctk.CTkFont(family="Courier New", size=8),
            text_color=COLORS["text_muted"],
        ).pack(padx=24, pady=(0, 8), anchor="w")

    # ─── Image loading ─────────────────────────────────────────────────────────

    def _load_header_image(self):
        """Return a CTkImage for the first available hawk logo file,
        or None if no file exists / Pillow is missing.

        The image is scaled to fit inside IMAGE_MAX_SIZE while preserving
        its aspect ratio — never upscaled.
        """
        path = next((p for p in _IMAGE_CANDIDATES if os.path.isfile(p)),
                    None)
        if path is None:
            return None
        try:
            from PIL import Image
        except ImportError:
            return None
        try:
            img = Image.open(path)
            # Respect aspect ratio, cap at IMAGE_MAX_SIZE.
            img.thumbnail(self.IMAGE_MAX_SIZE, Image.LANCZOS)
            # CTkImage scales correctly on HiDPI displays; it wants
            # the same PIL image for light/dark mode.
            return ctk.CTkImage(light_image=img, dark_image=img,
                                size=img.size)
        except Exception as e:
            print(f"[HAWK] splash image load failed: {e}")
            return None

    # ─── Animation ─────────────────────────────────────────────────────────────

    def _start_animation(self):
        """Eyes are drawn at build time and never change.  We go
        straight to the banner typewriter."""
        banner_text  = BANNER.lstrip("\n")
        self._chars  = list(banner_text)
        self._buffer = []
        self._type_next(0)

    def _type_next(self, idx: int):
        """Type one character at a time."""
        if self._skipped:
            return
        if idx < len(self._chars):
            self._buffer.append(self._chars[idx])
            self._banner_lbl.configure(text="".join(self._buffer))
            self.after(self.TYPING_SPEED_MS, lambda: self._type_next(idx + 1))
        else:
            # Banner done → show subtitle and start loading messages
            self.after(100, self._show_subtitle)

    def _show_subtitle(self):
        self._sub_lbl.configure(text=BANNER_SUBTITLE)
        self.after(80, self._show_sep)

    def _show_sep(self):
        self._sep_lbl.configure(text=BANNER_LINE)
        self.after(200, lambda: self._show_messages(0, []))

    def _show_messages(self, idx: int, shown: list):
        """Show loading messages one by one."""
        if self._skipped:
            return
        if idx < len(SPLASH_MESSAGES):
            shown.append(SPLASH_MESSAGES[idx])
            self._msg_lbl.configure(text="\n".join(shown))
            progress = (idx + 1) / len(SPLASH_MESSAGES)
            self._progress.set(progress)
            self.after(self.MSG_DELAY_MS, lambda: self._show_messages(idx + 1, shown))
        else:
            # All done
            self.after(self.FINISH_DELAY_MS, self._finish)

    def _skip(self):
        """Skip the splash animation immediately."""
        if self._skipped:
            return
        self._skipped = True
        self._finish()

    def _finish(self):
        self.grab_release()
        try:
            self.destroy()
        except Exception:
            pass
        self._on_done()
