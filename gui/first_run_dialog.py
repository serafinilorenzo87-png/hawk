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
HAWK - First-run environment setup dialog.

Shown once, on the very first launch, before the API key dialog. It offers
to grant nmap/masscan the raw-socket capabilities their SYN scans need
(setup_nmap_caps.sh), so HAWK's scan cards work without a sudo password
prompt mid-scan.

Scope is deliberately narrow: only the one-time capabilities step, which is
not covered anywhere else in the app. Per-tool installation stays on the
existing per-card "Run -> install" flow. tkinter is intentionally out of
scope: if this dialog can appear, the GUI already started, so tkinter is
present.

The operator reviews the command and runs it in an external terminal where
they type the root password; HAWK never handles the password itself.
"""

import os
import customtkinter as ctk
from utils.config import COLORS, SZ, BASE_DIR, CONFIGS_DIR

# Marker kept inside the HAWK folder (configs/), so the portable tree stays
# self-contained and the dialog never reappears after the first launch.
_FLAG        = os.path.join(CONFIGS_DIR, "first_run_done")
_CAPS_SCRIPT = os.path.join(BASE_DIR, "setup_nmap_caps.sh")


def is_first_run() -> bool:
    """True when the first-run marker is absent (dialog never shown before)."""
    try:
        return not os.path.exists(_FLAG)
    except OSError:
        return False


def mark_done() -> None:
    """Write the marker so the dialog does not show again. Best-effort: a
    failure here only means the popup may reappear next launch, which is
    harmless."""
    try:
        os.makedirs(CONFIGS_DIR, exist_ok=True)
        from datetime import datetime
        with open(_FLAG, "w", encoding="utf-8") as fh:
            fh.write("first-run completed "
                     f"{datetime.now().isoformat(timespec='seconds')}\n")
    except OSError:
        pass


def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")


def _caps_state():
    """Best-effort (has_nmap, nmap_caps, has_masscan, masscan_caps)."""
    import shutil
    try:
        from utils.runner import has_raw_caps
    except Exception:
        def has_raw_caps(_b):
            return False
    has_nmap    = bool(shutil.which("nmap"))
    has_masscan = bool(shutil.which("masscan"))
    return (
        has_nmap,
        has_raw_caps("nmap") if has_nmap else False,
        has_masscan,
        has_raw_caps("masscan") if has_masscan else False,
    )


class FirstRunDialog(ctk.CTkToplevel):
    """Modal first-run dialog. Calls on_done() when dismissed — whether the
    operator ran the setup or continued without it — and writes the
    first-run marker so it shows only once."""

    def __init__(self, parent, on_done):
        super().__init__(parent)
        # Hidden until the layout settles, like ApiKeyDialog, to avoid the
        # CTkToplevel default-size flash.
        self.withdraw()
        self._on_done = on_done

        self.title("HAWK — First-run setup")
        self.geometry("660x600")
        self.resizable(True, True)
        self.configure(fg_color=COLORS["bg_primary"])

        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"660x600+{(sw-660)//2}+{(sh-600)//2}")

        # Closing via the window X takes the same "continue" path: this
        # dialog runs with the root window withdrawn, and _on_done is what
        # hands control to the next startup step.
        self.protocol("WM_DELETE_WINDOW", self._continue)

        self._build()
        self.after(80, self._autosize)
        self.after(250, self._autosize)

        def _reveal():
            try:
                if not self.winfo_exists():
                    return
                self.deiconify()
                self.lift()
                self.focus_force()
                self.grab_set()
            except Exception:
                pass
        self.after(280, _reveal)

    def _autosize(self):
        try:
            self.update_idletasks()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            w = min(max(self.winfo_reqwidth() + 40, 660), int(sw * 0.92))
            h = min(max(self.winfo_reqheight() + 40, 600), int(sh * 0.92))
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _build(self):
        ctk.CTkFrame(self, fg_color=COLORS["border_green"],
                     height=2, corner_radius=0).pack(fill="x")

        ctk.CTkLabel(self, text="HAWK  —  First-run setup",
                     font=_f("xl", True),
                     text_color=COLORS["text_green"]).pack(pady=(20, 4))
        ctk.CTkLabel(self,
                     text="One-time: let nmap scan without a sudo password",
                     font=_f("sm"),
                     text_color=COLORS["text_muted"]).pack(pady=(0, 14))

        info = ctk.CTkFrame(self, fg_color=COLORS["bg_card"],
                            border_color=COLORS["border_dim"],
                            border_width=1, corner_radius=4)
        info.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(
            info,
            text=(
                "HAWK's scan cards run nmap / masscan SYN scans (-sS), which "
                "need raw-socket privileges. Without them nmap falls back to "
                "sudo and, with no cached password, a scan launched from a "
                "card can finish in a second with no results.\n\n"
                "The fix is a one-time setcap on the nmap / masscan binaries "
                "(setup_nmap_caps.sh): it grants cap_net_raw and lets HAWK "
                "drop sudo entirely — no password prompts mid-scan.\n\n"
                "Note: setcap changes the system nmap / masscan binaries "
                "(outside the HAWK folder). You run the command in a terminal "
                "and type your root password there — HAWK never handles it."
            ),
            font=_f("md"), text_color=COLORS["text_dim"],
            justify="left", anchor="w", wraplength=600).pack(
                padx=14, pady=12, anchor="w")

        self._state_lbl = ctk.CTkLabel(self, text=self._state_text(),
                                       font=_f("md"), justify="left",
                                       anchor="w")
        self._state_lbl.pack(fill="x", padx=24, pady=(6, 2))

        box = ctk.CTkFrame(self, fg_color=COLORS["bg_card"],
                           border_color=COLORS["border_dim"],
                           border_width=1, corner_radius=4)
        box.pack(fill="x", padx=24, pady=(8, 4))
        ctk.CTkLabel(box, text=f"sudo bash {_CAPS_SCRIPT}",
                     font=_f("sm"), text_color=COLORS["text_green"],
                     anchor="w", justify="left",
                     wraplength=600).pack(padx=12, pady=10, anchor="w")

        self._hint = ctk.CTkLabel(self, text="", font=_f("sm"),
                                   text_color=COLORS["text_muted"],
                                   wraplength=600, justify="left")
        self._hint.pack(pady=2)

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=18)
        ctk.CTkButton(
            btn_row, text="RUN IN TERMINAL",
            width=200, height=36, font=_f("md", True),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=4,
            command=self._run).pack(side="left", padx=8)
        ctk.CTkButton(
            btn_row, text="CONTINUE",
            width=150, height=36, font=_f("md"),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=4,
            command=self._continue).pack(side="left", padx=8)

        ctk.CTkLabel(
            self,
            text="You can re-run setup_nmap_caps.sh any time from the HAWK "
                 "folder.",
            font=_f("sm"), text_color=COLORS["text_muted"]).pack(pady=4)

    def _state_text(self):
        has_nmap, nmap_caps, has_masscan, masscan_caps = _caps_state()
        lines = []
        if not has_nmap:
            lines.append("  nmap: not installed — install it from the "
                         "Scanning cards")
        elif nmap_caps:
            lines.append("  ✓  nmap already has raw-socket caps — "
                         "nothing to do")
        else:
            lines.append("  ✗  nmap has no raw-socket caps — scans may "
                         "run empty")
        if has_masscan and masscan_caps:
            lines.append("  ✓  masscan already has raw-socket caps")
        elif has_masscan:
            lines.append("  ✗  masscan has no raw-socket caps")
        return "\n".join(lines)

    def _run(self):
        if not os.path.isfile(_CAPS_SCRIPT):
            self._hint.configure(
                text="  ✗  setup_nmap_caps.sh not found in the HAWK "
                     "folder",
                text_color=COLORS["text_yellow"])
            return
        opened = False
        try:
            from utils.runner import open_native_shell
            opened = open_native_shell(
                title="HAWK — nmap caps setup",
                initial_cmd=f'sudo bash "{_CAPS_SCRIPT}"',
                auto_close=False)
        except Exception:
            opened = False
        if opened:
            self._hint.configure(
                text="  A terminal opened — type your root password there. "
                     "When it finishes, restart HAWK so the new caps are "
                     "picked up.",
                text_color=COLORS["text_green"])
        else:
            self._hint.configure(
                text=f"  ✗  Could not open a terminal. Run manually:  "
                     f'sudo bash "{_CAPS_SCRIPT}"',
                text_color=COLORS["text_yellow"])

    def _continue(self):
        try:
            self.grab_release()
        except Exception:
            pass
        mark_done()
        try:
            self.destroy()
        except Exception:
            pass
        try:
            self._on_done()
        except Exception:
            pass
