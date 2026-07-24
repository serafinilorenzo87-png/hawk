# HAWK — Hostile Assessment WorKit
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
HAWK - Payload Selector Dialog v1.0
Shown when OS is not identified or user wants to override payload.
Lets user choose payload by OS, architecture, and shell type.
"""

import customtkinter as ctk
from utils.config import COLORS, SZ


def _f(key="md", bold=False):
    return ctk.CTkFont(family="Courier New", size=SZ.get(key, 14),
                       weight="bold" if bold else "normal")


# ─── Payload definitions ──────────────────────────────────────────────────────

PAYLOAD_CATEGORIES = {
    "Windows x64 (64-bit)": {
        "icon": "🪟",
        "payloads": [
            ("windows/x64/meterpreter/reverse_tcp",
             "Meterpreter — full featured, encrypted, most stable  ★ recommended"),
            ("windows/x64/meterpreter/reverse_http",
             "Meterpreter over HTTP — bypasses some firewalls"),
            ("windows/x64/meterpreter/reverse_https",
             "Meterpreter over HTTPS — hard to detect, SSL encrypted"),
            ("windows/x64/shell_reverse_tcp",
             "Raw cmd.exe shell — simple, no features but very compatible"),
            ("windows/x64/powershell_reverse_tcp",
             "PowerShell shell — good for post-exploitation on modern Windows"),
        ],
    },
    "Windows x86 (32-bit)": {
        "icon": "🪟",
        "payloads": [
            ("windows/meterpreter/reverse_tcp",
             "Meterpreter x86 — use when target is 32-bit Windows  ★"),
            ("windows/meterpreter/reverse_http",
             "Meterpreter x86 over HTTP"),
            ("windows/shell_reverse_tcp",
             "Raw cmd.exe shell x86 — most compatible with old systems"),
            ("windows/shell/reverse_tcp",
             "Staged cmd.exe shell x86"),
        ],
    },
    "Linux x64": {
        "icon": "🐧",
        "payloads": [
            ("linux/x64/meterpreter/reverse_tcp",
             "Meterpreter Linux x64 — full featured  ★ recommended"),
            ("linux/x64/shell_reverse_tcp",
             "Raw bash/sh shell — simple, very compatible"),
            ("linux/x64/shell/reverse_tcp",
             "Staged shell Linux x64"),
            ("linux/x64/meterpreter_reverse_tcp",
             "Stageless meterpreter — works without stager"),
        ],
    },
    "Linux x86": {
        "icon": "🐧",
        "payloads": [
            ("linux/x86/meterpreter/reverse_tcp",
             "Meterpreter Linux x86  ★"),
            ("linux/x86/shell_reverse_tcp",
             "Raw shell Linux x86"),
        ],
    },
    "Generic / Unknown OS": {
        "icon": "❓",
        "payloads": [
            ("generic/shell_reverse_tcp",
             "Generic reverse shell — works on both Windows and Linux  ★"),
            ("generic/shell_bind_tcp",
             "Bind shell — target connects back on a port (no firewall issues)"),
            ("java/meterpreter/reverse_tcp",
             "Java meterpreter — works if target runs JVM (Tomcat, Jenkins)"),
            ("python/meterpreter/reverse_tcp",
             "Python meterpreter — works if target has Python installed"),
            ("php/meterpreter/reverse_tcp",
             "PHP meterpreter — works if target runs PHP"),
        ],
    },
}


class PayloadSelectorDialog:
    """
    Shown when OS is unknown or user wants to override the auto-detected payload.
    Returns selected payload string via callback.
    """

    def __init__(self, parent, fp=None, callback=None,
                 reason: str = "OS not identified",
                 compatible_payloads=None,
                 exploit_name: str = ""):
        self._callback = callback
        self._fp       = fp
        # When provided, limit displayed payloads to this list (MSF probe result).
        self._compat   = set(compatible_payloads) if compatible_payloads else None
        self._exploit  = exploit_name or ""

        win = self._win = ctk.CTkToplevel(parent)
        # Hide until layout settles (see comment in gui/dialogs._make_win)
        win.withdraw()
        win.title("Select Payload")
        win.geometry("680x620")
        win.resizable(True, True)
        win.configure(fg_color=COLORS["bg_primary"])

        win.update_idletasks()
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"680x620+{(sw-680)//2}+{(sh-620)//2}")

        win.after(80, self._autosize)
        win.after(250, self._autosize)

        def _reveal():
            try:
                if not win.winfo_exists():
                    return
                win.deiconify(); win.lift(); win.focus_force()
            except Exception:
                pass
        win.after(280, _reveal)

        # Top accent
        ctk.CTkFrame(win, fg_color=COLORS["border_green"],
                     height=2, corner_radius=0).pack(fill="x")

        # Title
        ctk.CTkLabel(win, text="Select Payload",
                     font=_f("xl", True),
                     text_color=COLORS["text_bright"]).pack(pady=(14, 4))

        # Reason
        ctk.CTkLabel(win,
                     text=f"⚠  {reason}\n"
                          "Select the payload that matches your target.",
                     font=_f("md"), text_color=COLORS["text_yellow"],
                     justify="center").pack(pady=(0, 8))

        # MSF compatibility banner — shown when we probed `show payloads`
        if self._compat is not None:
            short = (self._exploit.split("/")[-1]
                     if self._exploit else "this module")
            ctk.CTkLabel(win,
                         text=f"🛈  Showing only the {len(self._compat)} payload(s) "
                              f"MSF reports as compatible with {short}.\n"
                              "Incompatible payloads hidden.",
                         font=_f("md", True),
                         text_color=COLORS["text_green"],
                         justify="center").pack(pady=(0, 8))

        # OS hint if we have fingerprint
        if fp and fp.platform:
            ctk.CTkLabel(win,
                         text=f"  Detected OS: {fp.summary()}  — "
                              "scroll to matching category below",
                         font=_f("md", True),
                         text_color=COLORS["text_green"]).pack(pady=(0, 6))

        # Scrollable payload list
        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_secondary"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"])
        scroll.pack(fill="both", expand=True, padx=16, pady=8)

        # Initial default. If we have a compatibility list, prefer the
        # first compatible entry (so an invalid default never ends up set).
        if self._compat:
            from utils.msf_payload_probe import pick_best_payload
            platform = (fp.platform if fp and fp.platform else "")
            initial = (pick_best_payload(list(self._compat), platform)
                       or next(iter(self._compat)))
        else:
            initial = "generic/shell_reverse_tcp"
        self._payload_var = ctk.StringVar(value=initial)

        # Auto-select recommended category based on partial OS info
        recommended_category = self._guess_category(fp)

        # Track which compatible payloads we've rendered so we can show
        # the rest in a catch-all category at the bottom.
        rendered: set[str] = set()

        for category, info in PAYLOAD_CATEGORIES.items():
            # When filtering by MSF compatibility, skip categories that
            # have no compatible entries.
            if self._compat is not None:
                visible = [(n, d) for n, d in info["payloads"]
                           if n in self._compat]
                if not visible:
                    continue
            else:
                visible = list(info["payloads"])
            # Category header
            is_recommended = (category == recommended_category)
            hdr_color = (COLORS["border_green"] if is_recommended
                         else COLORS["border_dim"])
            hdr = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"],
                               border_color=hdr_color,
                               border_width=1, corner_radius=4)
            hdr.pack(fill="x", padx=4, pady=(8, 2))

            hdr_row = ctk.CTkFrame(hdr, fg_color="transparent")
            hdr_row.pack(fill="x", padx=10, pady=(6, 4))

            ctk.CTkLabel(hdr_row,
                         text=f"  {info['icon']}  {category}",
                         font=_f("lg", True),
                         text_color=(COLORS["text_green"] if is_recommended
                                     else COLORS["text_bright"]),
                         anchor="w").pack(side="left")

            if is_recommended:
                ctk.CTkLabel(hdr_row,
                             text="  ★ recommended for this target",
                             font=_f("sm"),
                             text_color=COLORS["text_green"],
                             anchor="w").pack(side="left")

            # Payloads in this category (filtered by MSF compat if provided)
            for payload_name, payload_desc in visible:
                rendered.add(payload_name)
                rf = ctk.CTkFrame(hdr, fg_color="transparent")
                rf.pack(fill="x", padx=8, pady=3)

                is_rec_payload = ("★" in payload_desc and is_recommended)
                if (is_rec_payload
                        and self._payload_var.get() == "generic/shell_reverse_tcp"
                        and self._compat is None):
                    self._payload_var.set(payload_name)

                rb = ctk.CTkRadioButton(
                    rf,
                    text=payload_name,
                    variable=self._payload_var,
                    value=payload_name,
                    font=_f("md", True),
                    text_color=(COLORS["text_green"] if is_rec_payload
                                else COLORS["text_bright"]),
                    fg_color=COLORS["border_green"],
                    border_color=COLORS["border_dim"],
                )
                rb.pack(side="left")

                ctk.CTkLabel(rf,
                             text=f"  — {payload_desc.replace('★ recommended', '').replace('★', '').strip()}",
                             font=_f("sm"),
                             text_color=COLORS["text_dim"],
                             anchor="w").pack(side="left", padx=6)

            ctk.CTkLabel(hdr, text="", font=_f("sm")).pack(pady=2)

        # Catch-all: compatible payloads MSF reported that aren't in any
        # curated category above (ARM/MIPS, exotic transports, etc.).
        if self._compat is not None:
            leftover = sorted(p for p in self._compat if p not in rendered)
            if leftover:
                hdr = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"],
                                   border_color=COLORS["border_dim"],
                                   border_width=1, corner_radius=4)
                hdr.pack(fill="x", padx=4, pady=(8, 2))
                hdr_row = ctk.CTkFrame(hdr, fg_color="transparent")
                hdr_row.pack(fill="x", padx=10, pady=(6, 4))
                ctk.CTkLabel(hdr_row,
                             text="  📦  Other compatible payloads",
                             font=_f("lg", True),
                             text_color=COLORS["text_bright"],
                             anchor="w").pack(side="left")
                ctk.CTkLabel(hdr_row,
                             text=f"  ({len(leftover)} from MSF probe)",
                             font=_f("sm"),
                             text_color=COLORS["text_dim"],
                             anchor="w").pack(side="left")
                for payload_name in leftover:
                    rf = ctk.CTkFrame(hdr, fg_color="transparent")
                    rf.pack(fill="x", padx=8, pady=3)
                    rb = ctk.CTkRadioButton(
                        rf,
                        text=payload_name,
                        variable=self._payload_var,
                        value=payload_name,
                        font=_f("md", True),
                        text_color=COLORS["text_bright"],
                        fg_color=COLORS["border_green"],
                        border_color=COLORS["border_dim"],
                    )
                    rb.pack(side="left")
                ctk.CTkLabel(hdr, text="", font=_f("sm")).pack(pady=2)

        # Custom payload entry
        custom_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"],
                                    border_color=COLORS["border_dim"],
                                    border_width=1, corner_radius=4)
        custom_frame.pack(fill="x", padx=4, pady=8)
        ctk.CTkLabel(custom_frame,
                     text="  ✏  Custom payload (type any valid MSF payload):",
                     font=_f("md", True), text_color=COLORS["text_dim"],
                     anchor="w").pack(fill="x", padx=10, pady=(8, 4))

        self._custom_var = ctk.StringVar(value="")
        custom_entry = ctk.CTkEntry(
            custom_frame,
            textvariable=self._custom_var,
            placeholder_text="e.g. windows/x64/meterpreter/reverse_https",
            font=_f("md"), height=32,
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            placeholder_text_color=COLORS["text_muted"],
            corner_radius=3)
        custom_entry.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkLabel(custom_frame,
                     text="  Typing here overrides the radio selection above.",
                     font=_f("sm"), text_color=COLORS["text_muted"],
                     anchor="w").pack(fill="x", padx=10, pady=(0, 6))

        # Preview
        self._preview_var = ctk.StringVar(
            value=f"PAYLOAD: {self._payload_var.get()}")
        self._payload_var.trace_add("write", self._update_preview)
        self._custom_var.trace_add("write",  self._update_preview)

        ctk.CTkLabel(win, textvariable=self._preview_var,
                     font=_f("md", True),
                     text_color=COLORS["text_cyan"],
                     anchor="w").pack(fill="x", padx=24, pady=(0, 4))

        # Buttons
        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=12)

        ctk.CTkButton(
            btn_row, text="USE THIS PAYLOAD",
            width=180, height=34,
            font=_f("md", True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=4,
            command=self._confirm,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_row, text="CANCEL",
            width=100, height=34,
            font=_f("md"),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=4,
            command=self._cancel,
        ).pack(side="left", padx=8)

    def _guess_category(self, fp) -> str:
        """Guess recommended payload category from partial OS info."""
        if not fp or not fp.platform:
            return "Generic / Unknown OS"
        low = fp.platform.lower()
        if "windows" in low:
            # Try to determine architecture from version/banner
            return "Windows x64 (64-bit)"  # default to x64 for modern Windows
        elif "linux" in low:
            return "Linux x64"
        elif "android" in low:
            return "Linux x86"
        return "Generic / Unknown OS"

    def _update_preview(self, *_):
        custom = self._custom_var.get().strip()
        payload = custom if custom else self._payload_var.get()
        try:
            self._preview_var.set(f"PAYLOAD: {payload}")
        except Exception:
            pass

    def _confirm(self):
        custom = self._custom_var.get().strip()
        payload = custom if custom else self._payload_var.get()
        self._close()
        if self._callback:
            self._callback(payload)

    def _cancel(self):
        self._close()

    def _close(self):
        try:
            self._win.grab_release()
        except Exception:
            pass
        try:
            self._win.destroy()
        except Exception:
            pass
