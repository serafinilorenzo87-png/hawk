"""Floating cheatsheet dialog (FEATURE-B v1).

Per-service command reference, opened from the "📋 CMDS" button in
the Target Intel ports panel.  Non-modal — the operator opens it
alongside the Connect xterm, copies commands as they work.

Each row in the dialog is:
    <command in monospace>        <description>     [📋 COPY]
where the COPY button stuffs the command into the system clipboard
via Tk's clipboard primitives (no `pyperclip` dependency).

Tuples in the cheatsheet definition whose description is empty
("") are treated as inline section headers / notes — rendered as
a dim label spanning the whole row, no COPY button.

The cheatsheet content itself lives in
``TargetIntelWidget._CONNECT_CHEATSHEETS`` so that future iterations
(STEP 3 Fase 1: static expansion to ~15 DB profiles) only need to
add entries to that dict, no UI changes.
"""
from __future__ import annotations

import customtkinter as ctk

from gui.dialogs_common import _f, COLORS, _make_win, _title


def open_cheatsheet_dialog(parent, svc_key: str,
                            target: str, port,
                            app=None) -> None:
    """Open a non-modal Toplevel showing the cheatsheet for ``svc_key``.

    Parameters
    ----------
    parent : tkinter widget
        Used as the dialog's Tk parent — typically the TargetIntel
        widget itself.  The dialog is independent (not grab_set'd).
    svc_key : str
        Service identifier — accepts either a canonical cheatsheet
        key (``mysql``, ``postgresql``, ``mssql``, ``mongodb``,
        ``redis``) or a service-name alias (e.g. ``mariadb``,
        ``postgres``, ``ms-sql-s``, ``mongo``) which the
        ``_cheatsheet_key_for`` helper normalises.
    target : str
        Target host — embedded in the dialog header for context.
    port : int | str
        Target port — embedded in the dialog header for context.
    app : object | None
        HAWK app reference, optional.  Used only to push a terminal
        ↗ Cred message after each COPY click (so the operator gets
        a visual confirmation in the main HAWK terminal).
    """
    # Resolve the cheatsheet entry.  Import lazily to avoid an
    # import cycle with target_intel_widget.
    from gui.widgets.target_intel_widget import TargetIntelWidget
    canonical = (
        TargetIntelWidget._cheatsheet_key_for(svc_key) or svc_key)
    sheet = TargetIntelWidget._CONNECT_CHEATSHEETS.get(canonical)
    if not sheet:
        # No cheatsheet for this service — the button render path
        # should already have filtered this case, but bail safely.
        try:
            if app is not None:
                app.terminal.write(
                    f"  [!] No cheatsheet available for service "
                    f"'{svc_key}'.", "warn")
        except Exception:
            pass
        return

    title = sheet.get("title") or canonical.upper()
    intro = sheet.get("intro") or ""
    commands = sheet.get("commands") or []

    # ─── Build the Toplevel ─────────────────────────────────────────
    win = _make_win(
        parent,
        f"{title} commands — {target}:{port}",
        720, 540)
    _title(win, f"📋 {title} commands")

    # Header subline: target + port (context — the operator may
    # have multiple cheatsheet windows open at once).
    ctk.CTkLabel(
        win,
        text=f"Target: {target}:{port}",
        font=_f("md"),
        text_color=COLORS["text_cyan"],
    ).pack(pady=(0, 4))

    if intro:
        intro_lbl = ctk.CTkLabel(
            win, text=intro,
            font=_f("sm"),
            text_color=COLORS["text_dim"],
            wraplength=680, justify="left")
        intro_lbl.pack(padx=18, pady=(0, 8), anchor="w")

    # ─── Scrollable command list ────────────────────────────────────
    scroll = ctk.CTkScrollableFrame(
        win,
        fg_color=COLORS["bg_primary"],
        border_color=COLORS["border_dim"],
        border_width=1, corner_radius=4)
    scroll.pack(fill="both", expand=True, padx=14, pady=(0, 8))

    # Tk's clipboard primitives — no external dependency.  Persist
    # the value via update() so the clipboard survives even after
    # the dialog is destroyed (otherwise CLOSE wipes it).
    def _copy_to_clipboard(text: str) -> None:
        try:
            win.clipboard_clear()
            win.clipboard_append(text)
            win.update()   # flush to the X server / Wayland comp
        except Exception:
            pass
        if app is not None:
            try:
                preview = text if len(text) <= 60 else text[:57] + "…"
                app.terminal.write(
                    f"  ↗  Copied to clipboard: {preview}",
                    "finding")
            except Exception:
                pass

    for cmd_text, desc in commands:
        # Inline section header / note: description empty → render
        # as a single dim label across the row, no COPY button.
        if not desc:
            ctk.CTkLabel(
                scroll, text=cmd_text,
                font=_f("sm"),
                text_color=COLORS["text_yellow"],
                anchor="w").pack(fill="x", padx=8, pady=(8, 2))
            continue

        # Command row.
        row = ctk.CTkFrame(scroll, fg_color="transparent")
        row.pack(fill="x", padx=4, pady=2)

        # Command — monospace, selectable.  Use CTkLabel for now
        # (selecting is via right-click "copy" + the COPY button;
        # CTkTextbox would be heavier and visually noisier).
        cmd_lbl = ctk.CTkLabel(
            row, text=cmd_text,
            font=_f("md", True),
            text_color=COLORS["text_bright"],
            anchor="w", justify="left", wraplength=380)
        cmd_lbl.pack(side="left", padx=(6, 8))

        # Description — dim text.
        desc_lbl = ctk.CTkLabel(
            row, text=desc,
            font=_f("sm"),
            text_color=COLORS["text_dim"],
            anchor="w", justify="left", wraplength=220)
        desc_lbl.pack(side="left", padx=(0, 6), fill="x", expand=True)

        # COPY button — single click → clipboard.
        ctk.CTkButton(
            row, text="📋 COPY",
            width=70, height=20,
            font=_f("sm", True),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["text_cyan"], border_width=1,
            text_color=COLORS["text_cyan"], corner_radius=2,
            command=lambda c=cmd_text: _copy_to_clipboard(c),
        ).pack(side="right", padx=(0, 6))

    # ─── Footer ────────────────────────────────────────────────────
    footer = ctk.CTkFrame(win, fg_color="transparent")
    footer.pack(fill="x", padx=14, pady=(0, 12))
    ctk.CTkLabel(
        footer,
        text=("Tip: paste the command into your Connect xterm "
              "(MySQL/Postgres/etc.).  This window is non-modal — "
              "leave it open while you work."),
        font=_f("sm"),
        text_color=COLORS["text_dim"],
        wraplength=560, justify="left").pack(side="left", padx=4)

    ctk.CTkButton(
        footer, text="CLOSE",
        width=90, height=24,
        font=_f("sm", True),
        fg_color=COLORS["bg_secondary"],
        hover_color=COLORS["bg_card_hover"],
        border_color=COLORS["border_dim"], border_width=1,
        text_color=COLORS["text_dim"], corner_radius=2,
        command=win.destroy,
    ).pack(side="right", padx=4)
