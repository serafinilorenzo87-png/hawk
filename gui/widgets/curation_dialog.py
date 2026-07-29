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
Pre-export curation dialog — a THIN Tk shell over CurationController.

All mutation + persistence + report generation lives in the headless
controller (modules.report.curation); this file only wires Tk widgets to
the controller's setters and reads its views.  Keeping the logic out of
the widget is why the feature is unit-tested without a display — this
module is intentionally byte-compile-only in CI.

The operator reviews every finding once, just before producing the
deliverable: include/exclude, mark false-positive, override severity
(objective severity is never overwritten — effective = override or
severity), and annotate.  A live "X of Y included" counter reflects the
curated set; "Generate report" runs the engine on exactly that set.
"""

import tkinter as tk

import customtkinter as ctk

from gui.dialogs_common import _f, COLORS, _make_win, _title, _btn, _btn_row
from modules.report.curation import CurationController, SEVERITIES

_KEEP_LABEL = "(keep original)"
_SEV_CHOICES = [_KEEP_LABEL] + list(SEVERITIES)


def _sev_color(sev: str) -> str:
    return COLORS.get(f"sev_{sev}", COLORS["text_dim"])


def open_curation_dialog(app, session, on_generated=None) -> None:
    """Open the pre-export curation review.  ``on_generated`` is called
    with the primary deliverable path (HTML) after a successful generate,
    preserving the one-path contract the report button expects."""
    controller = CurationController(session)
    win = _make_win(app, "HAWK — Curate findings before export", 920, 640)
    _title(win, "Review findings before generating the report")

    counter = ctk.CTkLabel(win, text="", font=_f("md", True),
                           text_color=COLORS["text_bright"])
    counter.pack(pady=(0, 6))

    status = ctk.CTkLabel(win, text="", font=_f("sm"),
                          text_color=COLORS["text_dim"])

    def _refresh_counter():
        inc, total = controller.included_count()
        counter.configure(text=f"{inc} of {total} findings included")

    scroll = ctk.CTkScrollableFrame(win, fg_color=COLORS["bg_secondary"])
    scroll.pack(fill="both", expand=True, padx=10, pady=6)

    def _add_row(parent, item):
        view = controller.view(item)
        row = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"],
                           border_color=COLORS["border_dim"],
                           border_width=1, corner_radius=4)
        row.pack(fill="x", padx=6, pady=3)

        top = ctk.CTkFrame(row, fg_color="transparent")
        top.pack(fill="x", padx=8, pady=(6, 2))

        sev_badge = ctk.CTkLabel(
            top, text=view["effective_severity"].upper(), width=88,
            font=_f("sm", True),
            text_color=_sev_color(view["effective_severity"]))
        sev_badge.pack(side="left")

        ctk.CTkLabel(top, text=view["title"], font=_f("md", True),
                     text_color=COLORS["text_bright"], anchor="w",
                     wraplength=520, justify="left").pack(side="left", padx=6)

        if view["kev"]:
            kev_txt = "KEV / RANSOMWARE" if view["kev_ransomware"] else "KEV"
            ctk.CTkLabel(top, text=kev_txt, font=_f("sm", True),
                         text_color=COLORS["text_red"]).pack(side="left",
                                                             padx=6)

        ctrl = ctk.CTkFrame(row, fg_color="transparent")
        ctrl.pack(fill="x", padx=8, pady=(0, 6))

        inc_var = tk.BooleanVar(value=view["included"])
        fp_var = tk.BooleanVar(value=view["false_positive"])

        def _on_include(it=item, v=inc_var):
            controller.set_included(it, bool(v.get()))
            _refresh_counter()

        def _on_fp(it=item, v=fp_var):
            controller.set_false_positive(it, bool(v.get()))
            _refresh_counter()

        ctk.CTkCheckBox(ctrl, text="Include", variable=inc_var,
                        command=_on_include, font=_f("sm"),
                        width=20).pack(side="left", padx=(0, 10))
        ctk.CTkCheckBox(ctrl, text="False positive", variable=fp_var,
                        command=_on_fp, font=_f("sm"),
                        width=20).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(ctrl, text="Severity:", font=_f("sm"),
                     text_color=COLORS["text_dim"]).pack(side="left")
        sev_initial = (view["severity_override"]
                       if view["overridden"] else _KEEP_LABEL)

        def _on_sev(choice, it=item, badge=sev_badge):
            controller.set_severity_override(
                it, None if choice == _KEEP_LABEL else choice)
            v = controller.view(it)
            badge.configure(text=v["effective_severity"].upper(),
                            text_color=_sev_color(v["effective_severity"]))

        sev_menu = ctk.CTkOptionMenu(ctrl, values=_SEV_CHOICES,
                                     command=_on_sev, width=130,
                                     font=_f("sm"))
        sev_menu.pack(side="left", padx=(4, 0))
        sev_menu.set(sev_initial)

        # ATT&CK override: blank = use the curated auto-map (shown as the
        # placeholder hint); type technique ids to override per finding.
        tq_var = tk.StringVar(value=" ".join(view["technique_ids"]))
        auto_hint = ", ".join(view["techniques_resolved"]) or "none"
        tq = ctk.CTkEntry(ctrl, textvariable=tq_var,
                          placeholder_text=f"ATT&CK (auto: {auto_hint})",
                          font=_f("sm"), width=180)
        tq.pack(side="left", padx=(10, 0))

        def _on_tq(_evt=None, it=item, v=tq_var):
            controller.set_techniques(it, v.get())
        tq.bind("<FocusOut>", _on_tq)

        note_var = tk.StringVar(value=view["operator_note"])
        note = ctk.CTkEntry(ctrl, textvariable=note_var,
                            placeholder_text="operator note",
                            font=_f("sm"), width=200)
        note.pack(side="left", padx=(10, 0), fill="x", expand=True)

        def _on_note(_evt=None, it=item, v=note_var):
            controller.set_operator_note(it, v.get())
        note.bind("<FocusOut>", _on_note)

    for label, items in controller.groups():
        ctk.CTkLabel(scroll, text=label, font=_f("lg", True),
                     text_color=COLORS["text_green"], anchor="w").pack(
            fill="x", padx=6, pady=(10, 2))
        for it in items:
            _add_row(scroll, it)

    status.pack(pady=(2, 0))
    _refresh_counter()

    # ── action buttons ──
    bar = _btn_row(win)

    def _close():
        try:
            win.destroy()
        except Exception:
            pass

    def _on_generate(btn=None):
        status.configure(text="Generating report…",
                         text_color=COLORS["text_dim"])
        try:
            win.update_idletasks()
            paths = controller.generate()
        except Exception as e:
            status.configure(text=f"Report failed: {e}",
                             text_color=COLORS["text_red"])
            return
        # Tell the operator which formats were produced; if the optional
        # PDF was skipped, result_summary appends the print-from-browser
        # hint.  The note colour flags a missing PDF without alarming.
        from modules.report import result_summary
        summary = result_summary(paths)
        try:
            self_app = app
            self_app.terminal.write(f"  [+] {summary}",
                                    "warn" if "pdf" not in paths
                                    else "success")
        except Exception:
            pass
        status.configure(
            text=summary,
            text_color=(COLORS["text_yellow"] if "pdf" not in paths
                        else COLORS["text_green"]))
        primary = (paths.get("html") or paths.get("md")
                   or next(iter(paths.values()), ""))
        try:
            if on_generated:
                on_generated(primary)
        except Exception:
            pass
        _close()

    _btn(bar, "Cancel", _close, w=120)
    _btn(bar, "Generate report", _on_generate, primary=True, w=180)
