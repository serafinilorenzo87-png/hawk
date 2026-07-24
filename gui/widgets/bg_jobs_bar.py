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
HAWK - Background Jobs Bar
Shows running background jobs (brute force etc.) with elapsed time,
estimated completion, and result notification.
"""

import customtkinter as ctk
import threading
from datetime import datetime
from utils.config import COLORS


def _mono(size=8, bold=False):
    return ctk.CTkFont(family="Courier New", size=size,
                       weight="bold" if bold else "normal")


class BackgroundJob:
    """Represents one background running tool.

    Optional brute-force fields (added 2026-04-29):
    ``log_path`` — path to a tail-able log file with the live tool
                    output.  When set, the BgJobsBar shows an OPEN button
                    that spawns ``xterm -e "tail -f <log_path>"``.
    ``killable``  — when True, the BgJobsBar shows a STOP button that
                    calls ``runner.kill()``.  When False (informational
                    jobs that don't have a real subprocess), STOP is
                    hidden.
    ``host``/``port``/``service`` — context for a richer label and
                    to drive the OPEN xterm title.
    """

    def __init__(self, job_id: str, label: str, estimated_secs: int,
                 runner, done_callback=None,
                 log_path: str = "", killable: bool = False,
                 host: str = "", port: int = 0, service: str = ""):
        self.job_id         = job_id
        self.label          = label
        self.estimated_secs = estimated_secs
        self.runner         = runner
        self.done_callback  = done_callback
        self.start_time     = datetime.now()
        self.finished       = False
        self.result         = None
        # Per-job action support
        self.log_path       = log_path
        self.killable       = killable
        self.host           = host
        self.port           = port
        self.service        = service

    def elapsed_str(self) -> str:
        delta = (datetime.now() - self.start_time).seconds
        h = delta // 3600
        m = (delta % 3600) // 60
        s = delta % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

    def remaining_str(self) -> str:
        elapsed = (datetime.now() - self.start_time).seconds
        rem     = max(0, self.estimated_secs - elapsed)
        h = rem // 3600
        m = (rem % 3600) // 60
        return f"~{h}h {m:02d}min" if h > 0 else f"~{m}min"


class BgJobsBar(ctk.CTkFrame):
    """
    Background-jobs bar shown below the main area.

    Two layout modes (auto-switched based on current jobs):
      • Idle / non-actionable jobs  → compact 30 px bar (single line)
      • ≥1 job with actions (OPEN / STOP) → expanded bar with one row
        per job (40 px each), each row carrying its action buttons
        (26 px tall) — sized so buttons render cleanly on fullscreen
        and HiDPI displays.

    Compact rendering keeps the screen real-estate usage low when
    there's nothing happening; the row-per-job rendering is reserved
    for actively-running brute-force / long-running jobs that the user
    wants to monitor or interrupt.

    Total expanded-mode height: ``_COMPACT_H + (_ROW_H × N) + 6 px
    bottom padding``.  Capped at ``_COMPACT_H + 320`` (≈ 6 jobs) so
    pathological cases don't swallow the main area.  The parent grid
    uses row weight 0 for this widget, so the height we configure is
    what gets allocated.
    """

    # Visual heights — kept generous so the action buttons fit cleanly
    # even on fullscreen / HiDPI where customtkinter's internal padding
    # adds a few pixels per widget.  Previously 26/30 was too tight and
    # buttons got clipped on a 1080p fullscreen window.
    _COMPACT_H = 30      # idle / non-actionable bar height
    _ROW_H     = 40      # per active-action job row (button=26 + pad)
    _BTN_H     = 26      # per-row action button height
    _HEADER_H  = 24      # compact header label band inside expanded mode

    def __init__(self, parent, app, **kwargs):
        super().__init__(
            parent,
            fg_color=COLORS["bg_header"],
            border_color=COLORS["border_dim"],
            border_width=1,
            height=self._COMPACT_H,
            corner_radius=0,
            **kwargs
        )
        self.app   = app
        self._jobs: dict[str, BackgroundJob] = {}
        self._lock = threading.Lock()
        self._row_widgets: dict[str, dict] = {}  # job_id → {frame, labels…}
        self._collapsed = False  # user-toggle: forces compact mode when True
        self.grid_propagate(False)
        self._build_ui()
        self._tick()

    def _build_ui(self):
        # Compact-mode widgets (always built so we can swap visibility).
        self.grid_columnconfigure(1, weight=1)

        self._compact_prefix = ctk.CTkLabel(
            self, text="  BG:",
            font=_mono(12, True), text_color=COLORS["text_muted"],
        )
        self._compact_prefix.grid(row=0, column=0, padx=(6, 4), pady=2, sticky="w")

        self._jobs_label = ctk.CTkLabel(
            self, text="No background jobs",
            font=_mono(12), text_color=COLORS["text_muted"],
            anchor="w",
        )
        self._jobs_label.grid(row=0, column=1, padx=4, pady=2, sticky="w")

        self._cpu_label = ctk.CTkLabel(
            self, text="",
            font=_mono(11), text_color=COLORS["text_yellow"],
            anchor="e",
        )
        self._cpu_label.grid(row=0, column=2, padx=(4, 10), pady=2, sticky="e")

        # Collapse / expand toggle. Sits at column=3 so it's always visible
        # in compact and expanded modes. Hidden when there are zero jobs
        # (nothing to collapse).
        self._toggle_btn = ctk.CTkButton(
            self, text="▼", width=28, height=20,
            font=_mono(11, True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_muted"], corner_radius=3,
            command=self._toggle_collapsed,
        )
        self._toggle_btn.grid(row=0, column=3, padx=(0, 8), pady=2, sticky="e")
        self._toggle_btn.grid_remove()  # shown only when there are jobs

        # Expanded-mode container (one row per job with actions).
        # Scrollable so an unbounded number of jobs doesn't push the rest
        # of the app off-screen. Lives on row=1 so it appears under the
        # compact header. Hidden by default.
        self._rows_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["text_muted"])
        self._rows_frame.grid(
            row=1, column=0, columnspan=4, sticky="nsew",
            padx=4, pady=(0, 2))
        self._rows_frame.grid_columnconfigure(0, weight=1)
        self._rows_frame.grid_remove()  # hidden until needed

    # ─── Public API ────────────────────────────────────────────────────────────

    def add_job(self, job: BackgroundJob):
        with self._lock:
            self._jobs[job.job_id] = job
        if len(self._jobs) > 1:
            self.app.terminal.write(
                f"  ⚠  {len(self._jobs)} background jobs active — "
                "system performance may be reduced.",
                "warn"
            )
        self.app.ui_call(self._update_display)

    def finish_job(self, job_id: str, result_summary: str = ""):
        with self._lock:
            job = self._jobs.pop(job_id, None)
        if not job:
            return
        job.finished = True
        job.result   = result_summary

        # Show completion popup
        from gui.dialogs import BackgroundJobDialog
        def _show():
            BackgroundJobDialog(
                self.app, job.label, result_summary or "Completed.",
                callback=lambda: self.app.terminal.section(
                    f"BG JOB RESULT  ·  {job.label}"
                )
            )
        self.app.after(0, _show)
        self.app.ui_call(self._update_display)

    # ─── Internal ──────────────────────────────────────────────────────────────

    def _tick(self):
        self._update_display()
        self.after(1000, self._tick)

    def _update_display(self):
        with self._lock:
            jobs = list(self._jobs.values())

        # ── Idle path ────────────────────────────────────────────────
        if not jobs:
            self._jobs_label.configure(
                text="No background jobs",
                text_color=COLORS["text_muted"]
            )
            self._cpu_label.configure(text="")
            self._teardown_rows()
            self.configure(height=self._COMPACT_H)
            self._rows_frame.grid_remove()
            self._toggle_btn.grid_remove()
            return

        # Toggle button visible whenever there's at least one job.
        self._toggle_btn.grid()
        self._toggle_btn.configure(text="▼" if self._collapsed else "▲")

        # ── Decide layout: any job has per-job actions? ─────────────
        actionable = [j for j in jobs
                      if j.killable or j.log_path]

        # User-collapsed OR no actionable jobs → compact mode.
        if self._collapsed or not actionable:
            if actionable and self._collapsed:
                # Collapsed but with actions: tell the user the bar is
                # hiding rows so they expand it when they need to act.
                self._jobs_label.configure(
                    text=f"{len(jobs)} job"
                         f"{'s' if len(jobs) != 1 else ''} running "
                         f"(collapsed — click ▼ to expand)",
                    text_color=COLORS["text_yellow"]
                )
            else:
                parts = []
                for job in jobs:
                    parts.append(
                        f"◉ {job.label}  {job.elapsed_str()} elapsed"
                        f"  ·  {job.remaining_str()} remaining"
                    )
                self._jobs_label.configure(
                    text="    ".join(parts),
                    text_color=COLORS["text_yellow"]
                )
            self._teardown_rows()
            self._rows_frame.grid_remove()
            self.configure(height=self._COMPACT_H)
        else:
            # Expanded mode: compact header summary + per-job rows below.
            self._jobs_label.configure(
                text=f"{len(jobs)} job"
                     f"{'s' if len(jobs) != 1 else ''} running — "
                     f"{len(actionable)} with actions",
                text_color=COLORS["text_yellow"]
            )
            self._sync_rows(jobs)
            self._rows_frame.grid()
            # Cap visible rows to 4 — beyond that the inner scrollable
            # frame takes over so the bar never grows past ~210px and
            # the rest of the app stays visible.
            visible = min(len(jobs), 4)
            new_h = self._COMPACT_H + (self._ROW_H * visible) + 6
            self.configure(height=new_h)

        # CPU warning (independent of layout)
        n = len(jobs)
        if n >= 3:
            warn = f"⚠  {n} active jobs — system under stress"
        elif n == 2:
            warn = f"⚠  2 active jobs — high CPU usage"
        else:
            warn = ""
        self._cpu_label.configure(text=warn)

    def _toggle_collapsed(self) -> None:
        self._collapsed = not self._collapsed
        self._update_display()

    def _teardown_rows(self) -> None:
        """Destroy any per-job action rows.  Called when we leave the
        expanded layout (no jobs, or all jobs are non-actionable)."""
        for rec in list(self._row_widgets.values()):
            try:
                rec["frame"].destroy()
            except Exception:
                pass
        self._row_widgets.clear()

    def _sync_rows(self, jobs: list) -> None:
        """Reconcile the per-job rows with the current job list.

        Only creates / destroys row widgets when the job set changes.
        Existing rows just get their elapsed-time label updated, so
        the 1 Hz refresh never destroys/recreates buttons (avoids
        click-during-redraw races and the "pop" flash you'd otherwise
        see on every tick)."""
        wanted = {j.job_id: j for j in jobs}
        # Remove rows for jobs no longer in the active set
        for jid in list(self._row_widgets.keys()):
            if jid not in wanted:
                try:
                    self._row_widgets[jid]["frame"].destroy()
                except Exception:
                    pass
                del self._row_widgets[jid]

        # Add rows for new jobs, in insertion order
        for idx, (jid, job) in enumerate(wanted.items()):
            if jid not in self._row_widgets:
                self._row_widgets[jid] = self._build_row(job, idx)
            # Refresh the dynamic label even when the row already exists
            rec = self._row_widgets[jid]
            try:
                rec["status"].configure(
                    text=f"◉ {job.label}   {job.elapsed_str()} elapsed"
                )
            except Exception:
                pass

    def _build_row(self, job: BackgroundJob, idx: int) -> dict:
        """Build one job row inside ``_rows_frame``.  Returns a dict of
        the row's key widgets so ``_sync_rows`` can update them.

        Sizing notes: ``_ROW_H`` (40) is the row container height and
        ``_BTN_H`` (26) is the inner button height — leaves ~7 px of
        vertical padding on each side so buttons render cleanly even
        on HiDPI / fullscreen."""
        row = ctk.CTkFrame(
            self._rows_frame, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3, height=self._ROW_H - 2)
        row.grid(row=idx, column=0, sticky="ew", padx=2, pady=2)
        row.grid_columnconfigure(0, weight=1)
        row.grid_propagate(False)

        # Status label (label + elapsed) — left-aligned, fills row
        status_lbl = ctk.CTkLabel(
            row,
            text=f"◉ {job.label}   {job.elapsed_str()} elapsed",
            font=_mono(12, True), text_color=COLORS["text_yellow"],
            anchor="w")
        status_lbl.grid(row=0, column=0, padx=(10, 4), pady=4, sticky="w")

        # Action buttons — right-aligned
        btns = ctk.CTkFrame(row, fg_color="transparent")
        btns.grid(row=0, column=1, padx=(4, 8), pady=4, sticky="e")

        if job.log_path:
            ctk.CTkButton(
                btns, text="▶ OPEN", width=80, height=self._BTN_H,
                font=_mono(11, True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"], border_width=1,
                text_color=COLORS["text_green"], corner_radius=3,
                command=lambda j=job: self._open_job_log(j),
            ).pack(side="left", padx=3)

        if job.killable:
            ctk.CTkButton(
                btns, text="⏹ STOP", width=80, height=self._BTN_H,
                font=_mono(11, True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color="#FF4444", border_width=1,
                text_color="#FF6666", corner_radius=3,
                command=lambda j=job: self._stop_job(j),
            ).pack(side="left", padx=3)

        return {"frame": row, "status": status_lbl}

    # ─── Per-job action handlers ─────────────────────────────────────────────

    def _open_job_log(self, job: BackgroundJob) -> None:
        """Spawn an xterm running ``tail -f <log>`` so the user can watch
        the job's live output without interrupting it.  Closing the xterm
        only closes the viewer — the underlying process keeps running."""
        if not job.log_path:
            self.app.terminal.write(
                f"  [!] BG job '{job.label}' has no log file to tail.",
                "warn")
            return
        try:
            from utils.runner import open_native_shell
            title = f"HAWK — tail · {job.label}"
            # tail -F (capital F) keeps following even if the file is
            # truncated/rotated — safer than -f when the writer might
            # rotate logs mid-run.  ``read`` keeps the xterm alive after
            # the tail ends so the user sees the final lines.
            tail_cmd = (
                f"echo '[HAWK] tailing {job.label} — Ctrl-C to close'; "
                f"echo '[HAWK] log: {job.log_path}'; echo ''; "
                f"tail -n 200 -F '{job.log_path}'"
            )
            ok = open_native_shell(title, tail_cmd, auto_close=False)
            if not ok:
                self.app.terminal.write(
                    f"  [!] Could not open xterm to tail '{job.label}'.",
                    "warn")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] OPEN failed for '{job.label}': {e}", "warn")

    def _stop_job(self, job: BackgroundJob) -> None:
        """Kill the running tool.  Uses ``ToolRunner.kill()`` which
        already implements SIGTERM → SIGKILL escalation in a background
        thread, so the click never blocks the UI."""
        runner = job.runner
        if runner is None:
            self.app.terminal.write(
                f"  [!] BG job '{job.label}' has no runner reference — "
                f"cannot stop.", "warn")
            return
        try:
            self.app.terminal.write(
                f"  [*] Stopping BG job: {job.label} …", "warn")
            runner.kill()
            # The job will be removed from the bar by finish_job() once
            # the runner's done_callback fires after the process exits.
            # Don't pop it here — would cause double-removal races.
        except Exception as e:
            self.app.terminal.write(
                f"  [!] STOP failed for '{job.label}': {e}", "warn")
