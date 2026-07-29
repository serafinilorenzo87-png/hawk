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
Report engine orchestrator.

Builds the shared ReportContext once (curation + counts applied there),
runs the ordered provider list into a list of Sections, then renders that
SAME list into each requested format and writes the files under
REPORTS_DIR.  All artifacts stay inside the HAWK tree (require_within_base
guard), consistent with the portability pillar.
"""

from __future__ import annotations

import os
import sys

from utils.config import REPORTS_DIR, require_within_base
from modules.report.model import ReportContext, load_branding
from modules.report.providers import CORE_PROVIDERS
from modules.report import render


# Primary first: HTML is the rich deliverable, then the spreadsheet dump,
# then the Markdown serializer, then the OPTIONAL best-effort PDF.  "pdf"
# is just another format whose render target tries WeasyPrint and degrades
# silently when it (or its native libs) is absent — the expected state.
REPORT_FORMATS = ("html", "csv", "md", "pdf")

# Text render targets only.  PDF is handled separately: it is binary and
# is produced from the already-rendered HTML, not from the sections.
_RENDERERS = {
    "html": render.render_html,
    "csv":  render.render_csv,
    "md":   render.render_markdown,
}


def build_sections(ctx, providers=None) -> list:
    """Run each applicable provider into a Section.  A provider that
    raises is skipped (logged) rather than killing the whole report —
    one bad section never sinks the deliverable."""
    sections = []
    for provider in (providers or CORE_PROVIDERS):
        try:
            if not provider.applies(ctx):
                continue
            section = provider.build(ctx)
            if section is not None and section.blocks:
                sections.append(section)
        except Exception as e:
            print(f"[HAWK] report provider '{getattr(provider, 'id', '?')}' "
                  f"failed: {e}", file=sys.stderr)
    return sections


def generate(session, formats=REPORT_FORMATS, *, branding=None,
             out_dir=None, providers=None) -> dict:
    """Generate the report in each requested format.

    Returns ``{fmt: path}`` for every format written.  Curation
    (included / false_positive) and effective_severity are applied once
    in ReportContext, so all formats carry identical numbers.

    ``out_dir`` defaults to REPORTS_DIR; any override must still resolve
    inside the HAWK tree (require_within_base) — the deliverable never
    escapes the portable folder.
    """
    ctx = ReportContext(session, branding=load_branding(branding))
    sections = build_sections(ctx, providers=providers)

    target_dir = out_dir or REPORTS_DIR
    os.makedirs(target_dir, exist_ok=True)
    safe = (session.target_ip or "target").replace(".", "_").replace(":", "_")
    ts = ctx.generated_at.strftime("%Y%m%d_%H%M%S")

    def _dst(fmt: str) -> str:
        return require_within_base(
            os.path.join(target_dir, f"{safe}_report_{ts}.{fmt}"),
            "report write")

    # HTML is rendered once and reused for both the .html file and the
    # best-effort PDF (same template -> identical layout).
    want_html = "html" in formats
    want_pdf = "pdf" in formats
    html_str = render.render_html(ctx, sections) \
        if (want_html or want_pdf) else None

    paths = {}
    for fmt in formats:
        if fmt == "pdf":
            continue                       # handled after the text formats
        content = html_str if fmt == "html" else None
        if content is None:
            renderer = _RENDERERS.get(fmt)
            if renderer is None:
                continue
            content = renderer(ctx, sections)
        path = _dst(fmt)
        # CSV: render_csv uses csv.writer, which ALREADY emits "\r\n" line
        # terminators.  Opening in text mode without newline="" lets the
        # platform translate the "\n" again (-> "\r\r\n" on Windows: a blank
        # row between records in Excel).  newline="" disables that so CSV
        # rows end in a single "\r\n" everywhere.  HTML/MD keep native EOL.
        newline = "" if fmt == "csv" else None
        with open(path, "w", newline=newline, encoding="utf-8") as f:
            f.write(content)
        paths[fmt] = path

    # ── Optional PDF: best-effort, binary, silent on absence ──
    if want_pdf and html_str is not None:
        pdf_bytes = render.render_pdf_from_html(html_str)
        if pdf_bytes:
            path = _dst("pdf")
            with open(path, "wb") as f:
                f.write(pdf_bytes)
            paths["pdf"] = path
        else:
            # render_pdf_from_html already logged the reason; the result
            # dict simply carries no "pdf" key and HTML/MD/CSV stand.
            print("[HAWK] report: PDF format requested but WeasyPrint "
                  "unavailable — HTML/MD/CSV produced, PDF skipped.",
                  file=sys.stderr)
    return paths


def result_summary(paths: dict) -> str:
    """Human-readable one-liner of what was produced, for the caller to
    show the operator.  When PDF was requested-but-skipped, appends a
    clear pointer to print the HTML from a browser.  Pure + headless so
    the caller's messaging is unit-testable."""
    made = [f.upper() for f in ("html", "pdf", "md", "csv") if f in paths]
    msg = ("Generated: " + ", ".join(made)) if made \
        else "No report produced"
    if "pdf" not in paths:
        note = "PDF not available"
        if not render.weasyprint_available():
            note += (" (WeasyPrint not installed) — open the HTML and "
                     "print to PDF from your browser")
        msg += "  |  " + note
    return msg
