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
Render targets: HTML (primary, self-contained), Markdown, CSV.

All three consume the SAME ordered list of Sections + the shared
ReportContext, so the numbers are identical across formats by
construction.  Each target switches only on ``Block.type`` — adding a
provider that reuses the block vocabulary needs no change here.

HTML uses a SINGLE Jinja2 template with inline CSS and a base64-embedded
logo: no external assets, no CDN, no remote fonts — it opens offline.
Markdown and CSV are pure-Python (no jinja2 needed), so the engine still
produces those formats even if jinja2 were somehow unavailable.
"""

from __future__ import annotations

import csv
import io
import json

from utils.config import APP_NAME, APP_VERSION


# ─── HTML (primary deliverable) ─────────────────────────────────────────────

_TEMPLATE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ doc_title }}</title>
<style>
  :root { --crit:#b00020; --high:#d9534f; --med:#e0a800; --low:#2e7d32;
          --info:#607d8b; --ink:#1a1f24; --muted:#5b6770; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial,
         sans-serif; color:#1a1f24; max-width:980px; margin:0 auto;
         padding:32px 28px; line-height:1.5; background:#fff; }
  header.brand { border-bottom:3px solid #00838f; padding-bottom:16px;
                 margin-bottom:24px; display:flex; align-items:center;
                 gap:18px; }
  header.brand img { max-height:64px; max-width:200px; }
  header.brand .meta { flex:1; }
  header.brand h1 { margin:0 0 4px; font-size:24px; }
  header.brand .sub { color:#5b6770; font-size:13px; }
  h2 { margin-top:34px; padding-bottom:6px; border-bottom:1px solid #d7dde2;
       font-size:19px; }
  h3 { font-size:15px; margin:18px 0 8px; }
  h4 { font-size:14px; margin:18px 0 6px; }
  table { border-collapse:collapse; width:100%; margin:10px 0; font-size:13px; }
  th, td { border:1px solid #d7dde2; padding:6px 9px; text-align:left;
           vertical-align:top; }
  th { background:#f1f4f6; }
  dl.kv { display:grid; grid-template-columns:max-content 1fr; gap:4px 16px;
          margin:8px 0; font-size:14px; }
  dl.kv dt { font-weight:600; color:#3a444c; }
  dl.kv dd { margin:0; }
  pre { background:#f6f8fa; border:1px solid #e1e4e8; border-radius:5px;
        padding:10px 12px; overflow:auto; font-size:12px;
        white-space:pre-wrap; word-wrap:break-word; }
  .sev { display:inline-block; padding:1px 8px; border-radius:10px;
         color:#fff; font-size:11px; font-weight:700; letter-spacing:.3px; }
  .sev-critical{background:var(--crit);} .sev-high{background:var(--high);}
  .sev-medium{background:var(--med);} .sev-low{background:var(--low);}
  .sev-info{background:var(--info);}
  .finding { border:1px solid #e1e4e8; border-left-width:4px; border-radius:6px;
             padding:12px 14px; margin:12px 0; }
  .finding.sevb-critical{border-left-color:var(--crit);}
  .finding.sevb-high{border-left-color:var(--high);}
  .finding.sevb-medium{border-left-color:var(--med);}
  .finding.sevb-low{border-left-color:var(--low);}
  .finding.sevb-info{border-left-color:var(--info);}
  .finding h4 { margin:0 0 6px; }
  .finding .src { color:#5b6770; font-size:12px; }
  .note { background:#fff8e1; border:1px solid #ffe0a3; border-radius:5px;
          padding:8px 10px; font-size:13px; margin:8px 0; }
  .phase { margin:14px 0; }
  .phase .status { color:#5b6770; font-size:12px; font-weight:600; }
  details { margin:6px 0; }
  summary { cursor:pointer; font-size:13px; font-weight:600; }
  footer { margin-top:40px; padding-top:14px; border-top:1px solid #d7dde2;
           color:#8a949c; font-size:12px; }
</style>
</head>
<body>
<header class="brand">
  {% if branding.logo_data_uri %}<img src="{{ branding.logo_data_uri }}" alt="logo">{% endif %}
  <div class="meta">
    <h1>{{ branding.firm_name or (app_name ~ ' Pentest Report') }}</h1>
    <div class="sub">
      {% if branding.firm_name %}Penetration Test Report &middot; {% endif %}
      Target <strong>{{ target }}</strong> &middot; {{ generated }}
      {% if branding.client_name %}<br>Prepared for {{ branding.client_name }}{% endif %}
      {% if branding.prepared_by %} &middot; by {{ branding.prepared_by }}{% endif %}
    </div>
  </div>
</header>

{% for section in sections %}
<section id="sec-{{ section.id }}">
<h2>{{ section.title }}</h2>
{% for block in section.blocks %}
  {% if block.type == 'keyvalue' %}
    <dl class="kv">
      {% for row in block.data.rows %}<dt>{{ row[0] }}</dt><dd>{{ row[1] }}</dd>{% endfor %}
    </dl>
  {% elif block.type == 'table' %}
    <table>
      <thead><tr>{% for c in block.data.columns %}<th>{{ c }}</th>{% endfor %}</tr></thead>
      <tbody>
      {% for row in block.data.rows %}<tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>{% endfor %}
      </tbody>
    </table>
  {% elif block.type == 'paragraph' %}
    <p>{{ block.data.text }}</p>
  {% elif block.type == 'findings' %}
    {% for it in block.data['items'] %}
    <div class="finding sevb-{{ it.severity_key }}">
      <h4>{{ it.n }}. {{ it.title }}
        <span class="sev sev-{{ it.severity_key }}">{{ it.severity }}</span></h4>
      <div class="src">Source: {{ it.source or '-' }}
        {%- if it.overridden %} &middot; severity overridden (objective: {{ it.original_severity }}){% endif %}</div>
      {% if it.fields %}<dl class="kv">{% for fr in it.fields %}<dt>{{ fr[0] }}</dt><dd>{{ fr[1] }}</dd>{% endfor %}</dl>{% endif %}
      {% if it.description %}<pre>{{ it.description }}</pre>{% endif %}
      {% if it.impact %}<p><strong>Impact:</strong> {{ it.impact }}</p>{% endif %}
      {% if it.remediation %}<p><strong>Remediation:</strong> {{ it.remediation }}</p>{% endif %}
      {% if it.operator_note %}<div class="note"><strong>Note:</strong> {{ it.operator_note }}</div>{% endif %}
    </div>
    {% endfor %}
  {% elif block.type == 'phases' %}
    {% for ph in block.data['items'] %}
    <div class="phase">
      <h3>{{ ph.icon }}{% if ph.icon %} &middot; {% endif %}{{ ph.label }}
        <span class="status">[{{ ph.status }}]</span></h3>
      {% if ph.findings %}
        <ul>{% for f in ph.findings %}<li><span class="sev sev-{{ f.severity|lower }}">{{ f.severity }}</span> {{ f.title }}</li>{% endfor %}</ul>
      {% else %}<p class="src">No findings recorded.</p>{% endif %}
      {% for o in ph.outputs %}
      <details><summary>{{ o.tool }} &middot; {{ o.ts }}</summary><pre>{% for ln in o.lines %}{{ ln }}
{% endfor %}</pre></details>
      {% endfor %}
    </div>
    {% endfor %}
  {% endif %}
{% endfor %}
</section>
{% endfor %}

<footer>Generated by {{ app_name }} v{{ app_version }} &middot; {{ generated }} &middot; Created by Lorenzo Serafini</footer>
</body>
</html>
"""


def weasyprint_available() -> bool:
    """True iff WeasyPrint imports AND its native stack (pango/cairo/
    fontconfig) loads.  The expected default state is False — PDF is an
    optional enhancement, never a declared dependency."""
    try:
        import weasyprint  # noqa: F401
        return True
    except Exception:
        return False


def render_pdf_from_html(html: str) -> "bytes | None":
    """Best-effort PDF: render the ALREADY-built self-contained HTML to
    PDF bytes via WeasyPrint, so the PDF is byte-identical in layout to
    the HTML deliverable.  Returns the PDF bytes, or None when WeasyPrint
    (or its native libs) is unavailable or rendering fails.

    NEVER raises — the absence of WeasyPrint is the normal, expected
    state, not an error.  This is the ONE auditable WeasyPrint
    touch-point in HAWK: keep all WeasyPrint imports here.
    """
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except Exception as e:
        import sys as _s
        print(f"[HAWK] PDF skipped (WeasyPrint unavailable): "
              f"{type(e).__name__}: {e}", file=_s.stderr)
        return None


def render_html(ctx, sections) -> str:
    """Render the single self-contained HTML deliverable.  jinja2 is
    imported lazily so the engine module stays importable (and MD/CSV
    keep working) even if jinja2 is unavailable."""
    try:
        from jinja2 import Environment, select_autoescape
    except Exception as e:   # pragma: no cover - jinja2 ships in requirements
        raise RuntimeError(
            "HTML report needs jinja2 (pip install -r requirements.txt): "
            f"{e}")
    env = Environment(autoescape=select_autoescape(["html", "xml"]),
                      trim_blocks=True, lstrip_blocks=True)
    tmpl = env.from_string(_TEMPLATE_HTML)
    return tmpl.render(
        doc_title=f"{APP_NAME} Pentest Report — {ctx.session.target_ip}",
        app_name=APP_NAME, app_version=APP_VERSION,
        branding=ctx.branding,
        target=ctx.session.target_ip or "",
        generated=ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        sections=sections,
    )


# ─── Markdown (reconciles the legacy reporting.py serializer) ───────────────

def render_markdown(ctx, sections) -> str:
    b = ctx.branding
    out = []
    title = b.get("firm_name") or f"{APP_NAME} Pentest Report"
    out += [f"# {title}", ""]
    sub = [f"**Target**: `{ctx.session.target_ip}`",
           f"**Date**: {ctx.generated_at.strftime('%Y-%m-%d %H:%M:%S')}"]
    if b.get("client_name"):
        sub.append(f"**Client**: {b['client_name']}")
    if b.get("prepared_by"):
        sub.append(f"**Prepared by**: {b['prepared_by']}")
    out += ["  ".join(s + "  " for s in sub), "", "---", ""]

    for section in sections:
        out += [f"## {section.title}", ""]
        for block in section.blocks:
            out += _md_block(block)
        out += ["---", ""]
    out += [f"*Generated by {APP_NAME} v{APP_VERSION} - Created by Lorenzo Serafini*"]
    return "\n".join(out)


def _md_escape_cell(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def _md_safe(v) -> str:
    s = "" if v is None else str(v)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_fence_line(line) -> str:
    s = str(line)
    if s.lstrip().startswith("```"):
        return s.replace("```", "`` `")
    return _md_safe(s)


def _md_block(block) -> list:
    t, d = block.type, block.data
    if t == "keyvalue":
        lines = ["| Field | Value |", "|-------|-------|"]
        for row in d.get("rows", []):
            lines.append(f"| {_md_escape_cell(row[0])} | "
                         f"{_md_escape_cell(row[1])} |")
        return lines + [""]
    if t == "table":
        cols = d.get("columns", [])
        lines = ["| " + " | ".join(cols) + " |",
                 "|" + "|".join(["---"] * len(cols)) + "|"]
        for row in d.get("rows", []):
            lines.append("| " + " | ".join(_md_escape_cell(c)
                                           for c in row) + " |")
        return lines + [""]
    if t == "paragraph":
        return [d.get("text", ""), ""]
    if t == "findings":
        lines = []
        for it in d.get("items", []):
            lines += [f"#### Finding {it['n']}: {_md_safe(it['title'])}", "",
                      f"**Severity**: {_md_safe(it['severity'])}  ",
                      f"**Source**: {_md_safe(it['source'] or '-')}  "]
            if it.get("overridden"):
                lines.append(f"**Severity overridden** (objective: "
                             f"{_md_safe(it['original_severity'])})  ")
            for fr in it.get("fields", []):
                lines.append(f"**{_md_safe(fr[0])}**: `{_md_safe(fr[1])}`  ")
            lines.append("")
            if it.get("description"):
                lines += ["```", _md_fence_line(it["description"]), "```", ""]
            if it.get("impact"):
                lines += [f"**Impact**: {_md_safe(it['impact'])}", ""]
            if it.get("remediation"):
                lines += [f"**Remediation**: {_md_safe(it['remediation'])}", ""]
            if it.get("operator_note"):
                lines += [f"**Note**: {_md_safe(it['operator_note'])}", ""]
        return lines
    if t == "phases":
        lines = []
        for ph in d.get("items", []):
            marker = f"{_md_safe(ph['icon'])} · " if ph.get("icon") else ""
            lines += [f"### {marker}{_md_safe(ph['label'])}", "",
                      f"**Status**: `{_md_safe(ph['status'])}`", ""]
            if ph.get("findings"):
                for f in ph["findings"]:
                    lines.append(f"- **[{_md_safe(f['severity'])}]** "
                                 f"{_md_safe(f['title'])}")
                lines.append("")
            else:
                lines += ["_No findings recorded._", ""]
            for o in ph.get("outputs", []):
                lines += [f"<details>",
                          f"<summary><b>{_md_safe(o['tool'])}</b> — "
                          f"{_md_safe(o['ts'])}</summary>",
                          "", "```"]
                lines += [_md_fence_line(ln) for ln in o.get("lines", [])]
                lines += ["```", "", "</details>", ""]
        return lines
    return []


# ─── CSV (flat findings dump for the PM's spreadsheet) ──────────────────────

_CSV_COLUMNS = ["n", "effective_severity", "original_severity",
                "severity_overridden", "origin", "phase", "source",
                "title", "endpoint", "parameter", "confidence", "method",
                "port", "kev", "operator_note"]

# Excel / LibreOffice / Google Sheets treat a cell starting with any of
# these as a FORMULA.  Finding titles and descriptions are tool output —
# i.e. text the target controls — so an endpoint or banner beginning with
# "=" would execute on the PM's machine when they open the deliverable.
_CSV_FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value) -> str:
    """Neutralise a spreadsheet formula lead by prefixing an apostrophe —
    the standard defusing: the sheet shows the original text, the parser
    no longer sees a formula.  Non-strings pass through str()."""
    s = "" if value is None else str(value)
    if s[:1] in _CSV_FORMULA_LEADS:
        return "'" + s
    return s


def render_csv(ctx, sections=None) -> str:
    """Flat dump of the CURATED, visible findings (same set + same
    effective severity the HTML/MD counts use).  ``sections`` is accepted
    for a uniform render-target signature but unused: CSV is a findings
    export, not a section view."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV_COLUMNS)
    ordered = ctx.sort_by_severity(ctx.findings)
    for i, f in enumerate(ordered, 1):
        v = ctx.finding_view(f, i)
        fields = {k.lower(): val for k, val in v["fields"]}
        w.writerow([_csv_cell(c) for c in (
            v["n"], v["severity_key"], (v["original_severity"] or "").lower(),
            "yes" if v["overridden"] else "no", v["origin"], v["phase_id"],
            v["source"], v["title"], fields.get("endpoint", ""),
            fields.get("parameter", ""), fields.get("confidence", ""),
            fields.get("method", ""), fields.get("port", ""),
            fields.get("kev", ""),
            v["operator_note"].replace("\n", " "),
        )])
    return buf.getvalue()


# ─── JSON (machine-readable; same curated data as HTML/MD) ──────────────────

def render_json(ctx, sections) -> str:
    """Machine-readable deliverable with format parity: the summary numbers
    come from the SAME ReportContext the HTML/MD/CSV use, and the section
    tree is the SAME ordered Sections the text renderers consume — so a
    consumer parsing the JSON sees exactly the report's data, curated once.

    The branding logo data-URI is deliberately excluded (only firm /
    client / prepared-by strings are carried) so the JSON stays small and
    free of an embedded base64 blob."""
    b = ctx.branding
    doc = {
        "tool":      APP_NAME,
        "version":   APP_VERSION,
        "target":    ctx.session.target_ip or "",
        "generated": ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        "branding":  {k: b.get(k) for k in
                      ("firm_name", "client_name", "prepared_by")
                      if b.get(k)},
        "summary": {
            "total_findings":  ctx.total_findings,
            "high_critical":   ctx.high_critical,
            "severity_counts": dict(ctx.severity_counts),
            "kev":             ctx.kev_count,
            "kev_ransomware":  ctx.kev_ransomware_count,
        },
        "sections": [
            {"id": s.id, "title": s.title,
             "blocks": [{"type": bl.type, "data": bl.data} for bl in s.blocks]}
            for s in sections
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
