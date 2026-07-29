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
Core section providers.

Each returns a Section of typed Blocks (see model.py contract) built from
the shared, already-curated ReportContext.  Phase labels/order/count are
sourced from config.KILL_CHAIN_PHASES — the single source of truth — so a
phase is never silently dropped or duplicated here.
"""

from __future__ import annotations

from modules.report.model import (
    Block, Section, SectionProvider,
    BLOCK_KEYVALUE, BLOCK_TABLE, BLOCK_FINDINGS, BLOCK_PHASES,
    SEVERITIES,
)
from utils.config import KILL_CHAIN_PHASES


# Phase display metadata from the single source of truth.  Label is the
# config name title-cased (matches reporting.py); the numeric "NN" icon
# is used as an emoji-free phase marker.
_PHASE_META = {p["id"]: p for p in KILL_CHAIN_PHASES}
_PHASE_ORDER = [p["id"] for p in KILL_CHAIN_PHASES]


def _phase_label(phase_id: str) -> str:
    name = (_PHASE_META.get(phase_id, {}).get("name") or "").title()
    return name or phase_id.replace("_", " ").title()


def _phase_icon(phase_id: str) -> str:
    return _PHASE_META.get(phase_id, {}).get("icon", "")


class ExecutiveSummaryProvider(SectionProvider):
    id = "exec_summary"
    title = "Executive Summary"

    def build(self, ctx) -> "Section | None":
        s = ctx.session
        done = sum(1 for p in s.phases.values()
                   if isinstance(p, dict) and p.get("status") == "done")
        total_phases = len(KILL_CHAIN_PHASES)

        target = s.target_ip or ""
        if getattr(s, "target_domain", ""):
            target = f"{target} ({s.target_domain})"

        rows = [["Target", target]]
        if ctx.branding.get("client_name"):
            rows.append(["Client", ctx.branding["client_name"]])
        rows += [
            ["Test Date", ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S")],
            ["Phases Completed", f"{done}/{total_phases}"],
            ["Total Findings", str(ctx.total_findings)],
            ["High/Critical Issues", str(ctx.high_critical)],
            # KEV prioritization signal, counted over the SAME visible
            # findings via the shared cisa_kev helper (see ReportContext).
            ["Actively Exploited (KEV)", str(ctx.kev_count)],
            ["Ransomware-Linked", str(ctx.kev_ransomware_count)],
        ]

        # Severity breakdown over the curated set (effective severity).
        sev_rows = [[sev.upper(), str(ctx.severity_counts[sev])]
                    for sev in SEVERITIES]

        return Section(self.id, self.title, [
            Block(BLOCK_KEYVALUE, {"rows": rows}),
            Block(BLOCK_TABLE, {"columns": ["Severity", "Count"],
                                "rows": sev_rows}),
        ])


class TargetIntelProvider(SectionProvider):
    id = "target_intel"
    title = "Target Intelligence"

    def applies(self, ctx) -> bool:
        return bool(ctx.auto_findings())

    def build(self, ctx) -> "Section | None":
        auto = ctx.sort_by_severity(ctx.auto_findings())
        if not auto:
            return None
        views = [ctx.finding_view(f, i) for i, f in enumerate(auto, 1)]

        index_rows = [[str(v["n"]), v["severity"], v["source"] or "-",
                       v["title"]] for v in views]
        return Section(self.id, self.title, [
            Block(BLOCK_TABLE, {
                "columns": ["#", "Severity", "Source", "Title"],
                "rows": index_rows}),
            Block(BLOCK_FINDINGS, {"items": views}),
        ])


class CredentialsProvider(SectionProvider):
    id = "credentials"
    title = "Credentials Discovered"

    def _creds(self, ctx) -> list:
        try:
            return [c for c in (getattr(ctx.session, "credentials", []) or [])
                    if isinstance(c, dict)]
        except Exception:
            return []

    def applies(self, ctx) -> bool:
        return bool(self._creds(ctx))

    def build(self, ctx) -> "Section | None":
        creds = self._creds(ctx)
        if not creds:
            return None
        rows = []
        for i, c in enumerate(creds, 1):
            if c.get("cracked"):
                status = "cracked"
            elif c.get("verified") is False:
                status = "unverified"
            else:
                status = "-"
            rows.append([
                str(i),
                c.get("cred_type") or "-",
                c.get("username") or "-",
                "+".join(c.get("services") or []) or "any",
                c.get("host") or "any",
                c.get("source_phase") or "-",
                status,
            ])
        return Section(self.id, self.title, [
            Block(BLOCK_TABLE, {
                "columns": ["#", "Type", "Username", "Service(s)",
                            "Host", "Source", "Status"],
                "rows": rows}),
        ])


class ArgusProvider(SectionProvider):
    """Reserved provider slot for the ARGUS plugin.

    Product-first decision (#4): ARGUS occupies ONE provider slot exactly
    like a core section, through the SAME internal interface — but there
    is NO public registry or OSS contract spec yet.  Until a plugin fills
    this slot, ``applies`` is False so the engine skips it cleanly.  The
    slot existing here is what proves the architecture: a future ATT&CK
    or ARGUS section enters by adding a provider, never by touching a
    render target.
    """

    id = "argus"
    title = "ARGUS"

    def applies(self, ctx) -> bool:
        return False

    def build(self, ctx) -> "Section | None":
        return None


class PerPhaseProvider(SectionProvider):
    id = "phases"
    title = "Kill Chain Phases"

    def build(self, ctx) -> "Section | None":
        s = ctx.session
        items = []
        for pid in _PHASE_ORDER:
            pdata = s.phases.get(pid) if isinstance(s.phases, dict) else None
            if not isinstance(pdata, dict):
                continue
            findings = ctx.sort_by_severity(ctx.phase_findings(pid))
            f_views = [{"severity": ctx._eff(f).upper(),
                        "title": (f.title or "").strip() or "(untitled)"}
                       for f in findings]
            outputs = []
            for entry in (pdata.get("output") or []):
                if not isinstance(entry, dict):
                    continue
                outputs.append({
                    "tool": entry.get("tool", "unknown"),
                    "ts": (entry.get("timestamp", "") or "")[:16]
                          .replace("T", " "),
                    "lines": list(entry.get("lines") or []),
                })
            items.append({
                "id": pid,
                "label": _phase_label(pid),
                "icon": _phase_icon(pid),
                "status": (pdata.get("status", "ready") or "ready").upper(),
                "findings": f_views,
                "outputs": outputs,
            })
        return Section(self.id, self.title, [
            Block(BLOCK_PHASES, {"items": items}),
        ])


class AttackProvider(SectionProvider):
    """MITRE ATT&CK coverage by tactic, with evidence.

    For every VISIBLE finding it resolves technique ids (operator override
    Finding.technique_ids wins, else the curated auto-map in
    utils.attack), groups them by tactic via the offline reference, and
    emits a per-tactic coverage table plus a findings evidence block.
    Findings with no resolved technique simply don't appear — the matrix
    is never polluted.  Reuses ONLY the existing table + findings blocks,
    so it lands without touching any render target (the product-first
    architecture proof).
    """

    id = "attack"
    title = "MITRE ATT&CK Coverage"

    @staticmethod
    def _short(name: str, maxlen: int = 48) -> str:
        # Technique names are long ("Steal or Forge Kerberos Tickets:
        # Kerberoasting"); keep the part after the last colon for the
        # compact label.
        n = name.split(":")[-1].strip() if ":" in name else name
        return n if len(n) <= maxlen else n[:maxlen - 3] + "..."

    def _resolved(self, ctx) -> list:
        """[(finding, [AttackTechnique, ...])] for visible findings that
        resolve to at least one KNOWN technique."""
        from utils import attack as _at
        out = []
        for f in ctx.findings:
            ids = _at.resolve_finding(
                getattr(f, "source", "") or "",
                getattr(f, "title", "") or "",
                getattr(f, "technique_ids", None))
            techs = [t for t in (_at.technique(i) for i in ids) if t]
            if techs:
                out.append((f, techs))
        return out

    def applies(self, ctx) -> bool:
        return bool(self._resolved(ctx))

    def build(self, ctx) -> "Section | None":
        from utils import attack as _at
        resolved = self._resolved(ctx)
        if not resolved:
            return None

        tac_techs: dict = {}     # tactic -> {tech_id: name}
        tac_findings: dict = {}  # tactic -> set(finding number)
        views = []
        for n, (f, techs) in enumerate(resolved, 1):
            view = ctx.finding_view(f, n)
            label = ", ".join(f"{t.id} {self._short(t.name)}" for t in techs)
            view["fields"] = list(view["fields"]) + [["ATT&CK", label]]
            views.append(view)
            for t in techs:
                for tac in (t.tactics or ("Unmapped",)):
                    tac_techs.setdefault(tac, {})[t.id] = t.name
                    tac_findings.setdefault(tac, set()).add(n)

        rows = []
        for tac in sorted(tac_techs, key=_at.tactic_index):
            techs_map = tac_techs[tac]
            tech_str = ", ".join(f"{tid} {self._short(name)}"
                                 for tid, name in sorted(techs_map.items()))
            rows.append([tac, tech_str,
                         str(len(tac_findings.get(tac, ())))])

        return Section(self.id, self.title, [
            Block(BLOCK_TABLE, {
                "columns": ["Tactic", "Techniques", "Findings"],
                "rows": rows}),
            Block(BLOCK_FINDINGS, {"items": views}),
        ])


# Ordered provider list — the report's section order.  ATT&CK sits high
# (right after the executive summary) so the tactic coverage frames the
# detail below.  The ARGUS slot sits among the core providers (after
# credentials) so a filled plugin lands in a sensible place without
# reordering.  Append new core providers here; render targets are
# untouched as long as they reuse the Block vocabulary.
CORE_PROVIDERS = [
    ExecutiveSummaryProvider(),
    AttackProvider(),
    TargetIntelProvider(),
    CredentialsProvider(),
    ArgusProvider(),
    PerPhaseProvider(),
]
