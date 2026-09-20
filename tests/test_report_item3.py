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

"""Report deliverable hardening (reporting re-confirmation on the dense
.177 AD session).  Three defects the critical read surfaced:

  e  The Credentials section named the accounts but dropped every
     recovered SECRET — the DCSync'd NT hashes, the cracked svc_*
     passwords, the vagrant password — and a verified/live credential
     showed no status ("-") at all.
  a  The ATT&CK section re-rendered every mapped finding as a second full
     card, so 75 findings became 95 visible cards with two "Finding 1"s
     and a HIGH card sitting above the criticals.
  h  A crashed tool's Python traceback (bloodhound-python) was dumped
     verbatim into the client-facing report.

All headless — no display, no customtkinter.
"""

import csv
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils.session import Session                                  # noqa: E402
from modules.report import engine, render                         # noqa: E402
from modules.report.model import ReportContext                    # noqa: E402
from modules.report.providers import (                            # noqa: E402
    CredentialsProvider, AttackProvider, _strip_internal_tracebacks)

try:
    import jinja2                                                  # noqa: F401
    _HAS_JINJA2 = True
except Exception:
    _HAS_JINJA2 = False


def _md(session) -> str:
    ctx = ReportContext(session)
    return render.render_markdown(ctx, engine.build_sections(ctx))


# ─── e — credentials must carry the recovered secrets + a real status ──────

class CredentialsSecretsTests(unittest.TestCase):

    def _session(self):
        s = Session("10.0.0.1")
        s.credentials = [
            {"cred_type": "cleartext", "username": "vagrant",
             "password": "vagrant", "verified": True},
            {"cred_type": "hash", "username": "svc_deleg",
             "hash_type": "Kerberos TGS", "cracked": True,
             "cracked_pass": "Password1", "hash_val": "$krb5tgs$23$*svc*"},
            {"cred_type": "hash", "username": "Administrator",
             "hash_type": "NTLM", "verified": False,
             "hash_val": ("Administrator:500:aad3b435b51404eeaad3b435b51404"
                          "ee:e02bc503339d51f71d913c245d35b50b:::")},
        ]
        return s

    def _rows(self):
        ctx = ReportContext(self._session())
        sec = CredentialsProvider().build(ctx)
        table = sec.blocks[0]
        self.cols = table.data["columns"]
        return {r[self.cols.index("Username")]: r for r in table.data["rows"]}

    def test_secret_column_exists(self):
        by = self._rows()
        self.assertIn("Secret / Hash", self.cols)

    def test_cleartext_password_and_valid_status(self):
        by = self._rows()
        row = by["vagrant"]
        self.assertEqual(row[self.cols.index("Secret / Hash")], "vagrant")
        # verified=True must read "valid", never the old bare "-".
        self.assertEqual(row[self.cols.index("Status")], "valid")

    def test_cracked_password_is_shown(self):
        by = self._rows()
        row = by["svc_deleg"]
        self.assertEqual(row[self.cols.index("Secret / Hash")], "Password1")
        self.assertEqual(row[self.cols.index("Status")], "cracked")
        self.assertEqual(row[self.cols.index("Type")], "hash (Kerberos TGS)")

    def test_nt_hash_is_shown(self):
        by = self._rows()
        row = by["Administrator"]
        self.assertIn("e02bc503339d51f71d913c245d35b50b",
                      row[self.cols.index("Secret / Hash")])
        self.assertEqual(row[self.cols.index("Type")], "hash (NTLM)")
        self.assertEqual(row[self.cols.index("Status")], "unverified")

    def test_secrets_reach_the_rendered_markdown(self):
        body = _md(self._session())
        self.assertIn("Secret / Hash", body)
        self.assertIn("e02bc503339d51f71d913c245d35b50b", body)
        self.assertIn("Password1", body)


# ─── a — ATT&CK maps findings, it does not re-render them ──────────────────

class AttackNoDuplicateCardsTests(unittest.TestCase):

    def _session(self):
        s = Session("10.0.0.2")
        s.target_intel = {"auto_findings": [
            {"title": "DCSYNC dumped 10 NTLM hashes", "severity": "critical",
             "source": "secretsdump", "technique_ids": ["T1003.006"]},
            {"title": "KERBEROAST 2 TGS hashes", "severity": "high",
             "source": "kerberoast", "technique_ids": ["T1558.003"]},
            {"title": "Anonymous FTP login", "severity": "medium",
             "source": "nmap"},                     # resolves to nothing
        ]}
        return s

    def test_total_finding_cards_equal_the_finding_count(self):
        """Two of the three findings map to ATT&CK. The old section
        re-rendered those two as full cards -> 5 cards for 3 findings."""
        s = self._session()
        ctx = ReportContext(s)
        self.assertEqual(ctx.total_findings, 3)
        body = render.render_markdown(ctx, engine.build_sections(ctx))
        self.assertEqual(body.count("#### Finding "), 3)

    @unittest.skipUnless(_HAS_JINJA2, "jinja2 not installed")
    def test_html_cards_equal_the_finding_count(self):
        s = self._session()
        ctx = ReportContext(s)
        html = render.render_html(ctx, engine.build_sections(ctx))
        self.assertEqual(html.count('class="finding '), 3)

    def test_attack_section_still_maps_techniques(self):
        s = self._session()
        ctx = ReportContext(s)
        sec = AttackProvider().build(ctx)
        # coverage table + evidence index, both tables, no findings block
        self.assertTrue(all(b.type == "table" for b in sec.blocks))
        body = render.render_markdown(ctx, engine.build_sections(ctx))
        self.assertIn("MITRE ATT&CK Coverage", body)
        self.assertIn("T1003.006", body)
        self.assertIn("T1558.003", body)
        self.assertIn("Technique(s)", body)

    def test_csv_and_markdown_agree_on_the_count(self):
        s = self._session()
        ctx = ReportContext(s)
        rows = list(csv.reader(io.StringIO(render.render_csv(ctx))))
        self.assertEqual(len(rows) - 1, 3)          # minus header


# ─── h — a tool's Python traceback must not reach the report ───────────────

class TracebackStripTests(unittest.TestCase):

    _LINES = [
        "INFO: BloodHound.py starting",
        "Traceback (most recent call last):",
        '  File "/usr/bin/bloodhound-python", line 33, in <module>',
        "    sys.exit(load_entry_point()())",
        "    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^",
        "ImportError: cannot import name 'ADAuthentication'",
        "INFO: collection finished",
    ]

    def test_unit_strips_the_block_keeps_the_rest(self):
        out = _strip_internal_tracebacks(self._LINES)
        self.assertNotIn("Traceback (most recent call last):", out)
        self.assertFalse(any("ImportError" in l for l in out))
        self.assertFalse(any("bloodhound-python" in l for l in out))
        self.assertTrue(any("traceback omitted" in l for l in out))
        # output before AND after the block survives
        self.assertIn("INFO: BloodHound.py starting", out)
        self.assertIn("INFO: collection finished", out)

    def test_no_traceback_is_left_untouched(self):
        clean = ["line a", "line b", "SeDebugPrivilege enabled"]
        self.assertEqual(_strip_internal_tracebacks(clean), clean)

    def test_traceback_does_not_reach_the_report(self):
        s = Session("10.0.0.3")
        pid = list(s.phases.keys())[0]
        s.phases[pid]["output"] = [{
            "tool": "BLOODHOUND", "timestamp": "2026-09-10T15:10:00",
            "lines": list(self._LINES)}]
        body = _md(s)
        self.assertNotIn("Traceback (most recent call last):", body)
        self.assertIn("[tool traceback omitted from report]", body)
        self.assertIn("INFO: collection finished", body)


# ─── g — JSON is a real format with parity to HTML/MD/CSV ──────────────────

class JsonFormatParityTests(unittest.TestCase):

    def _session(self):
        s = Session("10.0.0.4")
        s.target_intel = {"auto_findings": [
            {"title": "DCSYNC dumped hashes", "severity": "critical",
             "source": "secretsdump", "technique_ids": ["T1003.006"]},
            {"title": "KERBEROAST 2 TGS", "severity": "high",
             "source": "kerberoast", "technique_ids": ["T1558.003"]},
            {"title": "Anonymous FTP login", "severity": "medium",
             "source": "nmap"},
        ]}
        s.credentials = [{"cred_type": "hash", "username": "Administrator",
                          "hash_type": "NTLM", "hash_val": "Administrator:500"}]
        return s

    def test_json_is_registered_as_a_format(self):
        self.assertIn("json", engine.REPORT_FORMATS)
        self.assertIn("json", engine._RENDERERS)

    def test_render_json_is_valid_and_carries_the_summary(self):
        s = self._session()
        ctx = ReportContext(s)
        doc = json.loads(render.render_json(ctx, engine.build_sections(ctx)))
        self.assertEqual(doc["summary"]["total_findings"], ctx.total_findings)
        self.assertEqual(doc["summary"]["severity_counts"],
                         dict(ctx.severity_counts))
        self.assertEqual(doc["target"], "10.0.0.4")

    def test_json_sections_mirror_the_other_formats(self):
        s = self._session()
        ctx = ReportContext(s)
        sections = engine.build_sections(ctx)
        doc = json.loads(render.render_json(ctx, sections))
        self.assertEqual([sec["id"] for sec in doc["sections"]],
                         [sec.id for sec in sections])
        # a finding title and a recovered secret are both present
        blob = json.dumps(doc)
        self.assertIn("DCSYNC dumped hashes", blob)
        self.assertIn("Administrator:500", blob)

    def test_count_parity_json_matches_csv_and_markdown(self):
        s = self._session()
        ctx = ReportContext(s)
        doc = json.loads(render.render_json(ctx, engine.build_sections(ctx)))
        csv_rows = len(list(csv.reader(
            io.StringIO(render.render_csv(ctx))))) - 1
        md_cards = render.render_markdown(
            ctx, engine.build_sections(ctx)).count("#### Finding ")
        self.assertEqual(doc["summary"]["total_findings"], 3)
        self.assertEqual(csv_rows, 3)
        self.assertEqual(md_cards, 3)

    def test_generate_writes_a_json_file(self):
        d = tempfile.mkdtemp(prefix="_repjson_", dir=os.path.dirname(__file__))
        try:
            paths = engine.generate(self._session(),
                                    formats=("csv", "md", "json"), out_dir=d)
            self.assertIn("json", paths)
            with open(paths["json"], encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["summary"]["total_findings"], 3)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_json_survives_a_dead_html_target(self):
        """JSON has no third-party dependency, like MD/CSV: an HTML blow-up
        must not cost it."""
        d = tempfile.mkdtemp(prefix="_repjson2_",
                             dir=os.path.dirname(__file__))
        real = render.render_html
        try:
            render.render_html = lambda ctx, sections: (_ for _ in ()).throw(
                RuntimeError("boom"))
            paths = engine.generate(self._session(),
                                    formats=("html", "json"), out_dir=d)
            self.assertNotIn("html", paths)
            self.assertIn("json", paths)
        finally:
            render.render_html = real
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
