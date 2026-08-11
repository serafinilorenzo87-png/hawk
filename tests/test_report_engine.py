"""Report-engine contracts (TIER 2 of the whole-app audit).

The report is the only artefact the operator hands to the client, so the
three things it must never do:

  H7  come out EMPTY without saying so.  The live findings sit in the
      Target Intel panel; the report reads the SESSION.  Nothing copied
      one into the other until a save happened — and autosave is off by
      default, so "run the tools, click REPORT" shipped a report with no
      findings, no Target Intelligence section and no error.
  H8  lose the operator's curation on the next save.  The session's
      auto-findings are clones rebuilt from the panel on every save, so
      curating the clone meant the excluded false positive came back.
  H9  mutate the session when the operator clicks Cancel.  The setters
      write straight into the persisted dicts.

Plus the hardening around them: the logo path (H10/M22), CSV formula
injection (M20) and per-format degradation (M15).

No display and no customtkinter needed — the whole path under test is
headless by design.
"""

import ast
import csv
import io
import os
import shutil
import sys
import tempfile
import unittest
from copy import deepcopy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import utils.session as session_mod                       # noqa: E402
from utils.session import Session, Finding                # noqa: E402
from utils.target_intel_sync import sync_target_intel     # noqa: E402
from modules.report import engine, model, render          # noqa: E402
from modules.report.curation import CurationController    # noqa: E402
from modules.report.model import ReportContext            # noqa: E402

try:                                        # HTML is the only format
    import jinja2                           # with a third-party dep
    _HAS_JINJA2 = True
except Exception:
    _HAS_JINJA2 = False


# ─── fakes: the smallest thing that looks like the running app ─────────────

class _FakeIntel:
    """Stand-in for TargetIntelWidget: only the three attributes the
    snapshot reads."""

    def __init__(self, auto_findings):
        self._auto_findings = auto_findings
        self._fp = None
        self._exploits = []


class _FakeApp:
    def __init__(self, auto_findings):
        self.target_intel = _FakeIntel(auto_findings)


def _live_findings():
    return [
        {"title": "Anonymous FTP login allowed", "severity": "high",
         "source": "nmap", "description": "vsftpd 2.3.4 anonymous login",
         "run_count": 2, "occurrences": [{"n": 1}],
         # in-memory-only keys: the snapshot must drop these
         "_frame_ref": object(), "_raw_description": "token=SECRET"},
        {"title": "Directory listing /backup", "severity": "medium",
         "source": "gobuster", "description": "autoindex on"},
    ]


def _session_with_live_app():
    s = Session("10.10.10.5")
    s.target_intel = {}                     # never saved: the H7 setup
    app = _FakeApp(_live_findings())
    return s, app


def _titles_in_report(session) -> str:
    ctx = ReportContext(session)
    return render.render_markdown(ctx, engine.build_sections(ctx))


# ─── H7 — the report must see findings that were never saved ───────────────

class ReportSeesLiveFindingsTests(unittest.TestCase):

    def test_unsynced_session_is_the_empty_report(self):
        """The bug, pinned: without the snapshot the session knows
        nothing, and nothing anywhere says so."""
        s, _app = _session_with_live_app()
        ctx = ReportContext(s)
        self.assertEqual(ctx.total_findings, 0)

    def test_sync_makes_the_live_findings_reach_the_report(self):
        s, app = _session_with_live_app()

        self.assertTrue(sync_target_intel(app, s))

        ctx = ReportContext(s)
        self.assertEqual(ctx.total_findings, 2)
        body = render.render_markdown(ctx, engine.build_sections(ctx))
        self.assertIn("Anonymous FTP login allowed", body)
        self.assertIn("Directory listing /backup", body)

    def test_curation_collects_the_live_findings(self):
        s, app = _session_with_live_app()
        sync_target_intel(app, s)

        ctrl = CurationController(s, app=app)

        self.assertEqual(ctrl.included_count(), (2, 2))
        self.assertEqual(ctrl.warning(), "")

    def test_snapshot_drops_the_in_memory_only_keys(self):
        s, app = _session_with_live_app()
        sync_target_intel(app, s)

        saved = s.target_intel["auto_findings"][0]
        self.assertNotIn("_frame_ref", saved)
        self.assertNotIn("_raw_description", saved)
        # ... and keeps the merge bookkeeping the report and the panel
        # both rely on.
        self.assertEqual(saved["run_count"], 2)
        self.assertEqual(saved["occurrences"], [{"n": 1}])

    def test_empty_collection_is_reported_not_swallowed(self):
        s = Session("10.10.10.5")
        s.target_intel = {}

        ctrl = CurationController(s)

        self.assertEqual(ctrl.included_count(), (0, 0))
        self.assertTrue(ctrl.warning())
        self.assertIn("EMPTY", ctrl.warning())

    def test_report_button_syncs_before_opening_the_curation_dialog(self):
        """The runtime wiring, statically: `_generate_report` must take
        the snapshot BEFORE the dialog reads the session.  Order matters
        — syncing after would be the same empty report."""
        path = os.path.join(ROOT, "gui", "widgets", "card_widget.py")
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)

        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_generate_report")
        calls = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                name = (f.id if isinstance(f, ast.Name)
                        else getattr(f, "attr", ""))
                if name in ("sync_target_intel", "open_curation_dialog"):
                    calls.append((node.lineno, name))
        ordered = [name for _ln, name in sorted(calls)]

        self.assertIn("sync_target_intel", ordered)
        self.assertIn("open_curation_dialog", ordered)
        self.assertLess(ordered.index("sync_target_intel"),
                        ordered.index("open_curation_dialog"))


# ─── H8 — curation must survive the next save ──────────────────────────────

class CurationSurvivesSaveTests(unittest.TestCase):

    def test_curation_of_an_auto_finding_survives_the_next_snapshot(self):
        s, app = _session_with_live_app()
        sync_target_intel(app, s)           # what the REPORT path does
        ctrl = CurationController(s, app=app)

        ftp = next(it for it in ctrl.items
                   if it.raw["title"].startswith("Anonymous FTP"))
        ctrl.set_false_positive(ftp, True)
        ctrl.set_operator_note(ftp, "vendor appliance, by design")
        ctrl.set_severity_override(ftp, "low")
        ctrl.set_techniques(ftp, "t1078, t1133")
        self.assertEqual(ctrl.included_count(), (1, 2))

        # ... and now the operator presses SAVE ten minutes later.
        sync_target_intel(app, s)

        saved = next(f for f in s.target_intel["auto_findings"]
                     if f["title"].startswith("Anonymous FTP"))
        self.assertTrue(saved["false_positive"])
        self.assertEqual(saved["operator_note"], "vendor appliance, by design")
        self.assertEqual(saved["severity_override"], "low")
        self.assertEqual(saved["technique_ids"], ["T1078", "T1133"])
        # The objective severity is never overwritten.
        self.assertEqual(saved["severity"], "high")
        # The false positive stays OUT of the report.
        ctx = ReportContext(s)
        self.assertEqual(ctx.total_findings, 1)
        self.assertNotIn("Anonymous FTP login allowed",
                         render.render_markdown(ctx,
                                                engine.build_sections(ctx)))

    def test_curation_writes_through_to_the_live_panel_list(self):
        s, app = _session_with_live_app()
        sync_target_intel(app, s)
        ctrl = CurationController(s, app=app)

        ctrl.set_included(ctrl.items[0], False)

        live = app.target_intel._auto_findings
        self.assertIs(ctrl.items[0].raw, live[0])
        self.assertFalse(live[0]["included"])

    def test_without_an_app_it_curates_the_session_snapshot(self):
        """A session loaded from disk has no live panel behind it — the
        session copy IS authoritative there."""
        s = Session("10.10.10.5")
        s.target_intel = {"auto_findings": [
            {"title": "Self-XSS in profile", "severity": "medium",
             "source": "manual"}]}

        ctrl = CurationController(s)

        self.assertEqual(ctrl.included_count(), (1, 1))
        ctrl.set_false_positive(ctrl.items[0], True)
        self.assertTrue(s.target_intel["auto_findings"][0]["false_positive"])


# ─── H9 — Cancel must actually cancel ──────────────────────────────────────

class CurationRollbackTests(unittest.TestCase):

    def _controller(self):
        s = Session("10.10.10.5")
        s.phases["vuln_scan"]["findings"] = [
            {"text": "TLS 1.0 enabled", "severity": "medium",
             "timestamp": "2026-06-11T10:00:00"}]
        s.target_intel = {"auto_findings": [
            # one finding that ALREADY carries curation from an earlier
            # review: revert must restore those values, not erase them.
            {"title": "Directory listing /backup", "severity": "high",
             "source": "gobuster", "operator_note": "confirmed on 07-14",
             "technique_ids": ["T1083"], "included": False}]}
        return s, CurationController(s)

    def test_revert_restores_the_exact_prior_state(self):
        s, ctrl = self._controller()
        before = deepcopy([it.raw for it in ctrl.items])

        for it in ctrl.items:
            ctrl.set_included(it, False)
            ctrl.set_false_positive(it, True)
            ctrl.set_severity_override(it, "critical")
            ctrl.set_operator_note(it, "scratch note")
            ctrl.set_techniques(it, "T1190")
        self.assertNotEqual([it.raw for it in ctrl.items], before)

        ctrl.revert()

        self.assertEqual([it.raw for it in ctrl.items], before)

    def test_revert_removes_keys_that_were_absent(self):
        """A cancelled exclusion must not linger as an explicit
        ``included: True`` — the key was ABSENT and has to be absent
        again, or the session JSON grows keys the operator never set."""
        s, ctrl = self._controller()
        phase_item = next(it for it in ctrl.items if it.origin == "phase")

        ctrl.set_included(phase_item, False)
        ctrl.set_operator_note(phase_item, "maybe")
        self.assertIn("included", phase_item.raw)

        ctrl.revert()

        self.assertNotIn("included", phase_item.raw)
        self.assertNotIn("operator_note", phase_item.raw)
        self.assertNotIn("severity_override", phase_item.raw)

    def test_revert_restores_pre_existing_curation_values(self):
        s, ctrl = self._controller()
        auto = next(it for it in ctrl.items if it.origin == "auto")

        ctrl.set_operator_note(auto, "overwritten")
        ctrl.set_techniques(auto, "T9999")
        ctrl.set_included(auto, True)
        ctrl.revert()

        self.assertEqual(auto.raw["operator_note"], "confirmed on 07-14")
        self.assertEqual(auto.raw["technique_ids"], ["T1083"])
        self.assertIs(auto.raw["included"], False)

    def test_revert_is_scoped_to_the_curation_keys(self):
        s, ctrl = self._controller()
        auto = next(it for it in ctrl.items if it.origin == "auto")
        auto.raw["run_count"] = 7           # merge bookkeeping, not curation

        ctrl.set_false_positive(auto, True)
        ctrl.revert()

        self.assertEqual(auto.raw["run_count"], 7)
        self.assertEqual(auto.raw["severity"], "high")

    def test_baseline_covers_every_curation_key(self):
        """If a curation key is ever added to the model, revert() has to
        learn about it in the same commit."""
        s, ctrl = self._controller()
        setters = ("set_included", "set_false_positive",
                   "set_severity_override", "set_operator_note",
                   "set_techniques")
        self.assertEqual(len(Finding._CURATION_KEYS), len(setters))


# ─── H10 / M22 — the logo is a path the operator chose ─────────────────────

class LogoEmbeddingTests(unittest.TestCase):

    # 1x1 transparent PNG.
    _PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00"
            b"\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\n"
            b"IDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00"
            b"\x00IEND\xaeB`\x82")

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="_logo_",
                                    dir=os.path.dirname(__file__))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, name, payload):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(payload)
        return path

    def test_logo_inside_the_tree_is_embedded(self):
        uri = model._logo_data_uri(self._write("logo.png", self._PNG))
        self.assertTrue(uri.startswith("data:image/png;base64,"))

    def test_logo_outside_the_tree_is_refused(self):
        outside = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        outside.write(self._PNG)
        outside.close()
        try:
            self.assertEqual(model._logo_data_uri(outside.name), "")
        finally:
            os.unlink(outside.name)

    def test_traversal_out_of_the_tree_is_refused(self):
        self.assertEqual(
            model._logo_data_uri(os.path.join("..", "..", "etc", "logo.png")),
            "")

    def test_oversized_logo_is_refused_before_the_read(self):
        big = self._write("huge.png",
                          self._PNG + b"\x00" * (model._LOGO_MAX_BYTES + 1))
        self.assertEqual(model._logo_data_uri(big), "")

    def test_unlisted_extension_is_refused(self):
        """No "image/png by default": an unknown extension is a mistyped
        path, not a picture."""
        key = self._write("id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----")
        self.assertEqual(model._logo_data_uri(key), "")

    def test_missing_logo_is_the_documented_empty_string(self):
        self.assertEqual(model._logo_data_uri(""), "")
        self.assertEqual(
            model._logo_data_uri(os.path.join(self.dir, "nope.png")), "")

    def test_non_string_logo_path_never_raises(self):
        """M22 — load_branding() documents "Never raises"."""
        self.assertEqual(model._logo_data_uri(None), "")
        self.assertEqual(model._logo_data_uri(1234), "")
        branding = model.load_branding({"logo_path": ["/etc/passwd"]})
        self.assertEqual(branding["logo_data_uri"], "")


# ─── M20 — a finding title is attacker-controlled text ─────────────────────

class CsvInjectionTests(unittest.TestCase):

    def _csv_rows(self, title, note=""):
        s = Session("10.10.10.5")
        raw = {"text": title, "severity": "high",
               "timestamp": "2026-06-11T10:00:00"}
        if note:
            raw["operator_note"] = note
        s.phases["vuln_scan"]["findings"] = [raw]
        ctx = ReportContext(s)
        return list(csv.reader(io.StringIO(render.render_csv(ctx))))

    def test_formula_lead_in_a_title_is_defused(self):
        rows = self._csv_rows('=cmd|\' /c calc\'!A1')
        self.assertEqual(rows[1][_col("title")], "'=cmd|' /c calc'!A1")

    def test_every_formula_lead_is_covered(self):
        for lead in ("=", "+", "-", "@"):
            rows = self._csv_rows(f"{lead}HYPERLINK(\"http://evil\")")
            self.assertTrue(rows[1][_col("title")].startswith("'" + lead),
                            f"lead {lead!r} not defused")

    def test_operator_note_is_defused_too(self):
        rows = self._csv_rows("TLS 1.0 enabled", note="@SUM(A1:A9)")
        self.assertTrue(rows[1][_col("operator_note")].startswith("'@"))

    def test_ordinary_text_is_untouched(self):
        rows = self._csv_rows("TLS 1.0 enabled")
        self.assertEqual(rows[1][_col("title")], "TLS 1.0 enabled")


def _col(name):
    return render._CSV_COLUMNS.index(name)


# ─── F-06 — operator session notes must reach the report ───────────────────

class SessionNotesInReportTests(unittest.TestCase):
    """The operator writes free-text notes in the report card; they were
    captured onto session.notes but never rendered.  They must now land in
    Markdown and HTML."""

    _NOTE = "Foothold via vsftpd backdoor; pivoted to 10.10.10.20."

    def test_notes_reach_the_markdown_report(self):
        s = Session("10.10.10.5")
        s.notes = self._NOTE
        ctx = ReportContext(s)
        body = render.render_markdown(ctx, engine.build_sections(ctx))
        self.assertIn("Session Notes", body)
        self.assertIn(self._NOTE, body)

    @unittest.skipUnless(_HAS_JINJA2, "jinja2 not installed")
    def test_notes_reach_the_html_report(self):
        s = Session("10.10.10.5")
        s.notes = self._NOTE
        ctx = ReportContext(s)
        html = render.render_html(ctx, engine.build_sections(ctx))
        self.assertIn("Session Notes", html)
        self.assertIn(self._NOTE, html)

    def test_no_notes_means_no_section(self):
        s = Session("10.10.10.5")
        s.notes = "   "                         # blank/whitespace only
        ctx = ReportContext(s)
        body = render.render_markdown(ctx, engine.build_sections(ctx))
        self.assertNotIn("Session Notes", body)

    def test_notes_section_is_omitted_from_csv(self):
        """CSV is a per-finding dump: a free-text note has no column and
        must not corrupt the header/row contract."""
        s = Session("10.10.10.5")
        s.notes = self._NOTE
        ctx = ReportContext(s)
        rows = list(csv.reader(io.StringIO(render.render_csv(ctx))))
        self.assertEqual(rows[0], render._CSV_COLUMNS)


# ─── M15 — one dead format must not kill the others ────────────────────────

class PerFormatDegradationTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="_rep_",
                                    dir=os.path.dirname(__file__))
        self.sessions = tempfile.mkdtemp(prefix="_sess_",
                                         dir=os.path.dirname(__file__))
        self._real_sessions_dir = session_mod.SESSIONS_DIR
        session_mod.SESSIONS_DIR = self.sessions
        self._real_html = render.render_html

    def tearDown(self):
        render.render_html = self._real_html
        session_mod.SESSIONS_DIR = self._real_sessions_dir
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.sessions, ignore_errors=True)

    def _session(self):
        s = Session("10.10.10.5")
        s.phases["vuln_scan"]["findings"] = [
            {"text": "TLS 1.0 enabled", "severity": "medium",
             "timestamp": "2026-06-11T10:00:00"}]
        return s

    def test_a_failing_html_target_still_yields_md_and_csv(self):
        def _boom(ctx, sections):
            raise RuntimeError("template exploded")
        render.render_html = _boom

        paths = engine.generate(self._session(), formats=("html", "csv", "md"),
                                out_dir=self.dir)

        self.assertNotIn("html", paths)
        self.assertIn("md", paths)
        self.assertIn("csv", paths)
        for fmt in ("md", "csv"):
            self.assertTrue(os.path.isfile(paths[fmt]))

    @unittest.skipUnless(_HAS_JINJA2, "jinja2 not installed")
    def test_all_targets_healthy_writes_all_of_them(self):
        paths = engine.generate(self._session(), formats=("html", "csv", "md"),
                                out_dir=self.dir)
        self.assertEqual(sorted(paths), ["csv", "html", "md"])

    def test_a_missing_jinja2_no_longer_costs_the_whole_report(self):
        """Not hypothetical: render_html raises outright when jinja2 is
        absent, which used to mean HAWK produced NOTHING on such a box —
        not even the two formats that have no dependencies at all."""
        def _boom(ctx, sections):
            raise RuntimeError("HTML report needs jinja2")
        render.render_html = _boom

        paths = engine.generate(self._session(),
                                formats=("html", "csv", "md", "pdf"),
                                out_dir=self.dir)

        self.assertEqual(sorted(paths), ["csv", "md"])


if __name__ == "__main__":
    unittest.main()
