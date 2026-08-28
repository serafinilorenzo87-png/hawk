r"""SQLMAP card review — parser + route hardening.

Reviewed against a live run on MS2 (nothing injectable there — Mutillidae
was above security level 0) plus the sqlmap output format:

  HIGH  the 'injectable' regex ("Parameter:...is vulnerable") required
        both tokens on ONE line and matched NEITHER real sqlmap form
        ("Parameter: username (GET)" / "parameter 'username' is
        vulnerable"), so a confirmed injection lost its parameter name
        and was scored 'high' instead of 'critical'.  Fixed.
  MED   no replace=True → "SQL Injection — target" cards stacked on
        rerun.  Fixed.
  MED   reactive-but-not-injectable (heuristic positive, sqlmap advising
        higher --level/--risk) produced silence → operator could read a
        level-1 negative as "no SQLi".  Now emits an escalation hint.
  MED   sqlmap wrote its session DB + output to HGFS (XDG_DATA) on every
        request → --output-dir now points at a local dir.
  MED   ran foreground → now a bg-job like nuclei/nikto/wpscan.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# Import the pure parser without the GUI stack, then undo the import side
# effects so other test modules see the real (or absent) customtkinter.
from unittest.mock import MagicMock
_mods_before = set(sys.modules)
if "customtkinter" not in sys.modules:
    sys.modules["customtkinter"] = MagicMock()
try:
    from gui.widgets.card_parsers_service import CardServiceParserMixin
    _IMPORT_OK = True
except Exception as _e:                      # pragma: no cover - headless
    _IMPORT_OK = False
    CardServiceParserMixin = None
for _k in list(sys.modules):
    if _k not in _mods_before and (
            _k == "customtkinter" or _k == "gui" or _k.startswith("gui.")):
        del sys.modules[_k]


_POSITIVE = [
    "[17:01:33] [INFO] testing for SQL injection on GET parameter 'username'",
    "GET parameter 'username' is vulnerable. Do you want to keep testing "
    "the others (if any)? [y/N] N",
    "sqlmap identified the following injection point(s) with a total of 47 "
    "HTTP(s) requests:",
    "---",
    "Parameter: username (GET)",
    "    Type: error-based",
    "    Title: MySQL >= 5.0 AND error-based - WHERE clause (FLOOR)",
    "    Payload: page=user-info.php&username=1' AND (SELECT 1)-- -",
    "---",
    "[17:01:40] [INFO] fetching database names",
    "available databases [5]:",
    "[*] information_schema",
    "[*] metasploit",
    "[*] mysql",
    "[*] owasp10",
    "[*] tikiwiki",
    "",
]

_INCONCLUSIVE = [
    "[17:01:32] [INFO] heuristic (basic) test shows that GET parameter "
    "'username' might be injectable (possible DBMS: 'MySQL')",
    "[17:01:33] [INFO] testing for SQL injection on GET parameter 'username'",
    "[17:06:22] [WARNING] GET parameter 'username' does not seem to be "
    "injectable",
    "[17:06:22] [ERROR] all tested parameters do not appear to be "
    "injectable. Try to increase values for '--level'/'--risk' options.",
]

_INCONCLUSIVE_L3 = [
    "[INFO] heuristic (basic) test shows that GET parameter 'username' "
    "might be injectable (possible DBMS: 'MySQL')",
    "for the remaining tests, do you want to include all tests for "
    "'MySQL' extending provided level (3) and risk (2) values? [Y/n] Y",
    "[INFO] testing for SQL injection on GET parameter 'username'",
    "[WARNING] GET parameter 'username' does not seem to be injectable",
    "[CRITICAL] all tested parameters do not appear to be injectable. "
    "Try to increase values for '--level'/'--risk' options.",
]

_NOPARAM = [
    "[CRITICAL] no parameter(s) found for testing in the provided data",
]

_CLEAN = [
    "[17:06:22] [WARNING] POST parameter 'username' might not be injectable",
    "[17:06:33] [WARNING] POST parameter 'username' does not seem to be "
    "injectable",
]


@unittest.skipUnless(_IMPORT_OK, "card_parsers_service import failed")
class SqlmapParserTests(unittest.TestCase):
    def _run(self, lines):
        findings, warns = [], []
        stub = types.SimpleNamespace()
        stub._get_target = lambda: "192.168.177.134"
        stub.app = types.SimpleNamespace(
            after=lambda ms, fn: fn(),
            target_intel=types.SimpleNamespace(
                add_auto_finding=lambda **kw: findings.append(kw)),
            terminal=types.SimpleNamespace(
                write=lambda *a, **k: warns.append(a[0] if a else "")))
        tool = types.SimpleNamespace(name="SQLMAP", binary="sqlmap",
                                     id="sqlmap")
        log = [("info", l) for l in lines]
        ret = CardServiceParserMixin._parse_sqlmap_to_intel(stub, tool, log)
        return ret, findings, warns

    def test_confirmed_injection_is_critical_with_param(self):
        ret, findings, _ = self._run(_POSITIVE)
        self.assertTrue(ret)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "critical")
        self.assertTrue(f["replace"])
        self.assertTrue(f["title"].startswith("SQL Injection"))
        d = f["description"]
        self.assertIn("username", d)            # param name recovered
        self.assertIn("information_schema", d)
        self.assertIn("owasp10", d)
        self.assertIn("Databases (5)", d)

    def test_inconclusive_emits_escalation_hint(self):
        ret, findings, warns = self._run(_INCONCLUSIVE)
        self.assertTrue(ret)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "info")
        self.assertIn("inconclusive", f["title"].lower())
        self.assertTrue(f["replace"])
        self.assertIn("Level 3", f["description"])
        self.assertTrue(any("Level 3" in w for w in warns))

    def test_inconclusive_already_escalated_changes_advice(self):
        # sqlmap echoed "extending provided level (3) and risk (2)": the
        # hint must NOT tell the operator to re-run at level 3 (they just
        # did) — it flips to tamper/WAF advice.
        ret, findings, warns = self._run(_INCONCLUSIVE_L3)
        self.assertTrue(ret)
        self.assertEqual(len(findings), 1)
        d = findings[0]["description"]
        self.assertIn("level 3 / risk 2", d)
        self.assertIn("already escalated", d)
        self.assertIn("--tamper", d)
        self.assertNotIn("Escalate: re-run", d)
        self.assertTrue(any("already escalated" in w for w in warns))

    def test_no_parameters_makes_no_card(self):
        ret, findings, warns = self._run(_NOPARAM)
        self.assertTrue(ret)
        self.assertEqual(findings, [])
        self.assertTrue(any("no injectable parameters" in w for w in warns))

    def test_clean_negative_makes_no_card(self):
        # Not injectable AND no heuristic hit / escalation advice → stay
        # silent, no false-positive card.
        ret, findings, _ = self._run(_CLEAN)
        self.assertTrue(ret)
        self.assertEqual(findings, [])


class SqlmapRouteStaticTests(unittest.TestCase):
    def setUp(self):
        self.src = _src("gui/widgets/card_routes_web.py")

    def _func(self, name):
        start = self.src.index(f"def {name}")
        end = self.src.index("\n    def ", start + 1)
        return self.src[start:end]

    def test_sqlmap_runs_as_bg_job(self):
        body = self._func("_route_sqlmap")
        self.assertIn("_run_in_background(tool, cmd", body)
        self.assertNotIn("_run_raw(tool", body)

    def test_sqlmap_output_dir_is_local(self):
        body = self._func("_route_sqlmap")
        self.assertIn("--output-dir", body)
        self.assertIn("resolve_tool_tmpdir", body)


if __name__ == "__main__":
    unittest.main()
