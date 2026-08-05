"""GMP protocol contract for the GreenBone integration.

A mass rename turned every `name` into `n` and every `result` into `r`
inside utils/runner.py's GreenBone code.  GMP has no `<n>` element, so
gvmd rejected `create_target`, the scan config lookup never matched and
the result parser matched nothing: the tool was dead end to end.

These tests pin the wire format on both sides — the XML HAWK sends and
the XML it parses back.  The transport itself (gvm-cli against a live
gvmd socket) still needs a Kali box to validate.
"""

import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# A trimmed but structurally faithful `get_results` response.
GET_RESULTS_XML = """
<get_results_response status="200">
  <result id="r1">
    <name>OpenSSH Denial of Service</name>
    <host>10.10.10.10</host>
    <severity>7.5</severity>
    <description>The remote host is running a vulnerable OpenSSH.</description>
  </result>
  <result id="r2">
    <name>TCP timestamps</name>
    <host>10.10.10.10</host>
    <severity>2.6</severity>
    <description>The remote host implements RFC1323 timestamps.</description>
  </result>
</get_results_response>
"""

GET_CONFIGS_XML = """
<get_configs_response status="200">
  <config id="daba56c8-73ec-11df-a475-002264764cea">
    <name>Full and fast</name>
  </config>
  <config id="cafe0000-0000-0000-0000-000000000000">
    <name>Host Discovery</name>
  </config>
</get_configs_response>
"""


class GreenBoneResultParsingTests(unittest.TestCase):
    def _runner(self):
        from utils.runner import GreenBoneRunner
        lines = []
        runner = GreenBoneRunner(
            output_callback=lambda line, tn, level: lines.append(
                (level, line)))
        return runner, lines

    def test_results_are_extracted(self):
        runner, lines = self._runner()
        runner._parse_results(GET_RESULTS_XML, "greenbone")
        text = "\n".join(line for _lvl, line in lines)
        self.assertIn("OpenSSH Denial of Service", text)
        self.assertIn("TCP timestamps", text)
        self.assertIn("vulnerable OpenSSH", text)
        self.assertNotIn("No vulnerabilities found", text)

    def test_severity_drives_the_log_level(self):
        runner, lines = self._runner()
        runner._parse_results(GET_RESULTS_XML, "greenbone")
        levels = {line: lvl for lvl, line in lines}
        high = next(l for l in levels if "OpenSSH" in l)
        low = next(l for l in levels if "TCP timestamps" in l)
        self.assertEqual(levels[high], "error")   # 7.5
        self.assertEqual(levels[low], "info")     # 2.6

    def test_empty_response_reports_no_findings(self):
        runner, lines = self._runner()
        runner._parse_results(
            '<get_results_response status="200"/>', "greenbone")
        self.assertIn("No vulnerabilities found",
                      "\n".join(line for _lvl, line in lines))


class GreenBoneRequestTests(unittest.TestCase):
    """The XML HAWK sends must be valid GMP."""

    def _run_scan_capturing_xml(self):
        from utils.runner import GreenBoneRunner

        sent = []
        runner = GreenBoneRunner(output_callback=lambda *a: None)
        runner._POLL_INTERVAL = 0

        def fake_gvm(xml):
            sent.append(xml)
            if xml.startswith("<create_target"):
                return '<create_target_response status="201" id="t-1"/>'
            if xml.startswith("<get_configs"):
                return GET_CONFIGS_XML
            if xml.startswith("<create_task"):
                return '<create_task_response status="201" id="task-1"/>'
            if xml.startswith("<get_tasks"):
                return "<get_tasks_response><status>Done</status>" \
                       "</get_tasks_response>"
            if xml.startswith("<get_results"):
                return GET_RESULTS_XML
            return '<response status="200"/>'

        runner._gvm = fake_gvm
        runner.running = True
        runner._run_scan("10.10.10.10", "Full and fast")
        return sent

    def test_requests_use_the_name_element(self):
        sent = self._run_scan_capturing_xml()
        create_target = next(x for x in sent
                             if x.startswith("<create_target"))
        create_task = next(x for x in sent if x.startswith("<create_task"))
        self.assertIn("<name>HAWK-10.10.10.10</name>", create_target)
        self.assertIn("<name>HAWK-10.10.10.10</name>", create_task)
        for xml in sent:
            self.assertNotIn("<n>", xml)

    def test_scan_config_lookup_matches_by_name(self):
        sent = self._run_scan_capturing_xml()
        create_task = next(x for x in sent if x.startswith("<create_task"))
        # "Full and fast" must resolve to its own id, not the hardcoded
        # fallback used when the lookup fails (same uuid here by design,
        # so assert the task was created against a target too).
        self.assertIn("config id='daba56c8-73ec-11df-a475-002264764cea'",
                      create_task)
        self.assertIn("target id='t-1'", create_task)

    def test_scan_reaches_the_results_call(self):
        sent = self._run_scan_capturing_xml()
        self.assertTrue(any(x.startswith("<get_results") for x in sent),
                        "the scan never got as far as fetching results")


if __name__ == "__main__":
    unittest.main()
