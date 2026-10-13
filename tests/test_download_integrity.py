r"""E-01 (CWE-494): every operator-side download must surface its hash.

Chisel runs on the KALI operator box and gets model (b) enforcement:
  download the release's own checksums.txt, verify with sha256sum -c,
  refuse to install (fail-closed) on mismatch or missing checksums.

Tool-framework downloads (linpeas, winpeas, pspy, lse, PrivescCheck,
PowerUp) run on the TARGET, not the operator.  They get model (d):
  sha256sum printed after download so the operator can verify manually.
  NOT fail-closed (transparency, not enforcement).  HTTPS + operator-
  initiated fetch + target-side execution = acceptable residual risk;
  pin-version+hash (model a) remains an opt-in hardening path.

Static source-shape tests — no customtkinter, headless-safe.
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class ChiselIntegrityTests(unittest.TestCase):
    """E-01 model (b): chisel download verifies against release checksums."""

    def setUp(self):
        self.src = _src("gui/widgets/card_ad_routes.py")

    def test_fetches_checksums_file(self):
        self.assertIn("chisel_checksums.txt", self.src)
        self.assertIn("checksums.txt", self.src)

    def test_verifies_with_sha256sum(self):
        self.assertIn("sha256sum -c", self.src)

    def test_fail_closed_on_missing_checksums(self):
        self.assertIn("Could not fetch checksums.txt", self.src)
        self.assertIn("exit 1", self.src)

    def test_fail_closed_on_hash_mismatch(self):
        self.assertIn("SHA-256 verification FAILED", self.src)
        self.assertIn('rm -f \\"$gz\\"', self.src)


_DOWNLOAD_TOOLS = {
    "linpeas":          ["{payloads}/linpeas.sh"],
    "lse":              ["{payloads}/lse.sh"],
    "pspy":             ["{payloads}/pspy32", "{payloads}/pspy64"],
    "winpeas":          ["{payloads}/winpeas.bat"],
    "winpeas_exe":      ["{payloads}/winpeas.exe"],
    "powerup_download": ["{payloads}/PowerUp.ps1"],
    "privesc_check":    ["{payloads}/PrivescCheck.ps1"],
}


class ToolFrameworkHashTests(unittest.TestCase):
    """E-01 model (d): every tool-framework download prints sha256sum."""

    def setUp(self):
        self.src = _src("modules/post_exploit.py")

    def _template_for(self, tool_id):
        pat = re.compile(
            rf'id="{tool_id}".*?cmd_template=\((.*?)\),',
            re.DOTALL)
        m = pat.search(self.src)
        self.assertIsNotNone(m, f"Tool {tool_id!r} not found")
        return m.group(1)

    def test_every_download_prints_sha256sum(self):
        for tool_id, files in _DOWNLOAD_TOOLS.items():
            tpl = self._template_for(tool_id)
            for f in files:
                self.assertIn(
                    f"sha256sum {f}",
                    tpl,
                    f"{tool_id}: cmd_template must print sha256sum "
                    f"for {f}")


if __name__ == "__main__":
    unittest.main()
