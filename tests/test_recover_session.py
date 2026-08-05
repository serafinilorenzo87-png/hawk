"""Regression tests for tools/recover_session.py.

The recovery tool exists for exactly one file shape: a session JSON that
`json.dump` left truncated because a widget reference wasn't
serializable.  Such a file ALWAYS contains at least one `_*_ref` key.
The first strip pass used to eat the comma on BOTH sides of that key,
so the tool broke every file it was written to save.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools.recover_session import _strip_widget_ref_lines, recover  # noqa: E402


class StripWidgetRefTests(unittest.TestCase):
    """The strip pass must leave parseable JSON in every position."""

    def _roundtrip(self, text):
        return json.loads(_strip_widget_ref_lines(text))

    def test_ref_between_two_keys(self):
        data = self._roundtrip(
            '{"a": 1, "_frame_ref": "<tk.Frame object>", "b": 2}')
        self.assertEqual(data, {"a": 1, "b": 2})

    def test_ref_first_key(self):
        data = self._roundtrip('{"_badge_ref": null, "b": 2}')
        self.assertEqual(data, {"b": 2})

    def test_ref_last_key(self):
        data = self._roundtrip('{"a": 1, "_mark_btn_ref": "<btn>"}')
        self.assertEqual(data, {"a": 1})

    def test_ref_only_key(self):
        self.assertEqual(self._roundtrip('{"_frame_ref": "<x>"}'), {})

    def test_multiline_refs_between_keys(self):
        data = self._roundtrip(
            '{\n'
            '  "user": "admin",\n'
            '  "_frame_ref": "<tk.Frame object .!frame>",\n'
            '  "password": "pw",\n'
            '  "_badge_ref": null,\n'
            '  "verified": true\n'
            '}')
        self.assertEqual(
            data, {"user": "admin", "password": "pw", "verified": True})


class RecoverTruncatedFileTests(unittest.TestCase):
    """End-to-end: the file shape the tool was written for."""

    # A session killed mid-`json.dump`: two credentials are complete,
    # each carrying a widget ref between two real keys, and the write
    # died inside target_intel.
    TRUNCATED = (
        '{\n'
        '  "session_id": "20260730-1200",\n'
        '  "target_ip": "10.10.10.10",\n'
        '  "credentials": [\n'
        '    {"user": "admin", "_frame_ref": "<tk.Frame object .!f>", '
        '"password": "Passw0rd!", "verified": true},\n'
        '    {"user": "svc_sql", "_badge_ref": null, '
        '"password": "Summer2026", "verified": false}\n'
        '  ],\n'
        '  "executed_tools": ["nmap_quick", "smb_enum"],\n'
        '  "target_intel": {"auto_findings": [{"title": "SMB signing off"'
    )

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="hawk_recover_test_")
        self.src = os.path.join(self.tmpdir, "session_20260730.json")
        with open(self.src, "w", encoding="utf-8") as fh:
            fh.write(self.TRUNCATED)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_truncated_file_with_widget_ref_recovers(self):
        out = recover(self.src)
        self.assertTrue(out, "recover() gave up on a recoverable file")
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)

        self.assertEqual(data["target_ip"], "10.10.10.10")
        self.assertEqual(len(data["credentials"]), 2)
        self.assertEqual(data["credentials"][0]["password"], "Passw0rd!")
        self.assertEqual(data["credentials"][1]["user"], "svc_sql")
        self.assertEqual(data["executed_tools"], ["nmap_quick", "smb_enum"])
        # Widget refs must not survive into the recovered file.
        for cred in data["credentials"]:
            self.assertNotIn("_frame_ref", cred)
            self.assertNotIn("_badge_ref", cred)


if __name__ == "__main__":
    unittest.main()
