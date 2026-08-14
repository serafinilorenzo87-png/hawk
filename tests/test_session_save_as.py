"""Explicit SAVE must not silently spawn a second file per session.

The SAVE button used to call ``Session.save(new_file=True)``, which
always minted a fresh timestamped snapshot — pressing it twice on one
target left two files on disk for the same session.  SAVE now either
overwrites the session's own file or writes a user-named one via
``save_as``.  These tests pin the session-level pieces the GUI relies
on (the dialog wiring itself is Tk and verified in the app).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class SaveAsTests(unittest.TestCase):
    def setUp(self):
        import utils.session as session_mod
        self.session_mod = session_mod
        self._real_dir = session_mod.SESSIONS_DIR
        self.tmp = tempfile.mkdtemp(prefix="hawk_saveas_")
        session_mod.SESSIONS_DIR = self.tmp

    def tearDown(self):
        self.session_mod.SESSIONS_DIR = self._real_dir
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sess(self):
        from utils.session import Session
        return Session("10.10.10.5")

    @contextmanager
    def _accept_tmp_paths(self):
        # save() and _atomic_write_json both containment-check the path
        # (in utils.session and utils.config respectively); the temp dir
        # is outside BASE, so relax both for these unit tests.
        with patch("utils.session.is_within_base", return_value=True), \
             patch("utils.config.is_within_base", return_value=True):
            yield

    def _jsons(self):
        return sorted(f for f in os.listdir(self.tmp) if f.endswith(".json"))

    def test_save_as_writes_named_file_and_adopts_it(self):
        with self._accept_tmp_paths():
            s = self._sess()
            created = s.created_at
            path = s.save_as("my snapshot")
        self.assertEqual(os.path.basename(path), "my_snapshot.json")
        self.assertEqual(s.file_path, path)
        self.assertTrue(os.path.isfile(path))
        d = json.load(open(path, encoding="utf-8"))
        self.assertEqual(d["created_at"], created)  # same logical session

    def test_save_as_sanitizes_name(self):
        with self._accept_tmp_paths():
            s = self._sess()
            path = s.save_as("../weird name!!.json")
        base = os.path.basename(path)
        self.assertEqual(base, "weird_name.json")
        self.assertNotIn("..", base)

    def test_save_as_does_not_clobber_a_different_file(self):
        with self._accept_tmp_paths():
            p1 = self._sess().save_as("shared")
            p2 = self._sess().save_as("shared")
        self.assertNotEqual(p1, p2)
        self.assertTrue(os.path.isfile(p1))
        self.assertTrue(os.path.isfile(p2))
        self.assertEqual(self._jsons(), ["shared(1).json", "shared.json"])

    def test_overwrite_after_save_as_reuses_same_file(self):
        """The core of the fix: an explicit overwrite makes no new file."""
        with self._accept_tmp_paths():
            s = self._sess()
            p1 = s.save_as("box-lab")
            self.assertEqual(self._jsons(), ["box-lab.json"])
            p2 = s.save(new_file=False)
        self.assertEqual(p1, p2)
        self.assertEqual(self._jsons(), ["box-lab.json"])  # still one file

    def test_default_save_stem_carries_the_target(self):
        stem = self._sess().default_save_stem()
        self.assertIn("10.10.10.5", stem)
        self.assertFalse(stem.endswith(".json"))

    # ── Filename format: ip_date_time (underscores between the three
    #    parts), not the old all-dashes ip-date-time. ────────────────
    _FMT = r"^10\.10\.10\.5_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}"

    def test_snapshot_path_uses_underscore_format(self):
        base = os.path.basename(self._sess()._make_snapshot_path())
        self.assertRegex(base, self._FMT + r"\.json$")

    def test_default_stem_uses_underscore_format(self):
        self.assertRegex(self._sess().default_save_stem(), self._FMT + r"$")

    def test_name_timestamp_parses_both_old_and_new(self):
        from utils.session import session_name_timestamp
        old = "10.10.10.5-2026-08-13-17-32-09.json"
        new = "10.10.10.5_2026-08-13_17-32-09.json"
        self.assertEqual(session_name_timestamp(old), "2026-08-13-17-32-09")
        self.assertEqual(session_name_timestamp(new), "2026-08-13-17-32-09")


if __name__ == "__main__":
    unittest.main()
