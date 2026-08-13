"""Headless tests for the LOAD-dialog session ordering.

The two sort modes are deliberately distinct: 'Last modified' orders by
the file's mtime (when it was last written to disk) while 'Date' orders
by the timestamp embedded in the file name (when the session was first
created).  An old session re-saved today has an old name-date but a
fresh mtime, so the two modes must NOT collapse into one.

These tests exercise the pure sort_sessions()/session_name_timestamp()
functions with fake file names and fake mtimes — no disk, no Tk — so
they run everywhere (the Tk dialog test stays gated on customtkinter).
"""

import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils.session import (  # noqa: E402
    SESSION_SORT_MODES,
    SORT_DATE,
    SORT_LAST_MODIFIED,
    session_name_timestamp,
    sort_sessions,
)


def _rec(tag, name, mtime):
    return {"session": tag, "file_name": name, "mtime": mtime}


class NameTimestampTests(unittest.TestCase):
    def test_extracts_stamp(self):
        self.assertEqual(
            session_name_timestamp("192.168.177.134-2026-08-06-09-46-38.json"),
            "2026-08-06-09-46-38",
        )

    def test_missing_stamp_is_empty(self):
        self.assertEqual(session_name_timestamp("no-timestamp-here.json"), "")
        self.assertEqual(session_name_timestamp(""), "")
        self.assertEqual(session_name_timestamp(None), "")

    def test_lexical_order_is_chronological(self):
        older = session_name_timestamp("h-2026-07-15-23-59-59.json")
        newer = session_name_timestamp("h-2026-08-01-00-00-00.json")
        self.assertLess(older, newer)


class SortSessionsTests(unittest.TestCase):
    def setUp(self):
        # mtime and in-name date deliberately disagree so a mode mix-up
        # would show up as a different ordering.
        self.records = [
            _rec("A", "10.0.0.1-2026-08-01-09-00-00.json", 500.0),
            _rec("B", "10.0.0.2-2026-08-06-09-46-38.json", 100.0),
            _rec("C", "10.0.0.3-2026-07-15-23-59-59.json", 900.0),
        ]

    def _order(self, mode):
        return [r["session"] for r in sort_sessions(self.records, mode)]

    def test_modes_constant(self):
        self.assertEqual(SESSION_SORT_MODES, (SORT_LAST_MODIFIED, SORT_DATE))

    def test_last_modified_is_newest_mtime_first(self):
        self.assertEqual(self._order(SORT_LAST_MODIFIED), ["C", "A", "B"])

    def test_date_is_newest_name_stamp_first(self):
        self.assertEqual(self._order(SORT_DATE), ["B", "A", "C"])

    def test_modes_differ(self):
        # Guards against the pre-fix behaviour where a single ordering
        # served both menu entries.
        self.assertNotEqual(
            self._order(SORT_LAST_MODIFIED), self._order(SORT_DATE))

    def test_unknown_mode_falls_back_to_last_modified(self):
        self.assertEqual(self._order("bogus"), self._order(SORT_LAST_MODIFIED))

    def test_input_not_mutated(self):
        before = list(self.records)
        sort_sessions(self.records, SORT_DATE)
        self.assertEqual(self.records, before)

    def test_nameless_file_sinks_to_bottom_in_date_mode(self):
        recs = self.records + [_rec("Z", "corrupt.json", 999.0)]
        self.assertEqual(sort_sessions(recs, SORT_DATE)[-1]["session"], "Z")

    def test_stable_on_ties(self):
        recs = [
            _rec("first", "h-2026-08-01-00-00-00.json", 50.0),
            _rec("second", "h-2026-08-01-00-00-00.json", 50.0),
        ]
        # Equal keys in both modes -> incoming order preserved.
        self.assertEqual(
            [r["session"] for r in sort_sessions(recs, SORT_DATE)],
            ["first", "second"])
        self.assertEqual(
            [r["session"] for r in sort_sessions(recs, SORT_LAST_MODIFIED)],
            ["first", "second"])


if __name__ == "__main__":
    unittest.main()
