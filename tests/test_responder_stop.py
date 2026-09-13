r"""RESPONDER card review fixes (MS2, live pass 2026-08-31).

Two HIGH bugs confirmed live:

  * orphan STOP — the poisoner (root, `python3 ./Responder.py -I ...`)
    survived STOP: stop_responder_process pkilled a `responder/Responder.py`
    pattern that misses a relative-path launch, used a non-privileged pkill
    that can't touch a root process, and returned success on rc 0/1 even
    when it killed nothing.  pgrep showed the poisoner still alive while
    HAWK said "session stopped".  Fix: match the real python-Responder.py,
    kill with privilege, escalate SIGINT->SIGKILL, and confirm death via
    pgrep before returning True (else return False and warn honestly).  The
    kill now runs off the UI thread.

  * duplicate finding — the Target Intel finding title embedded the per-run
    elapsed seconds with no replace=True, so every STOP stacked a new card.
    Fix: stable title + replace=True (counts/elapsed live in the body).

(utils/responder is importable but the kill orchestrates pgrep/pkill
subprocesses; card_routes_responder can't import headless — both are
checked as source-shape.)
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _method(src, name):
    i = src.index(f"def {name}")
    j = len(src)
    for pat in ("\n    def ", "\nclass "):
        k = src.find(pat, i + 1)
        if k != -1:
            j = min(j, k)
    return src[i:j]


def _func(src, name):
    """Extract a TOP-LEVEL (0-indent) function, spanning its nested defs."""
    i = src.index(f"def {name}")
    j = len(src)
    for pat in ("\ndef ", "\nclass "):
        k = src.find(pat, i + 1)
        if k != -1:
            j = min(j, k)
    return src[i:j]


class ResponderStopKillTests(unittest.TestCase):
    def setUp(self):
        self.body = _func(_src("utils/responder.py"),
                          "stop_responder_process")

    def test_matches_real_python_responder_not_old_pattern(self):
        # the kill pattern matches the real python-Responder.py command line
        # (any path), not the old bare responder/Responder.py that missed a
        # relative-path ./Responder.py launch.
        self.assertIn('PAT = r"python', self.body)
        self.assertIn("Responder", self.body)

    def test_verifies_death_and_escalates(self):
        self.assertIn("pgrep", self.body)            # re-check it's gone
        self.assertIn('"-9"', self.body)             # SIGKILL escalation
        # honest return — not the old "rc in (0, 1) => always success"
        self.assertNotIn("(0, 1)", self.body)


class ResponderStopThreadedTests(unittest.TestCase):
    def setUp(self):
        self.body = _method(
            _src("gui/widgets/card_routes_responder.py"), "_do_stop")

    def test_kill_runs_off_ui_thread(self):
        self.assertIn("Thread", self.body)
        self.assertIn("stop_responder_process", self.body)

    def test_warns_when_poisoner_may_survive(self):
        self.assertIn("may STILL be running", self.body)


class ResponderFindingDedupTests(unittest.TestCase):
    def test_finding_has_stable_title_and_replaces(self):
        body = _method(
            _src("gui/widgets/card_routes_responder.py"),
            "_push_responder_finding")
        self.assertIn("replace=True", body)
        # snapshot: clear prior Responder cards (incl. stale ones) first
        self.assertIn("remove_auto_findings_by_source", body)
        # title no longer embeds the per-run counts/elapsed
        self.assertNotIn('f"RESPONDER — {counters', body)

    def test_close_also_pushes_finding(self):
        src = _src("gui/widgets/card_routes_responder.py")
        body = _method(src, "_do_close_only")
        self.assertIn("_push_responder_finding", body)


if __name__ == "__main__":
    unittest.main()
