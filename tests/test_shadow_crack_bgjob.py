r"""SHADOW CRACK must run john as a proper, killable, resource-capped bg-job.

Found live on MS2: john pegged all 8 CPU cores AND saturated the vmhgfs
shared-folder channel (session/.pot churn on TMP_DIR = HGFS), with no way to
STOP it from the UI (had to `pkill john`), and the cracked creds were saved
without the Credential Store "new" badge.

Fix contract (this test locks it in — the module subclasses customtkinter and
can't import headless, so these are source-shape checks):
  • john runs via ToolRunner as a killable BackgroundJob (STOP in the BG bar),
    NOT a bare foreground Popen read loop.
  • CPU is capped (OMP_NUM_THREADS + nice) so it doesn't freeze the VM.
  • john's churning session files go on resolve_tool_tmpdir() (local tmp),
    while HAWK's own input files stay contained under TMP_DIR.
  • cracked creds are badged via cred_store.mark_captured (blinks the tab),
    not a silent refresh().
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SRC_PATH = os.path.join(ROOT, "gui", "widgets", "card_routes_access.py")


def _method(src, name):
    i = src.index(f"def {name}")
    j = len(src)
    for pat in ("\n    def ", "\nclass "):
        k = src.find(pat, i + 1)
        if k != -1:
            j = min(j, k)
    return src[i:j]


class ShadowCrackBgJobTests(unittest.TestCase):
    def setUp(self):
        with open(SRC_PATH, encoding="utf-8") as fh:
            self.src = fh.read()
        self.worker = _method(self.src, "_shadow_crack_worker")
        self.save = _method(self.src, "_shadow_save_credentials")

    def test_runs_via_toolrunner_bg_job(self):
        self.assertIn("ToolRunner(", self.worker)
        self.assertIn("BackgroundJob(", self.worker)
        self.assertIn("killable=True", self.worker)
        self.assertIn("bg_jobs_bar.add_job", self.worker)

    def test_no_foreground_blocking_popen_loop(self):
        # the old bare Popen + `for line in proc.stdout` foreground read (no
        # STOP, orphan on timeout) must be gone — john streams through the
        # ToolRunner's output_callback now, not a manual proc.stdout loop.
        self.assertNotIn("proc.stdout", self.worker)
        self.assertNotIn("for line in proc", self.worker)

    def test_cpu_is_capped(self):
        self.assertIn("OMP_NUM_THREADS", self.worker)
        self.assertIn("nice", self.worker)

    def test_session_files_on_local_tmp_inputs_contained(self):
        # john's churning session/.pot go on the local tmpdir helper...
        self.assertIn("resolve_tool_tmpdir()", self.worker)
        # ...while HAWK's own input files stay under the contained TMP_DIR.
        self.assertIn("dir=TMP_DIR", self.worker)

    def test_credential_badge_is_triggered(self):
        # mark_captured marks NEW + blinks the tab; a bare refresh() does not.
        self.assertIn("mark_captured", self.save)

    def test_pushes_target_intel_finding(self):
        # Cracked shadow passwords must also land on Target Intel (like hydra's
        # weak-cred finding), not only in the Credential Store — snapshot
        # semantics (remove-by-source) so a re-run doesn't duplicate.
        self.assertIn("add_auto_finding", self.save)
        self.assertIn('"Shadow Crack"', self.save)
        self.assertIn("remove_auto_findings_by_source", self.save)


if __name__ == "__main__":
    unittest.main()
