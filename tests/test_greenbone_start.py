r"""Greenbone START must not re-run the installer.

Bug (observed live): with GVM already installed but not running, the
dialog's START button called GreenBoneInstaller.install_in_xterm(), which
runs `apt install && gvm-setup && gvm-start` — so gvm-setup re-synced the
multi-GB feeds (10-20 min) on every start, and the browser opened before
the service was ready.

Fix: START uses a start-only script (sudo gvm-start, never gvm-setup),
and install_in_xterm is idempotent (skips setup when already set up).
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


class GreenboneStartTests(unittest.TestCase):
    def test_start_button_does_not_call_installer(self):
        body = _method(_src("gui/dialogs_core.py"), "_start_xterm")
        self.assertIn("start_in_xterm", body)
        self.assertNotIn("install_in_xterm", body)

    def test_start_script_starts_without_setup(self):
        body = _method(_src("utils/runner.py"), "start_in_xterm")
        self.assertIn("gvm-start", body)
        # Only the executable script matters — the comment is allowed to
        # name the call it deliberately avoids.
        code = "\n".join(l for l in body.splitlines()
                         if not l.lstrip().startswith("#"))
        self.assertNotIn("gvm-setup", code)

    def test_install_is_idempotent(self):
        body = _method(_src("utils/runner.py"), "install_in_xterm")
        # Guards the slow setup behind an "already set up?" check.
        self.assertIn("gvm-check-setup", body)
        self.assertIn("already installed", body.lower())
        # Still performs the real install on the else branch.
        self.assertIn("gvm-setup", body)


class GreenboneCredsAndGateTests(unittest.TestCase):
    """The runner's default GMP password must match what the UI's reset
    helpers set, and a missing SCAP/CERT feed must not block an NVT scan."""

    def test_runner_cred_default_matches_reset_helper(self):
        rsrc = _src("utils/runner.py")
        dsrc = _src("gui/dialogs_core.py")
        self.assertIn('password or "admin123"', rsrc)
        self.assertIn("new-password=admin123", dsrc)

    def test_scap_missing_is_non_blocking(self):
        body = _method(_src("gui/dialogs_core.py"), "_show_start_dialog")
        self.assertIn('"scap" in low', body)
        self.assertIn("blockers", body)
        self.assertIn("_show_ready_to_start(parent, soft)", body)


class GreenboneRunOpensWebTests(unittest.TestCase):
    """RUN, when GVM is up, opens the Greenbone web dashboard — the
    operator drives scans from the web UI, not the GMP scan path."""

    def test_run_routes_to_web_when_running(self):
        src = _src("gui/dialogs_core.py")
        self.assertIn("_open_web_and_panel(parent) if running", src)
        self.assertIn("def _open_web_and_panel", src)

    def test_web_open_does_not_launch_gmp_scan(self):
        body = _method(_src("gui/dialogs_core.py"), "_open_web_and_panel")
        self.assertIn("webbrowser.open", body)
        self.assertIn("_show_access_panel", body)
        self.assertNotIn("_run_greenbone", body)


if __name__ == "__main__":
    unittest.main()
