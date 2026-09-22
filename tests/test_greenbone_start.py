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


def _class(src, name):
    i = src.index(f"class {name}")
    nl = chr(10) + "class "
    j = src.find(nl, i + 1)
    return src[i:] if j == -1 else src[i:j]


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

    def test_run_routes_to_web_when_web_ui_up(self):
        # The ready branch is now gated on the WEB UI (gsad), so the
        # variable name reflects that (web_up), not the old gvmd `running`.
        src = _src("gui/dialogs_core.py")
        self.assertIn("_open_web_and_panel(parent) if web_up", src)
        self.assertIn("def _open_web_and_panel", src)

    def test_web_open_does_not_launch_gmp_scan(self):
        body = _method(_src("gui/dialogs_core.py"), "_open_web_and_panel")
        self.assertIn("webbrowser.open", body)
        self.assertIn("_show_access_panel", body)
        self.assertNotIn("_run_greenbone", body)


class GreenboneReadinessPollTests(unittest.TestCase):
    """open_greenbone_when_ready must not fling a browser at a dead port.

    Regression (observed live): the timeout fallback called
    webbrowser.open() unconditionally, so a cold-sudo START (password never
    entered in the xterm -> gsad never came up) still opened a browser on a
    port that never answered.  It must now open only when the port answers.
    """

    def _run(self, tcp, https, timeout=0.12, poll=0.01):
        from unittest import mock
        import utils.runner as r
        r._reset_greenbone_open_state()
        opened, msgs = [], []
        with mock.patch.object(r, "_gb_tcp_open", return_value=tcp), \
             mock.patch.object(r, "_gb_https_answers", return_value=https), \
             mock.patch("webbrowser.open",
                        side_effect=lambda u: opened.append(u)):
            r.open_greenbone_when_ready(timeout=timeout, poll_interval=poll,
                                        on_status=msgs.append)
            t = r._GB_POLL_THREAD
            if t:
                t.join(5)
        return opened, msgs

    def test_no_browser_when_port_stays_down(self):
        opened, msgs = self._run(tcp=False, https=False)
        self.assertEqual(opened, [])                       # no dead-port tab
        self.assertTrue(
            any("9392" in m and "xterm" in m for m in msgs),
            f"expected an actionable message, got {msgs}")

    def test_opens_browser_when_web_answers(self):
        opened, _ = self._run(tcp=True, https=True)
        self.assertEqual(opened, ["https://127.0.0.1:9392"])

    def test_opens_at_timeout_only_if_port_answers(self):
        # tcp stays down so the loop never probes https; the sole https
        # check is the post-timeout guard -> True -> open via fallback.
        opened, msgs = self._run(tcp=False, https=True)
        self.assertEqual(opened, ["https://127.0.0.1:9392"])
        self.assertTrue(any("answering" in m for m in msgs))

    def test_greenbone_web_up_probe(self):
        from unittest import mock
        import utils.runner as r
        with mock.patch.object(r, "_gb_https_answers", return_value=False), \
             mock.patch.object(r, "_gb_tcp_open", return_value=False):
            self.assertFalse(r.greenbone_web_up())
        with mock.patch.object(r, "_gb_https_answers", return_value=True):
            self.assertTrue(r.greenbone_web_up())


class GreenboneStartVerifyTests(unittest.TestCase):
    """START must (a) verify gsad actually came up instead of printing a
    fixed 'services started', and (b) skip a redundant gvm-start when the
    web UI is already listening."""

    def test_start_script_verifies_gsad_listening(self):
        body = _method(_src("utils/runner.py"), "start_in_xterm")
        self.assertTrue("ss -tln" in body or "is-active" in body)
        self.assertIn(":9392", body)
        self.assertIn("FAILED", body)                  # honest failure branch
        self.assertIn("sudo password", body.lower())   # explicit prompt notice

    def test_start_preflight_skips_gvm_start_when_up(self):
        body = _method(_src("gui/dialogs_core.py"), "_start_and_open")
        self.assertIn("greenbone_web_up", body)        # probe first
        self.assertIn("_start_xterm", body)            # still starts when down
        self.assertIn("else:", body)                   # start is guarded


class GreenboneWebGateTests(unittest.TestCase):
    """RUN's ready branch and the Access Panel's OPEN BROWSER must hinge on
    the WEB UI (gsad on :9392), not the Manager (gvmd).

    Bug (observed live): with gvmd up but gsad down, is_running() (a gvmd
    gvm-cli probe) reported "running", so RUN opened the Access Panel and a
    browser on a dead :9392, and the panel's OPEN BROWSER button re-opened
    the same dead page unconditionally.  Both paths now probe
    greenbone_web_up() (a direct gsad :9392 check) first.
    """

    def test_g1_ready_branch_gated_on_web_ui_not_gvmd(self):
        cls = _class(_src("gui/dialogs_core.py"), "GreenboneDialog")
        # __init__ decides RUN's route with the gsad probe...
        self.assertIn("lambda: greenbone_web_up()", cls)
        self.assertIn("_open_web_and_panel(parent) if web_up", cls)
        # ...and no longer with the gvmd Manager probe.
        self.assertNotIn("GreenBoneRunner.is_running()", cls)

    def test_g2_access_panel_button_populates_app(self):
        # The ACCESS PANEL card button builds the dialog via __new__
        # (skipping __init__), so it MUST set _app — otherwise the panel's
        # terminal.write() calls (incl. G2's web-UI-down warning) raise
        # AttributeError and vanish to stderr instead of the HAWK terminal.
        src = _src("gui/widgets/card_widget.py")
        i = src.index("def _open_access_panel")
        j = src.index("access_btn = ctk.CTkButton", i)
        body = src[i:j]
        self.assertIn("GreenboneDialog.__new__", body)
        self.assertIn("dlg._app", body)

    def test_g2_access_panel_open_browser_gated_on_web_ui(self):
        body = _method(_src("gui/dialogs_core.py"), "_show_access_panel")
        # greenbone_web_up() is consulted BEFORE webbrowser.open() so a dead
        # :9392 never gets a browser opened at it.
        self.assertIn("greenbone_web_up", body)
        self.assertLess(body.index("greenbone_web_up"),
                        body.index("webbrowser.open"))
        # Down path returns without opening + emits an actionable message.
        gate = body[body.index("def _open_browser"):]
        self.assertIn("if not greenbone_web_up()", gate)
        self.assertIn("return", gate[:gate.index("webbrowser.open")])
        self.assertIn(":9392", gate)
        self.assertIn("gsad", gate)
        self.assertIn('"warn"', gate)


if __name__ == "__main__":
    unittest.main()
