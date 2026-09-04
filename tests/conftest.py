r"""Cross-test isolation for the HAWK test suite.

Two guardrails run for every test, both installed here so no test file
has to know about them:

1. Purge cached gui.* modules between tests.  Many test files stub
   sys.modules["customtkinter"] with a _DummyCtk class in setUp and
   restore it in tearDown.  During setUp the stub is live, so any gui.*
   import in the test body captures the stub as its `ctk` binding.
   After tearDown restores sys.modules["customtkinter"], those already-
   imported gui.* modules KEEP the stubbed `ctk` reference: their
   `import customtkinter as ctk` was evaluated once and is not re-run.

   Symptoms of the resulting cross-test pollution:
     * a REAL-widget test running after a stub-installing one gets
       _DummyCtk fonts and fails with "Wrong font type"
       (test_dialog_smoke).
     * a STUB-widget test running after a real-widget one gets real
       ctk.StringVar which needs a Tk root and raises "Too early to
       create variable" (test_gobuster_thread_default).

   Purging gui.* after every test forces the NEXT test to re-import
   gui.* against whatever customtkinter is live at that moment.

2. Redirect utils.session.SESSIONS_DIR to a per-run tempdir.  Several
   tests build a real Session (e.g. `Session(target_ip="10.10.10.10")`
   in test_dialog_smoke's SmbAnonymousParserTests) which triggers
   Session.save() → JSON file dropped in <repo>/sessions/.  Every
   pytest run littered 3–6 `10.10.10.10_<timestamp>.json` files there;
   individual tests that already manage their own SESSIONS_DIR keep
   working because they save/restore the value themselves.
"""

import os
import shutil
import sys
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _purge_gui_between_tests():
    yield
    for name in list(sys.modules):
        if name == "gui" or name.startswith("gui."):
            sys.modules.pop(name, None)


@pytest.fixture(autouse=True, scope="session")
def _redirect_sessions_dir_for_tests():
    """Redirect Session.save()'s dump directory to a run-scoped tempdir.

    Session.save() writes to `utils.session.SESSIONS_DIR` (imported at
    module load time — patching utils.config.SESSIONS_DIR alone won't
    reach it).  We patch both bindings so tests that touch either name
    end up in the same tempdir, and we restore both at session end.

    The tempdir MUST live under the HAWK tree — `Session.save()` calls
    `require_within_base(path)` which refuses to write outside
    utils.config.BASE_DIR (self-contained-policy).  So we host the
    per-run dir under `<HAWK>/tmp/` instead of the system `/tmp`.
    """
    import utils.config as _cfg
    import utils.session as _sess
    hawk_tmp_root = os.path.join(_cfg.BASE_DIR, "tmp")
    os.makedirs(hawk_tmp_root, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="hawk_test_sessions_", dir=hawk_tmp_root)
    orig_cfg = _cfg.SESSIONS_DIR
    orig_sess = _sess.SESSIONS_DIR
    _cfg.SESSIONS_DIR = tmp
    _sess.SESSIONS_DIR = tmp
    try:
        yield tmp
    finally:
        _cfg.SESSIONS_DIR = orig_cfg
        _sess.SESSIONS_DIR = orig_sess
        shutil.rmtree(tmp, ignore_errors=True)
