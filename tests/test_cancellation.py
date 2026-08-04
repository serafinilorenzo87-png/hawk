# HAWK — Hostile Assessment War-Kit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0
#
# Attribution "Created by Lorenzo Serafini" must be preserved in all
# redistributed and Derivative Works — see NOTICE for details.

"""Cancellation and UI-thread marshalling tests.

Two invariants are locked down here:

1. `AssaultState.cancel_event` is a STABLE object.  Jobs capture the
   Event once at construction time, so `reset_cancel()` / `bind_target()`
   must clear it in place — rebinding a fresh Event would make `cancel()`
   set something nobody is watching (audit findings S4 / M8).

2. A cancelled job reports the cancellation instead of publishing a
   definitive negative ("No weak secret in wordlist", "0 confirmed").

Plus the thread-safety guarantee for the CONNECT parse path: everything
reached from the xterm watcher thread must be marshalled onto the Tk
main thread (audit finding X2).
"""

import os
import sys
import types
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ── Cancel event identity ───────────────────────────────────────────

class CancelEventIdentityTests(unittest.TestCase):

    def _state(self):
        from utils.assault_state import AssaultState
        return AssaultState()

    def test_reset_cancel_keeps_the_same_event_object(self):
        state = self._state()
        before = state.cancel_event
        state.cancel()
        state.reset_cancel()
        self.assertIs(state.cancel_event, before)
        self.assertFalse(state.cancel_event.is_set())
        self.assertFalse(state.is_cancelled())

    def test_captured_reference_sees_a_later_cancel(self):
        """A job that grabbed the Event BEFORE reset_cancel() must still
        observe the next cancel()."""
        state = self._state()
        captured = state.cancel_event      # what a job stores at __init__
        state.reset_cancel()
        state.cancel()
        self.assertTrue(captured.is_set())

    def test_bind_target_keeps_the_same_event_object(self):
        state = self._state()
        before = state.cancel_event
        state.cancel()
        state.bind_target("http://10.10.10.10/")
        self.assertIs(state.cancel_event, before)
        self.assertFalse(before.is_set())

    def test_stop_pipeline_flag_does_not_leak_into_the_next_run(self):
        state = self._state()
        captured = state.cancel_event
        state.cancel()                     # STOP PIPELINE
        state.reset_cancel()               # next job starting up
        self.assertFalse(state.is_cancelled())
        self.assertFalse(captured.is_set())


# ── Cancelled jobs must not publish a false negative ────────────────

class CancelledResultTests(unittest.TestCase):

    # A syntactically valid HS256 token (signature is junk — it will
    # never crack, which is exactly the "false negative" scenario).
    TOKEN = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
             "eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ."
             "ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWY")

    def test_cancelled_jwt_analysis_is_marked_cancelled(self):
        from utils.jwt_analyzer import analyze_token
        result = analyze_token(self.TOKEN, do_brute=True, do_none=True,
                               is_cancelled=lambda: True)
        self.assertTrue(result.cancelled)
        titles = [f.get("title", "") for f in result.findings]
        self.assertIn("JWT analysis cancelled", titles)
        self.assertTrue(result.to_dict()["cancelled"])

    def test_uncancelled_jwt_analysis_is_not_marked_cancelled(self):
        from utils.jwt_analyzer import analyze_token
        result = analyze_token(self.TOKEN, do_brute=False, do_none=False,
                               is_cancelled=lambda: False)
        self.assertFalse(result.cancelled)
        titles = [f.get("title", "") for f in result.findings]
        self.assertNotIn("JWT analysis cancelled", titles)

    def test_cancelled_brute_force_does_not_claim_no_weak_secret(self):
        """crack_hs256 returns None on cancel exactly like it does on a
        clean miss — the result must not read as a clean miss."""
        from utils.jwt_analyzer import analyze_token
        gate = {"n": 0}

        def _is_cancelled():
            # False for the pre-brute checkpoint, True from the
            # wordlist loop onwards.
            gate["n"] += 1
            return gate["n"] > 1

        logged = []
        result = analyze_token(
            self.TOKEN, do_brute=True, do_none=False,
            is_cancelled=_is_cancelled,
            log_cb=lambda m, l="info": logged.append(m))
        self.assertTrue(result.cancelled)
        self.assertNotIn("[brute] No weak secret in wordlist", logged)

    def test_cancelled_injection_job_reports_cancelled_stats(self):
        from utils.injection_tester import InjectionTesterJob, InjectTarget
        job = InjectionTesterJob(
            targets=[InjectTarget(url="http://127.0.0.1/x", method="GET",
                                  params=["id"], upload_field=None)],
            tests={"sqli": True}, mode="safe", target_host="127.0.0.1")
        done = threading.Event()
        seen = {}

        job.on_done = lambda stats: (seen.update(stats), done.set())
        job.cancel()                       # STOP before the first target
        job.start()
        self.assertTrue(done.wait(10), "injection job did not finish")
        self.assertTrue(seen.get("cancelled"))
        self.assertEqual(seen.get("tested"), 0)


# ── X2 — CONNECT parsing must reach the UI thread ───────────────────

class _DummyCtk:
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, _name):
        return _DummyCtk

    def __call__(self, *args, **kwargs):
        return _DummyCtk()


def _install_customtkinter_stub():
    module = types.ModuleType("customtkinter")
    for name in (
        "CTkFrame", "CTkFont", "CTkButton", "CTkLabel", "CTkEntry",
        "CTkTextbox", "CTkToplevel", "CTkScrollableFrame", "CTkOptionMenu",
        "CTkCheckBox", "CTkRadioButton", "CTkProgressBar", "CTkTabview",
        "CTkSwitch", "StringVar", "BooleanVar", "IntVar",
    ):
        setattr(module, name, _DummyCtk)
    sys.modules["customtkinter"] = module


class _FakeTerminal:
    def __init__(self):
        self.lines = []

    def write(self, text, level="info"):
        self.lines.append((level, text))


class _FakeApp:
    """Stand-in for HawkApp: `ui_call` queues the callback instead of
    running it, so the test can drain the queue on the main thread the
    way Tk's `after(0)` would."""

    def __init__(self):
        self.terminal = _FakeTerminal()
        self.queue = []

    def ui_call(self, fn, *args, **kwargs):
        self.queue.append((fn, args, kwargs))

    def drain(self):
        pending, self.queue = self.queue, []
        for fn, args, kwargs in pending:
            fn(*args, **kwargs)


class ConnectParseMarshallingTests(unittest.TestCase):

    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is not None:
            sys.modules["customtkinter"] = self._old_ctk
        else:
            sys.modules.pop("customtkinter", None)

    def test_session_end_marshals_the_parser_to_the_ui_thread(self):
        from gui.widgets.target_intel_connect_runtime import (
            TargetIntelConnectRuntimeMixin)
        from utils import runner as runner_mod

        calls = []

        class _Widget(TargetIntelConnectRuntimeMixin):
            def __init__(self, app):
                self.app = app

            def _inspect_connect_session(self, *a, **k):
                pass

            def _parse_connect_result(self, *a, **k):
                calls.append(threading.current_thread())

        app = _FakeApp()
        widget = _Widget(app)

        captured = {}

        def _fake_shell(title, cmd, on_exit_callback=None,
                        on_line_callback=None, auto_close=False):
            captured["on_exit"] = on_exit_callback
            return True

        old = runner_mod.open_native_shell_captured
        runner_mod.open_native_shell_captured = _fake_shell
        try:
            widget._open_connect_terminal(
                "smbclient -L //10.10.10.10", "10.10.10.10", 445, "smb",
                action={"id": "list_shares"}, used_creds=None)
        finally:
            runner_mod.open_native_shell_captured = old

        self.assertIn("on_exit", captured)

        # The watcher thread fires the callback — nothing may be parsed
        # there.
        t = threading.Thread(target=captured["on_exit"],
                             args=(["line"], 0), daemon=True)
        t.start()
        t.join(10)
        self.assertEqual(calls, [],
                         "parser ran on the watcher thread")

        # ...it must be sitting in the UI queue instead.
        self.assertTrue(app.queue, "nothing was marshalled to the UI")
        app.drain()
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0], threading.main_thread())

    def test_add_auto_finding_redispatches_from_a_worker_thread(self):
        from gui.widgets.target_intel_render import TargetIntelRenderMixin

        app = _FakeApp()
        add = TargetIntelRenderMixin.add_auto_finding
        fake_self = types.SimpleNamespace(app=app)
        # The guard re-dispatches `self.add_auto_finding` — bind it.
        fake_self.add_auto_finding = (
            lambda *a, **k: add(fake_self, *a, **k))

        err = []

        def _worker():
            try:
                add(fake_self, "Finding from a worker", "body",
                    severity="high", source="unit-test")
            except Exception as e:      # pragma: no cover - diagnostic
                err.append(e)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(10)

        self.assertEqual(err, [])
        self.assertEqual(len(app.queue), 1,
                         "worker-thread push was not marshalled")
        fn, args, kwargs = app.queue[0]
        self.assertEqual(args[0], "Finding from a worker")
        self.assertEqual(kwargs.get("severity"), "high")


if __name__ == "__main__":
    unittest.main()
