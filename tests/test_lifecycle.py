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

"""Lifecycle invariants: session switch, STOP, shutdown, timers.

The audit called the lifecycle the weakest point of the design:
switching session did not stop the tools in flight, STOP lied in five
places, and closing HAWK left the subprocesses running.  The invariants
locked down here:

1. A job that finishes AFTER a session switch does not write into the
   new session.  This is the last open data-corruption class.
2. Session switch aborts what is in flight instead of letting it write
   somewhere wrong.
3. `kill()` before `run()` really aborts the spawn — `self.process`
   stays None and no child is created.
4. STOP reports failure when there is nothing it can stop, instead of
   flipping the button back to RUN and calling it done.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


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
        "CTk", "CTkFrame", "CTkFont", "CTkButton", "CTkLabel", "CTkEntry",
        "CTkTextbox", "CTkToplevel", "CTkScrollableFrame", "CTkOptionMenu",
        "CTkCheckBox", "CTkRadioButton", "CTkProgressBar", "CTkTabview",
        "CTkSwitch", "CTkComboBox", "CTkSlider", "CTkSegmentedButton",
        "StringVar", "BooleanVar", "IntVar", "DoubleVar",
    ):
        setattr(module, name, _DummyCtk)
    module.set_appearance_mode = lambda *a, **k: None
    module.set_default_color_theme = lambda *a, **k: None
    sys.modules["customtkinter"] = module


class _Terminal:
    """Capture-only terminal stand-in."""

    def __init__(self):
        self.messages = []

    def write(self, message, level="info"):
        self.messages.append((message, level))

    def section(self, *_a, **_k):
        pass

    def output_callback(self, *_a, **_k):
        pass

    def flush_tool_output(self, *_a, **_k):
        pass

    def opsec_notes(self, *_a, **_k):
        pass

    def text(self):
        return "\n".join(m for m, _ in self.messages)


class _Session:
    def __init__(self, session_id, target_ip="10.10.10.1"):
        self.session_id = session_id
        self.target_ip = target_ip
        self.platform = "HTB"
        self.credentials = []
        self.executed_tools = []
        self.terminal_lines = []
        self.outputs = []

    def add_output(self, phase_id, tool_name, lines):
        self.outputs.append((phase_id, tool_name, list(lines)))

    def finish_tool_execution(self, exec_id, rc, lines, status):
        self.executed_tools.append((exec_id, rc, status))

    def save(self, **_k):
        self.saves = getattr(self, "saves", 0) + 1
        return ""


class _SessionManager:
    def __init__(self, session=None):
        self.current = session


def _app_host(session_id="aaaaaaaa-1111"):
    """Bare object carrying the real HawkApp lifecycle methods.

    The methods under test only touch `session_manager`, `terminal`,
    `bg_jobs_bar`, `kill_chain_panel` and `cred_store`, so binding them
    to a plain object exercises the shipped implementation without a
    live Tk root.
    """
    _install_customtkinter_stub()
    from gui.app import HawkApp

    class Host:
        pass

    host = Host()
    host.session_manager = _SessionManager(_Session(session_id))
    host.terminal = _Terminal()
    for name in ("collect_active_runners", "abort_running_tools",
                 "session_token", "session_token_valid"):
        setattr(host, name, getattr(HawkApp, name).__get__(host, Host))
    return host


# ── Session identity guard ──────────────────────────────────────────

class SessionTokenTests(unittest.TestCase):

    def test_token_matches_active_session(self):
        app = _app_host()
        token = app.session_token()
        self.assertTrue(app.session_token_valid(token))
        self.assertEqual(app.terminal.messages, [])

    def test_token_from_a_previous_session_is_rejected_out_loud(self):
        app = _app_host("old-session")
        stale = app.session_token()
        app.session_manager.current = _Session("new-session", "10.10.10.2")

        self.assertFalse(app.session_token_valid(stale, "nmap output"))
        text = app.terminal.text()
        self.assertIn("discarded", text)
        self.assertIn("nmap output", text)

    def test_no_token_never_blocks(self):
        """Callers that predate the guard must keep working."""
        app = _app_host()
        self.assertTrue(app.session_token_valid(None))


# ── The batch's most important test ─────────────────────────────────

class LateJobDoesNotWriteIntoNewSessionTests(unittest.TestCase):
    """A background job that completes after NEW SESSION / LOAD must
    not file its credentials or its output under the session that
    happens to be active when it ends."""

    def _card(self, app):
        _install_customtkinter_stub()
        from gui.widgets.card_runtime import CardRuntimeMixin

        class Card(CardRuntimeMixin):
            def __init__(self, app):
                self.app = app
                self.phase_id = "recon"
                self.phase_config = {"id": "recon", "name": "RECON"}
                self._tool_widgets = {}
                self._tool_runners = {}
                self._raw_logs = {}
                self._raw_log = []
                self.statuses = []
                self.toggles = []

            def after(self, _delay, fn=None):
                if fn is not None:
                    fn()

            def _set_tool_status(self, tid, status):
                self.statuses.append((tid, status))

            def _toggle_run_btn(self, tool, running):
                self.toggles.append((tool.id, running))

            def set_status(self, *_a, **_k):
                pass

            def _get_target(self):
                return "10.10.10.1"

            def __getattr__(self, name):
                # The happy path fans out into ~40 optional parser and
                # notification hooks that live on sibling mixins. These
                # tests are about the session guard and the per-tool
                # buffer, not about them.
                if name.startswith("_"):
                    return lambda *a, **k: False
                raise AttributeError(name)

        return Card(app)

    def _tool(self):
        return types.SimpleNamespace(
            id="nmap_quick", name="Nmap Quick", binary="nmap")

    def test_on_done_discards_output_from_the_previous_session(self):
        app = _app_host("session-A")
        card = self._card(app)
        tool = self._tool()

        # Tool launched under session A.
        card._tool_widgets[tool.id] = {"_session_token": app.session_token()}
        card._raw_logs[tool.id] = ["22/tcp open ssh"]

        # Operator switches target while the scan is in flight.
        app.session_manager.current = _Session("session-B", "10.10.10.2")

        # Late completion. Would have run every parser and written the
        # execution record into session B before the guard existed.
        touched = []
        app.target_intel = types.SimpleNamespace(
            update_from_nmap=lambda log: touched.append(log))
        card._on_done(tool, "Nmap Quick", 0, [("info", "22/tcp open ssh")])

        self.assertEqual(touched, [],
                         "old target's nmap output reached the new session")
        self.assertIn("discarded", app.terminal.text())
        self.assertEqual(app.session_manager.current.executed_tools, [])
        # The row must not claim a completed run in the new session.
        self.assertIn((tool.id, "ready"), card.statuses)
        self.assertNotIn((tool.id, "done"), card.statuses)

    def test_on_done_runs_normally_when_the_session_is_unchanged(self):
        app = _app_host("session-A")
        card = self._card(app)
        tool = self._tool()
        card._tool_widgets[tool.id] = {"_session_token": app.session_token()}
        card._raw_logs[tool.id] = []

        card._on_done(tool, "Nmap Quick", 0, [])

        self.assertIn((tool.id, "done"), card.statuses)
        self.assertNotIn("discarded", app.terminal.text())


# ── Per-tool raw log (Z6) ───────────────────────────────────────────

class RawLogIsPerToolTests(LateJobDoesNotWriteIntoNewSessionTests):
    """A second tool running on the same card used to zero the shared
    `_raw_log`, destroying the first tool's intel before _on_done got
    to parse it."""

    def test_each_tool_is_parsed_from_its_own_buffer(self):
        app = _app_host("session-A")
        card = self._card(app)
        first = types.SimpleNamespace(
            id="nmap_quick", name="Nmap Quick", binary="nmap")
        second = types.SimpleNamespace(
            id="nmap_full", name="Nmap Full", binary="nmap")

        for tool in (first, second):
            card._tool_widgets[tool.id] = {
                "_session_token": app.session_token()}
        card._raw_logs[first.id] = ["22/tcp open ssh"]
        # Second tool starts on the same card while the first is still
        # in flight.
        card._raw_logs[second.id] = ["80/tcp open http"]

        seen = []
        app.target_intel = types.SimpleNamespace(
            update_from_nmap=lambda log: seen.append(list(log)),
            update_from_vuln_scripts=lambda log: None)
        app.target_bar = types.SimpleNamespace(
            auto_detect_vhost=lambda *_a: None)

        card._on_done(first, "Nmap Quick", 0, [])
        self.assertEqual(seen, [["22/tcp open ssh"]],
                         "the first tool's output was overwritten")

        card._on_done(second, "Nmap Full", 0, [])
        self.assertEqual(seen[-1], ["80/tcp open http"])


# ── Abort on session switch ─────────────────────────────────────────

class _FakeRunner:
    def __init__(self, running=True, kill_result=True):
        self.running = running
        self.killed = False
        self._kill_result = kill_result

    def kill(self):
        self.killed = True
        return self._kill_result


class AbortRunningToolsTests(unittest.TestCase):

    def _app_with_jobs(self):
        app = _app_host()
        import threading

        bg_runner = _FakeRunner()
        card_runner = _FakeRunner()
        crack_runner = _FakeRunner()

        job = types.SimpleNamespace(label="Hydra SSH", runner=bg_runner)
        bar = types.SimpleNamespace(_jobs={"j1": job},
                                    _lock=threading.Lock())
        card = types.SimpleNamespace(_tool_runners={"nmap_full": card_runner})
        app.bg_jobs_bar = bar
        app.kill_chain_panel = types.SimpleNamespace(_cards={"recon": card})
        app.cred_store = types.SimpleNamespace(
            _active_cracks={0: {"runner": crack_runner}})
        return app, (bg_runner, card_runner, crack_runner)

    def test_every_owner_of_a_runner_is_enumerated(self):
        app, runners = self._app_with_jobs()
        labels = [lbl for lbl, _ in app.collect_active_runners()]
        self.assertEqual(len(labels), 3)
        self.assertIn("Hydra SSH", labels)
        self.assertIn("nmap_full", labels)

    def test_finished_card_runners_are_not_reported_as_active(self):
        app, _ = self._app_with_jobs()
        app.kill_chain_panel._cards["recon"]._tool_runners["old"] = \
            _FakeRunner(running=False)
        labels = [lbl for lbl, _ in app.collect_active_runners()]
        self.assertNotIn("old", labels)

    def test_abort_kills_all_three_owners(self):
        app, (bg, card, crack) = self._app_with_jobs()
        n = app.abort_running_tools("NEW SESSION")
        self.assertEqual(n, 3)
        self.assertTrue(bg.killed and card.killed and crack.killed)

    def test_a_runner_that_cannot_be_stopped_is_named(self):
        app, (bg, card, crack) = self._app_with_jobs()
        bg._kill_result = False
        n = app.abort_running_tools("NEW SESSION")
        self.assertEqual(n, 2)
        self.assertIn("could not be stopped", app.terminal.text())
        self.assertIn("Hydra SSH", app.terminal.text())

    def test_no_jobs_no_noise(self):
        app = _app_host()
        self.assertEqual(app.abort_running_tools("NEW SESSION"), 0)
        self.assertEqual(app.terminal.messages, [])


class _Recorder:
    """Records every attribute access and call made on it."""

    def __init__(self, calls, path="app"):
        object.__setattr__(self, "_calls", calls)
        object.__setattr__(self, "_path", path)

    def __getattr__(self, name):
        return _Recorder(self._calls, f"{self._path}.{name}")

    def __setattr__(self, name, value):
        pass

    def __call__(self, *args, **kwargs):
        self._calls.append(self._path)
        return None

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return True


class ApplySessionResetsPanelsTests(unittest.TestCase):
    """LOAD used to repoint `session_manager.current` without touching
    the panels: the previous target's Target Intel, kill-chain dots,
    credential rows (with their stale indices) and findings survived
    into the loaded session and were written to its file."""

    def _bar(self, calls):
        _install_customtkinter_stub()
        from gui.widgets.target_bar import TargetBar

        class Bar:
            def __init__(self):
                self.app = _Recorder(calls, "app")
                self._autosave_on = False
                self.terminal = _Terminal()

            def __getattr__(self, name):
                return _Recorder(calls, f"bar.{name}")

        bar = Bar()
        bar.apply_session = TargetBar.apply_session.__get__(bar, Bar)
        return bar

    def _session(self):
        sess = _Session("loaded-session", "10.10.10.9")
        sess.target_domain = ""
        sess.file_path = "/tmp/s.json"
        sess.target_intel = {}
        sess.hawk_hosts_entries = []
        sess.discovered_users = []
        sess.discovered_shares = []
        sess.terminal_lines = [{"ts": "", "level": "info", "text": "old line"}]
        sess.last_status_per_tool = lambda: {}
        sess.summary = lambda: {"target_ip": sess.target_ip,
                                "platform": "HTB",
                                "session_id": sess.session_id,
                                "created_at": "", "last_saved": "",
                                "tools_run": 0, "terminal_lines": 1,
                                "creds_found": 0}
        return sess

    def test_load_resets_panels_and_realigns_the_credential_store(self):
        calls = []
        bar = self._bar(calls)
        bar.apply_session(self._session())

        self.assertIn("bar._reset_all_panels", calls,
                      "LOAD left the previous session's panels on screen")
        self.assertIn("app.cred_store.refresh", calls,
                      "credential rows kept the previous session's indices")
        self.assertIn("app.rehydrate_findings_panel", calls,
                      "FINDINGS still showed the previous target")

    def test_load_aborts_tools_running_against_the_old_target(self):
        calls = []
        bar = self._bar(calls)
        bar.apply_session(self._session())
        self.assertIn("app.abort_running_tools", calls)

    def test_reset_runs_before_the_terminal_is_restored(self):
        """The reset clears the terminal — and clearing wipes
        `session.terminal_lines`.  Reloading the ACTIVE session must
        still replay its history."""
        calls = []
        bar = self._bar(calls)
        sess = self._session()
        bar.apply_session(sess)

        self.assertLess(calls.index("bar._reset_all_panels"),
                        calls.index("app.terminal.restore_lines"))
        self.assertEqual(len(sess.terminal_lines), 1)


if __name__ == "__main__":
    unittest.main()
