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

"""Lazy session model of the network sweep (spec §3 / OBS-3).

The sweep writes an inventory whose per-host `session_ref` starts null and
is meant to MATERIALISE on the first click of that host's graph node, so a
later click LOADS the same session instead of spawning a new one.  These
tests pin that promotion flow:

  first promotion of a null-ref host creates ONE session and records the
  resulting `session_ref` in both the in-memory inventory and the on-disk
  artifact; a second promotion loads it (no second session); a failed
  inventory write degrades to a terminal line, never a crash.

The promotion methods live on TargetBar; they are bound onto a bare host
object so the shipped logic runs without a live Tk root.  The customtkinter
stub is installed per-test and torn back down (same discipline as
tests/test_netexec_dialog.py) so it never leaks into another module's
collection-time `pytest.importorskip("customtkinter")`.
"""

import json
import os
import shutil
import sys
import tempfile
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


class _CtkStub:
    """Install the customtkinter stub for the duration of a test and
    restore sys.modules afterwards — same discipline as
    tests/test_netexec_dialog.py."""

    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        super().setUp()

    def tearDown(self):
        super().tearDown()
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk


# ── Lightweight stand-ins for the pieces promotion touches ───────────

class _Terminal:
    def __init__(self):
        self.messages = []

    def write(self, message, level="info"):
        self.messages.append((message, level))

    def text(self):
        return "\n".join(m for m, _ in self.messages)


class _FakeEntry:
    """Just enough CTkEntry surface for the target field."""

    def __init__(self):
        self._value = ""

    def delete(self, _start, _end):
        self._value = ""

    def insert(self, _index, text):
        self._value += text

    def get(self):
        return self._value


class _FakeVar:
    def __init__(self, value=""):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class _SessionManager:
    def __init__(self):
        self.current = None


class _PromotionBase(_CtkStub, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix="hawk_sweep_")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        super().tearDown()

    # ── Host factory ────────────────────────────────────────────────
    def _make_host(self, platform="HTB"):
        from gui.widgets.target_bar import TargetBar

        class Host:
            pass

        h = Host()
        h._tmp = self._tmp
        h.app = types.SimpleNamespace(
            terminal=_Terminal(),
            session_manager=_SessionManager(),
        )
        h._ip_entry = _FakeEntry()
        h._platform_var = _FakeVar(platform)
        h._sweep_graph_win = None            # _close_sweep_graph → no-op
        h._new_session_calls = 0
        h.apply_session_calls = []

        inv = {
            "range": "10.0.0.0/24", "started": "", "finished": "",
            "aborted": "", "method": "nmap-sn",
            "hosts": [
                {"ip": "10.0.0.5", "alive": True,
                 "responded_via": ["arp", "syn:445"], "port_hints": [445],
                 "os_hint": "windows", "session_ref": None},
                {"ip": "10.0.0.9", "alive": True,
                 "responded_via": ["arp"], "port_hints": [],
                 "os_hint": "unknown", "session_ref": None},
            ],
        }
        inv_path = os.path.join(self._tmp, "inv.json")
        with open(inv_path, "w", encoding="utf-8") as fh:
            json.dump(inv, fh)
        h._sweep_inventory = inv
        h._sweep_inventory_path = inv_path

        # Stand in for the heavy _new_session(): create a REAL Session so
        # the file_path/session_id recorded in the ref are genuine and can
        # be reloaded end to end, without the full panel reset / Tk work.
        def _new_session():
            from utils.session import Session
            ip = h._ip_entry.get()
            sess = Session(ip)
            sess.platform = h._platform_var.get()
            path = os.path.join(h._tmp, f"sess_{sess.session_id[:8]}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"target_ip": ip, "session_id": sess.session_id,
                           "platform": sess.platform}, fh)
            sess.file_path = path
            h.app.session_manager.current = sess
            h._new_session_calls += 1

        h._new_session = _new_session
        h.apply_session = lambda sess: h.apply_session_calls.append(sess)

        for name in ("_promote_sweep_host", "_materialize_sweep_session",
                     "_load_sweep_session", "_close_sweep_graph"):
            setattr(h, name, getattr(TargetBar, name).__get__(h, Host))
        return h

    def _host_ref(self, h, ip):
        host = next(x for x in h._sweep_inventory["hosts"]
                    if x["ip"] == ip)
        return host["session_ref"]


# ── Lazy materialisation ─────────────────────────────────────────────

class MaterialiseTests(_PromotionBase):

    def test_first_promotion_creates_session_and_records_ref(self):
        h = self._make_host()
        h._promote_sweep_host("10.0.0.5")

        # Exactly one session was created, none loaded.
        self.assertEqual(h._new_session_calls, 1)
        self.assertEqual(h.apply_session_calls, [])

        # In-memory inventory now carries the ref.
        ref = self._host_ref(h, "10.0.0.5")
        self.assertIsNotNone(ref, "session_ref stayed null after promotion")
        self.assertTrue(ref["session_id"])
        self.assertTrue(ref["file"])

        # The materialised session got the node's IP — no stale target.
        self.assertEqual(h.app.session_manager.current.target_ip, "10.0.0.5")
        self.assertEqual(h._ip_entry.get(), "10.0.0.5")

    def test_ref_is_persisted_to_the_inventory_artifact(self):
        h = self._make_host()
        h._promote_sweep_host("10.0.0.5")

        with open(h._sweep_inventory_path, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        disk_host = next(x for x in on_disk["hosts"]
                         if x["ip"] == "10.0.0.5")
        self.assertIsNotNone(disk_host["session_ref"])
        self.assertEqual(disk_host["session_ref"]["session_id"],
                         self._host_ref(h, "10.0.0.5")["session_id"])
        # The other host is untouched — only the promoted one is filled.
        other = next(x for x in on_disk["hosts"] if x["ip"] == "10.0.0.9")
        self.assertIsNone(other["session_ref"])

    def test_second_promotion_loads_the_existing_session(self):
        h = self._make_host()
        h._promote_sweep_host("10.0.0.5")          # materialise
        self.assertEqual(h._new_session_calls, 1)
        created_id = self._host_ref(h, "10.0.0.5")["session_id"]

        h._promote_sweep_host("10.0.0.5")          # ref set → LOAD

        # No second session; the recorded one was applied with its IP.
        self.assertEqual(h._new_session_calls, 1)
        self.assertEqual(len(h.apply_session_calls), 1)
        loaded = h.apply_session_calls[0]
        self.assertEqual(loaded.target_ip, "10.0.0.5")
        self.assertEqual(loaded.session_id, created_id)

    def test_inventory_write_failure_keeps_ref_in_memory_and_warns(self):
        h = self._make_host()
        # A directory can't be opened for writing → OSError on persist.
        h._sweep_inventory_path = self._tmp
        h._promote_sweep_host("10.0.0.9")

        # In-memory ref survived; the operator was told the file lagged.
        self.assertIsNotNone(self._host_ref(h, "10.0.0.9"))
        self.assertTrue(
            any("Inventory NOT updated" in m
                for m, _ in h.app.terminal.messages),
            h.app.terminal.text())
        # The promotion still completed (session created).
        self.assertEqual(h._new_session_calls, 1)

    def test_missing_session_file_reports_error(self):
        h = self._make_host()
        ref = {"session_id": "abc12345", "file": "/does/not/exist.json"}
        h._load_sweep_session("10.0.0.5", {"ip": "10.0.0.5"}, ref)
        self.assertEqual(h.apply_session_calls, [])
        self.assertTrue(
            any("Session file not found" in m
                for m, _ in h.app.terminal.messages),
            h.app.terminal.text())


if __name__ == "__main__":
    unittest.main()
