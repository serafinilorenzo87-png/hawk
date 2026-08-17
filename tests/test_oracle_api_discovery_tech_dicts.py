r"""ORACLE's API discovery must build its tech signature from the
profile's tech dicts, not treat them as strings.

profile["tech"] is a list of dicts ({name, version, source}).  The old
_run_api_discovery did `" ".join(t.lower() for t in profile["tech"])`,
which raised `AttributeError: 'dict' object has no attribute 'lower'` on
the first element.  The exception was swallowed by the caller with a
single warn, so the ENTIRE framework-aware phase silently never ran:
no agnostic probes, no framework paths, no swagger/graphql parsing,
empty API surface -- while the operator saw a green "ORACLE completed".

This was audit finding D1 (utils/web_oracle.py:1087).  The signature is
now built from the dict fields, lowercased.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class _DummyCtk:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, _n):
        return _DummyCtk

    def __call__(self, *a, **k):
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


class OracleApiTechDictTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _make_oracle(self, captured):
        from utils.web_oracle import WebOracleRunner
        oracle = WebOracleRunner.__new__(WebOracleRunner)
        oracle._cancelled = False
        # Offline: no baseline, every probe skipped -> no network, [] back.
        oracle._curl_probe = lambda *a, **k: None
        oracle._emit = lambda *a, **k: None

        def _cap(sig):
            captured["sig"] = sig
            return WebOracleRunner._detect_framework(oracle, sig)

        oracle._detect_framework = _cap
        return oracle

    def test_dict_tech_does_not_crash_and_builds_signature(self):
        captured = {}
        oracle = self._make_oracle(captured)
        profile = {"tech": [
            {"name": "Apache", "version": "2.2.8", "source": "whatweb"},
            {"name": "PHP", "version": "5.2.4", "source": "whatweb"},
        ]}
        # Pre-fix this raised AttributeError before returning.
        result = oracle._run_api_discovery("http://192.168.177.134:80/",
                                           profile)
        self.assertEqual(result, [])   # offline -> nothing discovered
        # Signature is lowercased name + version, so _detect_framework can
        # actually see the stack (here: PHP -> framework probes).
        self.assertIn("php", captured["sig"])
        self.assertIn("apache", captured["sig"])
        self.assertIn("5.2.4", captured["sig"])

    def test_mixed_and_empty_tech_are_robust(self):
        from utils.web_oracle import WebOracleRunner
        # A stray non-dict entry must not crash the join.
        captured = {}
        oracle = self._make_oracle(captured)
        oracle._run_api_discovery(
            "http://t/", {"tech": [{"name": "nginx"}, "garbage", None]})
        self.assertIn("nginx", captured["sig"])

        # Missing / empty tech key must not crash either.
        captured2 = {}
        oracle2 = self._make_oracle(captured2)
        self.assertEqual(
            oracle2._run_api_discovery("http://t/", {}), [])
        self.assertEqual(captured2["sig"], "")


if __name__ == "__main__":
    unittest.main()
