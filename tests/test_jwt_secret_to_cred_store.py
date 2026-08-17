r"""A recovered JWT signing secret must land in the Credential Store.

The JWT Analyzer cracks the HS* signing secret and reports it — but the
findings only carry a MASKED copy ("se**et") and the raw value is
stripped at session-save time.  Without pushing it to the Credential
Store the crack is unusable after the run (you know it's 6 chars but not
the value) and it never reaches the report.  A signing secret is a
high-value credential (forge any token → auth bypass), so _jwt_finalize
now pushes the full secret to the Credential Store.
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


class _Terminal:
    def write(self, *a, **k):
        pass

    def section(self, *a, **k):
        pass


class _CredRec:
    def __init__(self):
        self.added = []

    def add_credential(self, cred):
        self.added.append(cred)


def _result(cracked):
    return types.SimpleNamespace(
        token="x.y.z", header={"alg": "HS256"},
        payload={"user": "admin", "role": "admin", "iat": 1516239022},
        decoded_ok=True, algorithm="HS256",
        expires_at=None, expired=False, issued_at=None,
        issued_in_future=False, priv_claims=["role"],
        cracked_secret=cracked,
        wordlist_used="/usr/share/wordlists/jwt/jwt.secrets.list",
        forged_none="n.o.ne", forged_admin="a.d.min",
        findings=[], elapsed_secs=0.43, cancelled=False)


def _run(cracked):
    from gui.widgets.card_routes_assault import CardAssaultRoutesMixin
    store = _CredRec()
    findings = []

    class Host:
        def __init__(self):
            self.phase_id = "web_assault"
            self.app = types.SimpleNamespace(
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                cred_store=store,
                terminal=_Terminal())

        def _get_target(self):
            return "192.168.177.134"

        def _on_done(self, *a, **k):
            pass

    CardAssaultRoutesMixin._jwt_finalize(Host(), object(), _result(cracked), [])
    return store, findings


class JwtSecretCredTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_recovered_secret_is_pushed_as_credential(self):
        store, _ = _run("secret")
        self.assertEqual(len(store.added), 1, "secret must reach the store")
        c = store.added[0]
        self.assertEqual(c.password, "secret", "full secret, not masked")
        self.assertEqual(c.username, "admin")      # from the sub/user claim
        self.assertEqual(c.cred_type, "jwt-secret")
        self.assertIn("JWT", c.services)
        self.assertTrue(c.verified)

    def test_no_secret_pushes_nothing(self):
        store, _ = _run(None)
        self.assertEqual(store.added, [],
                         "no crack -> no credential")

    def test_findings_use_replace_so_reruns_dont_stack(self):
        # Each JWT run is a complete current analysis; the cards must
        # replace (not append run-varying lines like Elapsed/wordlist).
        _, findings = _run("secret")
        self.assertTrue(findings, "expected at least the index card")
        self.assertTrue(all(f.get("replace") for f in findings), findings)


if __name__ == "__main__":
    unittest.main()
