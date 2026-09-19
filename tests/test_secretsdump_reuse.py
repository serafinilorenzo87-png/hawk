"""secretsdump — full NT hashes in the finding + a password-reuse finding.

Two review points against the live DCSync run:
  * the finding truncated each NT hash to 8 chars + "…"; the operator
    wants to read/copy the WHOLE hash from the finding.
  * identical NT hash across accounts = identical password.  secretsdump
    now raises a dedicated PASSWORD REUSE finding so the operator is
    signalled (crack one → own the group / pass-the-hash), rather than
    HAWK auto-propagating a cracked password.
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
    def __init__(self):
        self.messages = []

    def write(self, msg, style=None):
        self.messages.append((msg, style))

    def section(self, title):
        self.messages.append((title, "section"))


class _Store:
    def __init__(self):
        self.added = []

    def add_credential(self, cred):
        self.added.append(cred)

    def batch(self):
        """No-op batch() so the parser's
        `with self.app.cred_store.batch():` wrapper works with the
        fake store — the real widget defers per-cred save+refresh
        inside batch(), but this fake has neither, so a plain
        pass-through context manager is enough."""
        from contextlib import contextmanager

        @contextmanager
        def _cm():
            yield
        return _cm()


# e02bc503… shared by Administrator + vagrant; 64f12cdd… shared by the two
# svc accounts; krbtgt unique; Guest is the empty-password NT hash.
_ADMIN_NT = "e02bc503339d51f71d913c245d35b50b"
_SVC_NT   = "64f12cddaa88057e06a81b54e73b949b"
_LM = "aad3b435b51404eeaad3b435b51404ee"
_DUMP = [
    "Impacket v0.13.0 - Copyright Fortra, LLC",
    "[*] Using the DRSUAPI method to get NTDS.DIT secrets",
    f"Administrator:500:{_LM}:{_ADMIN_NT}:::",
    f"vagrant:1000:{_LM}:{_ADMIN_NT}:::",
    f"svc_sql:1109:{_LM}:{_SVC_NT}:::",
    f"svc_asrep:1110:{_LM}:{_SVC_NT}:::",
    f"krbtgt:502:{_LM}:6c1394ac8fa011c7a75e0756828d0f00:::",
    f"Guest:501:{_LM}:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    "[*] Cleaning up...",
]


def _run(log):
    from gui.widgets.card_parsers_ad import CardADParserMixin

    findings = []
    store = _Store()

    class Host(CardADParserMixin):
        def __init__(self):
            self.phase_id = "ad_pentesting"
            self.app = types.SimpleNamespace(
                cred_store=store,
                target_intel=types.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                terminal=_Terminal(),
                after=lambda _d, fn: fn())

        def _get_target(self):
            return "192.0.2.10"

        def _strip_ansi(self, s):
            return s

    tool = types.SimpleNamespace(
        name="SECRETSDUMP (DCSync)", binary="impacket-secretsdump",
        id="impacket_secretsdump")
    Host()._parse_secretsdump_to_intel(
        tool, [("out", ln) for ln in log])
    return findings, store


class SecretsdumpReuseTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_finding_shows_full_nt_hash(self):
        findings, _ = _run(_DUMP)
        dump = next(f for f in findings
                    if f["title"].startswith("SECRETSDUMP"))
        # The WHOLE 32-char NT hash, not an 8-char "e02bc503…" teaser.
        self.assertIn(_ADMIN_NT, dump["description"])
        self.assertNotIn("…", dump["description"])
        self.assertEqual(dump["severity"], "critical")

    def test_password_reuse_finding(self):
        findings, _ = _run(_DUMP)
        reuse = [f for f in findings
                 if f["title"].startswith("PASSWORD REUSE")]
        self.assertEqual(len(reuse), 1)
        f = reuse[0]
        self.assertEqual(f["severity"], "high")
        d = f["description"]
        # Both reuse groups, by hash, naming the members.
        self.assertIn(_ADMIN_NT, d)
        self.assertIn("Administrator", d)
        self.assertIn("vagrant", d)
        self.assertIn(_SVC_NT, d)
        self.assertIn("svc_sql", d)
        self.assertIn("svc_asrep", d)
        # 4 accounts across 2 shared hashes.
        self.assertIn("4 accounts", f["title"])

    def test_unique_and_empty_hashes_are_not_reuse(self):
        findings, _ = _run(_DUMP)
        reuse = next(f for f in findings
                     if f["title"].startswith("PASSWORD REUSE"))
        # krbtgt has a unique hash; Guest's is the empty-password NT.
        self.assertNotIn("krbtgt", reuse["description"])
        self.assertNotIn("Guest", reuse["description"])

    def test_no_reuse_when_all_hashes_distinct(self):
        log = [
            "Impacket v0.13.0",
            f"Administrator:500:{_LM}:{_ADMIN_NT}:::",
            f"svc_sql:1109:{_LM}:{_SVC_NT}:::",
        ]
        findings, _ = _run(log)
        self.assertFalse(any(f["title"].startswith("PASSWORD REUSE")
                             for f in findings))


if __name__ == "__main__":
    unittest.main()
