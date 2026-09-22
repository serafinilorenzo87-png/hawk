r"""LSASSY card — remote in-memory LSASS dump into the Credential Store.

HAWK covered the at-rest credential dump (SecretsDump: SAM/LSA/NTDS/
DCSync) but not the in-memory one (LSASS).  The LSASSY card runs
netexec's lsassy module against a host you OWN and feeds every recovered
secret into the Credential Store exactly the way SecretsDump does:
  * NT hashes  -> cred_type "hash", hash_type "NTLM" (hashcat -m 1000),
  * cleartext  -> cred_type "cleartext", usable as-is.

Static checks assert the card exists and is wired (the GUI card modules
don't import headless); dynamic checks drive the parser -> cred_store.
"""

import os
import sys
import types
import unittest
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ── Static wiring: the card exists and is routed + parsed ──────────────
class LsassyWiringTests(unittest.TestCase):
    def test_card_registered_in_ad_module(self):
        # modules.ad_pentesting imports only modules.base (no ctk) -> it
        # loads headless, so we can inspect the real Tool object.
        import modules.ad_pentesting as m
        tools = {t.id: t for t in m.ADPentestingModule.TOOLS}
        self.assertIn("lsassy", tools)
        t = tools["lsassy"]
        self.assertEqual("nxc", t.binary)
        self.assertIn("-M lsassy", t.cmd_template)
        self.assertIn("{user}", t.cmd_template)
        self.assertIn("{password}", t.cmd_template)
        self.assertEqual("ad", t.category)

    def test_routed_through_shared_ad_auth_dialog(self):
        # user / password / NTLM-hash (PtH) / domain dialog is
        # _AD_TEMPLATE_AUTH_IDS -> _route_ad_template.
        src = _src("gui/widgets/card_routes_scan.py")
        start = src.index("_AD_TEMPLATE_AUTH_IDS = {")
        end = src.index("if tool.id in _AD_TEMPLATE_AUTH_IDS", start)
        self.assertIn('"lsassy"', src[start:end])

    def test_parser_wired_in_ad_dispatch(self):
        src = _src("gui/widgets/card_runtime.py")
        self.assertRegex(src, r'"lsassy":\s*self\._parse_lsassy_to_intel')

    def test_hint_entry_present(self):
        src = _src("gui/widgets/card_widget.py")
        self.assertRegex(src, r'"lsassy":\s*\{')
        # nanodump offered as a method chip (task: "nanodump ... come chip")
        self.assertIn("METHOD=nanodump", src)


# ── Dynamic parser: nxc -M lsassy output -> Credential Store ───────────
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


_LM = "aad3b435b51404eeaad3b435b51404ee"          # empty-LM sentinel
_NT = "8846f7eaee8fb117ad06bdd830b7586c"          # NT of "password"
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"    # NT of ""


def _p(payload):
    """Wrap a payload in nxc's `SMB <ip> <port> <host>  ` prefix."""
    return ("info", f"SMB         10.10.10.10     445    DC01             {payload}")


# A realistic lsassy run: banner, Pwn3d! marker, one NT hash, one
# cleartext, and a blank-password (empty-NT) row that must be dropped.
_LOG_CREDS = [
    _p(r"[*] Windows 10.0 Build 19041 (name:DC01) (domain:PROVA) (signing:True)"),
    _p(r"[+] PROVA\administrator:Password1 (Pwn3d!)"),
    _p(r"PROVA\administrator " + _LM + ":" + _NT),
    _p(r"PROVA\svc_sql Summer2024!"),
    _p(r"PROVA\disabled " + _LM + ":" + _EMPTY_NT),
]

# lsassy python package missing -> ImportError at module load.
_LOG_MODULE_MISSING = [
    _p(r"[*] Windows 10.0 (name:DC01) (domain:PROVA)"),
    _p(r"[+] PROVA\administrator:Password1 (Pwn3d!)"),
    ("error", "Traceback (most recent call last):"),
    ("error", "ModuleNotFoundError: No module named 'lsassy'"),
]

# authenticated but NOT local admin -> lsassy can't dump.
_LOG_NOT_ADMIN = [
    _p(r"[*] Windows 10.0 (name:DC01) (domain:PROVA)"),
    _p(r"[-] PROVA\lowpriv:Password1 "),
    _p(r"[-] Unable to dump lsass (not admin)"),
]


class LsassyParserTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    @contextmanager
    def _parser(self):
        from gui.widgets.card_parsers_ad import CardADParserMixin

        class _Store:
            def __init__(self):
                self.creds = []

            @contextmanager
            def batch(self):
                yield

            def add_credential(self, c):
                self.creds.append(c)

            def refresh(self):
                pass

        class _Parser(CardADParserMixin):
            phase_id = "ad_pentesting"

            def _get_target(self):
                return "10.10.10.10"

            def _strip_ansi(self, s):
                return s

        parser = _Parser()
        store = _Store()
        findings = []
        parser.app = types.SimpleNamespace(
            cred_store=store,
            target_intel=types.SimpleNamespace(
                add_auto_finding=lambda **k: findings.append(k)),
            terminal=types.SimpleNamespace(write=lambda *a, **k: None),
            after=lambda _delay, fn: fn())
        yield parser, store, findings

    _TOOL = types.SimpleNamespace(id="lsassy", name="LSASSY (LSASS dump)")

    def test_hashes_and_cleartext_feed_cred_store(self):
        with self._parser() as (parser, store, findings):
            used = parser._parse_lsassy_to_intel(self._TOOL, _LOG_CREDS)
            self.assertTrue(used)
            # Empty-NT row dropped: exactly one NT hash + one cleartext.
            self.assertEqual(2, len(store.creds))
            by_type = {c.cred_type for c in store.creds}
            self.assertEqual({"hash", "cleartext"}, by_type)

            h = next(c for c in store.creds if c.cred_type == "hash")
            self.assertEqual("NTLM", h.hash_type)
            # Stored as LM:NT so the store's extract_ntlm() hands hashcat
            # the bare NT for -m 1000.
            self.assertEqual(f"{_LM}:{_NT}", h.hash_val)
            self.assertIn("administrator", h.username.lower())
            self.assertFalse(h.verified)            # dumped loot != proven login
            self.assertIn(_NT, h.notes)

            p = next(c for c in store.creds if c.cred_type == "cleartext")
            self.assertEqual("Summer2024!", p.password)
            self.assertIn("svc_sql", p.username.lower())
            self.assertFalse(p.verified)

    def test_summary_finding_counts_and_severity(self):
        with self._parser() as (parser, store, findings):
            parser._parse_lsassy_to_intel(self._TOOL, _LOG_CREDS)
            self.assertEqual(1, len(findings))
            f = findings[0]
            self.assertIn("LSASSY", f["title"])
            self.assertIn("10.10.10.10", f["title"])
            # Cleartext present -> critical; the actual secret is shown.
            self.assertEqual("critical", f["severity"])
            self.assertIn("Summer2024!", f["description"])
            self.assertIn(_NT, f["description"])
            self.assertTrue(f.get("replace"))
            self.assertTrue(f.get("linked_run_id"))

    def test_module_missing_is_actionable_no_creds(self):
        with self._parser() as (parser, store, findings):
            used = parser._parse_lsassy_to_intel(
                self._TOOL, _LOG_MODULE_MISSING)
            self.assertTrue(used)
            self.assertEqual(0, len(store.creds))
            self.assertEqual(1, len(findings))
            desc = findings[0]["description"]
            self.assertIn("lsassy", desc.lower())
            self.assertIn("pipx inject netexec lsassy", desc)

    def test_no_secrets_gives_reason_and_runbook(self):
        with self._parser() as (parser, store, findings):
            used = parser._parse_lsassy_to_intel(self._TOOL, _LOG_NOT_ADMIN)
            self.assertTrue(used)
            self.assertEqual(0, len(store.creds))
            self.assertEqual(1, len(findings))
            desc = findings[0]["description"]
            self.assertIn("LOCAL ADMIN", desc)
            self.assertIn("SecretsDump", desc)   # at-rest fallback pointer


if __name__ == "__main__":
    unittest.main()
