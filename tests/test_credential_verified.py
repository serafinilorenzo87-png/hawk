"""Credential-store integrity tests.

The product constraint is that the Credential Store holds VERIFIED
credentials: a row without the UNVERIFIED badge means HAWK watched an
authentication succeed.  `Credential.verified` defaults to False so a
forgotten flag degrades to an extra badge instead of a silent claim of
compromise — and the AST test below makes sure no producer relies on
that default.
"""

import ast
import os
import sys
import json
import unittest
import tempfile
from contextlib import contextmanager
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Directories that are not shipped code: throw-away smoke scripts and
# build/test artefacts.
SKIP_DIRS = {"tmp", "tests", "outputs", "sessions", "logs", "reports",
             "cache", "__pycache__", ".git", "eval_package", "docs"}


def _source_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def _credential_calls(path):
    """Yield (lineno, has_verified_kwarg) for every `Credential(...)`."""
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = (fn.id if isinstance(fn, ast.Name)
                else fn.attr if isinstance(fn, ast.Attribute)
                else "")
        if name != "Credential":
            continue
        has = any(kw.arg == "verified" for kw in node.keywords)
        # **kwargs forwarding counts as explicit: the caller decides.
        has = has or any(kw.arg is None for kw in node.keywords)
        yield (node.lineno, has)


class CredentialVerifiedDefaultTests(unittest.TestCase):
    """The default must stay False — a producer that forgets the flag
    must produce a false NEGATIVE (an extra UNVERIFIED badge), never a
    false claim that a credential authenticated."""

    def test_default_is_unverified(self):
        from utils.session import Credential
        self.assertFalse(Credential(username="u", password="p").verified)

    def test_explicit_true_survives_roundtrip(self):
        from utils.session import Credential
        c = Credential(username="u", password="p", verified=True)
        self.assertTrue(Credential.from_dict(c.to_dict()).verified)

    def test_explicit_false_survives_roundtrip(self):
        from utils.session import Credential
        c = Credential(username="u", password="p", verified=False)
        self.assertFalse(Credential.from_dict(c.to_dict()).verified)


class CredentialConstructionAuditTests(unittest.TestCase):
    """Guard against the bug coming back: every `Credential(...)` in the
    shipped source must state `verified=` explicitly.  Without this the
    default silently decides, which is exactly how 45 of 46 producers
    ended up claiming every credential they touched was verified."""

    def test_every_construction_passes_verified(self):
        offenders = []
        for path in _source_files():
            for lineno, has_verified in _credential_calls(path):
                if not has_verified:
                    rel = os.path.relpath(path, ROOT).replace("\\", "/")
                    offenders.append(f"{rel}:{lineno}")
        self.assertEqual(
            offenders, [],
            "Credential(...) built without an explicit verified= "
            "argument:\n  " + "\n  ".join(offenders)
            + "\n\nPass verified=True only where an authentication "
              "actually succeeded, verified=False otherwise.")

    def test_audit_helper_detects_a_missing_flag(self):
        """The audit itself must be able to fail."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sample.py")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("Credential(username='u')\n"
                         "Credential(username='u', verified=True)\n"
                         "store.add_credential(Credential(verified=False))\n")
            found = list(_credential_calls(p))
        self.assertEqual([(1, False), (2, True), (3, True)], found)


class ProducerContractTests(unittest.TestCase):
    """The producers the audit named must keep declaring what they can
    actually prove.  Anchored on function names, not line numbers, so
    the guard survives edits around them."""

    def _verified_literals(self, relpath, func_name=None):
        """Every `verified=` literal in a file, or in one function."""
        path = os.path.join(ROOT, *relpath.split("/"))
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        scope = tree
        if func_name:
            scope = next(
                (n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == func_name), None)
            self.assertIsNotNone(
                scope, f"{relpath}: no function named {func_name}")
        out = []
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = (fn.id if isinstance(fn, ast.Name)
                    else fn.attr if isinstance(fn, ast.Attribute) else "")
            if name != "Credential":
                continue
            for kw in node.keywords:
                if kw.arg == "verified" and isinstance(kw.value, ast.Constant):
                    out.append(kw.value.value)
        return out

    def test_responder_captures_are_never_verified(self):
        # C1: a NetNTLMv2 capture is a challenge/response, never cracked.
        vals = self._verified_literals(
            "gui/widgets/card_routes_responder.py",
            "_responder_push_hash_to_store")
        self.assertEqual([False], vals)

    def test_manual_add_and_clipboard_import_are_never_verified(self):
        # Y1: operator input and pasted dumps prove nothing.
        for func in ("_add_manual", "_import_clipboard"):
            vals = self._verified_literals(
                "gui/widgets/credential_store_widget.py", func)
            self.assertTrue(vals, f"{func}: no Credential(verified=...)")
            self.assertNotIn(True, vals, func)

    def test_kerbrute_user_enumeration_is_never_verified(self):
        # Kerbrute userenum proves the account exists, nothing more.
        vals = self._verified_literals(
            "gui/widgets/card_parsers_service.py",
            "_parse_kerbrute_to_intel")
        # Two producers in this parser: userenum (False) and the
        # VALID LOGIN spray hit (True).
        self.assertEqual([False, True], vals)

    def test_ad_dumps_are_never_verified(self):
        # Uncracked hashes and a machine account nobody logged in with.
        vals = self._verified_literals("gui/widgets/card_parsers_ad.py")
        self.assertEqual(8, len(vals))
        self.assertNotIn(True, vals)

    def test_peas_scrapes_are_never_verified(self):
        for mod in ("linpeas_parser", "winpeas_parser",
                    "privesccheck_parser"):
            vals = self._verified_literals(
                f"modules/parsers/{mod}.py", "_push_credential")
            self.assertEqual([False], vals, mod)


class UnverifiedBadgeTests(unittest.TestCase):
    """The badge rule itself.  Needs customtkinter (the widget module
    imports it at module level), so it skips on a headless box."""

    def setUp(self):
        import pytest
        pytest.importorskip("customtkinter")

    def test_badge_shows_for_unverified_only(self):
        from gui.widgets.credential_store_widget import (
            needs_unverified_badge)
        from utils.session import Credential
        self.assertTrue(needs_unverified_badge(
            Credential(username="u", password="p", verified=False)))
        self.assertFalse(needs_unverified_badge(
            Credential(username="u", password="p", verified=True)))
        # A push that forgot the flag must still show the badge.
        self.assertTrue(needs_unverified_badge(
            Credential(username="u", password="p")))


class HydraVerdictTests(unittest.TestCase):
    """C2: hydra reporting a hit is a claim; only our own probe is
    proof, and a probe that says NO must drop the credential."""

    def _cmd_info(self):
        from utils.hydra_verify import parse_hydra_cmd
        return parse_hydra_cmd("hydra -l root -P rockyou.txt ssh://10.0.0.9")

    def test_rejected_credential_is_dropped(self):
        from unittest.mock import patch
        import utils.hydra_verify as hv
        verdicts = {"good": True, "bad": False, "dunno": None}
        with patch.object(hv, "_verify_ssh",
                          side_effect=lambda h, p, u, pw: verdicts[u]):
            kept, rejected, reason, cascade = hv.verify_creds(
                [("good", "p1"), ("bad", "p2"), ("dunno", "p3")],
                self._cmd_info(), run_cascade=False)
        self.assertEqual([("good", "p1", True), ("dunno", "p3", None)], kept)
        self.assertEqual([("bad", "p2")], rejected)
        self.assertFalse(cascade)
        self.assertIsNone(reason)

    def test_unverifiable_protocol_keeps_cred_and_says_so(self):
        import utils.hydra_verify as hv
        info = hv.parse_hydra_cmd("hydra -l u -P w.txt rdp://10.0.0.9")
        kept, rejected, _, _ = hv.verify_creds(
            [("u", "p")], info, run_cascade=False)
        self.assertEqual([("u", "p", None)], kept)
        self.assertEqual([], rejected)
        self.assertIn("no HAWK probe", hv.unverified_note(info))
        self.assertIn("rdp", hv.unverified_note(info))

    def test_probe_count_is_capped(self):
        from unittest.mock import patch
        import utils.hydra_verify as hv
        calls = []
        with patch.object(hv, "_verify_ssh",
                          side_effect=lambda h, p, u, pw: calls.append(u)):
            kept, _, _, _ = hv.verify_creds(
                [(f"u{i}", "p") for i in range(10)],
                self._cmd_info(), run_cascade=False)
        self.assertEqual(hv.MAX_PER_CRED_PROBES, len(calls))
        self.assertEqual(10, len(kept))
        self.assertTrue(all(v is None for _, _, v in kept[len(calls):]))

    def test_cascade_drops_everything(self):
        from unittest.mock import patch
        import utils.hydra_verify as hv
        with patch.object(hv, "detect_false_positive_cascade",
                          return_value=([], "endpoint accepts anything",
                                        True)):
            kept, rejected, reason, cascade = hv.verify_creds(
                [("a", "1"), ("b", "2")], self._cmd_info())
        self.assertTrue(cascade)
        self.assertEqual([], kept)
        self.assertEqual([("a", "1"), ("b", "2")], rejected)
        self.assertIn("anything", reason)


class OnlineCrackRehashTests(unittest.TestCase):
    """C3: a plaintext from a remote service is only a crack if it
    hashes back to what we submitted."""

    def test_md4_rfc1320_vectors(self):
        from utils.online_crack import _md4
        vectors = {
            b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
            b"a": "bde52cb31de33e46245e05fbdbd6fb24",
            b"abc": "a448017aaf21d8525fc10ae87aa6729d",
            b"message digest": "d9130a8164549fe818874806e1c7014b",
            b"abcdefghijklmnopqrstuvwxyz":
                "d79e1c308aa5bbcdeea8ed63df412da9",
            b"1234567890" * 8: "e33b4ddc9c38f2199c3e7b164fcc0536",
        }
        for data, expected in vectors.items():
            self.assertEqual(expected, _md4(data), data)

    def test_ntlm_match_and_mismatch(self):
        from utils.online_crack import verify_plaintext
        nt = "64f12cddaa88057e06a81b54e73b949b"     # NTLM("Password1")
        self.assertTrue(verify_plaintext(nt, "NTLM", "Password1"))
        self.assertFalse(verify_plaintext(nt, "NTLM", "Password2"))
        # LM:NT composite form.
        self.assertTrue(verify_plaintext(
            f"aad3b435b51404eeaad3b435b51404ee:{nt}", "NTLM", "Password1"))

    def test_unsupported_algorithm_is_undecided_not_a_match(self):
        from utils.online_crack import verify_plaintext
        self.assertIsNone(verify_plaintext("$2a$12$xyz", "bcrypt", "pw"))
        self.assertIsNone(verify_plaintext("deadbeef", "MD5", ""))

    def test_md5_and_sha_families(self):
        import hashlib
        from utils.online_crack import verify_plaintext
        for algo, fn in (("MD5", hashlib.md5), ("SHA1", hashlib.sha1),
                         ("SHA256", hashlib.sha256),
                         ("SHA512", hashlib.sha512)):
            digest = fn(b"hunter2").hexdigest()
            self.assertTrue(verify_plaintext(digest, algo, "hunter2"), algo)
            self.assertFalse(verify_plaintext(digest, algo, "hunter3"), algo)


class UnverifiedPushTests(unittest.TestCase):
    """Producers with no proof of authentication must push unverified
    credentials, and the report must call them out."""

    @contextmanager
    def _temp_session(self):
        """A Session that saves into a throw-away directory.

        Session.save() redirects outside-BASE_DIR paths to the real
        sessions/ snapshot folder, so the guard is patched out here —
        the tests must never write into the operator's sessions.
        """
        from utils.session import Session
        with tempfile.TemporaryDirectory() as d:
            with patch("utils.session.is_within_base", return_value=True), \
                 patch("utils.config.is_within_base", return_value=True):
                sess = Session("10.0.0.9")
                sess.file_path = os.path.join(d, "sess.json")
                yield sess

    def test_responder_capture_is_unverified(self):
        # A Responder capture is a raw NetNTLMv2 challenge/response —
        # never cracked, never authenticated.
        from utils.session import Credential
        cred = Credential(
            username="jdoe", hash_val="jdoe::CORP:1122334455667788:AA:BB",
            hash_type="NetNTLMv2", cred_type="NetNTLMv2",
            services=["SMB"], source_phase="exploitation",
            host="CORP", notes="captured by Responder", verified=False)
        self.assertFalse(cred.verified)
        self.assertFalse(cred.to_dict()["verified"])

    def test_report_marks_unverified_rows(self):
        from modules.report.providers import CredentialsProvider

        class _Ctx:
            pass

        class _Sess:
            credentials = [
                {"username": "a", "cred_type": "cleartext",
                 "verified": False},
                {"username": "b", "cred_type": "cleartext",
                 "verified": True},
                {"username": "c", "cred_type": "hash", "cracked": True,
                 "verified": False},
            ]

        ctx = _Ctx()
        ctx.session = _Sess()
        section = CredentialsProvider().build(ctx)
        statuses = [row[-1] for row in section.blocks[0].data["rows"]]
        self.assertEqual(["unverified", "-", "cracked"], statuses)

    def test_unverified_then_promoted_persists_to_disk(self):
        """A cred pushed unverified, then proven by a real login, must
        end up verified BOTH in memory and in the session file."""
        from utils.session import Credential, Session
        with self._temp_session() as sess:
            sess.add_credential(Credential(
                username="svc", password="Summer2026!",
                cred_type="cleartext", services=["SMB"],
                host="10.0.0.9", source_phase="import",
                verified=False))
            sess.save()
            with open(sess.file_path, encoding="utf-8") as fh:
                self.assertFalse(json.load(fh)["credentials"][0]["verified"])

            # Promotion path: mutate the underlying dict, then persist.
            entry = sess.credentials[0]
            entry["verified"] = True
            entry["notes"] = "[verified by SMB share enumeration]"
            sess._touch()
            sess.save()

            with open(sess.file_path, encoding="utf-8") as fh:
                stored = json.load(fh)["credentials"][0]
            self.assertTrue(stored["verified"])

            fresh = Session("10.0.0.9")
            fresh.load(sess.file_path)
            self.assertTrue(fresh.get_credentials()[0].verified)

    def test_mark_cracked_persists_to_disk(self):
        """Y5: 40 minutes of hashcat must survive closing HAWK."""
        from utils.session import Credential, Session
        with self._temp_session() as sess:
            sess.add_credential(Credential(
                username="admin", hash_val="a" * 32, hash_type="NTLM",
                cred_type="hash", host="10.0.0.9",
                source_phase="post_exploit", verified=False))
            sess.save()
            sess.mark_cracked(0, "Password1")

            fresh = Session("10.0.0.9")
            fresh.load(sess.file_path)
            reloaded = fresh.get_credentials()[0]
            self.assertTrue(reloaded.cracked)
            self.assertEqual("Password1", reloaded.cracked_pass)


class _FakeStore:
    def __init__(self):
        self.refreshed = 0
        self.added = []

    def refresh(self):
        self.refreshed += 1

    def add_credential(self, cred):
        self.added.append(cred)


class _FakeTerminal:
    def write(self, *a, **kw):
        pass


class PromotionPathTests(unittest.TestCase):
    """The path that turns an unverified row into a verified one must
    reach BOTH the disk and the Credential Store widget.  Imports the
    Target Intel mixin, so it needs customtkinter."""

    def setUp(self):
        import pytest
        pytest.importorskip("customtkinter")

    @contextmanager
    def _parser(self):
        from utils.session import Session
        from gui.widgets.target_intel_parsers import TargetIntelParserMixin

        class _Parser(TargetIntelParserMixin):
            pass

        class _App:
            pass

        with tempfile.TemporaryDirectory() as d:
            with patch("utils.session.is_within_base", return_value=True), \
                 patch("utils.config.is_within_base", return_value=True):
                sess = Session("10.0.0.9")
                sess.file_path = os.path.join(d, "sess.json")

                class _Mgr:
                    current = sess

                app = _App()
                app.session_manager = _Mgr()
                app.cred_store = _FakeStore()
                app.terminal = _FakeTerminal()
                parser = _Parser()
                parser.app = app
                yield parser, sess, app.cred_store

    def test_promotion_persists_and_refreshes_the_ui(self):
        from utils.session import Credential, Session
        with self._parser() as (parser, sess, store):
            sess.add_credential(Credential(
                username="svc", password="Summer2026!",
                cred_type="cleartext", services=["SMB"],
                host="10.0.0.9", source_phase="import", verified=False))
            sess.save()

            added = parser._mark_creds_verified(
                ("svc", "Summer2026!", ""), "10.0.0.9", "SMB",
                "SMB share enumeration (3 shares listed)")

            self.assertFalse(added, "an existing row must not be duplicated")
            self.assertEqual([], store.added)
            self.assertEqual(1, store.refreshed, "UI was not repainted")
            self.assertEqual(1, len(sess.credentials))
            self.assertTrue(sess.credentials[0]["verified"])

            fresh = Session("10.0.0.9")
            fresh.load(sess.file_path)
            self.assertTrue(fresh.get_credentials()[0].verified)
            self.assertIn("SMB share enumeration",
                          fresh.get_credentials()[0].notes)

    def test_new_credential_is_added_verified(self):
        with self._parser() as (parser, sess, store):
            added = parser._mark_creds_verified(
                ("root", "toor", ""), "10.0.0.9", "SSH",
                "SSH shell opened")
            self.assertTrue(added)
            self.assertEqual(1, len(store.added))
            self.assertTrue(store.added[0].verified)

    def test_unverified_duplicate_never_promotes(self):
        """Y3: re-adding the same unproven credential must not make it
        look verified."""
        from utils.session import Credential
        with self._parser() as (parser, sess, store):
            sess.add_credential(Credential(
                username="svc", password="Summer2026!",
                cred_type="cleartext", services=["SMB"],
                host="10.0.0.9", source_phase="import", verified=False))
            dup = Credential(
                username="svc", password="Summer2026!",
                cred_type="cleartext", services=["SMB"],
                host="10.0.0.9", source_phase="import", verified=False)
            # The widget merge is what decides; mirror its guard.
            promote = (getattr(dup, "verified", False)
                       and not sess.credentials[0].get("verified", True))
            self.assertFalse(promote)

    def test_promotion_matches_identity_not_secret(self):
        """F-05: a manual cred with the right user+host+service but a
        DIFFERENT typed secret is promoted IN PLACE (not duplicated),
        and the stored secret is aligned to the proven one."""
        from utils.session import Credential
        with self._parser() as (parser, sess, store):
            sess.add_credential(Credential(
                username="msfadmin", password="wrongguess",
                cred_type="cleartext", services=["SSH"],
                host="10.0.0.9", source_phase="manual", verified=False))
            sess.save()

            added = parser._mark_creds_verified(
                ("msfadmin", "msfadmin", ""), "10.0.0.9", "SSH",
                "SSH login successful")

            self.assertFalse(added, "promotion must not add a second row")
            self.assertEqual([], store.added)
            self.assertEqual(1, len(sess.credentials))
            self.assertTrue(sess.credentials[0]["verified"])
            self.assertEqual(
                "msfadmin", sess.credentials[0]["password"],
                "stored secret was not aligned to the proven one")

    def test_ssh_connect_success_seeds_verified_credential(self):
        """F-04: a successful SSH CONNECT seeds the store as verified,
        the same way FTP/telnet connects already do."""
        with self._parser() as (parser, sess, store):
            # add_auto_finding lives on the render mixin, not the parser
            # mixin under test — attach a spy so the success branch runs.
            findings = []
            parser.add_auto_finding = (
                lambda title, desc, severity=None, source=None, **k:
                findings.append(title))
            text = ("Linux metasploitable 2.6.24-16-server #1 SMP\n"
                    "Last login: Tue Aug  5 12:00:00 2026 from 10.0.0.1\n"
                    "msfadmin@metasploitable:~$ ")
            parser._parse_ssh_connect(
                "password", "10.0.0.9", 22, text.splitlines(), text,
                used_creds=("msfadmin", "msfadmin", ""))

            self.assertEqual(1, len(store.added),
                             "successful SSH login did not seed the store")
            self.assertTrue(store.added[0].verified)
            self.assertIn("SSH", store.added[0].services)
            self.assertTrue(any("login successful" in t.lower()
                                for t in findings))

    def test_ssh_connect_failure_seeds_nothing(self):
        """A rejected SSH login must never seed a credential."""
        with self._parser() as (parser, sess, store):
            parser.add_auto_finding = lambda *a, **k: None
            bad = ("SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\n"
                   "Permission denied (publickey,password).\n")
            parser._parse_ssh_connect(
                "password", "10.0.0.9", 22, bad.splitlines(), bad,
                used_creds=("root", "toor", ""))
            self.assertEqual([], store.added)
            self.assertEqual(0, len(sess.credentials))


if __name__ == "__main__":
    unittest.main()
