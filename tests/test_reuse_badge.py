"""Credential-store password-reuse badge grouping.

The operator asked: with 10 dumped hashes, how do they see at a glance
which ones share a password?  The store now tags every credential that
shares an NT hash with "reused ×N" in a per-group colour.  This exercises
the pure grouping logic (_compute_reuse_info) — same NT hash ⇒ same group
⇒ same colour, distinct hashes ⇒ distinct colours, and the empty-password
NT hash / non-NTLM blobs never count as reuse.
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


_ADMIN_NT = "e02bc503339d51f71d913c245d35b50b"
_SVC_NT = "64f12cddaa88057e06a81b54e73b949b"
_UNIQ_NT = "6c1394ac8fa011c7a75e0756828d0f00"
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
_LM = "aad3b435b51404eeaad3b435b51404ee"


def _hash_cred(cid, user, nt, hash_val=None, cred_type="hash",
               hash_type="NTLM"):
    return types.SimpleNamespace(
        id=cid, username=user, cred_type=cred_type, hash_type=hash_type,
        hash_val=hash_val if hash_val is not None
        else f"{user}:1000:{_LM}:{nt}:::")


class ReuseBadgeTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.credential_store_widget import (
            CredentialStoreWidget)
        # Bare instance — _compute_reuse_info / _reuse_color only touch
        # class state, never Tk, so we skip __init__.
        self.w = CredentialStoreWidget.__new__(CredentialStoreWidget)

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_shared_hash_is_one_coloured_group(self):
        creds = [
            _hash_cred("a", "Administrator", _ADMIN_NT),
            _hash_cred("b", "vagrant", _ADMIN_NT),
            _hash_cred("c", "svc_sql", _SVC_NT),
            _hash_cred("d", "svc_asrep", _SVC_NT),
            _hash_cred("e", "krbtgt", _UNIQ_NT),
        ]
        info = self.w._compute_reuse_info(creds)
        # Two reuse groups of two; the unique hash is not in any group.
        self.assertEqual(set(info), {"a", "b", "c", "d"})
        self.assertNotIn("e", info)
        # Same group ⇒ same (count, colour); distinct groups ⇒ distinct.
        self.assertEqual(info["a"], info["b"])
        self.assertEqual(info["c"], info["d"])
        self.assertEqual(info["a"][0], 2)
        self.assertNotEqual(info["a"][1], info["c"][1])
        # First-seen group takes the first palette colour (cyan).
        self.assertEqual(info["a"][1], self.w._REUSE_PALETTE[0])

    def test_empty_and_unique_never_flagged(self):
        creds = [
            _hash_cred("a", "Guest", _EMPTY_NT),
            _hash_cred("b", "Guest2", _EMPTY_NT),   # both empty-password
            _hash_cred("c", "lonely", _UNIQ_NT),
        ]
        self.assertEqual(self.w._compute_reuse_info(creds), {})

    def test_lm_nt_and_bare_nt_shapes_group_together(self):
        creds = [
            _hash_cred("a", "u1", _ADMIN_NT, hash_val=f"{_LM}:{_ADMIN_NT}"),
            _hash_cred("b", "u2", _ADMIN_NT, hash_val=_ADMIN_NT),
        ]
        info = self.w._compute_reuse_info(creds)
        self.assertEqual(info["a"], info["b"])
        self.assertEqual(info["a"][0], 2)

    def test_non_hash_and_kerberos_blobs_ignored(self):
        creds = [
            _hash_cred("a", "u1", _ADMIN_NT),
            types.SimpleNamespace(  # cleartext cred, not a hash
                id="b", username="u2", cred_type="cleartext",
                hash_type="", hash_val=""),
            types.SimpleNamespace(  # Kerberos blob — nonce, not a password
                id="c", username="u3", cred_type="hash",
                hash_type="Kerberos TGS",
                hash_val="$krb5tgs$23$*u3$REALM$deadbeef"),
        ]
        # Only one plain NT hash → no reuse group at all.
        self.assertEqual(self.w._compute_reuse_info(creds), {})

    def test_colours_never_repeat_beyond_palette(self):
        pal = self.w._REUSE_PALETTE
        seen = [self.w._reuse_color(i) for i in range(len(pal) + 12)]
        self.assertEqual(len(seen), len(set(seen)), "reuse colours must "
                         "never repeat, even past the curated palette")
        self.assertEqual(seen[:len(pal)], list(pal))

    def test_palette_and_generated_colours_avoid_reserved_app_hues(self):
        import colorsys
        # Cyan / amber / red / orange are owned by the app UI.
        reserved = {"#00c8c8", "#e8a020", "#c84040", "#d06820"}
        bands = self.w._REUSE_SAFE_BANDS
        for i in range(len(self.w._REUSE_PALETTE) + 20):
            c = self.w._reuse_color(i).lower()
            self.assertNotIn(c, reserved)
            r = int(c[1:3], 16) / 255
            g = int(c[3:5], 16) / 255
            b = int(c[5:7], 16) / 255
            h = colorsys.rgb_to_hsv(r, g, b)[0]
            self.assertTrue(
                any(lo - 0.01 <= h <= hi + 0.01 for lo, hi in bands),
                f"colour {c} (hue {h:.3f}) is outside the safe bands")


if __name__ == "__main__":
    unittest.main()
