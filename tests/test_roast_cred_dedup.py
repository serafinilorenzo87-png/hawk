"""Re-roasting the same account must not stack duplicate rows.

Kerberos roast tickets ($krb5asrep$ / $krb5tgs$) embed a per-request
nonce + timestamp, so GetNPUsers / GetUserSPNs return a DIFFERENT hash
every run for the SAME account.  The credential-store dedup keyed on the
exact hash_val, so each re-roast looked like a brand-new secret and stacked
a duplicate svc_asrep / svc_sql row.  For roast hash types the identity is
(user, host, hash_type) — the hash value is expected to churn.
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


def _cred(**kw):
    from utils.session import Credential
    c = Credential(username=kw.get("username", ""),
                   password=kw.get("password", ""),
                   cred_type=kw.get("cred_type", "hash"),
                   host=kw.get("host", ""))
    c.hash_val = kw.get("hash_val", "")
    c.hash_type = kw.get("hash_type", "")
    return c


class RoastDedupTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.credential_store_widget import CredentialStoreWidget
        self._W = CredentialStoreWidget

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _finder(self, existing):
        stub = types.SimpleNamespace(
            app=types.SimpleNamespace(
                session_manager=types.SimpleNamespace(
                    current=types.SimpleNamespace(
                        get_credentials=lambda: existing))))
        return self._W._find_duplicate_index.__get__(stub)

    def test_reroast_same_user_dedups_despite_new_hash(self):
        old = _cred(username="svc_asrep", host="10.0.0.1",
                    hash_type="Kerberos AS-REP",
                    hash_val="$krb5asrep$23$svc_asrep@R:AAAA$1111")
        fdi = self._finder([old])
        # A FRESH roast of the same account = a different hash value.
        fresh = _cred(username="svc_asrep", host="10.0.0.1",
                      hash_type="Kerberos AS-REP",
                      hash_val="$krb5asrep$23$svc_asrep@R:BBBB$2222")
        self.assertEqual(fdi(fresh), 0, "re-roast must dedup to the "
                         "existing row, not stack a duplicate")

    def test_tgs_roast_also_dedups_on_identity(self):
        old = _cred(username="svc_sql", host="10.0.0.1",
                    hash_type="Kerberos TGS",
                    hash_val="$krb5tgs$23$*svc_sql$R$s*$AAAA")
        fresh = _cred(username="svc_sql", host="10.0.0.1",
                      hash_type="Kerberos TGS",
                      hash_val="$krb5tgs$23$*svc_sql$R$s*$BBBB")
        self.assertEqual(self._finder([old])(fresh), 0)

    def test_different_roast_user_is_not_a_dup(self):
        old = _cred(username="svc_asrep", host="10.0.0.1",
                    hash_type="Kerberos AS-REP", hash_val="$krb5asrep$23$a")
        other = _cred(username="svc_other", host="10.0.0.1",
                      hash_type="Kerberos AS-REP", hash_val="$krb5asrep$23$b")
        self.assertEqual(self._finder([old])(other), -1)

    def test_stable_ntlm_still_dedups_on_value_not_identity(self):
        # A non-roast hash keeps value-based dedup: two different NTLM
        # hashes for the same user are two distinct secrets, not one.
        old = _cred(username="admin", host="10.0.0.1",
                    hash_type="NTLM", hash_val="a" * 32)
        different = _cred(username="admin", host="10.0.0.1",
                          hash_type="NTLM", hash_val="b" * 32)
        self.assertEqual(self._finder([old])(different), -1)
        same = _cred(username="admin", host="10.0.0.1",
                     hash_type="NTLM", hash_val="a" * 32)
        self.assertEqual(self._finder([old])(same), 0)


if __name__ == "__main__":
    unittest.main()
