r"""Security regression — AD command construction must shell-quote every
attacker-influenced value (CWE-78), review finding A-01 / A-02.

HAWK pre-fills the AD tool dialogs from the Credential Store and the
parsed session (username, password, NT hash, domain, DC IP, computer
names a hostile target authors), then builds a shell string that runs
under `subprocess.Popen(..., shell=True)` (utils/runner.py) via
`_run_raw` or `_open_terminal`.  A value carrying shell metacharacters
(`; | $() \` && '`) must therefore reach the shell as a single literal
token, not as live syntax, or the target gets command execution on the
operator's Kali box.

The builders live inside Tk dialog methods in card_ad_routes.py and
cannot be imported headless, so — exactly like test_metasploit_fixes —
these are static source-shape checks: they assert the quoting helper
`_shq` (shlex.quote) wraps each interpolation and that the pre-fix bare
forms are gone.  Templates embed the placeholders inside larger tokens
(CORP\user, dom/user:pass, user@dom, dom/user:pass@host) and two
pre-wrap the token in literal single quotes, so the fix quotes the WHOLE
token — quoting a middle slice would not protect — which these checks
also pin.

shlex.quote is a no-op for clean IPs / hostnames / domains / usernames,
so for every normal run the built command is byte-identical to before.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_REL = "gui/widgets/card_ad_routes.py"


def _src(rel=_REL):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class A01IdentitySubstitutionTests(unittest.TestCase):
    """_route_ad_template._build_cmd — the HIGH finding: cred values from
    the store substituted into tool.cmd_template."""

    def setUp(self):
        self.src = _src()

    def test_standalone_identity_placeholders_are_quoted(self):
        # The five standalone substitutions all go through _shq.
        for needle in (
            ".replace(\"{target}\",   _shq(target))",
            ".replace(\"{user}\",     _shq(u) if u else \"<user>\")",
            ".replace(\"{password}\", _shq(p) if p else \"\")",
            ".replace(\"{domain}\",   _shq(d) if d else \"<domain>\")",
        ):
            self.assertIn(needle, self.src,
                          f"identity substitution not quoted: {needle}")

    def test_embedded_tokens_are_quoted_whole(self):
        # Embedded user:pass@host / dom\user / user@dom tokens are quoted
        # as a WHOLE token (quoting a middle slice would not protect).
        for needle in (
            "_shq(f\"{d}/{u}:{p}@{target}\")",
            "_shq(f\"{d}/{u}:{p}\")",
            "_shq(f\"{d}\\\\{u}\")",
            "_shq(f\"{u}@{d}\")",
        ):
            self.assertIn(needle, self.src,
                          f"embedded token not whole-quoted: {needle}")

    def test_rbcd_template_prequote_is_stripped_before_requoting(self):
        # rbcd's template pre-wraps the cred token in literal single
        # quotes; we drop those so the value's own quoting is the only
        # layer (otherwise a hostile value double-quotes and breaks out).
        self.assertIn(
            ".replace(\"'{domain}/{user}:{password}'\",", self.src)

    def test_hash_value_is_quoted_not_the_option(self):
        # Pass-the-hash rewrites inject the hash VALUE; quote the value,
        # never the -hashes/-H/--hashes option text.
        for needle in ("f\"--hashes {_shq(nt_fmt)}\"",
                       "f\"-hashes {_shq(nt_fmt)}\"",
                       "f\"-H {_shq(nt_fmt)}\"",
                       " -hashes {_shq(nt_fmt)} -no-pass\""):
            self.assertIn(needle, self.src,
                          f"hash value not quoted: {needle}")

    def test_dynamic_placeholder_values_are_quoted(self):
        # <CA_NAME> / <TEMPLATE> / <DOMAIN_SID> / <*_COMPUTER> are also
        # attacker-influenced; quoted whole, with the rbcd '<X>$' prequote
        # stripped first.
        self.assertIn("cmd.replace(f\"'<{ph}>$'\", _shq(f\"{val}$\"))",
                      self.src)
        self.assertIn("cmd.replace(f\"<{ph}>\", _shq(val))", self.src)


class A02DirectBuilderTests(unittest.TestCase):
    """Direct f-string builders that reach _open_terminal / _run_raw:
    target / user / pivot / dc must be quoted at every site."""

    def setUp(self):
        self.src = _src()

    def test_quoted_sites_present(self):
        for needle in (
            "f\"/v:{_shq(target)}\"",                       # RDP
            "f\"{bin_} -i {_shq(target)} -u {_shq(u)} \"",  # evil-winrm
            "{_shq(user_part)}@{_shq(target)}",             # impacket PtH
            "{_shq(user_part)}:{_shq(pw)}@{_shq(target)}",  # impacket pw
            "_shq(f'{u}@{pivot}')",                        # local forward
            "_shq(f'{u}@{target}')",                        # SOCKS / sshuttle
            "f\"-dc-ip {_shq(dc) if dc else '<dc-ip>'}",    # certipy auth
            "_shq(f'{_OUTPUTS_DIR}/ntds-{target}')",        # secretsdump path
            "-dc-ip {_shq(target)} -no-pass \"",            # GetNPUsers
            "_shq(f'{domain}/')",                           # GetNPUsers domain
            "_shq(f'{d}/{u}')",                             # AS-REP go
        ):
            self.assertIn(needle, self.src,
                          f"A-02 site not quoted: {needle}")

    def test_prefix_bare_forms_are_gone(self):
        # The exact pre-fix unquoted forms must no longer appear.
        for bare in (
            "f\"/v:{target}\",",
            "f\"-r {u}@{target} 0/0 --dns\")",
            "f\"-dc-ip {dc or '<dc-ip>'} -no-save\"]",
            "f\"-just-dc -outputfile {_OUTPUTS_DIR}/ntds-{target}\")",
        ):
            self.assertNotIn(bare, self.src,
                             f"pre-fix bare form still present: {bare}")


class RunRawGuardIntactTests(unittest.TestCase):
    """The fix must not disturb the _run_raw safety guard that blocks a
    command still carrying unfilled <PLACEHOLDER> literals."""

    def test_guard_still_present(self):
        src = _src("gui/widgets/card_runtime.py")
        self.assertIn("placeholder_hits", src)
        self.assertIn("blocked — command still has unfilled", src)


if __name__ == "__main__":
    unittest.main()
