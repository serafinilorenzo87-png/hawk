"""Contract tests for the post-RCE quick-recon snippet generators.

The Windows snippet is pasted verbatim into a cmd.exe reverse shell,
so its cmd-level quoting is a correctness property, not cosmetics:
one stray double quote closes the argument early and hands the rest
of the payload to cmd's parser.
"""

import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils import post_rce_recon_win  # noqa: E402


# cmd.exe metacharacters that change the meaning of a command line
# when they are NOT inside a quoted argument.
_CMD_METACHARS = "<>|&^"


def _outside_quotes(cmdline: str) -> str:
    """Return the parts of `cmdline` cmd.exe would parse unquoted.

    cmd toggles quoting state on every double quote; text seen while
    the state is "outside" is subject to redirection/pipe parsing.
    """
    out = []
    inside = False
    for ch in cmdline:
        if ch == '"':
            inside = not inside
            continue
        if not inside:
            out.append(ch)
    return "".join(out)


class WindowsSnippetQuotingTests(unittest.TestCase):
    def test_snippet_has_exactly_the_wrapper_quote_pair(self):
        snippet = post_rce_recon_win.generate_snippet()
        self.assertEqual(
            snippet.count('"'), 2,
            "the cmd wrapper must supply the only double quotes")
        self.assertTrue(
            snippet.startswith(
                'powershell -NoProfile -ExecutionPolicy Bypass '
                '-Command "'))
        self.assertTrue(snippet.endswith('"'))

    def test_no_metacharacter_escapes_the_cmd_quoting(self):
        """The regression that shipped: ~1100 chars outside the quotes.

        With an odd number of double quotes the argument never closes,
        so `| Select-Object`, `2>$null` and `<<<END:UNQUOTED_SVC>>>`
        reach cmd as a pipe, a redirection and a redirection — cmd
        answers "The syntax of the command is incorrect." and no
        ___HAWK_BEGIN___ block ever comes back.
        """
        snippet = post_rce_recon_win.generate_snippet()
        unquoted = _outside_quotes(snippet)
        leaked = sorted({c for c in unquoted if c in _CMD_METACHARS})
        self.assertEqual(
            leaked, [],
            f"metacharacters parsed by cmd outside quotes: {leaked}")
        # Only the invocation itself may sit outside the quotes.
        self.assertEqual(
            unquoted.strip(),
            "powershell -NoProfile -ExecutionPolicy Bypass -Command")

    def test_payload_still_carries_every_section_marker(self):
        """Quoting fix must not drop or mangle the analyzer contract."""
        snippet = post_rce_recon_win.generate_snippet()
        for name in ("WHOAMI", "PRIV_TOKENS", "GROUPS", "LOCAL_ADMINS",
                     "AIE", "UNQUOTED_SVC", "SCHED_TASKS", "SAVED_CREDS",
                     "OS_VERSION", "AV", "INTERNET"):
            self.assertIn(f"<<<SECTION:{name}>>>", snippet)
            self.assertIn(f"<<<END:{name}>>>", snippet)
        self.assertIn("___HAWK_BEGIN___", snippet)
        self.assertIn("___HAWK_END___", snippet)

    def test_unquoted_service_filter_uses_the_hex_escape(self):
        """`-notmatch '^"'` became `-notmatch '^\\x22'`.

        \\x22 is the .NET-regex escape for a double quote, so the
        emitted filter still means "PathName does not start with a
        quote" while costing the payload no literal quote.
        """
        snippet = post_rce_recon_win.generate_snippet()
        self.assertIn("-notmatch '^\\x22'", snippet)

    def test_http_code_line_is_concatenated_not_interpolated(self):
        """`Write-Host "http_code=$($r.StatusCode)"` is the other one.

        The analyzer only needs `http_code=<digits>` on stdout, which
        concatenation produces just as well.
        """
        snippet = post_rce_recon_win.generate_snippet()
        self.assertIn("Write-Host ('http_code=' + $r.StatusCode)", snippet)
        self.assertIn("Write-Host 'http_code=000'", snippet)

    def test_generator_refuses_to_emit_a_broken_wrapper(self):
        """The invariant is enforced, not just documented.

        Injecting a double quote through the section marker template
        is the cheapest way to reproduce "some future edit adds a
        quote to the payload".
        """
        original = post_rce_recon_win._SECTION_MARK
        post_rce_recon_win._SECTION_MARK = '<<<SECTION:"{}">>>'
        try:
            with self.assertRaises(AssertionError) as ctx:
                post_rce_recon_win.generate_snippet()
            self.assertIn("double quotes", str(ctx.exception))
        finally:
            post_rce_recon_win._SECTION_MARK = original

        # Guard restored: the generator works again.
        self.assertEqual(
            post_rce_recon_win.generate_snippet().count('"'), 2)


# ═══════════════════════════════════════════════════════════════════
#  W-08 — the snippet must stay PowerShell-2.0-compatible (2008 R2)
# ═══════════════════════════════════════════════════════════════════

class Ps2CompatibleCmdletTests(unittest.TestCase):
    """Server 2008 R2 ships Windows PowerShell 2.0, and it is exactly the
    box where winPEASany.exe won't run — so the recon snippet is the only
    enumeration that works there.  Get-CimInstance (PS 3.0+) and
    Get-ScheduledTask (PS 3.0+ / Win8+ module) both error out on 2008 R2
    and produced empty sections.  The snippet must use the PS 2.0 forms.
    """

    def setUp(self):
        self.snippet = post_rce_recon_win.generate_snippet()

    def test_service_enum_uses_get_wmiobject(self):
        self.assertIn("Get-WmiObject Win32_Service", self.snippet)
        self.assertNotIn("Get-CimInstance", self.snippet)

    def test_scheduled_tasks_use_native_schtasks(self):
        self.assertIn("schtasks /query", self.snippet)
        self.assertNotIn("Get-ScheduledTask", self.snippet)

    def test_av_enum_uses_get_wmiobject(self):
        self.assertIn(
            "Get-WmiObject -Namespace 'root\\SecurityCenter2'",
            self.snippet)


# ═══════════════════════════════════════════════════════════════════
#  W-09 — _trim_to_markers must keep the FIRST real block
# ═══════════════════════════════════════════════════════════════════

# A genuine recon block: markers on their OWN lines, SeImpersonate enabled.
_REAL_BLOCK = (
    "___HAWK_BEGIN___\n"
    "<<<SECTION:WHOAMI>>>\n"
    "prova\\svc_sql\n"
    "DC01\n"
    "<<<END:WHOAMI>>>\n"
    "<<<SECTION:PRIV_TOKENS>>>\n"
    "SeImpersonatePrivilege        Impersonate a client after "
    "authentication   Enabled\n"
    "<<<END:PRIV_TOKENS>>>\n"
    "___HAWK_END___\n"
)

# cmd.exe echoes the pasted command ABOVE the output: one line that
# repeats every marker literally, mid-line, inside the Write-Host quotes.
_CMD_ECHO_ABOVE = (
    "PS C:\\> powershell -NoProfile -ExecutionPolicy Bypass -Command "
    "\"Write-Host '___HAWK_BEGIN___'; Write-Host '<<<SECTION:WHOAMI>>>'; "
    "whoami; Write-Host '<<<END:WHOAMI>>>'; "
    "Write-Host '<<<SECTION:SCHED_TASKS>>>'; "
    "schtasks /query; Write-Host '<<<END:SCHED_TASKS>>>'; "
    "Write-Host '___HAWK_END___'\"\n"
)

# PowerShell 2.0 re-echoes the whole command in an error BELOW the real
# output when a cmdlet is missing — the decoy that the old rfind grabbed,
# dropping SeImpersonate and fabricating a SYSTEM-scheduled-task finding.
_PS2_ERROR_ECHO_BELOW = (
    "The term 'Get-ScheduledTask' is not recognized as the name of a "
    "cmdlet, function, script file, or operable program.\n"
    "At line:1 char:1\n"
    "+ Write-Host '___HAWK_BEGIN___'; Write-Host '<<<SECTION:SCHED_TASKS>>>'; "
    "Write-Host 'Run As User: SYSTEM'; Write-Host '<<<END:SCHED_TASKS>>>'; "
    "Write-Host '___HAWK_END___'\n"
)


class TrimToFirstRealBlockTests(unittest.TestCase):
    def _titles(self, out):
        return [f["title"] for f in out["findings"]]

    def test_command_echo_above_is_skipped(self):
        out = post_rce_recon_win.analyze_output(
            _CMD_ECHO_ABOVE + _REAL_BLOCK)
        # WHOAMI came from the REAL block, not the echoed command line.
        self.assertEqual(out["user"], "prova\\svc_sql")
        self.assertTrue(
            any("SeImpersonatePrivilege" in t for t in self._titles(out)),
            self._titles(out))

    def test_ps2_error_echo_below_is_skipped(self):
        out = post_rce_recon_win.analyze_output(
            _REAL_BLOCK + _PS2_ERROR_ECHO_BELOW)
        # SeImpersonate is NOT dropped …
        self.assertTrue(
            any("SeImpersonatePrivilege" in t for t in self._titles(out)),
            self._titles(out))
        # … and the "Run As User: SYSTEM" inside the error echo does NOT
        # fabricate a SYSTEM-scheduled-task finding (there was no real
        # SCHED_TASKS section in the genuine block).
        self.assertFalse(
            any("scheduled task" in t.lower() for t in self._titles(out)),
            self._titles(out))

    def test_both_decoys_at_once(self):
        out = post_rce_recon_win.analyze_output(
            _CMD_ECHO_ABOVE + _REAL_BLOCK + _PS2_ERROR_ECHO_BELOW)
        self.assertEqual(out["user"], "prova\\svc_sql")
        self.assertTrue(
            any("SeImpersonatePrivilege" in t for t in self._titles(out)))

    def test_command_echo_alone_is_flagged_not_parsed(self):
        # Only the echoed command, no real block: this is not snippet
        # output and must warn instead of reporting a clean empty parse.
        out = post_rce_recon_win.analyze_output(_CMD_ECHO_ABOVE)
        self.assertTrue(out["parse_warnings"])
        self.assertFalse(
            any("SeImpersonatePrivilege" in f["title"]
                for f in out["findings"]))


# ═══════════════════════════════════════════════════════════════════
#  W-08/W-09 live — a PS 2.0 error echo INSIDE the block (mid-snippet)
# ═══════════════════════════════════════════════════════════════════

# On Server 2008 R2 the AIE `reg query ... 2>&1` for a missing key made PS 2.0
# wrap reg.exe's stderr in a NativeCommandError and RE-ECHO the whole one-line
# command — markers included — right inside the AIE section.  That echo carries
# an embedded ___HAWK_END___ (which truncated the block, dropping every later
# section) AND echoed <<<SECTION:...>>> markers (which seeded decoy section
# bodies).  The fix is twofold: AIE now suppresses stderr with 2>$null, and the
# analyzer matches EVERY marker line-anchored.  This sample keeps the echo so
# the analyzer stays robust even if some other command re-echoes on a target.
_MIDBLOCK_ERROR_ECHO = (
    "___HAWK_BEGIN___\n"
    "<<<SECTION:WHOAMI>>>\n"
    "prova\\vagrant\n"
    "vagrant-2008R2\n"
    "<<<END:WHOAMI>>>\n"
    "<<<SECTION:PRIV_TOKENS>>>\n"
    "SeImpersonatePrivilege        Impersonate a client after authentication"
    "   Enabled\n"
    "SeBackupPrivilege             Back up files and directories            "
    "   Enabled\n"
    "<<<END:PRIV_TOKENS>>>\n"
    "<<<SECTION:LOCAL_ADMINS>>>\n"
    "Alias name     administrators\n"
    "Members\n"
    "vagrant\n"
    "<<<END:LOCAL_ADMINS>>>\n"
    "<<<SECTION:AIE>>>\n"
    "powershell.exe : reg.exe : ERROR: The system was unable to find the "
    "specified registry key or value.\n"
    "    + FullyQualifiedErrorId : NativeCommandError\n"
    "powershell.exe : At line:1 char:564\n"
    "powershell.exe : + Write-Host '___HAWK_BEGIN___'; Write-Host "
    "'<<<SECTION:UNQUOTED_SVC>>>'; Get-WmiObject Win32_Service | Where\n"
    "powershell.exe :  Write-Host '<<<END:UNQUOTED_SVC>>>'; Write-Host "
    "'<<<SECTION:SCHED_TASKS>>>'; Write-Host 'Run As User: SYSTEM'\n"
    "powershell.exe :  Write-Host '<<<END:SCHED_TASKS>>>'; Write-Host "
    "'http_code=000' }; Write-Host '___HAWK_END___'\n"
    "    + FullyQualifiedErrorId : NativeCommandError\n"
    "<<<END:AIE>>>\n"
    "<<<SECTION:UNQUOTED_SVC>>>\n"
    "Name    PathName                             StartMode StartName\n"
    "VulnSvc C:\\Program Files\\Vuln App\\svc.exe  Auto      LocalSystem\n"
    "<<<END:UNQUOTED_SVC>>>\n"
    "<<<SECTION:SCHED_TASKS>>>\n"
    "TaskName:                             \\Microsoft\\Windows\\Defrag\\"
    "ScheduledDefrag\n"
    "Run As User:                          SYSTEM\n"
    "<<<END:SCHED_TASKS>>>\n"
    "<<<SECTION:OS_VERSION>>>\n"
    "OS Name:                   Microsoft Windows Server 2008 R2 Standard\n"
    "System Type:               x64-based PC\n"
    "<<<END:OS_VERSION>>>\n"
    "<<<SECTION:INTERNET>>>\n"
    "http_code=000\n"
    "<<<END:INTERNET>>>\n"
    "___HAWK_END___\n"
    # A second PS 2.0 error re-echo dumped BELOW the block (the classic decoy).
    "powershell.exe : + Write-Host '___HAWK_BEGIN___'; Write-Host "
    "'<<<SECTION:SCHED_TASKS>>>'; Write-Host 'Run As User: SYSTEM'; "
    "Write-Host '___HAWK_END___'\n"
)


class MidBlockErrorEchoTests(unittest.TestCase):
    """A PS 2.0 error echo INSIDE the block must neither truncate it nor seed a
    decoy section: every marker is matched line-anchored (live-validation)."""

    def setUp(self):
        self.out = post_rce_recon_win.analyze_output(_MIDBLOCK_ERROR_ECHO)

    def _titles(self):
        return [f["title"] for f in self.out["findings"]]

    def test_user_from_the_real_whoami(self):
        self.assertEqual(self.out["user"], "prova\\vagrant")

    def test_seimpersonate_is_not_dropped(self):
        self.assertTrue(
            any("SeImpersonatePrivilege" in t for t in self._titles()),
            self._titles())

    def test_sections_after_the_embedded_end_are_recovered(self):
        # UNQUOTED_SVC / SCHED_TASKS / OS_VERSION follow the embedded
        # ___HAWK_END___ inside the AIE echo and were silently dropped before
        # the fix truncated the block there.
        titles = " ".join(self._titles()).lower()
        self.assertIn("unquoted service", titles)
        self.assertIn("scheduled task", titles)
        self.assertIn("os fingerprint", titles)

    def test_echoed_markers_do_not_fabricate_or_double_count(self):
        # Exactly one unquoted-svc finding (1 real service) and one SYSTEM-task
        # finding (1 real task): the echoed <<<SECTION:...>>> copies inside the
        # AIE dump and below the block must not add or inflate findings.
        unq = [t for t in self._titles() if "unquoted service" in t.lower()]
        sched = [t for t in self._titles() if "scheduled task" in t.lower()]
        self.assertEqual(len(unq), 1, unq)
        self.assertEqual(len(sched), 1, sched)
        self.assertIn("(1)", unq[0])
        self.assertIn("(1)", sched[0])


class AieSectionPs2ErrorEchoTests(unittest.TestCase):
    """W-08 root cause: the AIE reg queries must send stderr to $null, not
    2>&1, so a missing key can't trigger the PS 2.0 whole-command re-echo."""

    def test_aie_uses_2_to_null_and_snippet_has_no_2to1(self):
        snip = post_rce_recon_win.generate_snippet()
        self.assertEqual(
            snip.count("AlwaysInstallElevated 2>$null"), 2,
            "both AIE reg queries must suppress stderr with 2>$null")
        self.assertNotIn("2>&1", snip)


if __name__ == "__main__":
    unittest.main()
