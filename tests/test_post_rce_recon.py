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


if __name__ == "__main__":
    unittest.main()
