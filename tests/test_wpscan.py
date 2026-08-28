r"""WPSCAN card review — parser + route hardening.

Findings fixed (static review; WPSCAN is not runnable on MS2 which has no
WordPress, so the parser is covered here with representative sample
output and must still be validated on a real WP box):

  HIGH  wpscan findings were discarded on non-zero exit — wpscan exits 5
        exactly when it FINDS vulnerabilities, and it had no specialized
        parser, so it fell to the rc==0-gated generic parser and its
        results vanished.  Fixed by _parse_wpscan_to_intel (runs
        regardless of rc, like nuclei/nikto).
  HIGH  the WPScan API token was registered in the API Key Manager but
        never passed to wpscan → no CVE lookups.  Route now injects
        --api-token from keys_for_tool("wpscan").
  MED   wpscan ran foreground (no STOP) → now a bg-job like nuclei/nikto.
  MED   _detect_wordpress set a PROCESS-WIDE socket timeout → removed.
  LOW   None-slice on a header value → guarded.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# The parser lives on a mixin in a module that imports customtkinter at
# top level; the pytest env has no GUI stack, and the parser itself never
# touches customtkinter, so stub it just long enough to import the pure
# method under test — then undo every import side effect so other test
# modules keep importing the real (or absent) GUI stack exactly as before.
from unittest.mock import MagicMock

_mods_before = set(sys.modules)
if "customtkinter" not in sys.modules:
    sys.modules["customtkinter"] = MagicMock()
try:
    from gui.widgets.card_parsers_web import CardWebParserMixin
    _IMPORT_OK = True
except Exception as _e:                      # pragma: no cover - headless
    _IMPORT_OK = False
    _IMPORT_ERR = repr(_e)
    CardWebParserMixin = None
# The class object stays alive via the name binding above even after we
# drop its module from the cache.
for _k in list(sys.modules):
    if _k not in _mods_before and (
            _k == "customtkinter" or _k == "gui" or _k.startswith("gui.")):
        del sys.modules[_k]


_SAMPLE_FULL = [
    "[+] URL: http://192.168.177.134/ [192.168.177.134]",
    "[+] Started: Mon",
    "[+] WordPress version 5.7.2 identified (Insecure, released 2021-05-12).",
    "[i] Plugin(s) Identified:",
    "[+] contact-form-7",
    " | Location: http://192.168.177.134/wp-content/plugins/contact-form-7/",
    " | [!] 1 vulnerability identified:",
    " | [!] Title: Contact Form 7 < 5.3.2 - Unrestricted File Upload",
    " |     Fixed in: 5.3.2",
    " |     References:",
    " |      - cve: 2020-35489",
    " |      - https://wpscan.com/vulnerability/abc",
    "[+] XML-RPC seems to be enabled: http://192.168.177.134/xmlrpc.php",
    "[+] WordPress readme found: http://192.168.177.134/readme.html",
    "[i] User(s) Identified:",
    "[+] admin",
    " | Found By: Author Posts - Display Name (Passive Detection)",
    "[+] editor",
    " | Found By: Rss Generator (Aggressive Detection)",
    "[i] No Config Backups Found.",
    "[+] Finished: Mon",
    "[+] Requests Done: 220",
]


@unittest.skipUnless(_IMPORT_OK, "card_parsers_web import failed (no display?)")
class WpscanParserTests(unittest.TestCase):
    def _run(self, lines):
        findings = []
        stub = types.SimpleNamespace()
        stub._strip_ansi = lambda s: s
        stub._extract_web_target_label = \
            lambda tool: "http://192.168.177.134/"
        stub.app = types.SimpleNamespace(
            after=lambda ms, fn: fn(),
            target_intel=types.SimpleNamespace(
                add_auto_finding=lambda **kw: findings.append(kw)),
            terminal=types.SimpleNamespace(write=lambda *a, **k: None))
        tool = types.SimpleNamespace(name="WPSCAN", binary="wpscan",
                                     id="wpscan")
        log = [("info", l) for l in lines]
        ret = CardWebParserMixin._parse_wpscan_to_intel(stub, tool, log)
        return ret, findings

    def test_full_scan_extracts_everything(self):
        ret, findings = self._run(_SAMPLE_FULL)
        self.assertTrue(ret)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")     # vulns + CVE present
        self.assertEqual(f["source"], "WPSCAN")
        self.assertTrue(f["replace"])
        d = f["description"]
        self.assertIn("v5.7.2", d)
        self.assertIn("OUTDATED", d)                 # (Insecure ...) flag
        self.assertIn("Unrestricted File Upload", d)
        self.assertIn("CVE-2020-35489", d)           # from "cve: 2020-35489"
        self.assertIn("admin, editor", d)            # users, in order
        self.assertNotIn("Requests", d)              # not mistaken for a user
        self.assertIn("XML-RPC", d)

    def test_not_wordpress_is_info_not_high(self):
        ret, findings = self._run([
            "[+] URL: http://192.168.177.134/",
            "[!] The remote website is up, but does not seem to be "
            "running WordPress.",
        ])
        self.assertTrue(ret)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertIn("not running WordPress", findings[0]["description"])

    def test_nothing_structured_returns_false(self):
        # No WP version, no vulns, no users, no exposures → let the caller
        # decide; do NOT fabricate a card.
        ret, findings = self._run([
            "[+] URL: http://x/",
            "[+] Started: Mon",
            "[+] Finished: Mon",
        ])
        self.assertFalse(ret)
        self.assertEqual(findings, [])


class WpscanRouteStaticTests(unittest.TestCase):
    def setUp(self):
        self.src = _src("gui/widgets/card_routes_web.py")

    def _func(self, name):
        start = self.src.index(f"def {name}")
        end = self.src.index("\n    def ", start + 1)
        return self.src[start:end]

    def test_wpscan_runs_as_bg_job(self):
        body = self._func("_route_wpscan")
        self.assertIn("_run_in_background(tool, cmd", body)
        self.assertNotIn("_run_raw(tool", body)

    def test_wpscan_injects_api_token(self):
        body = self._func("_route_wpscan")
        self.assertIn('keys_for_tool("wpscan")', body)
        self.assertIn("--api-token", body)

    def test_detect_wordpress_has_no_global_socket_timeout(self):
        body = self._func("_detect_wordpress")
        # Only the executable code matters — the explanatory comment is
        # allowed to name the call it deliberately avoids.
        offenders = [l for l in body.splitlines()
                     if "setdefaulttimeout" in l
                     and not l.lstrip().startswith("#")]
        self.assertEqual(offenders, [],
                         "must not mutate the process-wide socket timeout")

    def test_header_evidence_guards_none(self):
        body = self._func("_detect_wordpress")
        self.assertIn("(hval or '')", body)


class WpscanDispatchStaticTests(unittest.TestCase):
    def test_on_done_dispatches_wpscan_parser(self):
        src = _src("gui/widgets/card_runtime.py")
        self.assertIn("_parse_wpscan_to_intel", src)
        self.assertIn('tool.binary == "wpscan"', src)


if __name__ == "__main__":
    unittest.main()
