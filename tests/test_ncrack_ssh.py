r"""NCRACK SSH — legacy-capable SSH brute card.

hydra's SSH module (libssh) can't negotiate the old KEX/MAC/cipher
algorithms a pre-2016 OpenSSH offers (Metasploitable2 = OpenSSH 4.7), so
it dies at key-exchange before trying a password — and exposes no option
to force the old algos.  ncrack has its own SSH stack and speaks legacy
crypto, so HAWK gets a dedicated NCRACK SSH card:

  * a Tool `ncrack_ssh` right under HYDRA SSH,
  * its own dialog with a Concurrency (CL) field,
  * a parser that lands the found cred (verified) + a stable
    "Weak credentials — SSH on <host>" finding,
  * a legacy-detection heads-up + "Open NCRACK SSH" button in the HYDRA
    SSH dialog, and a post-run kex-error explainer.

The routing/dialog/parser live on customtkinter widget mixins that can't
import headless, so those are static source-shape checks; the ncrack
output regex and the Tool registration are functional.
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# The exact regex used by _parse_ncrack_to_intel.
_NCRACK_RE = re.compile(
    r"(\S+)\s+(\d+)/tcp\s+ssh:\s*'([^']*)'\s+'([^']*)'", re.I)


class NcrackOutputRegexTests(unittest.TestCase):
    def test_parses_discovered_credential_line(self):
        line = "192.168.177.134 22/tcp ssh: 'msfadmin' 'msfadmin'"
        m = _NCRACK_RE.search(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "192.168.177.134")
        self.assertEqual(int(m.group(2)), 22)
        self.assertEqual(m.group(3), "msfadmin")
        self.assertEqual(m.group(4), "msfadmin")

    def test_tolerates_leading_terminal_indent(self):
        m = _NCRACK_RE.search("   10.0.0.5 2222/tcp ssh: 'root' 'toor'")
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(2)), 2222)
        self.assertEqual((m.group(3), m.group(4)), ("root", "toor"))

    def test_ignores_non_credential_lines(self):
        for noise in (
            "Starting Ncrack 0.7 ( http://ncrack.org )",
            "Discovered credentials for ssh on 192.168.177.134 22/tcp:",
            "Ncrack done: 1 service scanned in 3.01 seconds.",
        ):
            self.assertIsNone(_NCRACK_RE.search(noise))


class NcrackToolRegistrationTests(unittest.TestCase):
    def test_tool_registered_right_under_hydra_ssh(self):
        from modules.exploitation import ExploitationModule
        ids = [t.id for t in ExploitationModule.TOOLS]
        self.assertIn("ncrack_ssh", ids)
        self.assertIn("hydra_ssh", ids)
        self.assertEqual(ids.index("ncrack_ssh"),
                         ids.index("hydra_ssh") + 1)
        t = next(t for t in ExploitationModule.TOOLS
                 if t.id == "ncrack_ssh")
        self.assertEqual(t.binary, "ncrack")
        self.assertEqual(t.name, "NCRACK SSH")


class NcrackWiringShapeTests(unittest.TestCase):
    def test_dispatch_routes_ncrack_ssh(self):
        src = _src("gui/widgets/card_routes_scan.py")
        self.assertIn('tool.id == "ncrack_ssh"', src)
        self.assertIn("self._route_ncrack_ssh(tool)", src)

    def test_route_builds_ncrack_command_with_cl(self):
        src = _src("gui/widgets/card_routes_hydra.py")
        self.assertIn("def _route_ncrack_ssh", src)
        self.assertIn("def _show_ncrack_ssh_dialog", src)
        # Concurrency exposed and mapped to ncrack's connection limit,
        # run as a bg job.
        self.assertIn("ncrack --connection-limit ", src)
        self.assertIn("Concurrency (CL)", src)
        self.assertIn("_run_in_background(tool, cmd", src)

    def test_parser_lands_cred_and_finding(self):
        src = _src("gui/widgets/card_parsers_service.py")
        self.assertIn("def _parse_ncrack_to_intel", src)
        self.assertIn("Weak credentials — SSH on", src)
        self.assertIn('source="ncrack"', src)
        self.assertIn("verified=True", src)

    def test_parser_invoked_and_excluded_from_generic_fallback(self):
        src = _src("gui/widgets/card_runtime.py")
        self.assertIn("_parse_ncrack_to_intel", src)
        i = src.index("_NO_GENERIC_FALLBACK = {")
        j = src.index("}", i)
        self.assertIn('"ncrack"', src[i:j])


class HydraSshLegacyGuidanceTests(unittest.TestCase):
    def test_hydra_dialog_detects_legacy_and_offers_ncrack(self):
        src = _src("gui/widgets/card_routes_hydra.py")
        self.assertIn("def _ssh_is_legacy", src)
        self.assertIn('tool.id == "hydra_ssh"', src)
        self.assertIn("Open NCRACK SSH", src)
        self.assertIn('get_tool("ncrack_ssh")', src)

    def test_kex_error_explainer_points_to_ncrack(self):
        src = _src("gui/widgets/card_parsers_post.py")
        self.assertIn("no match for method", src)
        self.assertIn("NCRACK SSH", src)


if __name__ == "__main__":
    unittest.main()
