"""IMPACKET SecretsDump consolidation contract.

The two legacy standalone cards (Exploitation-phase Target-dump and
AD PENTESTING DCSync) collapsed into ONE card in AD PENTESTING with
a MODE dropdown that picks the impacket-secretsdump invocation at
run time.  These tests lock the invariant:

  1. The registry exposes exactly ONE ``impacket_secretsdump`` card
     (in AD PENTESTING), and NO ``secretsdump_dcsync`` id anywhere.
  2. The base cmd_template is minimal (no cablate -just-dc); mode-
     specific flags are added by the dialog's MODE dropdown as
     extras, keeping the DEFAULT-COMMAND MINIMO invariant.
  3. Each mode composes into the correct impacket invocation:
     Target dump → creds@target only; DCSync → same + -just-dc +
     -outputfile <OUTPUTS>/ntds-<target>.
  4. Pass-the-hash (NTLM hash field) still works in both modes
     (transformed to -hashes :NT -no-pass by _route_ad_template
     for impacket binaries).

The command shape (auth handling + hash transform) is exercised
elsewhere; this file focuses on the CONSOLIDATION contract.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.exploitation import ExploitationModule   # noqa: E402
from modules.ad_pentesting import ADPentestingModule  # noqa: E402


def _all_tools():
    return list(ExploitationModule.TOOLS) + list(ADPentestingModule.TOOLS)


def _all_ids():
    return {t.id for t in _all_tools()}


class RegistryConsolidationTests(unittest.TestCase):

    def test_single_impacket_secretsdump_card_in_registry(self):
        matches = [t for t in _all_tools()
                   if t.id == "impacket_secretsdump"]
        self.assertEqual(
            len(matches), 1,
            "Expected exactly one Tool(id='impacket_secretsdump'); "
            f"found {len(matches)}.")

    def test_card_is_homed_in_ad_pentesting(self):
        """After consolidation the card lives in AD PENTESTING; the
        old Exploitation-phase duplicate has been removed."""
        ad_ids = {t.id for t in ADPentestingModule.TOOLS}
        expl_ids = {t.id for t in ExploitationModule.TOOLS}
        self.assertIn("impacket_secretsdump", ad_ids)
        self.assertNotIn("impacket_secretsdump", expl_ids)

    def test_no_secretsdump_dcsync_id_anywhere(self):
        """The old AD-phase id must not linger — one tool, one home,
        one id."""
        self.assertNotIn("secretsdump_dcsync", _all_ids())


class TemplateMinimalityTests(unittest.TestCase):
    """cmd_template is INFORMATIONAL — mode-specific flags are
    injected by the dialog's MODE dropdown as extras, so the tool's
    default template must NOT hard-code -just-dc or -outputfile.
    Regression guard for the DEFAULT-COMMAND MINIMO invariant."""

    def setUp(self):
        matches = [t for t in _all_tools()
                   if t.id == "impacket_secretsdump"]
        self.assertEqual(len(matches), 1)
        self.tool = matches[0]

    def test_template_contains_the_placeholders(self):
        for ph in ("{user}", "{password}", "{target}"):
            self.assertIn(ph, self.tool.cmd_template)

    def test_template_does_not_cable_dcsync_flags(self):
        for cablate in ("-just-dc", "-outputfile", "-just-dc-ntlm"):
            self.assertNotIn(
                cablate, self.tool.cmd_template,
                f"{cablate} is cablate in the default template — "
                "must be an extra selected by the MODE dropdown.")

    def test_binary_still_impacket_secretsdump(self):
        self.assertEqual(self.tool.binary, "impacket-secretsdump")


class ModeExtrasCompositionTests(unittest.TestCase):
    """Replicate the dialog's mode-to-extras mapping and assert the
    composed command line for each mode.

    The dialog's _apply_mode() writes into extras_var; _build_cmd()
    later appends extras_var to the substituted template.  This
    test re-implements the same composition so a drift in either
    place is caught."""

    _TARGET   = "10.0.0.10"
    _DOMAIN   = "prova.prova.com"
    _USER     = "vagrant"
    _PASSWORD = "Vagrant2026"

    def _substitute(self, template):
        return (template
                .replace("{domain}", self._DOMAIN)
                .replace("{user}",   self._USER)
                .replace("{password}", self._PASSWORD)
                .replace("{target}", self._TARGET))

    def _mode_extras(self, mode):
        from utils.config import OUTPUTS_DIR
        if mode == "DCSync":
            return (
                f"-just-dc -outputfile {OUTPUTS_DIR}/"
                f"ntds-{self._TARGET}")
        return ""

    def _compose(self, mode):
        tool = next(t for t in _all_tools()
                    if t.id == "impacket_secretsdump")
        base = self._substitute(tool.cmd_template)
        extras = self._mode_extras(mode)
        return (base.rstrip() + " " + extras) if extras else base

    def test_target_dump_mode_produces_bare_creds_at_target(self):
        cmd = self._compose("Target dump")
        self.assertEqual(
            cmd,
            "impacket-secretsdump "
            f"{self._DOMAIN}/{self._USER}:{self._PASSWORD}@"
            f"{self._TARGET}")

    def test_dcsync_mode_appends_just_dc_and_outputfile(self):
        from utils.config import OUTPUTS_DIR
        cmd = self._compose("DCSync")
        self.assertEqual(
            cmd,
            "impacket-secretsdump "
            f"{self._DOMAIN}/{self._USER}:{self._PASSWORD}@"
            f"{self._TARGET} "
            f"-just-dc -outputfile {OUTPUTS_DIR}/ntds-"
            f"{self._TARGET}")

    def test_dcsync_outputfile_lives_under_the_outputs_dir(self):
        """Every AD tool writes artefacts under <HAWK>/outputs/;
        the DCSync -outputfile must follow that convention so the
        raw .ntds / .sam / .security land next to the other AD
        dumps (adidnsdump, ldapdomaindump, kerberoast, ...)."""
        from utils.config import OUTPUTS_DIR
        cmd = self._compose("DCSync")
        self.assertIn(f"{OUTPUTS_DIR}/ntds-{self._TARGET}", cmd)


class RoutingContractTests(unittest.TestCase):
    """The consolidated card must route through _AD_TEMPLATE_AUTH
    (the general AD-template dialog with per-tool {user}/{password}/
    {domain} substitution), NOT through the impacket-user@host
    dialog (_IMPACKET_AUTH).  Otherwise the {domain} placeholder
    is not filled and DCSync auth fails."""

    def _routing_src(self):
        src_path = os.path.join(
            ROOT, "gui", "widgets", "card_routes_scan.py")
        with open(src_path, encoding="utf-8") as f:
            return f.read()

    def test_routed_via_ad_template(self):
        src = self._routing_src()
        i = src.index("_AD_TEMPLATE_AUTH_IDS = {")
        j = src.index("}", i)
        block = src[i:j]
        self.assertIn('"impacket_secretsdump"', block)

    def test_not_in_impacket_auth_ids(self):
        src = self._routing_src()
        i = src.index("_IMPACKET_AUTH_IDS = {")
        j = src.index("}", i)
        block = src[i:j]
        # The old routing for the Exploitation-phase card lived
        # here — must not linger, or the AD-side {domain}
        # substitution never runs and the DCSync mode fails auth.
        # An in-line NOTE comment mentioning the id is fine
        # (comments are stripped implicitly by not appearing as a
        # quoted string element); assert the id is NOT a string
        # entry by requiring the SPECIFIC line
        # `            "impacket_secretsdump",` is absent.
        self.assertNotIn(
            '            "impacket_secretsdump",',
            block,
            "impacket_secretsdump must not be a string entry in "
            "_IMPACKET_AUTH_IDS any more (it's routed via "
            "_AD_TEMPLATE_AUTH_IDS with a MODE dropdown).")


if __name__ == "__main__":
    unittest.main()
