r"""Hardening regression — review findings A-03 and C-01 (both LOW,
defense-in-depth, not live injection).

C-01 (CWE-23, path traversal defense-in-depth): a validated target cannot
carry `/` or `..`, so it is safe as an output-filename component.  The rule
now lives in `utils.config.is_valid_target` (outside the GUI), the target bar
delegates to it, `Session.load` re-validates a loaded `target_ip` (untrusted
session file), and the AD output paths are additionally routed through
`require_within_base` as a containment net.

A-03 (CWE-77): the Metasploit-from-Intel launcher rejects CR/LF in the fields
that become msfconsole resource-script directives, and a malformed LPORT.

`is_valid_target` is pure and headless, so it is tested behaviorally; the rest
live in GUI-/session-bound code and are verified as static source-shape checks
(same approach as test_metasploit_fixes / test_ad_cmd_quoting).
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class IsValidTargetTests(unittest.TestCase):
    """Behavioral — the canonical target validator (C-01 primary defense)."""

    def setUp(self):
        from utils.config import is_valid_target
        self.v = is_valid_target

    def test_accepts_ipv4_and_hostnames(self):
        for ok in ("10.10.10.1", "192.168.176.132", "255.255.255.255",
                   "dc01", "dc01.prova.com", "a-b.example.co.uk"):
            self.assertTrue(self.v(ok), f"should accept {ok!r}")

    def test_rejects_traversal_and_metacharacters(self):
        # The whole point: nothing with a path separator or shell/space
        # metacharacter is a valid target, so it can never reach a filename
        # component or an argv token as live syntax.
        # NB: "10.0.0.x" is intentionally NOT here — it is a syntactically
        # valid hostname (alphanumeric labels), correctly accepted.
        for bad in ("", "../../etc/passwd", "a/b", "/abs", "..",
                    "1.2.3.4; id", "1.2.3.4 && rm -rf /", "a|b",
                    "$(id)", "a b", "host\n", "1.2.3.4\n"):
            self.assertFalse(self.v(bad), f"should reject {bad!r}")

    def test_rejects_out_of_range_octets(self):
        for bad in ("999.1.1.1", "256.0.0.1", "1.2.3.400"):
            self.assertFalse(self.v(bad), f"should reject {bad!r}")


class SessionLoadRevalidatesTargetTests(unittest.TestCase):
    """C-01: Session.load re-validates a loaded target_ip, but only when
    non-empty ('' is legitimate for a new session)."""

    def setUp(self):
        self.src = _src("utils/session.py")

    def test_load_revalidates_nonempty_target(self):
        self.assertIn("is_valid_target", self.src)
        # Guarded on non-empty so a new session's "" still loads.
        self.assertIn("if _loaded_target and not is_valid_target(_loaded_target)",
                      self.src)
        self.assertIn("dropping malformed target_ip", self.src)

    def test_validator_imported_from_config_not_gui(self):
        # The rule must not be imported from the gui/ layer into session.
        self.assertIn("from utils.config import", self.src)
        self.assertNotIn("from gui", self.src)


class OutputPathContainmentNetTests(unittest.TestCase):
    """C-01: AD output paths built from target go through require_within_base."""

    def test_card_ad_routes_output_paths_contained(self):
        src = _src("gui/widgets/card_ad_routes.py")
        # secretsdump ntds path pre-contained, then quoted as one token
        self.assertIn("require_within_base(", src)
        self.assertIn('f"{_OUTPUTS_DIR}/ntds-{target}"', src)
        self.assertIn("_shq(_ntds_out)", src)
        self.assertIn("secretsdump ntds output", src)
        # asrep output paths wrapped too
        self.assertIn('"AS-REP output"', src)

    def test_card_parsers_ad_output_path_contained(self):
        src = _src("gui/widgets/card_parsers_ad.py")
        self.assertIn("require_within_base(", src)
        self.assertIn("\"AS-REP output\"", src)


class MsfLaunchHardeningTests(unittest.TestCase):
    """A-03: the MSF-from-Intel launcher rejects newlines and a bad LPORT."""

    def setUp(self):
        self.src = _src("gui/widgets/target_intel_msf.py")

    def test_rejects_newline_in_fields(self):
        self.assertIn('"\\n" in _val or "\\r" in _val', self.src)
        self.assertIn("contains a newline", self.src)

    def test_validates_lport_range(self):
        self.assertIn("1 <= int(_v_lport.strip()) <= 65535", self.src)
        self.assertIn("invalid LPORT", self.src)


class ReportFilePermsTests(unittest.TestCase):
    """D-01: report deliverables (containing recovered creds) are chmod 0o600."""

    def setUp(self):
        self.src = _src("modules/report/engine.py")

    def test_text_report_restricted(self):
        idx = self.src.index('open(path, "w"')
        chunk = self.src[idx:idx + 200]
        self.assertIn("os.chmod(path, 0o600)", chunk)

    def test_pdf_report_restricted(self):
        idx = self.src.index('open(path, "wb"')
        chunk = self.src[idx:idx + 200]
        self.assertIn("os.chmod(path, 0o600)", chunk)


class TempDirHardeningTests(unittest.TestCase):
    """G-01: fallback temp dir is created 0o700 and verified (owner, not
    symlink) before use.  Fail-closed to TMP_DIR on any check failure."""

    def setUp(self):
        self.src = _src("utils/config.py")

    def test_creates_with_restricted_mode(self):
        self.assertIn("mode=0o700", self.src)

    def test_rejects_symlink(self):
        self.assertIn("S_ISLNK", self.src)

    def test_checks_ownership(self):
        self.assertIn("st.st_uid != os.getuid()", self.src)

    def test_tightens_existing_perms(self):
        self.assertIn("S_IMODE(st.st_mode) != 0o700", self.src)
        self.assertIn("os.chmod(external_tmp, 0o700)", self.src)

    def test_imports_stat(self):
        self.assertIn("import stat", self.src)


if __name__ == "__main__":
    unittest.main()
