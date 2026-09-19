r"""W-07 regression: winPEAS.bat (legacy ASCII) must yield findings.

winPEAS.bat — the only variant that runs on Server 2008 R2, where
winPEASany.exe needs a .NET runtime the box hasn't got — carries NO
box-drawing section headers.  Its :ColorLine helper prints "[*] NAME"
(major) / " [+] NAME" (subsection) instead.  Before the fix the section
splitter only knew the box-drawing dialect, so every .bat run landed
entirely in `_preamble`, every section parser looked up a section that
never got created, and the run produced ZERO findings even with
SeImpersonate on screen.

These tests lock two things at once:
  * .bat ASCII output now splits into sections and surfaces the
    SeImpersonate finding (the whole point of W-07);
  * .exe box-drawing output still splits on the box characters and
    keeps "[+]" as an inline banner, so the ASCII dialect never hijacks
    a real winPEASany.exe run.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.parsers import winpeas_parser as wp   # noqa: E402


# winPEAS.bat dumps `whoami /all` under its "[+] CURRENT USER" section —
# the only place the privileges table (and SeImpersonate) appears in .bat
# output.  No box-drawing anywhere: this is the ASCII dialect.
_BAT_OUTPUT = (
    "\n"
    "[*] BASIC SYSTEM INFORMATION\n"
    "Host Name:                 DC01\n"
    "OS Name:                   Microsoft Windows Server 2008 R2 Datacenter\n"
    "OS Version:                6.1.7601 Service Pack 1\n"
    "\n"
    "[+] CURRENT USER\n"
    "whoami\n"
    "prova\\svc_sql\n"
    "\n"
    "USER INFORMATION\n"
    "----------------\n"
    "User Name     SID\n"
    "============= =============================================\n"
    "prova\\svc_sql S-1-5-21-1004336348-1177238915-682003330-1108\n"
    "\n"
    "PRIVILEGES INFORMATION\n"
    "----------------------\n"
    "Privilege Name                Description                               State\n"
    "============================= ========================================= ========\n"
    "SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled\n"
    "SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled\n"
    "SeImpersonatePrivilege        Impersonate a client after authentication Enabled\n"
    "SeCreateGlobalPrivilege       Create global objects                     Enabled\n"
)


# winPEASany.exe: real box-drawing headers, and "[+]" reused as an inline
# banner INSIDE a section (must NOT be treated as a section boundary).
_EXE_OUTPUT = "\n".join([
    "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Current Token privileges",
    "\u255a Check if you have some abusable token privilege",
    "    [+] Checking token privileges",
    "    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED",
    "    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED",
    "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Interesting Services -non Microsoft-",
    "    some.service  ->  C:\\Program Files\\Vendor\\svc.exe",
])


class WinpeasBatAsciiSectionTests(unittest.TestCase):
    def test_bat_output_splits_into_ascii_sections(self):
        sections = wp._split_into_sections(_BAT_OUTPUT)
        # The whole run must NOT collapse into _preamble.
        self.assertNotEqual(list(sections.keys()), ["_preamble"])
        # Section titles are normalised (lowercased, whitespace-compressed).
        self.assertIn("current user", sections)
        self.assertIn("basic system information", sections)

    def test_bat_output_yields_seimpersonate_finding(self):
        sections = wp._split_into_sections(_BAT_OUTPUT)
        findings = []
        wp._parse_token_privs(sections, "192.168.176.177", findings)
        seimp = [f for f in findings
                 if "SeImpersonatePrivilege" in f["title"]]
        self.assertEqual(len(seimp), 1,
                         [f["title"] for f in findings])
        self.assertEqual(seimp[0]["severity"], "high")

    def test_bat_disabled_privilege_is_not_a_finding(self):
        sections = wp._split_into_sections(_BAT_OUTPUT)
        findings = []
        wp._parse_token_privs(sections, "192.168.176.177", findings)
        # SeAssignPrimaryTokenPrivilege is Disabled in the sample.
        self.assertFalse(
            any("SeAssignPrimaryTokenPrivilege" in f["title"]
                for f in findings),
            [f["title"] for f in findings])


class WinpeasExeBoxDrawingNoRegressionTests(unittest.TestCase):
    def test_exe_output_still_splits_on_box_headers(self):
        sections = wp._split_into_sections(_EXE_OUTPUT)
        self.assertIn("current token privileges", sections)

    def test_inline_plus_banner_is_not_a_section_in_box_mode(self):
        sections = wp._split_into_sections(_EXE_OUTPUT)
        # "[+] Checking token privileges" is a banner, not a header, so no
        # section may be keyed on it.
        self.assertNotIn("checking token privileges", sections)

    def test_exe_flag_constant_privilege_is_detected(self):
        sections = wp._split_into_sections(_EXE_OUTPUT)
        findings = []
        wp._parse_token_privs(sections, "192.168.176.177", findings)
        self.assertTrue(
            any("SeImpersonatePrivilege" in f["title"] for f in findings),
            [f["title"] for f in findings])


if __name__ == "__main__":
    unittest.main()
