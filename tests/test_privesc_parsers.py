"""Contract tests for the privesc parsers (linPEAS / PrivescCheck /
post-RCE recon).

Samples are real tool output.  Where the exact wording of a linPEAS
subsection header could not be verified, the test drives the parser
function directly with a section body instead of guessing a header.
"""

import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.parsers import linpeas_parser as lp        # noqa: E402
from modules.parsers import privesccheck_parser as pc   # noqa: E402
from utils import post_rce_recon as prr                 # noqa: E402
from utils import post_rce_recon_win as prw             # noqa: E402


# ═══════════════════════════════════════════════════════════════════
#  linPEAS — file capabilities
# ═══════════════════════════════════════════════════════════════════

# `getcap -r /` output, as linPEAS reproduces it.
_CAPS_SECTION = """\
Files with capabilities (limited to 50):
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/python3.11 = cap_setuid+ep
"""


class LinpeasCapabilityTests(unittest.TestCase):
    def _run(self, body):
        findings = []
        lp._parse_capabilities({"capabilities": body}, "10.10.10.5",
                               findings)
        return findings

    def test_default_cap_net_raw_holders_are_not_privesc_findings(self):
        """cap_net_raw on ping is every distro's default.

        Reporting it as a HIGH privesc vector fires on every single
        Linux target and buries the real hit under noise.
        """
        titles = [f["title"] for f in self._run(_CAPS_SECTION)]
        self.assertNotIn("Capability cap_net_raw on ping", titles)
        self.assertNotIn("Capability cap_net_raw on mtr-packet", titles)
        self.assertNotIn(
            "Capability cap_net_raw on traceroute6.iputils", titles)

    def test_the_real_hit_survives(self):
        findings = self._run(_CAPS_SECTION)
        self.assertEqual(len(findings), 1, [f["title"] for f in findings])
        self.assertEqual(findings[0]["title"],
                         "Capability cap_setuid on python3.11")
        self.assertEqual(findings[0]["severity"], "high")

    def test_cap_net_raw_on_a_non_default_binary_is_medium(self):
        """It is still worth reporting - it is just not a root path."""
        findings = self._run("/opt/vendor/agent = cap_net_raw+ep\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")


# ═══════════════════════════════════════════════════════════════════
#  linPEAS — writable critical files
# ═══════════════════════════════════════════════════════════════════

class LinpeasWritableCriticalFilesTests(unittest.TestCase):
    def _run(self, body):
        findings = []
        lp._parse_writable_critical_files(
            {"interesting files": body}, "10.10.10.5", findings)
        return [f["title"] for f in findings]

    def test_not_writable_is_not_writable(self):
        """"writable" is a substring of "not writable".

        The old pattern read the negation as a confirmation and
        produced a CRITICAL "/etc/passwd appears writable".
        """
        body = ("/etc/passwd is not writable\n"
                "/etc/shadow is not writable\n")
        self.assertEqual(self._run(body), [])

    def test_a_www_data_row_of_etc_passwd_is_not_evidence(self):
        """grep output whose FILE is /etc/passwd and whose MATCH is the
        www-data account: `/etc/passwd` followed by `ww`.

        The old pattern accepted `ww` as a permission token, so this
        line alone asserted a writable /etc/passwd.
        """
        body = ("/etc/passwd:www-data:x:33:33:www-data:"
                "/var/www:/usr/sbin/nologin\n")
        self.assertEqual(self._run(body), [])

    def test_default_ls_l_permissions_are_not_evidence(self):
        body = "-rw-r--r-- 1 root root 2872 Jul 30 09:11 /etc/passwd\n"
        self.assertEqual(self._run(body), [])

    def test_world_writable_mode_is_evidence(self):
        body = "-rw-rw-rw- 1 root root 2872 Jul 30 09:11 /etc/passwd\n"
        self.assertEqual(self._run(body), ["/etc/passwd appears writable"])

    def test_explicit_writable_annotation_is_evidence(self):
        body = "/etc/passwd is writable\n"
        self.assertEqual(self._run(body), ["/etc/passwd appears writable"])


# ═══════════════════════════════════════════════════════════════════
#  linPEAS — credentials grepped out of config files
# ═══════════════════════════════════════════════════════════════════

# linPEAS greps config files and prints `<file>:<matching line>`.
_PASSWORD_SECTION = """\
/etc/php/8.2/cli/php.ini:session.cookie_domain = example.com
/etc/php/8.2/cli/php.ini:session.cookie_lifetime = 0
/var/www/html/.env:DB_PASSWORD=Sup3rS3cret!
/var/www/html/.env.example:DB_PASSWORD=${DB_PASSWORD}
"""


class LinpeasPasswordGrepTests(unittest.TestCase):
    def _run(self, body):
        findings, creds = [], []
        lp._parse_passwords_in_files(
            {"searching passwords in config php files": body},
            "10.10.10.5", findings, creds)
        return findings, creds

    def test_only_the_real_secret_becomes_a_credential(self):
        """A config knob on a secret-looking line is not a credential.

        `session.cookie_domain = example.com` matched the broad
        line-level secret regex (`cookie`) and the pair regex, so
        `example.com` was written to the Credential Store as a
        password - a fabricated fact that reaches the report.
        """
        _findings, creds = self._run(_PASSWORD_SECTION)
        self.assertEqual([c["password"] for c in creds], ["Sup3rS3cret!"])
        self.assertIn("DB_PASSWORD", creds[0]["notes"])

    def test_every_matched_line_is_still_shown_as_evidence(self):
        """Tightening the credential push must not hide the lines."""
        findings, _creds = self._run(_PASSWORD_SECTION)
        self.assertEqual(len(findings), 1)
        desc = findings[0]["description"]
        self.assertIn("cookie_domain", desc)
        self.assertIn("CANDIDATES", desc)
        self.assertIn("1 of them", desc)

    def test_env_var_reference_is_not_a_password(self):
        _findings, creds = self._run(
            "/var/www/html/.env.example:DB_PASSWORD=${DB_PASSWORD}\n")
        self.assertEqual(creds, [])


# ═══════════════════════════════════════════════════════════════════
#  PrivescCheck — phantom credential
# ═══════════════════════════════════════════════════════════════════

class PrivescCheckCredentialTests(unittest.TestCase):
    def test_a_cred_leaky_check_with_no_credential_pushes_nothing(self):
        """CREDENTIALS_VAULT that found nothing used to append
        {username: "", password: "", cred_type: "hash"} with no hash:
        a Credential Store row for a credential that does not exist.
        """
        findings, creds = [], []
        pc._emit_finding_and_cred(
            {"name": "CREDENTIALS_VAULT", "severity": "high",
             "body": "No entry found in the Credential Vault.",
             "status": "KO"},
            "10.10.10.7", findings, creds)
        self.assertEqual(len(findings), 1)
        self.assertEqual(creds, [])

    def test_an_extracted_credential_is_still_pushed(self):
        findings, creds = [], []
        pc._emit_finding_and_cred(
            {"name": "REGISTRY_AUTOLOGON", "severity": "high",
             "body": ("Domain     : CORP\n"
                      "Username   : svc_backup\n"
                      "Password   : Wint3r2026!\n"),
             "status": "OK"},
            "10.10.10.7", findings, creds)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["username"], "svc_backup")
        self.assertEqual(creds[0]["password"], "Wint3r2026!")
        self.assertEqual(creds[0]["cred_type"], "cleartext")

    def test_a_username_without_a_password_is_not_called_a_hash(self):
        findings, creds = [], []
        pc._emit_finding_and_cred(
            {"name": "CREDENTIALS_MANAGER", "severity": "high",
             "body": "Username   : CORP\\svc_sql\n",
             "status": "OK"},
            "10.10.10.7", findings, creds)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["password"], "")
        self.assertNotEqual(creds[0]["cred_type"], "hash")


# ═══════════════════════════════════════════════════════════════════
#  post-RCE recon (Windows) — AlwaysInstallElevated
# ═══════════════════════════════════════════════════════════════════

def _win_blob(aie_body: str) -> str:
    return (
        "___HAWK_BEGIN___\n"
        "<<<SECTION:AIE>>>\n"
        f"{aie_body}"
        "<<<END:AIE>>>\n"
        "___HAWK_END___\n"
    )


# `reg query` output: blank line, key path at column 0, indented values.
_AIE_HKCU_ONLY = """\

HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
    AlwaysInstallElevated    REG_DWORD    0x0


HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

"""

_AIE_BOTH = """\

HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

"""

_AIE_HKLM_MISSING = """\
ERROR: The system was unable to find the specified registry key or value

HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

"""


class AlwaysInstallElevatedTests(unittest.TestCase):
    def _titles(self, aie_body):
        out = prw.analyze_output(_win_blob(aie_body))
        return [f["title"] for f in out["findings"]]

    def test_hkcu_only_is_not_the_both_keys_condition(self):
        """The DOTALL `.*?` walked from HKLM into the HKCU block.

        A lone 0x1 on HKCU was reported as the CRITICAL "both keys are
        set" condition, which is not exploitable at all.
        """
        titles = self._titles(_AIE_HKCU_ONLY)
        self.assertTrue(any("half-set" in t for t in titles), titles)
        self.assertFalse(any("AlwaysInstallElevated enabled" in t
                             for t in titles), titles)

    def test_hklm_missing_entirely_is_not_the_both_keys_condition(self):
        titles = self._titles(_AIE_HKLM_MISSING)
        self.assertTrue(any("half-set" in t for t in titles), titles)
        self.assertFalse(any("AlwaysInstallElevated enabled" in t
                             for t in titles), titles)

    def test_both_keys_set_is_still_critical(self):
        out = prw.analyze_output(_win_blob(_AIE_BOTH))
        hit = [f for f in out["findings"]
               if "AlwaysInstallElevated enabled" in f["title"]]
        self.assertEqual(len(hit), 1,
                         [f["title"] for f in out["findings"]])
        self.assertEqual(hit[0]["severity"], "critical")

    def test_neither_key_set_reports_nothing(self):
        body = _AIE_BOTH.replace("0x1", "0x0")
        self.assertEqual(
            [t for t in self._titles(body) if "Install" in t], [])


# ═══════════════════════════════════════════════════════════════════
#  Snippet-level filters
# ═══════════════════════════════════════════════════════════════════

class SnippetFilterTests(unittest.TestCase):
    def test_unquoted_service_filter_tests_the_exe_path_only(self):
        """`-match ' '` over the whole PathName flagged every svchost.

        `C:\\Windows\\system32\\svchost.exe -k netsvcs -p` has spaces,
        but they are in the ARGUMENTS - Windows never mis-parses those.
        The filter has to look at what comes before `.exe`.
        """
        snippet = prw.generate_snippet()
        self.assertIn("(($_.PathName -split '(?i)\\.exe')[0]) -match ' '",
                      snippet)
        self.assertNotIn("$_.PathName -match ' '", snippet)

    def test_nss_group_membership_is_matched_exactly(self):
        """`grep -wq \"$_U\"` over the whole getent line over-matched.

        grep's word characters are [A-Za-z0-9_], so `-w svc` matched
        the member `svc-backup` and the analyzer reported a CRITICAL
        "id lies / hidden group" that was never real.
        """
        snippet = prr.generate_snippet()
        self.assertNotIn('grep -wq "$_U"', snippet)
        self.assertIn('cut -d: -f4', snippet)
        self.assertIn('case ",$_M," in *",$_U,"*)', snippet)


if __name__ == "__main__":
    unittest.main()
