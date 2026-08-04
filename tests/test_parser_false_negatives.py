"""Parsers that silently discarded data they had already seen.

Every sample is the real output shape of the tool it claims to come
from.  These are the bugs that survived precisely because the old
tests (where there were any) fed the parser output it was written
against instead of output the tool actually produces.
"""

import os
import sys
import time
import types
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.parsers import linpeas_parser as lp   # noqa: E402
from modules.parsers import winpeas_parser as wp   # noqa: E402
from utils import post_rce_recon as prr            # noqa: E402
from utils import post_rce_recon_win as prw        # noqa: E402


class _DummyCtk:
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, _name):
        return _DummyCtk

    def __call__(self, *args, **kwargs):
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


# ═══════════════════════════════════════════════════════════════════
#  linPEAS — SUID binaries
# ═══════════════════════════════════════════════════════════════════

# linPEAS runs `ls -l` and appends its own `--->` hints.  Note the
# human-readable size and the three date fields — the old pattern had
# a slot for neither and matched nothing at all.
_SUID_SECTION = """\
-rwsr-xr-x 1 root root 55K Jan 20  2022 /usr/bin/mount
-rwsr-xr-x 1 root root 67K Jan 20  2022 /usr/bin/su
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTF
-rwsr-xr-x 1 root root 1.2M Feb  7 09:11 /usr/bin/find
-rw-r--r-- 1 root root 2.9K Mar  3  2023 /etc/not-suid-at-all
"""


class LinpeasSuidTests(unittest.TestCase):
    def _run(self, body):
        findings = []
        lp._parse_suid_binaries({"suid": body}, "10.10.10.5", findings)
        return findings

    def test_real_ls_l_rows_are_parsed(self):
        findings = self._run(_SUID_SECTION)
        self.assertTrue(findings, "the whole SUID section was discarded")
        all_list = [f for f in findings
                    if f["title"].startswith("All SUID binaries")]
        self.assertEqual(len(all_list), 1)
        self.assertIn("/usr/bin/mount", all_list[0]["description"])
        self.assertIn("/usr/bin/at", all_list[0]["description"])

    def test_gtfobins_hit_is_flagged(self):
        findings = self._run(_SUID_SECTION)
        gtfo = [f for f in findings
                if "GTFOBins" in f["title"]]
        self.assertEqual(len(gtfo), 1, [f["title"] for f in findings])
        self.assertIn("find", gtfo[0]["description"])

    def test_non_suid_rows_are_ignored(self):
        findings = self._run(_SUID_SECTION)
        blob = "\n".join(f["description"] for f in findings)
        self.assertNotIn("/etc/not-suid-at-all", blob)


# ═══════════════════════════════════════════════════════════════════
#  linPEAS — SSH keys
# ═══════════════════════════════════════════════════════════════════

_SSH_SECTION = """\
/root/.ssh/id_rsa
/home/bob/.ssh/id_rsa
/home/bob/.ssh/id_rsa.pub
/home/bob/.ssh/authorized_keys
/home/svc/.ssh/id_ed25519
"""


class LinpeasSshKeyTests(unittest.TestCase):
    def _run(self, body):
        findings, creds = [], []
        lp._parse_ssh_keys({"ssh files": body}, "10.10.10.5",
                           findings, creds)
        return findings, creds

    def test_root_key_is_found(self):
        """`/root/.ssh/id_rsa` could never match the old pattern.

        It required at least one path component between the prefix and
        `/.ssh/`, which /root does not have - so the single most
        valuable key on any box was dropped every time.
        """
        _f, creds = self._run(_SSH_SECTION)
        paths = [c["notes"] for c in creds]
        self.assertTrue(any("/root/.ssh/id_rsa" in p for p in paths),
                        paths)

    def test_public_key_is_not_reported_as_private(self):
        """`id_\\w+` stopped at the dot, so `id_rsa.pub` was captured
        as `id_rsa` and a PUBLIC key became a private-key credential."""
        _f, creds = self._run(
            "/home/bob/.ssh/id_rsa.pub\n"
            "/home/bob/.ssh/authorized_keys\n")
        self.assertEqual(creds, [])

    def test_usernames_are_inferred(self):
        _f, creds = self._run(_SSH_SECTION)
        users = sorted(c["username"] for c in creds)
        self.assertEqual(users, ["bob", "root", "svc"])


# ═══════════════════════════════════════════════════════════════════
#  winPEAS — token privileges
# ═══════════════════════════════════════════════════════════════════

# winPEASx64.exe prints the flag constants, indented.
_WINPEAS_EXE_PRIVS = """\
    SeShutdownPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeDebugPrivilege: DISABLED
"""

# `whoami /priv` table — the shape the old pattern was written for.
_WHOAMI_PRIV_TABLE = """\
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeImpersonatePrivilege        Impersonate a client           Enabled
SeDebugPrivilege              Debug programs                 Disabled
"""


class WinpeasTokenPrivTests(unittest.TestCase):
    def _titles(self, body):
        findings = []
        wp._parse_token_privs({"current token privileges": body},
                              "10.10.10.7", findings)
        return [f["title"] for f in findings]

    def test_winpeas_exe_format_is_parsed(self):
        """SeImpersonatePrivilege is the prerequisite of the whole
        Potato chain and was lost on every winPEAS.exe run."""
        titles = self._titles(_WINPEAS_EXE_PRIVS)
        self.assertIn("Privilege enabled: SeImpersonatePrivilege",
                      titles)

    def test_disabled_privileges_are_not_reported(self):
        titles = self._titles(_WINPEAS_EXE_PRIVS)
        self.assertNotIn("Privilege enabled: SeDebugPrivilege", titles)

    def test_whoami_priv_table_still_works(self):
        titles = self._titles(_WHOAMI_PRIV_TABLE)
        self.assertIn("Privilege enabled: SeImpersonatePrivilege",
                      titles)
        self.assertNotIn("Privilege enabled: SeDebugPrivilege", titles)

    def test_enabled_by_default_alone_is_not_enabled(self):
        state = wp._priv_state(
            "SeUndockPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT")
        self.assertNotEqual(state, "enabled")


# ═══════════════════════════════════════════════════════════════════
#  winPEAS — scheduled tasks
# ═══════════════════════════════════════════════════════════════════

# `schtasks /query /fo LIST /v`.  Note the real field ORDER: the
# binary (`Task To Run`) comes BEFORE `Run As User`.
_SCHTASKS = """\
Folder: \\
HostName:                             WIN-DC01
TaskName:                             \\VendorUpdater
Next Run Time:                        04/08/2026 12:00:00
Status:                               Ready
Task To Run:                          C:\\Program Files\\Vendor\\upd.exe
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Run As User:                          SYSTEM

HostName:                             WIN-DC01
TaskName:                             \\UserSync
Next Run Time:                        04/08/2026 13:00:00
Status:                               Ready
Task To Run:                          C:\\Tools\\sync.exe
Start In:                             N/A
Scheduled Task State:                 Enabled
Run As User:                          CORP\\Administrator

HostName:                             WIN-DC01
TaskName:                             \\UserBackup
Next Run Time:                        04/08/2026 14:00:00
Task To Run:                          C:\\Tools\\backup.exe
Scheduled Task State:                 Enabled
Run As User:                          WIN-DC01\\bob
"""


class WinpeasScheduledTaskTests(unittest.TestCase):
    def _finding(self, body):
        findings = []
        wp._parse_scheduled_tasks({"scheduled tasks": body},
                                  "10.10.10.7", findings)
        return findings[0] if findings else None

    def test_each_task_keeps_its_own_binary(self):
        """The old regex went TaskName -> Run As User -> Task To Run.

        schtasks prints them the other way round, so the third hop
        crossed the record boundary and paired every task with the
        NEXT task's binary.
        """
        f = self._finding(_SCHTASKS)
        self.assertIsNotNone(f)
        desc = f["description"]
        self.assertIn("\\VendorUpdater", desc)
        self.assertIn("C:\\Program Files\\Vendor\\upd.exe", desc)
        self.assertIn("\\UserSync", desc)
        self.assertIn("C:\\Tools\\sync.exe", desc)
        # Pairing check: the updater must not carry sync.exe.
        for line in desc.splitlines():
            if "VendorUpdater" in line:
                self.assertIn("upd.exe", line)

    def test_unprivileged_tasks_are_filtered_out(self):
        f = self._finding(_SCHTASKS)
        self.assertNotIn("\\UserBackup", f["description"])
        self.assertIn("(2)", f["title"])

    def test_parsing_is_linear_not_cubic(self):
        """Three nested lazy `.*?` backtracked cubically.

        On a real host's task list a near-miss could pin the GUI
        thread for minutes.  This input is a normal size; a cubic
        parser does not finish it in seconds.
        """
        # ~600 records, none of which satisfies the old field order.
        block = ("HostName:      WIN-DC01\n"
                 "TaskName:      \\Task{}\n"
                 "Status:        Ready\n"
                 "Task To Run:   C:\\Windows\\system32\\noop.exe\n"
                 "Comment:       N/A\n\n")
        body = "".join(block.format(i) for i in range(600))
        t0 = time.time()
        wp._schtasks_records(body)
        self.assertLess(time.time() - t0, 2.0)


# ═══════════════════════════════════════════════════════════════════
#  winPEAS — Wi-Fi profiles
# ═══════════════════════════════════════════════════════════════════

# `netsh wlan show profile name=<x> key=clear`, two profiles.
_WIFI_SECTION = """\
Profile HomeNet on interface Wi-Fi:
=======================================================================

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "HomeNet"
    Network type           : Infrastructure

Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Security key           : Present
    Key Content            : Sup3rWiFi!2026

Profile CorpGuest on interface Wi-Fi:
=======================================================================

Connectivity settings
---------------------
    SSID name              : "CorpGuest"
    Network type           : Infrastructure

Security settings
-----------------
    Authentication         : WPA2-Personal
    Security key           : Present
    Key Content            : Guest-2026-Wifi
"""


class WinpeasWifiTests(unittest.TestCase):
    def _run(self, body):
        findings, creds = [], []
        wp._parse_wifi({"wifi": body}, "10.10.10.7", findings, creds)
        return findings, creds

    def test_every_profile_is_reported(self):
        """The greedy DOTALL tail consumed the rest of the section, so
        findall could only ever return the first profile."""
        _f, creds = self._run(_WIFI_SECTION)
        self.assertEqual([c["username"] for c in creds],
                         ["HomeNet", "CorpGuest"])

    def test_the_psk_is_the_psk_and_not_the_rest_of_the_section(self):
        _f, creds = self._run(_WIFI_SECTION)
        self.assertEqual(creds[0]["password"], "Sup3rWiFi!2026")
        self.assertEqual(creds[1]["password"], "Guest-2026-Wifi")

    def test_ssid_is_not_mangled(self):
        """`SSID[:\\s]+` matched the "SSID name" LABEL, so the captured
        SSID was `name              : "HomeNet"`."""
        _f, creds = self._run(_WIFI_SECTION)
        for c in creds:
            self.assertNotIn(":", c["username"])
            self.assertNotIn('"', c["username"])

    def test_present_flag_is_not_taken_as_a_key(self):
        _f, creds = self._run(
            '    SSID name              : "OpenNet"\n'
            '    Security key           : Absent\n')
        self.assertEqual(creds, [])


# ═══════════════════════════════════════════════════════════════════
#  winPEAS — AlwaysInstallElevated fallback
# ═══════════════════════════════════════════════════════════════════

class WinpeasAlwaysInstallElevatedTests(unittest.TestCase):
    def test_unrelated_registry_values_do_not_trigger_it(self):
        """The fallback grabs a whole unrelated section that merely
        MENTIONS the key, and `HKLM.*?(0x[01])` then walked to the
        first 0x1 anywhere below - a value belonging to another key.
        """
        body = (
            "    Checking AlwaysInstallElevated\n"
            "    HKLM AlwaysInstallElevated: not set\n"
            "    HKCU AlwaysInstallElevated: not set\n"
            "    HKLM\\System\\CurrentControlSet\\Control\\Lsa\n"
            "        RunAsPPL    REG_DWORD    0x1\n"
            "        LimitBlankPasswordUse    REG_DWORD    0x1\n"
        )
        findings = []
        wp._parse_always_install_elevated(
            {"system information": body}, "10.10.10.7", findings)
        self.assertEqual([f["title"] for f in findings], [])

    def test_both_keys_set_on_their_own_lines_is_still_critical(self):
        body = (
            "    HKLM AlwaysInstallElevated  REG_DWORD  0x1\n"
            "    HKCU AlwaysInstallElevated  REG_DWORD  0x1\n"
        )
        findings = []
        wp._parse_always_install_elevated(
            {"alwaysinstallelevated": body}, "10.10.10.7", findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")


# ═══════════════════════════════════════════════════════════════════
#  winPEAS — output with no section headers
# ═══════════════════════════════════════════════════════════════════

class WinpeasUnparsedOutputTests(unittest.TestCase):
    def test_header_less_output_is_reported_not_swallowed(self):
        """Without box-drawing headers everything lands in `_preamble`,
        all 13 section parsers return None, and the summary used to
        report a clean parse of nothing."""
        class Intel:
            def __init__(self):
                self.pushed = []

            def add_auto_finding(self, **kw):
                self.pushed.append(kw)

        class Store:
            def add_credential(self, *a, **kw):
                pass

        app = types.SimpleNamespace(
            target_intel=Intel(), cred_store=Store(),
            terminal=types.SimpleNamespace(
                write=lambda *a, **k: None))

        wp.parse_winpeas(
            "SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED\n"
            "Some other winpeas line without any box drawing\n",
            app, "10.10.10.7")
        titles = [p.get("title", "") for p in app.target_intel.pushed]
        self.assertTrue(
            any("no section headers" in t for t in titles), titles)


# ═══════════════════════════════════════════════════════════════════
#  post-RCE recon — pasted terminal scrollback
# ═══════════════════════════════════════════════════════════════════

class PostRceScrollbackTests(unittest.TestCase):
    def test_linux_analyzer_skips_the_echoed_command(self):
        """The pasted scrollback opens with the shell's echo of the
        command, and that line contains `echo ___HAWK_BEGIN___` …
        `echo ___HAWK_END___`.  Cutting at the FIRST of each kept the
        command and threw away every line of output: zero findings,
        rendered as a clean parse.
        """
        snippet = prr.generate_snippet()
        pasted = (
            f"bob@victim:/var/www$ {snippet}\n"
            "___HAWK_BEGIN___\n"
            "<<<SECTION:WHOAMI>>>\n"
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            "www-data\n"
            "victim\n"
            "Linux victim 5.15.0-91-generic #101-Ubuntu SMP x86_64\n"
            "<<<END:WHOAMI>>>\n"
            "___HAWK_END___\n"
            "bob@victim:/var/www$ \n"
        )
        out = prr.analyze_output(pasted)
        self.assertEqual(out["user"], "www-data")
        self.assertEqual(out["id_groups"], ["www-data"])
        self.assertIn("5.15.0-91-generic", out["kernel"])
        self.assertEqual(out["parse_warnings"], [])

    def test_windows_analyzer_skips_the_echoed_command(self):
        snippet = prw.generate_snippet()
        pasted = (
            f"C:\\inetpub\\wwwroot>{snippet}\n"
            "___HAWK_BEGIN___\n"
            "<<<SECTION:WHOAMI>>>\n"
            "iis apppool\\defaultapppool\n"
            "WIN-WEB01\n"
            "<<<END:WHOAMI>>>\n"
            "___HAWK_END___\n"
            "C:\\inetpub\\wwwroot>\n"
        )
        out = prw.analyze_output(pasted)
        self.assertEqual(out["user"], "iis apppool\\defaultapppool")

    def test_a_paste_with_no_output_says_so(self):
        snippet = prr.generate_snippet()
        out = prr.analyze_output(f"bob@victim:~$ {snippet}\n")
        self.assertTrue(
            any("No <<<SECTION:" in w for w in out["parse_warnings"]),
            out["parse_warnings"])


# ═══════════════════════════════════════════════════════════════════
#  john --show / HTTP headers
# ═══════════════════════════════════════════════════════════════════

class JohnShowTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_a_password_containing_a_colon_is_not_truncated(self):
        """`john --show` echoes the passwd line with the hash replaced.

        `^([^:]+):([^:]+):` stopped at the first colon inside the
        password and saved the fragment as if it were the password.
        """
        from gui.widgets.card_routes_access import parse_john_show
        out = parse_john_show(
            "bob:S3cr:et!:1001:1001::/home/bob:/bin/bash\n"
            "alice:plain123:1002:1002::/home/alice:/bin/bash\n"
            "\n"
            "2 password hashes cracked, 0 left\n")
        self.assertEqual(
            out, [("bob", "S3cr:et!"), ("alice", "plain123")])

    def test_the_summary_line_is_not_a_credential(self):
        from gui.widgets.card_routes_access import parse_john_show
        self.assertEqual(
            parse_john_show("0 password hashes cracked, 2 left\n"), [])


class HttpHeaderScopeTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_a_header_named_in_the_page_body_is_not_a_header(self):
        """curl -i output whose BODY is a hardening how-to.

        The old whole-text scan reported Strict-Transport-Security as
        PRESENT on a server that never sent it.
        """
        from gui.widgets.target_intel_parsers import extract_http_headers
        text = (
            "HTTP/1.1 200 OK\r\n"
            "Date: Mon, 04 Aug 2026 08:12:33 GMT\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "\r\n"
            "<html><body><h1>Hardening guide</h1><pre>\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "X-Frame-Options: DENY\n"
            "</pre></body></html>\n"
        )
        headers = extract_http_headers(text)
        self.assertEqual(headers.get("server"), "Apache/2.4.41 (Ubuntu)")
        self.assertNotIn("strict-transport-security", headers)
        self.assertNotIn("x-frame-options", headers)

    def test_the_last_response_of_a_redirect_chain_wins(self):
        from gui.widgets.target_intel_parsers import extract_http_headers
        text = (
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Server: nginx\r\n"
            "Location: https://target/app\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Server: gunicorn/20.1.0\r\n"
            "X-Frame-Options: SAMEORIGIN\r\n"
            "\r\n"
            "<html>...</html>\n"
        )
        headers = extract_http_headers(text)
        self.assertEqual(headers.get("server"), "gunicorn/20.1.0")
        self.assertEqual(headers.get("x-frame-options"), "SAMEORIGIN")


# ═══════════════════════════════════════════════════════════════════
#  Crawled forms / kerbrute summary
# ═══════════════════════════════════════════════════════════════════

class CrawledFormTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_a_post_login_form_is_not_recorded_as_get(self):
        """The greedy `[^>]*` after the action swallowed the rest of
        the tag, so the optional method group always matched empty and
        every crawled form was reported as GET."""
        from gui.widgets.card_routes_oracle import parse_html_forms
        html = (
            '<form method="post" action="/login.php">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<input type="submit" value="Log in">'
            '</form>')
        forms = parse_html_forms(html, "http://10.10.10.9/index.php")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["method"], "POST")
        self.assertEqual(forms[0]["action"],
                         "http://10.10.10.9/login.php")
        self.assertTrue(forms[0]["has_password"])
        self.assertEqual(forms[0]["fields"], ["username", "password"])

    def test_method_after_action_is_read_too(self):
        from gui.widgets.card_routes_oracle import parse_html_forms
        forms = parse_html_forms(
            '<form action="/search" method="POST">'
            '<input name="q"></form>',
            "http://10.10.10.9/")
        self.assertEqual(forms[0]["method"], "POST")

    def test_a_form_without_an_action_targets_the_current_url(self):
        from gui.widgets.card_routes_oracle import parse_html_forms
        forms = parse_html_forms(
            '<form method="post"><input name="q"></form>',
            "http://10.10.10.9/app/page.php")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"],
                         "http://10.10.10.9/app/page.php")

    def test_upload_forms_are_still_detected(self):
        from gui.widgets.card_routes_oracle import parse_html_forms
        forms = parse_html_forms(
            '<form action="/upload.php" method="post" '
            'enctype="multipart/form-data">'
            '<input type="file" name="avatar">'
            '</form>',
            "http://10.10.10.9/")
        self.assertEqual(forms[0]["file_inputs"], ["avatar"])
        self.assertEqual(forms[0]["method"], "POST")


class KerbruteSummaryTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_a_successful_spray_is_not_reported_as_no_paths_found(self):
        """kerbrute output matches none of the content-discovery
        regexes, so a spray that just handed over a domain account was
        summarised as "No paths found."."""
        from gui.widgets.card_runtime import kerbrute_run_summary
        lines = [
            "2026/08/04 10:12:33 >  Using KDC(s):",
            "2026/08/04 10:12:33 >  \tdc01.corp.local:88",
            "",
            "2026/08/04 10:12:34 >  [+] VALID LOGIN:\t "
            "svc_backup@corp.local:Winter2026!",
            "2026/08/04 10:12:35 >  Done! Tested 25 logins "
            "(1 successes) in 1.204 seconds",
        ]
        summary = kerbrute_run_summary(lines, 0)
        self.assertIn("1 valid login", summary)
        self.assertNotIn("path", summary)

    def test_userenum_hits_are_counted(self):
        from gui.widgets.card_runtime import kerbrute_run_summary
        lines = [
            "2026/08/04 10:12:34 >  [+] VALID USERNAME:\t "
            "admin@corp.local",
            "2026/08/04 10:12:34 >  [+] VALID USERNAME:\t "
            "jsmith@corp.local",
        ]
        self.assertIn("2 valid usernames",
                      kerbrute_run_summary(lines, 0))

    def test_an_empty_run_says_what_it_actually_checked(self):
        from gui.widgets.card_runtime import kerbrute_run_summary
        summary = kerbrute_run_summary(
            ["2026/08/04 10:12:35 >  Done! Tested 25 logins "
             "(0 successes) in 1.204 seconds"], 0)
        self.assertEqual(summary,
                         "No valid usernames or logins found.")


if __name__ == "__main__":
    unittest.main()
