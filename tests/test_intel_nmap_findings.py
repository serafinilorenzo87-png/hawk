"""Contract tests for the nmap-driven Target Intel finding emitters.

Every sample below is real nmap output text, copied in the exact shape
nmap prints it.  These parsers were written against imagined output,
which is how they came to claim more than they observed.
"""

import os
import sys
import types
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


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


def _build_intel():
    """TargetIntelRenderMixin host with no Tk and no session."""
    from gui.widgets.target_intel_render import TargetIntelRenderMixin
    from gui.widgets.target_intel_widget import TargetIntelWidget

    class Terminal:
        def __init__(self):
            self.messages = []

        def write(self, message, style=None):
            self.messages.append((message, style))

    class DummyIntel(TargetIntelRenderMixin):
        # The nmap/NSE regexes are class attributes of the composing
        # widget, not of the mixin under test.  Borrow them by
        # reference so the test breaks loudly if they move.
        _NSE_SCRIPT_HEADER_RE = TargetIntelWidget._NSE_SCRIPT_HEADER_RE
        _NSE_META_TAGS = TargetIntelWidget._NSE_META_TAGS
        _NSE_ERROR_RE = TargetIntelWidget._NSE_ERROR_RE
        _PORT_LINE_RE = TargetIntelWidget._PORT_LINE_RE
        _NMAP_META_RE = TargetIntelWidget._NMAP_META_RE
        _CVE_NAMES = TargetIntelWidget._CVE_NAMES
        _VULN_CVE_SEVERITY = TargetIntelWidget._VULN_CVE_SEVERITY
        _VULN_SCRIPT_SEVERITY = TargetIntelWidget._VULN_SCRIPT_SEVERITY

        def __init__(self):
            self._auto_findings = []
            self._collapsed = {"vulns": True}
            self._fp = None
            # No cred_store attribute: the credential auto-push is not
            # under test here and needs a real store.
            self.app = types.SimpleNamespace(terminal=Terminal())

        def _render_auto_findings(self):
            pass

        def _blink_start(self, count_as_new: bool = True):
            pass

        def _kb_correlate(self, *a, **kw):
            return None

        def _aiops_correlate(self, *a, **kw):
            return None

    return DummyIntel()


def _titles(intel):
    return [f["title"] for f in intel._auto_findings]


def _find(intel, needle, source=None):
    """First finding whose title contains `needle` (and matches source).

    `source` matters where the same vulnerability is emitted twice by
    two different paths — the NSE block parser and the banner matcher
    both speak about distcc, and only the banner one carries the port.
    """
    for f in intel._auto_findings:
        if needle.lower() not in f["title"].lower():
            continue
        if source is not None and f.get("source") != source:
            continue
        return f
    return None


# ─── Samba CVE-2007-2447 (T2) ──────────────────────────────────────
#
# The only nmap output form this detector's regex `Samba\s+(\d+\.\d+\.\d+)`
# can match is smb-os-discovery's "OS: Unix (Samba <version>)" line —
# `nmap -sV` prints "Samba smbd 3.0.20-Debian", where the `smbd` token
# sits between "Samba" and the digits.

_SMB_OS_DISCOVERY_3_0_20 = """\
Host script results:
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   NetBIOS computer name:
|   Workgroup: WORKGROUP\\x00
|_  System time: 2026-08-04T05:12:32-04:00
"""

_SMB_OS_DISCOVERY_3_2_5 = """\
Host script results:
| smb-os-discovery:
|   OS: Unix (Samba 3.2.5)
|   Computer name: fileserver
|   Workgroup: WORKGROUP\\x00
|_  System time: 2026-08-04T11:12:32+01:00
"""

_SMB_OS_DISCOVERY_3_3_10 = """\
Host script results:
| smb-os-discovery:
|   OS: Unix (Samba 3.3.10)
|   Computer name: fileserver
|_  Workgroup: WORKGROUP\\x00
"""

_PORT_TABLE_SMB = """\
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
"""


class SambaUsermapScriptTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _run(self, sample):
        intel = _build_intel()
        intel.update_from_vuln_scripts(
            (_PORT_TABLE_SMB + sample).splitlines())
        return intel

    def test_samba_3_0_20_still_reported(self):
        """Metasploitable2 must stay covered: 3.0.20 is in range."""
        intel = self._run(_SMB_OS_DISCOVERY_3_0_20)
        f = _find(intel, "CVE-2007-2447")
        self.assertIsNotNone(f, _titles(intel))
        self.assertEqual(f["port"], 445)

    def test_samba_3_2_5_is_not_reported(self):
        """The false positive: 3.2.5 is not affected by CVE-2007-2447.

        Ubuntu 8.10/9.04 shipped 3.2.5 and it turns up on plenty of
        HTB boxes.  The old gate (`major == 3 and minor < 4`) called it
        a confirmed CRITICAL root RCE.
        """
        intel = self._run(_SMB_OS_DISCOVERY_3_2_5)
        self.assertIsNone(_find(intel, "CVE-2007-2447"), _titles(intel))

    def test_samba_3_3_10_is_not_reported(self):
        intel = self._run(_SMB_OS_DISCOVERY_3_3_10)
        self.assertIsNone(_find(intel, "CVE-2007-2447"), _titles(intel))

    def test_finding_is_high_and_states_its_precondition(self):
        """The version alone does not make the box exploitable.

        CVE-2007-2447 needs `username map script` in smb.conf, which is
        not a default.  The card and the report row must say so instead
        of asserting a confirmed critical.
        """
        intel = self._run(_SMB_OS_DISCOVERY_3_0_20)
        f = _find(intel, "CVE-2007-2447")
        self.assertEqual(f["severity"], "high")
        desc = f["description"]
        self.assertIn("NOT CONFIRMED", desc)
        self.assertIn("username map script", desc)
        self.assertIn("3.0.0-3.0.25rc3", desc)


# ─── distcc CVE-2004-2687 ──────────────────────────────────────────
#
# `nmap -v -Pn --script vuln` (HAWK's NMAP Vuln Scripts command) runs
# no version detection, so the service column comes from nmap-services.

_METASPLOITABLE_DISTCC = """\
Nmap scan report for 10.10.10.5
Host is up (0.0011s latency).
PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687:
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3
|       Allows executing of arbitrary commands on systems running
|       distccd 3.1 and earlier.
|     References:
|_      https://nvd.nist.gov/vuln/detail/CVE-2004-2687
"""

# A web host with no distcc daemon anywhere.  http-enum prints the
# directory names it found, and one of them happens to be /distcc/.
_HTTP_ENUM_MENTIONS_DISTCC = """\
Nmap scan report for 10.10.10.9
Host is up (0.0018s latency).
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /distcc/: Potentially interesting folder
|_  /icons/: Potentially interesting folder w/ directory listing
"""


class DistccDetectionTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_open_distcc_port_is_reported_on_the_detected_port(self):
        intel = _build_intel()
        intel.update_from_vuln_scripts(
            _METASPLOITABLE_DISTCC.splitlines())
        f = _find(intel, "DistCC daemon RCE", source="nmap banner")
        self.assertIsNotNone(f, _titles(intel))
        self.assertEqual(f["port"], 3632)

    def test_bare_mention_of_distcc_is_not_a_finding(self):
        """The false positive: the substring used to be the whole gate.

        `distcc` anywhere in the output emitted a CRITICAL RCE
        hardcoded on port 3632 for a host that has no such service.
        """
        intel = _build_intel()
        intel.update_from_vuln_scripts(
            _HTTP_ENUM_MENTIONS_DISTCC.splitlines())
        self.assertIsNone(_find(intel, "DistCC"), _titles(intel))


# ─── Failed-NSE diagnostic finding ─────────────────────────────────
#
# Real nmap error lines: one per script, pipe-prefixed, with the
# script name in front of the ERROR sentinel.

_NSE_FAILURES = """\
Nmap scan report for 10.10.10.7
Host is up (0.0090s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
Host script results:
|_smb-vuln-ms17-010: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
|_ssl-ccs-injection: ERROR: Script execution failed (use -d to debug)
"""


class NseDiagnosticFindingTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_failed_scripts_produce_one_info_finding_and_no_vuln(self):
        intel = _build_intel()
        intel.update_from_vuln_scripts(_NSE_FAILURES.splitlines())
        self.assertEqual(len(intel._auto_findings), 1, _titles(intel))
        f = intel._auto_findings[0]
        self.assertEqual(f["severity"], "info")
        self.assertIn("smb-vuln-ms17-010", f["description"])

    def test_diagnostic_finding_gets_no_msf_button_and_no_cve_card(self):
        """A script that FAILED is not a vulnerability that was found.

        `_get_exploits_for_vuln` keyword-matches the description, and
        the description is a list of script names — so it happily
        returned the EternalBlue modules for a host that was never
        successfully tested for MS17-010.  Both the EXPLOIT WITH MSF
        button and the INFO dialog's CVE card key off the source.
        """
        from gui.widgets.target_intel_common import _get_exploits_for_vuln
        from gui.widgets.target_intel_render import (
            _is_diagnostic_source,
            _msf_suggestions_suppressed,
        )

        intel = _build_intel()
        intel.update_from_vuln_scripts(_NSE_FAILURES.splitlines())
        f = intel._auto_findings[0]

        # The overmatch is real — this is what used to reach the UI.
        self.assertTrue(
            _get_exploits_for_vuln(f["title"], f["description"]),
            "expected the keyword fallback to match ms17-010 here")

        # ...and this is what now stops it.
        self.assertTrue(_msf_suggestions_suppressed(f["source"]))
        self.assertTrue(_is_diagnostic_source(f["source"]))

    def test_non_diagnostic_findings_keep_their_msf_button(self):
        from gui.widgets.target_intel_render import (
            _is_diagnostic_source,
            _msf_suggestions_suppressed,
        )
        self.assertFalse(_msf_suggestions_suppressed("nmap banner"))
        self.assertFalse(_is_diagnostic_source("nmap vuln scripts"))


if __name__ == "__main__":
    unittest.main()
