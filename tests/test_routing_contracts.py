"""Routing and dispatch contracts: exploit relevance, msfconsole
failures, and tools that must never run on Kali.

The tool-id-vs-registry guard lives in test_dialog_contracts.py.
"""

import ast
import os
import subprocess
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules import exploit_suggester as es   # noqa: E402


class RequiredPortsTests(unittest.TestCase):
    def setUp(self):
        self.runner = es.MsfSearchRunner()

    def test_https_does_not_resolve_to_the_plain_http_ports(self):
        """`for svc in SERVICE_PORT_MAP` hit "http" before "https".

        Every HTTPS exploit got [80, 8080, …], so on a TLS-only target
        it was hidden with the self-contradictory reason "port 80 not
        open - HTTPS not detected".
        """
        ports = self.runner._required_ports(
            "exploit/windows/http/exchange_proxylogon_rce",
            "Microsoft Exchange ProxyLogon RCE over HTTPS")
        self.assertIn(443, ports)

    def test_a_web_exploit_is_reachable_on_a_tls_only_target(self):
        entry = es.ExploitEntry(
            name="exploit/multi/http/apache_normalize_path_rce",
            rank="excellent",
            description="Apache HTTP Server 2.4.49 path traversal RCE",
            matched_service="http")

        class _Fp:
            """TLS-only target: 443 open, no plain-HTTP listener."""
            def open_port_list(self):
                return [443]

        self.runner._results = [entry]
        self.runner._filter_by_ports(_Fp())
        self.assertTrue(
            entry.relevant,
            f"hidden with: {entry.skip_reason}")

    def test_a_non_web_service_keeps_its_own_ports(self):
        self.assertEqual(
            self.runner._required_ports("exploit/windows/smb/ms17_010",
                                        "SMB remote code execution"),
            [139, 445])

    def test_the_change_never_removes_ports(self):
        """Regression guard: the union rule must stay non-hiding.

        Whatever the old first-match loop would have returned, the new
        result has to be a superset — otherwise this fix trades one
        class of false negative for another.
        """
        samples = [
            ("exploit/multi/http/tomcat_mgr_upload",
             "Apache Tomcat manager HTTP upload"),
            ("exploit/linux/http/jenkins_script_console",
             "Jenkins-CI script console over HTTP"),
            ("exploit/windows/mssql/mssql_payload",
             "Microsoft SQL Server payload execution"),
            ("exploit/unix/ftp/vsftpd_234_backdoor",
             "VSFTPD v2.3.4 backdoor command execution"),
        ]
        for name, desc in samples:
            combined = name + " " + desc.lower()
            old = []
            for svc, ports in es.SERVICE_PORT_MAP.items():
                if svc in combined:
                    old = ports
                    break
            new = self.runner._required_ports(name, desc)
            with self.subTest(exploit=name):
                self.assertTrue(
                    set(old).issubset(set(new)),
                    f"{name}: lost {sorted(set(old) - set(new))}")


class MsfSearchFailureTests(unittest.TestCase):
    def test_a_missing_binary_is_not_a_successful_empty_search(self):
        """A bare `except Exception: return []` made a missing
        msfconsole indistinguishable from "found nothing"."""
        runner = es.MsfSearchRunner()
        real_run = subprocess.run

        def _boom(*a, **kw):
            raise FileNotFoundError("msfconsole")

        subprocess.run = _boom
        try:
            out = runner._run_one("search type:exploit smb", "smb", [445])
        finally:
            subprocess.run = real_run
        self.assertEqual(out, [])
        self.assertTrue(runner.errors)
        self.assertIn("msfconsole not found", runner.errors[0])

    def test_a_timeout_is_reported(self):
        runner = es.MsfSearchRunner()
        real_run = subprocess.run

        def _slow(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="msfconsole", timeout=60)

        subprocess.run = _slow
        try:
            runner._run_one("search type:exploit smb", "smb", [445])
        finally:
            subprocess.run = real_run
        self.assertTrue(any("timed out" in e for e in runner.errors))

    def test_repeated_failures_are_reported_once(self):
        runner = es.MsfSearchRunner()
        real_run = subprocess.run

        def _boom(*a, **kw):
            raise FileNotFoundError("msfconsole")

        subprocess.run = _boom
        try:
            for q in ("a", "b", "c"):
                runner._run_one(f"search {q}", "smb", [445])
        finally:
            subprocess.run = real_run
        self.assertEqual(len(runner.errors), 1)

    def test_a_real_empty_search_records_no_error(self):
        runner = es.MsfSearchRunner()
        real_run = subprocess.run

        class _R:
            returncode = 0
            stdout = "Matching Modules\n================\n\n"
            stderr = ""

        subprocess.run = lambda *a, **kw: _R()
        try:
            out = runner._run_one("search type:exploit nope", "smb", [])
        finally:
            subprocess.run = real_run
        self.assertEqual(out, [])
        self.assertEqual(runner.errors, [])


# ═══════════════════════════════════════════════════════════════════
#  runs_on_target must never take the local-run path
# ═══════════════════════════════════════════════════════════════════
#
# Several of these Windows built-ins have same-named binaries on Kali
# (`whoami`, `net`, `netstat` all exist there), so gating the SHOW
# dialog on `not tool.is_available()` sent them down the normal RUN
# path: HAWK executed them LOCALLY and reported Kali's users,
# privileges and listening ports as if they were the target's.
#
# Checked with AST rather than by driving Tk: the condition is the bug.

_CARD_WIDGET = os.path.join(ROOT, "gui", "widgets", "card_widget.py")


def _runs_on_target_conditions(path):
    """Every test whose operand mentions runs_on_target."""
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        src = ast.dump(node.test)
        if "runs_on_target" in src:
            yield node.lineno, node.test
        for clause in getattr(node, "orelse", []):
            if isinstance(clause, ast.If):
                continue  # walked separately


class RunsOnTargetTests(unittest.TestCase):
    def test_local_availability_never_gates_the_target_dialog(self):
        offenders = []
        for lineno, test in _runs_on_target_conditions(_CARD_WIDGET):
            dumped = ast.dump(test)
            if "is_available" in dumped or "installed" in dumped:
                offenders.append(lineno)
        self.assertEqual(
            offenders, [],
            "card_widget.py lines "
            + ", ".join(str(n) for n in offenders)
            + " gate runs_on_target on local binary availability — "
              "that is what made HAWK run Windows built-ins on Kali")

    def test_every_runs_on_target_tool_has_os_hint(self):
        """The declaration itself: nothing declared runs_on_target should be
        runnable locally in the first place.  This spans the Windows built-ins
        (reg/wmic/schtasks/...) AND the Linux post-exploit finders
        (SUID/caps/sudo -l/...) — both are copied into the target shell, so
        both must carry an os_hint the card face can key on."""
        import importlib
        import inspect

        from modules.base import BaseModule

        found = 0
        for fn in sorted(os.listdir(os.path.join(ROOT, "modules"))):
            if not fn.endswith(".py") or fn == "__init__.py":
                continue
            name = "modules." + fn[:-3]
            module = importlib.import_module(name)
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (not issubclass(obj, BaseModule) or obj is BaseModule
                        or obj.__module__ != name):
                    continue
                for tool in obj().get_tools() or []:
                    if getattr(tool, "runs_on_target", False):
                        found += 1
                        with self.subTest(tool=tool.id):
                            self.assertTrue(
                                getattr(tool, "os_hint", ""),
                                f"{tool.id} runs_on_target with no "
                                f"os_hint")
        self.assertGreater(found, 5)


if __name__ == "__main__":
    unittest.main()
