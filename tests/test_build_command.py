"""Registry-wide invariants for `Tool.build_command()`.

Every RUN button in HAWK goes through this one method, inside a Tk
callback.  An exception there does not reach the operator: the traceback
lands on stderr, the terminal panel stays silent and the row stays
"ready" — the app simply appears to do nothing.  So the contract is:

  1. build_command() never raises, for any tool in the registry.
  2. It never leaves an unresolved `{placeholder}` behind: either the
     value is substituted, or the placeholder is rendered as `<name>`,
     which is the form `_run_raw`'s guard recognises and refuses to run.

The templates are enumerated from the module registry, never from a
hand-written list, so a tool added tomorrow is covered today.
"""

import os
import re
import sys
import inspect
import pkgutil
import importlib
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import modules
from modules.base import BaseModule, Tool

# The placeholder grammar, restated here rather than imported: this is
# the contract build_command() has to honour, so the test must not move
# when the implementation does.
_PLACEHOLDER_RE = re.compile(r"\{[a-z_][a-z0-9_]*\}")


def _registry_tools():
    """(module_name, Tool) for every tool declared by a phase module."""
    out = []
    for info in pkgutil.iter_modules(modules.__path__):
        if info.ispkg:
            continue
        mod = importlib.import_module("modules." + info.name)
        for obj in vars(mod).values():
            if (inspect.isclass(obj)
                    and issubclass(obj, BaseModule)
                    and obj is not BaseModule):
                for tool in (obj.TOOLS or []):
                    out.append((info.name, tool))
    return out


class BuildCommandRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tools = _registry_tools()
        # Guard against the enumeration silently finding nothing and the
        # whole file passing vacuously.
        self.assertGreater(len(self.tools), 50,
                           "tool registry enumeration came back nearly "
                           "empty — the walk is broken, not the tools")

    def test_never_raises(self):
        for mod_name, tool in self.tools:
            with self.subTest(tool=f"{mod_name}:{tool.id}"):
                try:
                    tool.build_command("10.10.10.10")
                except Exception as exc:                 # noqa: BLE001
                    self.fail(f"{mod_name}:{tool.id} raised "
                              f"{type(exc).__name__}: {exc}")

    def test_never_raises_with_extra_args(self):
        for mod_name, tool in self.tools:
            with self.subTest(tool=f"{mod_name}:{tool.id}"):
                try:
                    tool.build_command("10.10.10.10", "--extra 1")
                except Exception as exc:                 # noqa: BLE001
                    self.fail(f"{mod_name}:{tool.id} raised "
                              f"{type(exc).__name__}: {exc}")

    def test_never_raises_on_empty_target(self):
        # Preview paths build a command before a session exists.
        for mod_name, tool in self.tools:
            with self.subTest(tool=f"{mod_name}:{tool.id}"):
                try:
                    tool.build_command("")
                except Exception as exc:                 # noqa: BLE001
                    self.fail(f"{mod_name}:{tool.id} raised "
                              f"{type(exc).__name__}: {exc}")

    def test_addcomputer_default_stays_placeholder_based(self):
        # ADD COMPUTER must NOT ship a hardcoded machine name/password in
        # its default command: they are prompted as required
        # <COMPUTER_NAME>/<COMPUTER_PASS> dialog fields instead.  Guards
        # both the "minimal default" rule and the re-run collision fix
        # against a regression that re-hardcodes a literal account.
        addc = [t for _m, t in self.tools if t.id == "addcomputer"]
        self.assertEqual(len(addc), 1,
                         "expected exactly one addcomputer tool")
        tmpl = addc[0].cmd_template
        self.assertIn("<COMPUTER_NAME>", tmpl)
        self.assertIn("<COMPUTER_PASS>", tmpl)
        self.assertNotIn("HAWK$", tmpl)
        self.assertNotIn("Hawk123!", tmpl)

    def test_adidnsdump_default_dumps_records(self):
        # ADIDNSDUMP's default must actually dump the zone to records.csv
        # (what the parser reads), NOT run with --print-zones, which only
        # lists zone names and exits without writing records.csv.
        adi = [t for _m, t in self.tools if t.id == "adidnsdump"]
        self.assertEqual(len(adi), 1,
                         "expected exactly one adidnsdump tool")
        self.assertNotIn("--print-zones", adi[0].cmd_template)

    def test_no_unresolved_placeholder_survives(self):
        """No `{name}` reaches the shell.

        Unknown placeholders must come out as `<name>`; known ones must
        be substituted.  Shell constructs (`${VER}`, `awk '{print $1}'`)
        are not placeholders and are deliberately left alone — the
        placeholder grammar is lowercase snake_case only.
        """
        for mod_name, tool in self.tools:
            cmd = tool.build_command("10.10.10.10")
            leftover = _PLACEHOLDER_RE.findall(cmd)
            with self.subTest(tool=f"{mod_name}:{tool.id}"):
                self.assertEqual(
                    leftover, [],
                    f"{mod_name}:{tool.id} emitted unresolved "
                    f"placeholder(s) {leftover} in: {cmd}")


class BuildCommandSubstitutionTests(unittest.TestCase):
    def _tool(self, template, **kw):
        kw.setdefault("binary", "echo")
        return Tool(id="t", name="T", desc="d",
                    cmd_template=template, **kw)

    def test_target_is_substituted(self):
        cmd = self._tool("nmap -sV {target}").build_command("10.10.10.10")
        self.assertEqual(cmd, "nmap -sV 10.10.10.10")

    def test_target_is_shell_quoted(self):
        """The target is free text and lands in a shell=True command."""
        cmd = self._tool("nmap {target}").build_command("1.2.3.4; id")
        self.assertNotIn("; id", cmd.replace("'1.2.3.4; id'", ""))
        self.assertIn("'1.2.3.4; id'", cmd)

    def test_plain_targets_are_not_rewritten(self):
        for target in ("10.10.10.10", "dc01.corp.local",
                       "10.10.0.0/24", "http://10.10.10.10:8080/"):
            with self.subTest(target=target):
                cmd = self._tool("nmap {target}").build_command(target)
                self.assertEqual(cmd, f"nmap {target}")

    def test_ad_placeholders_become_labels(self):
        cmd = self._tool(
            "impacket-x {domain}/{user}:{password}@{target}"
        ).build_command("10.10.10.10")
        self.assertEqual(
            cmd, "impacket-x <DOMAIN>/<user>:<password>@10.10.10.10")

    def test_unknown_placeholder_becomes_a_label(self):
        """`{share}` is filled by the dialog that owns the tool; until
        then it must read as a `<...>` label, which _run_raw refuses to
        launch."""
        cmd = self._tool("tool -o {share}/x").build_command("1.2.3.4")
        self.assertEqual(cmd, "tool -o <share>/x")

    def test_directory_placeholders_resolve_inside_the_tree(self):
        """`{outputs}` / `{payloads}` are the only way a template can
        save a file without dropping it in the working directory."""
        from utils.config import is_within_base

        for name in ("outputs", "payloads"):
            cmd = self._tool(f"curl -L http://x -o {{{name}}}/f.sh"
                             ).build_command("1.2.3.4")
            path = cmd.rsplit(" ", 1)[-1]
            self.assertTrue(is_within_base(path), path)
            self.assertTrue(os.path.isabs(path), path)

    def test_shell_braces_survive_untouched(self):
        """Two shell expansions in one template used to escape the
        one-shot KeyError fallback and kill the calling Tk callback."""
        template = ('curl -L "https://x/${VER}/chisel_${VER#v}.gz" '
                    "| awk '{print $1}'")
        cmd = self._tool(template).build_command("10.10.10.10")
        self.assertEqual(cmd, template)


class ChiselTemplateRegressionTests(unittest.TestCase):
    """The concrete tool that was dead on click."""

    def _chisel(self):
        from modules.lateral import LateralModule
        for tool in LateralModule.TOOLS:
            if tool.id == "chisel_win_download":
                return tool
        self.fail("chisel_win_download is no longer in the lateral module")

    def test_builds_and_keeps_both_shell_expansions(self):
        cmd = self._chisel().build_command("10.10.10.10")
        self.assertIn("${VER}", cmd)
        self.assertIn("${VER#v}", cmd)


if __name__ == "__main__":
    unittest.main()
