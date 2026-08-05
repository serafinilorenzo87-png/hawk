"""Static contracts around the shared dialog helpers.

`_btn` (gui/dialogs_common.py) packs its button in place and returns
None.  Two call sites got that wrong in the same way: one passed colour
kwargs it does not accept (TypeError — the dialog opened with no COPY
and no CLOSE button), the other kept the return value and called
`.configure()` on it inside a bare `except Exception: pass`, so the
"COPIED" feedback silently never happened.

Neither needs a display to catch, so these run everywhere — including
the headless machines where the dialog smoke test skips.
"""

import ast
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

GUI_DIR = os.path.join(ROOT, "gui")
HELPERS = os.path.join(GUI_DIR, "dialogs_common.py")


def _gui_sources():
    for dirpath, dirnames, filenames in os.walk(GUI_DIR):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def _parse(path):
    with open(path, "r", encoding="utf-8") as fh:
        return ast.parse(fh.read(), filename=path)


def _btn_signature():
    """(accepted keyword names, returns_a_value) for `_btn`."""
    for node in ast.walk(_parse(HELPERS)):
        if isinstance(node, ast.FunctionDef) and node.name == "_btn":
            args = node.args
            names = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
            returns = any(isinstance(n, ast.Return) and n.value is not None
                          for n in ast.walk(node))
            return names, returns
    raise AssertionError("_btn is gone from gui/dialogs_common.py")


def _btn_calls():
    """(path, lineno, node) for every `_btn(...)` call under gui/."""
    for path in _gui_sources():
        for node in ast.walk(_parse(path)):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_btn"):
                yield (os.path.relpath(path, ROOT), node.lineno, node)


class BtnHelperContractTests(unittest.TestCase):
    def setUp(self):
        self.accepted, self.returns_value = _btn_signature()
        self.calls = list(_btn_calls())
        self.assertGreater(len(self.calls), 100,
                           "the _btn call-site walk found almost nothing — "
                           "the AST scan is broken, not the call sites")

    def test_every_call_site_uses_accepted_keywords(self):
        for path, lineno, node in self.calls:
            for kw in node.keywords:
                if kw.arg is None:      # **kwargs forwarding
                    continue
                with self.subTest(site=f"{path}:{lineno}"):
                    self.assertIn(
                        kw.arg, self.accepted,
                        f"{path}:{lineno} passes `{kw.arg}=` to _btn, "
                        f"which accepts {sorted(self.accepted)}")

    def test_every_call_site_passes_enough_positionals(self):
        # parent, text, cmd are required.
        for path, lineno, node in self.calls:
            named = {kw.arg for kw in node.keywords}
            supplied = len(node.args) + len(named & {"parent", "text", "cmd"})
            with self.subTest(site=f"{path}:{lineno}"):
                self.assertGreaterEqual(
                    supplied, 3,
                    f"{path}:{lineno} calls _btn with {supplied} of the 3 "
                    f"required arguments")

    def test_return_value_is_never_used(self):
        """`_btn` returns None.  Keeping the result and calling
        `.configure()` on it is dead code inside a swallowing except."""
        self.assertFalse(
            self.returns_value,
            "_btn now returns a value — if that is intentional, drop this "
            "test and the call sites that build their button by hand")

        offenders = []
        for path in _gui_sources():
            for node in ast.walk(_parse(path)):
                if not isinstance(node, (ast.Assign, ast.AnnAssign,
                                         ast.AugAssign)):
                    continue
                value = node.value
                if (isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and value.func.id == "_btn"):
                    offenders.append(
                        f"{os.path.relpath(path, ROOT)}:{node.lineno}")
        self.assertEqual(
            offenders, [],
            "these keep _btn's return value, which is always None: "
            + ", ".join(offenders))


# ═══════════════════════════════════════════════════════════════════
#  Tool ids the GUI keys on must exist in the module registry
# ═══════════════════════════════════════════════════════════════════
#
# `modules/enumeration.py` registered the netexec tool as
# id="crackmapexec" while every dispatcher keyed on "netexec": the card
# never reached _show_crackmapexec_dialog, never ran its intel parser,
# and fell through to the generic raw-run path instead — silently, for
# as long as both spellings existed. `card_common.SMB_TOOLS` also held
# "crackmapexec_smb", a tool id that has never existed.
#
# A GUI that keys on a string the registry does not define is always a
# bug: the branch is unreachable. No display needed, so this runs
# everywhere.

# Names in gui/ whose value is a set/tuple/list of TOOL IDS.
_TOOL_ID_SETS = ("WEB_TOOLS", "SMB_TOOLS")

# Ids the GUI still routes for although no module registers them.
# MUST STAY EMPTY: every exception here is a GUI branch that cannot
# run.  The two it used to hold were closed by registering `dirb` in
# modules/enumeration.py (its `_route_dirb` dialog was complete but
# unreachable) and by dropping the bare `gobuster` alias in favour of
# the registered gobuster_dir / gobuster_dns ids.
_UNREGISTERED_GUI_TOOL_IDS = set()


def _registry_tool_ids():
    """Every tool id defined by a BaseModule subclass under modules/."""
    import importlib
    import inspect

    from modules.base import BaseModule

    ids = set()
    mod_dir = os.path.join(ROOT, "modules")
    for fn in sorted(os.listdir(mod_dir)):
        if not fn.endswith(".py") or fn == "__init__.py":
            continue
        name = "modules." + fn[:-3]
        module = importlib.import_module(name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, BaseModule) and obj is not BaseModule
                    and obj.__module__ == name):
                for tool in obj().get_tools() or []:
                    ids.add(tool.id)
    return ids


def _string_constants(node):
    """Every str constant directly inside `node` (or the node itself)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        out = []
        for elt in node.elts:
            out.extend(_string_constants(elt))
        return out
    return []


def _is_tool_id(node):
    return (isinstance(node, ast.Attribute) and node.attr == "id"
            and isinstance(node.value, ast.Name)
            and node.value.id in ("tool", "t"))


def _gui_tool_id_branches():
    """(path, lineno, [ids]) for every branch the GUI keys on tool.id.

    One entry per COMPARISON, because a tuple of ids is a set of
    accepted aliases: the branch is reachable as long as one of them
    exists.  `"ssh" in tool.id` is a substring test, not a membership
    test, and is skipped.
    """
    for path in _gui_sources():
        rel = os.path.relpath(path, ROOT)
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Compare):
                continue
            ids = []
            for op, right in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    if _is_tool_id(node.left):
                        ids += _string_constants(right)
                    elif _is_tool_id(right):
                        ids += _string_constants(node.left)
                elif isinstance(op, (ast.In, ast.NotIn)):
                    # Only `tool.id in (...)`; `"x" in tool.id` is a
                    # substring test on the id, not a lookup.
                    if _is_tool_id(node.left) and isinstance(
                            right, (ast.Tuple, ast.List, ast.Set)):
                        ids += _string_constants(right)
            if ids:
                yield (rel, node.lineno, ids)


def _gui_tool_id_sets():
    """(path, lineno, name, [ids]) for WEB_TOOLS / SMB_TOOLS."""
    for path in _gui_sources():
        rel = os.path.relpath(path, ROOT)
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (isinstance(target, ast.Name)
                        and target.id in _TOOL_ID_SETS):
                    yield (rel, node.lineno, target.id,
                           _string_constants(node.value))


class GuiToolIdContractTests(unittest.TestCase):
    def setUp(self):
        self.registry = _registry_tool_ids()
        self.assertGreater(
            len(self.registry), 50,
            "the registry walk found almost no tools — the walk is "
            "broken, not the tool ids")
        self.branches = list(_gui_tool_id_branches())
        self.assertGreater(
            len(self.branches), 20,
            "the GUI tool-id walk found almost nothing — the AST scan "
            "is broken, not the call sites")
        self.known = self.registry | _UNREGISTERED_GUI_TOOL_IDS

    def test_no_branch_keys_on_ids_that_do_not_exist(self):
        """A branch none of whose ids exist can never run."""
        dead = [(p, ln, ids) for p, ln, ids in self.branches
                if not any(i in self.known for i in ids)]
        self.assertEqual(
            dead, [],
            "these branches key on tool ids that no module defines, so "
            "they are unreachable: "
            + ", ".join(f"{p}:{ln} {ids}" for p, ln, ids in dead))

    def test_routing_sets_hold_real_tool_ids(self):
        bad = []
        for path, lineno, name, ids in _gui_tool_id_sets():
            self.assertTrue(ids, f"{path}:{lineno} {name} is empty")
            for tid in ids:
                if tid not in self.known:
                    bad.append(f"{path}:{lineno} {name} has {tid!r}")
        self.assertEqual(
            bad, [],
            "routing sets hold tool ids no module defines: "
            + ", ".join(bad))

    def test_the_netexec_card_reaches_its_dialog(self):
        """Regression pin for the specific case that started this."""
        self.assertIn("netexec", self.registry)
        self.assertNotIn("crackmapexec", self.registry)

        smb = [ids for _p, _l, name, ids in _gui_tool_id_sets()
               if name == "SMB_TOOLS"]
        self.assertEqual(len(smb), 1)
        self.assertIn("netexec", smb[0])
        for tid in smb[0]:
            self.assertIn(tid, self.registry,
                          f"SMB_TOOLS has {tid!r}")


if __name__ == "__main__":
    unittest.main()
