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


if __name__ == "__main__":
    unittest.main()
