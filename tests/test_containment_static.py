"""Static containment policy — everything HAWK writes stays under BASE_DIR.

HAWK is portable: the operator copies the folder, runs `python3 hawk.py`
and every artefact the app produces lives under that same tree
(sessions/ outputs/ payloads/ tmp/ cache/ dicts/ logs/ configs/
reports/).  Nothing lands in $HOME or in whatever directory the app
happened to be launched from, and the only writes outside the tree are
the two explicitly allowlisted system files in
`utils.config.ALLOWED_EXTERNAL_WRITES`.

`tests/test_self_contained.py` checks that the *constants* obey that
rule.  This file checks the *code*: it walks the AST of every
production source, finds each write (`open(..., "w")`, `os.makedirs`,
`shutil.copy*`, `tempfile.mkstemp(dir=…)`, …) and requires the written
path to be derived from a contained root — or to be listed below with a
reason.

Two lists carry the policy:

  ALLOWED_WRITES   — writes whose destination is NOT a contained root
                     and why that is acceptable.
  ALLOWED_MARKERS  — files that mention `os.getcwd()`,
                     `expanduser("~")` or `/tmp` at all, and why.

Both are keyed by (file, expression) rather than by line number so they
survive refactors.  A new write outside the tree fails the build; the
right fix is almost always to route it through `utils.config`, not to
add a line here.
"""

import ast
import os
import re
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# Production packages.  tests/ and tmp/ are excluded on purpose: test
# fixtures write to pytest temp dirs and tmp/ is the scratch area.
SCAN_DIRS = ("gui", "modules", "utils", "tools")
SCAN_FILES = ("hawk.py",)

# Tokens that mean "this path is rooted inside the HAWK tree".  Any
# write whose path expression (directly or through a local assignment)
# mentions one of these is contained by construction.
CONTAINED_TOKENS = (
    # utils.config roots (and the aliases modules import them under).
    "BASE_DIR", "SESSIONS_DIR", "OUTPUTS_DIR", "PAYLOADS_DIR",
    "TMP_DIR", "CACHE_DIR", "LOGS_DIR", "CONFIGS_DIR", "DICTS_DIR",
    "REPORTS_DIR", "SWEEPS_DIR",
    # A path built from a module's own location is inside the repo by
    # construction — that is how BASE_DIR itself is defined.
    "__file__",
    # utils.config helpers that enforce or guarantee containment.
    "hawk_path", "require_within_base", "require_writable",
    "contained_sibling",
    # modules.discovery path builders, all rooted at SWEEPS_DIR.
    "gnmap_path_for", "phase2_targets_path_for", "sweep_path_for",
    # utils.hosts_helper's tempfile wrapper, rooted at TMP_DIR.
    "_mk_hawk_temp",
)

# ── Writes that leave the tree, with the reason they are allowed ─────
# key: (path relative to the repo root, the written path expression)
# (/etc/hosts needs no entry: utils/hosts_helper never writes it from
# Python — it hands a TMP_DIR file to pkexec/sudo — and calls
# require_writable() first, which is where the allowlist is enforced.)
ALLOWED_WRITES = {
    ("gui/dialogs_ops.py", "conf_path"):
        "/etc/proxychains4.conf — on ALLOWED_EXTERNAL_WRITES; "
        "proxychains4 only reads its config from a fixed system path, "
        "so a copy inside the HAWK tree would not be used by the "
        "operator's own `proxychains4 <tool>` commands.",
    ("gui/dialogs_ops.py", "backup"):
        "/etc/proxychains4.conf.hawk_backup — the pre-write backup of "
        "the file above, same allowlist entry.",
    ("tools/recover_session.py", "dst"):
        "Standalone CLI: recovers the file the operator names on argv "
        "and writes the result next to it.  Not part of the app.",
    ("utils/config.py", "external_tmp"):
        "Subprocess TMPDIR env var handed to child tools (NOT HAWK's own "
        "temp).  Leaves the tree ONLY when the operator sets HAWK_TMPDIR "
        "or when BASE_DIR is on a temp-hostile filesystem (shared folder "
        "/ network mount) whose per-process temp I/O blocks and hangs "
        "tools like nuclei at shutdown.  Ephemeral tool scratch only; the "
        "default TMPDIR stays TMP_DIR and HAWK's explicit temp files never "
        "come here.  See utils.config.resolve_tool_tmpdir().",
}

# ── Files allowed to mention a non-contained path at all ─────────────
# key: (path relative to the repo root, marker)
ALLOWED_MARKERS = {
    # $HOME — read-only lookups and operator file pickers.
    ("modules/base.py", "expanduser"):
        "Read-only: alt binary directories (~/.local/bin, ~/go/bin …) "
        "scanned to resolve a tool that is not on $PATH.",
    ("utils/runner.py", "expanduser"):
        "Read-only: $HOME and /root scanned for installed tooling.",
    ("utils/web_oracle.py", "expanduser"):
        "Read-only: ~/go/bin and ~/.local/bin probed for httpx/nuclei.",
    ("utils/jwt_analyzer.py", "expanduser"):
        "Read-only: known wordlist locations for JWT secret cracking.",
    ("utils/crack_runner.py", "expanduser"):
        "Read-only: known wordlist locations (rockyou and friends).",
    ("utils/db_profile_loader.py", "expanduser"):
        "Read-only: ~/.config lookup for an existing DB profile.",
    ("utils/plugin_loader.py", "Path.home()"):
        "Read-only: default location of the ARGUS licence file the "
        "operator installs themselves (~/.hawk/argus_license.bin).",
    ("gui/dialogs_privesc.py", "expanduser"):
        "File-picker start directory only — the operator browses to a "
        "PEAS output wherever they left it.  What HAWK then WRITES "
        "goes through utils.config.contained_path().",
    # /tmp — paths on the TARGET, or shell snippets the operator runs.
    ("utils/privesc_patterns.py", "/tmp"):
        "Exploit commands executed ON THE TARGET, not on Kali.",
    ("modules/parsers/linpeas_parser.py", "/tmp"):
        "Linux paths quoted from linpeas output / remediation hints.",
    ("gui/dialogs_privesc.py", "/tmp"):
        "Upload destination ON THE TARGET for the PEAS workflow.",
    ("utils/stealth.py", "/tmp"):
        "Fallback drop path ON THE TARGET when stealth mode is off.",
    ("gui/widgets/card_routes_hydra.py", "/tmp"):
        "Command text shown to the operator for on-target execution.",
    ("gui/widgets/card_parsers_web.py", "/tmp"):
        "Remediation text quoting a webserver's own temp directory.",
    ("gui/widgets/card_routes_access.py", "/tmp"):
        "On-target paths inside copy-paste post-exploitation commands.",
    ("gui/widgets/card_runtime.py", "/tmp"):
        "On-target paths inside copy-paste commands.",
    ("gui/widgets/target_intel_widget.py", "/tmp"):
        "On-target path inside a copy-paste hint.",
    ("modules/base.py", "/tmp"):
        "On-target path inside a tool template's help text.",
    ("utils/post_rce_recon.py", "/tmp"):
        "Remediation prose describing what an attacker could do ON the "
        "target host.",
    ("utils/crack_runner.py", "/tmp"):
        "Hashcat/john help text quoting their own defaults.",
    ("gui/widgets/card_ad_routes.py", "/tmp"):
        "On-target paths inside the CHISEL Client guided workflow — "
        "wget/chmod/run commands the operator pastes into the pivot's "
        "shell, not Kali writes.",
}


# ── AST plumbing ─────────────────────────────────────────────────────

def _sources():
    for name in SCAN_FILES:
        path = os.path.join(ROOT, name)
        if os.path.isfile(path):
            yield path
    for sub in SCAN_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, sub)):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fn in sorted(filenames):
                if fn.endswith(".py"):
                    yield os.path.join(dirpath, fn)


def _rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def _dotted(node):
    """`os.path.join` for an Attribute/Name chain, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _kwarg(call, name):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_write_mode(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return any(c in node.value for c in "wax+")
    # Non-literal mode — assume the worst.
    return node is not None


# call name -> index of the positional argument holding the destination
_DEST_ARG = {
    "os.makedirs": 0, "os.mkdir": 0,
    "shutil.copy": 1, "shutil.copy2": 1, "shutil.copyfile": 1,
    "shutil.copytree": 1, "shutil.move": 1,
    "os.rename": 1, "os.replace": 1,
}
# call name -> keyword holding the parent directory
_DEST_KWARG = {
    "tempfile.mkstemp": "dir",
    "tempfile.mkdtemp": "dir",
    "tempfile.NamedTemporaryFile": "dir",
}


def _write_targets(tree):
    """Yield (lineno, unparsed destination expression) for every write."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        dest = None
        if name in ("open", "io.open", "codecs.open"):
            mode = (node.args[1] if len(node.args) > 1
                    else _kwarg(node, "mode"))
            if mode is not None and _is_write_mode(mode) and node.args:
                dest = node.args[0]
        elif name in _DEST_ARG:
            idx = _DEST_ARG[name]
            if len(node.args) > idx:
                dest = node.args[idx]
        elif name in _DEST_KWARG:
            dest = _kwarg(node, _DEST_KWARG[name])
            if dest is None:
                # No dir= at all: lands in the system temp directory.
                dest = ast.Constant(value="<system tempdir>")
                dest.lineno = node.lineno
        if dest is not None:
            yield node.lineno, ast.unparse(dest)


def _assignments(tree):
    """name -> [unparsed rhs, …] for everything that binds a name.

    Assignments, `with … as`, `for … in`, `from x import Y as Z` and
    function definitions (bound to their return expressions) — enough to
    follow a written path back to the constant it came from without
    leaving the file.
    """
    out = {}

    def bind(target, value_text):
        if isinstance(target, ast.Name):
            out.setdefault(target.id, []).append(value_text)
        elif isinstance(target, ast.Attribute):
            out.setdefault(target.attr, []).append(value_text)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                bind(elt, value_text)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, ast.unparse(node.value))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if node.value is not None:
                bind(node.target, ast.unparse(node.value))
        elif isinstance(node, ast.withitem) and node.optional_vars:
            bind(node.optional_vars, ast.unparse(node.context_expr))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bind(node.target, ast.unparse(node.iter))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname:
                    out.setdefault(alias.asname, []).append(alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and sub.value is not None:
                    out.setdefault(node.name, []).append(
                        ast.unparse(sub.value))
    return out


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _is_contained(expr, assigns, depth=0, seen=None):
    if any(tok in expr for tok in CONTAINED_TOKENS):
        return True
    if depth >= 4:
        return False
    seen = seen or set()
    for ident in set(_IDENT_RE.findall(expr)):
        if ident in seen:
            continue
        seen.add(ident)
        for rhs in assigns.get(ident, ()):
            if _is_contained(rhs, assigns, depth + 1, seen):
                return True
    return False


def _docstring_ids(tree):
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                ids.add(id(body[0].value))
    return ids


def _markers(tree):
    """Yield (lineno, marker) for escape hatches in string/AST form."""
    skip = _docstring_ids(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name.endswith("getcwd"):
                yield node.lineno, "os.getcwd()"
            elif name.endswith("expanduser"):
                arg = node.args[0] if node.args else None
                if (isinstance(arg, ast.Constant)
                        and isinstance(arg.value, str)
                        and arg.value.startswith("~")):
                    yield node.lineno, "expanduser"
            elif name in ("Path.home", "pathlib.Path.home"):
                yield node.lineno, "Path.home()"
        elif (isinstance(node, ast.Constant)
              and isinstance(node.value, str)
              and id(node) not in skip
              and re.search(r"(^|[\s\"'=(])/tmp(/|\b)", node.value)):
            yield node.lineno, "/tmp"


class WriteContainmentTests(unittest.TestCase):
    """Every write lands inside the HAWK tree or is allowlisted above."""

    def test_all_writes_are_contained(self):
        offenders = []
        for path in _sources():
            rel = _rel(path)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=path)
            assigns = _assignments(tree)
            for lineno, expr in _write_targets(tree):
                if _is_contained(expr, assigns):
                    continue
                if (rel, expr) in ALLOWED_WRITES:
                    continue
                offenders.append(f"{rel}:{lineno}  writes to `{expr}`")
        self.assertEqual(
            offenders, [],
            "these writes are not rooted in the HAWK tree — route them "
            "through utils.config or add an entry to ALLOWED_WRITES "
            "with the reason:\n  " + "\n  ".join(offenders))

    def test_escape_hatches_are_documented(self):
        offenders = []
        for path in _sources():
            rel = _rel(path)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=path)
            for lineno, marker in _markers(tree):
                if (rel, marker) in ALLOWED_MARKERS:
                    continue
                offenders.append(f"{rel}:{lineno}  uses `{marker}`")
        self.assertEqual(
            offenders, [],
            "these refer to a path outside the HAWK tree — use a "
            "utils.config root, or document the file in "
            "ALLOWED_MARKERS:\n  " + "\n  ".join(offenders))

    def test_allowlists_have_no_stale_entries(self):
        """A fixed violation must be removed from the allowlist."""
        seen_writes = set()
        seen_markers = set()
        for path in _sources():
            rel = _rel(path)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), filename=path)
            for _lineno, expr in _write_targets(tree):
                seen_writes.add((rel, expr))
            for _lineno, marker in _markers(tree):
                seen_markers.add((rel, marker))
        stale = ([f"ALLOWED_WRITES {k}" for k in ALLOWED_WRITES
                  if k not in seen_writes]
                 + [f"ALLOWED_MARKERS {k}" for k in ALLOWED_MARKERS
                    if k not in seen_markers])
        self.assertEqual(
            stale, [],
            "these allowlist entries no longer match any code — delete "
            "them:\n  " + "\n  ".join(stale))


def _download_targets(template):
    """`-o <dest>` / `--output <dest>` of every curl/wget in a template.

    Only the command segment that actually invokes the downloader
    counts: `grep -o` in a pipeline further along means something else
    entirely.
    """
    for segment in re.split(r"\|\||&&|[|;]", template):
        if not re.search(r"\b(curl|wget)\b", segment):
            continue
        for m in re.finditer(r"(?:^|\s)(?:-o|--output)\s+(\S+)", segment):
            yield m.group(1)


class ShellArtifactContainmentTests(unittest.TestCase):
    """Commands HAWK builds must not drop artefacts in the CWD either.

    The Python-level scan above cannot see where an external tool
    writes.  `curl -o <bare name>` and `searchsploit -m` land in the
    process working directory, which is wherever the operator started
    HAWK from.
    """

    def test_download_templates_write_into_the_tree(self):
        from modules.base import BaseModule
        import importlib
        import inspect

        offenders = []
        mod_dir = os.path.join(ROOT, "modules")
        for fn in sorted(os.listdir(mod_dir)):
            if not fn.endswith(".py") or fn == "__init__.py":
                continue
            module = importlib.import_module("modules." + fn[:-3])
            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (not issubclass(obj, BaseModule) or obj is BaseModule
                        or obj.__module__ != module.__name__):
                    continue
                for tool in obj().get_tools() or []:
                    if tool.runs_on_target:
                        continue        # paths belong to the victim host
                    for dest in _download_targets(tool.cmd_template):
                        if dest.startswith(("{", "/", "$", '"$')):
                            continue
                        offenders.append(
                            f"{tool.id}: `-o {dest}` lands in the CWD")
        self.assertEqual(
            offenders, [],
            "download templates must write into a HAWK directory "
            "(`-o {payloads}/name`):\n  " + "\n  ".join(offenders))


class TmpdirResolutionTests(unittest.TestCase):
    """utils.config.resolve_tool_tmpdir() keeps the subprocess TMPDIR
    contained (TMP_DIR) by default, and only leaves the tree for the two
    documented reasons: an explicit HAWK_TMPDIR, or BASE_DIR sitting on a
    temp-hostile filesystem whose temp I/O hangs tools (nuclei)."""

    def setUp(self):
        import utils.config as cfg
        self.cfg = cfg
        self._old_fstype = cfg._mount_fstype
        self._old_env = os.environ.get("HAWK_TMPDIR")
        os.environ.pop("HAWK_TMPDIR", None)
        cfg._TMPDIR_RELAX_WARNED = False

    def tearDown(self):
        self.cfg._mount_fstype = self._old_fstype
        if self._old_env is None:
            os.environ.pop("HAWK_TMPDIR", None)
        else:
            os.environ["HAWK_TMPDIR"] = self._old_env

    def test_default_tmpdir_is_contained(self):
        self.cfg._mount_fstype = lambda _p: "ext4"
        got = self.cfg.resolve_tool_tmpdir()
        self.assertEqual(got, self.cfg.TMP_DIR)
        self.assertTrue(self.cfg.is_within_base(got))

    def test_hostile_fs_falls_back_to_local(self):
        import tempfile
        self.cfg._mount_fstype = lambda _p: "fuse.vmhgfs-fuse"
        got = self.cfg.resolve_tool_tmpdir()
        self.assertFalse(
            self.cfg.is_within_base(got),
            "a temp-hostile BASE_DIR must fall back OUTSIDE the tree")
        self.assertTrue(got.startswith(tempfile.gettempdir()))

    def test_explicit_override_wins_even_on_hostile_fs(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="hawk_ovr_")
        os.environ["HAWK_TMPDIR"] = d
        self.cfg._mount_fstype = lambda _p: "vboxsf"
        self.assertEqual(self.cfg.resolve_tool_tmpdir(), d)


if __name__ == "__main__":
    unittest.main()
