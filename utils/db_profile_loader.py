"""DB profile loader (STEP 5 / Fase 3).

Reads cheatsheet definitions from per-DB YAML files instead of the
hard-coded Python dict in target_intel_widget.py.  Two source dirs
are scanned, in order — later entries override earlier ones at the
**same canonical key**:

  1. Built-in defaults shipped with HAWK:
        <hawkC>/profiles/db_profiles/*.yaml
  2. User-local extensions:
        ~/.config/hawk/db_profiles/*.yaml

The loader is **fault-tolerant**: any IO error, YAML parse error,
or schema violation logs a warning to stderr and SKIPS the offending
file — the rest of the directory still loads.  If PyYAML is not
installed the loader returns empty results and the caller MUST fall
back to its hard-coded defaults (target_intel_widget.py does this).

Schema (per file):
    name:    <str>             # canonical key (required)
    title:   <str>             # display title (required)
    aliases: [<str>, ...]      # optional service-name aliases
    intro:   <str>             # optional one-paragraph blurb
    commands:                  # required, list of:
      - cmd:  <str>            # required
        desc: <str>            # required (empty string = section
                               #           header / inline note)

The loader is **stateless and safe to call at module-import time**
of target_intel_widget — the only side effects are stderr writes
when a file is bad.  No filesystem mutation, no network.
"""
from __future__ import annotations

import os
import sys
from typing import Dict, List, Tuple


# Per-profile validation result.
_REQUIRED_TOP = ("name", "title", "commands")
_REQUIRED_CMD = ("cmd", "desc")


def _user_dir() -> str:
    """Return ~/.config/hawk/db_profiles/, expanded.

    Honours XDG_CONFIG_HOME (Linux/BSD/macOS); falls back to
    ~/.config on systems that don't define it.  Doesn't create
    the dir — non-existence is normal.
    """
    base = os.environ.get("XDG_CONFIG_HOME")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "hawk", "db_profiles")


def _builtin_dir() -> str:
    """Return <hawkC>/profiles/db_profiles/.

    Computed relative to THIS file (utils/) so the loader works
    regardless of HAWK's cwd at launch.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "profiles",
                                          "db_profiles"))


def _validate_profile(path: str, doc) -> str:
    """Return an error message string on schema violation, or '' OK.

    Lightweight check — we accept missing optional fields silently
    but require the structural skeleton.
    """
    if not isinstance(doc, dict):
        return "top-level YAML must be a mapping"
    for field in _REQUIRED_TOP:
        if field not in doc:
            return f"missing required field '{field}'"
    if not isinstance(doc["name"], str) or not doc["name"].strip():
        return "'name' must be a non-empty string"
    if not isinstance(doc["title"], str) or not doc["title"].strip():
        return "'title' must be a non-empty string"
    cmds = doc["commands"]
    if not isinstance(cmds, list) or not cmds:
        return "'commands' must be a non-empty list"
    for i, c in enumerate(cmds):
        if not isinstance(c, dict):
            return f"commands[{i}] must be a mapping"
        for f in _REQUIRED_CMD:
            if f not in c:
                return f"commands[{i}] missing field '{f}'"
        if not isinstance(c["cmd"], str):
            return f"commands[{i}].cmd must be a string"
        if not isinstance(c["desc"], str):
            return f"commands[{i}].desc must be a string"
        if not c["cmd"]:
            return f"commands[{i}].cmd must not be empty"
    # Aliases are optional; if present must be a list of strings.
    aliases = doc.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, list):
            return "'aliases' must be a list of strings"
        for j, a in enumerate(aliases):
            if not isinstance(a, str) or not a.strip():
                return f"aliases[{j}] must be a non-empty string"
    return ""


def _load_dir(path: str) -> List[Tuple[str, dict]]:
    """Read every *.yaml / *.yml file in `path`.  Returns a list of
    (filename, parsed_doc) tuples for files that pass validation.

    Missing dir -> empty list (silent — not all users have a user
    profiles dir).  Bad files -> stderr warning + skip.
    """
    try:
        import yaml
    except ImportError:
        sys.stderr.write(
            "[HAWK] db_profile_loader: PyYAML not installed — "
            "skipping YAML profiles (Python dict fallback in use)\n")
        return []
    out: List[Tuple[str, dict]] = []
    if not os.path.isdir(path):
        return out
    try:
        names = sorted(os.listdir(path))
    except OSError as e:
        sys.stderr.write(
            f"[HAWK] db_profile_loader: cannot list {path}: {e}\n")
        return out
    for name in names:
        if not (name.endswith(".yaml") or name.endswith(".yml")):
            continue
        full = os.path.join(path, name)
        try:
            with open(full, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            sys.stderr.write(
                f"[HAWK] db_profile_loader: skipping {full} "
                f"({type(e).__name__}: {e})\n")
            continue
        err = _validate_profile(full, doc)
        if err:
            sys.stderr.write(
                f"[HAWK] db_profile_loader: skipping {full}: {err}\n")
            continue
        out.append((name, doc))
    return out


def _to_runtime(doc: dict) -> Tuple[str, dict, List[str]]:
    """Convert a validated YAML doc into the runtime shape used by
    _CONNECT_CHEATSHEETS + the alias map.

    Returns ``(canonical_key, cheatsheet_entry, alias_list)``.
    """
    name = doc["name"].strip().lower()
    title = doc["title"].strip()
    intro = (doc.get("intro") or "").strip()
    commands = [
        (c["cmd"], c["desc"])
        for c in doc["commands"]
    ]
    aliases = [
        a.strip().lower()
        for a in (doc.get("aliases") or [])
        if a and a.strip()
    ]
    entry = {
        "title":    title,
        "intro":    intro,
        "commands": commands,
    }
    return name, entry, aliases


def load_profiles(builtin_dir: str = None,
                  user_dir: str = None,
                  verbose: bool = False
                  ) -> Tuple[Dict[str, dict], Dict[str, str]]:
    """Load all DB profiles and build (cheatsheets, alias_map).

    Returns a 2-tuple:
      cheatsheets: { canonical_key: {title, intro, commands} }
      alias_map:   { alias_lowercased: canonical_key }

    Built-in profiles load first; user profiles override on
    matching canonical key (the entire entry is replaced — no
    deep-merge).  Aliases from BOTH layers are merged into the
    alias map; on alias-collision the LATER source wins (user
    overrides built-in, last-loaded user file overrides earlier
    user files).
    """
    if builtin_dir is None:
        builtin_dir = _builtin_dir()
    if user_dir is None:
        user_dir = _user_dir()
    cheatsheets: Dict[str, dict] = {}
    alias_map: Dict[str, str] = {}

    def _ingest(source_label: str, dir_path: str):
        loaded = _load_dir(dir_path)
        if verbose and loaded:
            sys.stderr.write(
                f"[HAWK] db_profile_loader: {len(loaded)} profiles "
                f"from {source_label} ({dir_path})\n")
        for fname, doc in loaded:
            key, entry, aliases = _to_runtime(doc)
            cheatsheets[key] = entry
            # The canonical key itself counts as an alias so
            # _cheatsheet_key_for(canonical) works.
            alias_map[key] = key
            for a in aliases:
                alias_map[a] = key

    _ingest("built-in", builtin_dir)
    _ingest("user", user_dir)

    return cheatsheets, alias_map
