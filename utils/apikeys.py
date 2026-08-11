# HAWK — Hostile Assessment War-Kit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0
#
# Attribution "Created by Lorenzo Serafini" must be preserved in all
# redistributed and Derivative Works — see NOTICE for details.

"""
HAWK - Unified API key management.

Single source of truth for all third-party OSINT API keys used by
subfinder, amass, theHarvester, wpscan, nuclei, shodan, censys, ...

Keys are stored in  sessions/.apikeys.json  as a flat dict:
    { "shodan": "xxx", "censys_id": "yyy", "censys_secret": "zzz", ... }

Each tool's config file is generated on demand under hawkc/configs.
HAWK does not write persistent config into ~/.config or other home
directories.
"""

from __future__ import annotations
import json
import os
import pathlib
import shlex
from typing import Dict

from utils.config import CONFIGS_DIR, SESSIONS_DIR, require_within_base

KEYS_PATH = os.path.join(SESSIONS_DIR, ".apikeys.json")


def _config_file(*parts: str) -> pathlib.Path:
    path = require_within_base(os.path.join(CONFIGS_DIR, *parts),
                               "API config")
    return pathlib.Path(path)


# ─── Provider catalogue ──────────────────────────────────────────────────────

# Every entry: (key_id, display_name, tools_that_use_it, hint_url)
PROVIDERS = [
    # Key id,          Display,                    Tools,                     Signup URL
    ("shodan",         "Shodan API key",           ["subfinder", "amass", "theHarvester", "shodan"],
     "https://account.shodan.io/"),
    ("censys_id",      "Censys API ID",            ["subfinder", "amass", "censys"],
     "https://search.censys.io/account/api"),
    ("censys_secret",  "Censys API Secret",        ["subfinder", "amass", "censys"],
     "https://search.censys.io/account/api"),
    ("virustotal",     "VirusTotal API key",       ["subfinder", "amass", "theHarvester"],
     "https://www.virustotal.com/gui/my-apikey"),
    ("securitytrails", "SecurityTrails API key",   ["subfinder", "amass"],
     "https://securitytrails.com/corp/api"),
    ("binaryedge",     "BinaryEdge API key",       ["subfinder", "amass", "theHarvester"],
     "https://app.binaryedge.io/account/api"),
    ("github",         "GitHub token",             ["subfinder", "amass", "theHarvester"],
     "https://github.com/settings/tokens"),
    ("chaos",          "Chaos ProjectDiscovery",   ["subfinder", "amass"],
     "https://chaos.projectdiscovery.io/"),
    ("passivetotal_user",   "PassiveTotal user",   ["subfinder", "amass"],
     "https://community.riskiq.com/"),
    ("passivetotal_key",    "PassiveTotal key",    ["subfinder", "amass"],
     "https://community.riskiq.com/"),
    ("fullhunt",       "FullHunt API key",         ["subfinder", "amass"],
     "https://fullhunt.io/"),
    ("zoomeye",        "ZoomEye API key",          ["subfinder", "amass"],
     "https://www.zoomeye.org/profile/doc"),
    ("hunter",         "Hunter.io key",            ["theHarvester"],
     "https://hunter.io/api-keys"),
    ("wpscan",         "WPScan API token",         ["wpscan"],
     "https://wpscan.com/profile"),
    # NVD is the least sensitive key HAWK holds: free, read-only, and its
    # only effect is a higher rate limit (50 vs 5 requests / 30 s).  It is
    # persisted here alongside the OSINT keys — same 0600 sessions/
    # .apikeys.json — instead of being a session-only special case, so the
    # operator sets it once and never re-types it.  Consumed internally by
    # the CVE lookup (utils.cve_lookup), which reads it at boot and when
    # the operator changes it from the API Key Manager.
    ("nvd",            "NVD API key",              ["nvd"],
     "https://nvd.nist.gov/developers/request-an-api-key"),
]


# ─── Persistence ─────────────────────────────────────────────────────────────

def load_keys() -> Dict[str, str]:
    """Load the saved keys. Returns {} if file doesn't exist or is invalid."""
    if not os.path.exists(KEYS_PATH):
        return {}
    try:
        with open(KEYS_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {k: str(v) for k, v in data.items() if v}
    except Exception:
        pass
    return {}


def save_keys(keys: Dict[str, str]) -> bool:
    """Persist non-empty keys. Returns True on success."""
    tmp_path = ""
    try:
        os.makedirs(SESSIONS_DIR, exist_ok=True)
        clean = {k: v.strip() for k, v in keys.items() if v and v.strip()}
        tmp_path = KEYS_PATH + f".tmp-{os.getpid()}"
        # Create the temp file ALREADY at 0600 so the secrets are never,
        # not even for the instant between write and chmod, world-readable.
        # A plain open() honours the process umask (typically 0644), and
        # the old code only tightened permissions AFTER os.replace() — a
        # real window in which another local user could read the keys off
        # the temp/final file.  os.open with mode 0o600 sets the bits
        # before the first byte is written; the chmod below stays as a
        # belt-and-braces for the destination path.  (On Windows the mode
        # is mostly ignored, but there the multi-user threat model this
        # closes does not apply.)
        fd = os.open(tmp_path,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(clean, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, KEYS_PATH)
        try:
            os.chmod(KEYS_PATH, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False


def has_keys_for(tool: str) -> bool:
    """True if at least one key relevant to `tool` is set."""
    keys = load_keys()
    for kid, _, tools, _ in PROVIDERS:
        if tool in tools and keys.get(kid):
            return True
    return False


def keys_for_tool(tool: str) -> Dict[str, str]:
    """Return only the keys that apply to `tool`."""
    keys = load_keys()
    return {kid: keys[kid]
            for kid, _, tools, _ in PROVIDERS
            if tool in tools and keys.get(kid)}


# ─── Config writers per tool ─────────────────────────────────────────────────

def write_subfinder_config() -> str:
    """
    Generate hawkc/configs/subfinder/provider-config.yaml from current keys.
    Returns the path written, or '' on failure.
    """
    keys = load_keys()
    cfg_file = _config_file("subfinder", "provider-config.yaml")
    cfg_dir  = cfg_file.parent
    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        lines = []
        def _add(section, vals):
            vals = [v for v in vals if v]
            if not vals:
                return
            lines.append(f"{section}:")
            for v in vals:
                lines.append(f"  - {v}")

        _add("shodan",         [keys.get("shodan", "")])
        if keys.get("censys_id") and keys.get("censys_secret"):
            lines.append("censys:")
            lines.append(f"  - {keys['censys_id']}:{keys['censys_secret']}")
        _add("virustotal",     [keys.get("virustotal", "")])
        _add("securitytrails", [keys.get("securitytrails", "")])
        _add("binaryedge",     [keys.get("binaryedge", "")])
        _add("github",         [keys.get("github", "")])
        _add("chaos",          [keys.get("chaos", "")])
        if keys.get("passivetotal_user") and keys.get("passivetotal_key"):
            lines.append("passivetotal:")
            lines.append(f"  - {keys['passivetotal_user']}:{keys['passivetotal_key']}")
        _add("fullhunt",       [keys.get("fullhunt", "")])
        _add("zoomeye",        [keys.get("zoomeye", "")])

        cfg_file.write_text("\n".join(lines) + "\n")
        try: os.chmod(cfg_file, 0o600)
        except Exception: pass
        return str(cfg_file)
    except Exception:
        return ""


def write_amass_config() -> str:
    """
    Generate hawkc/configs/amass/config.ini with the current keys.
    """
    keys = load_keys()
    cfg_file = _config_file("amass", "config.ini")
    cfg_dir  = cfg_file.parent
    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        sections = []

        def _section(name, **kv):
            kv = {k: v for k, v in kv.items() if v}
            if not kv:
                return
            sections.append(f"[{name}]")
            sections.append(f"[{name}.Credentials]")
            for k, v in kv.items():
                sections.append(f"{k} = {v}")
            sections.append("")

        if keys.get("shodan"):
            _section("data_sources.Shodan.account",   apikey=keys["shodan"])
        if keys.get("censys_id") and keys.get("censys_secret"):
            _section("data_sources.Censys.account",
                     apikey=keys["censys_id"], secret=keys["censys_secret"])
        if keys.get("virustotal"):
            _section("data_sources.VirusTotal.account",   apikey=keys["virustotal"])
        if keys.get("securitytrails"):
            _section("data_sources.SecurityTrails.account", apikey=keys["securitytrails"])
        if keys.get("binaryedge"):
            _section("data_sources.BinaryEdge.account",   apikey=keys["binaryedge"])
        if keys.get("github"):
            _section("data_sources.GitHub.account",       apikey=keys["github"])
        if keys.get("chaos"):
            _section("data_sources.Chaos.account",        apikey=keys["chaos"])
        if keys.get("passivetotal_user") and keys.get("passivetotal_key"):
            _section("data_sources.PassiveTotal.account",
                     username=keys["passivetotal_user"], apikey=keys["passivetotal_key"])

        cfg_file.write_text("\n".join(sections) + "\n")
        try: os.chmod(cfg_file, 0o600)
        except Exception: pass
        return str(cfg_file)
    except Exception:
        return ""


def write_theharvester_config() -> str:
    """
    Generate hawkc/configs/theHarvester/api-keys.yaml.
    """
    keys = load_keys()
    cfg_file = _config_file("theHarvester", "api-keys.yaml")
    cfg_dir  = cfg_file.parent
    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        lines = ["apikeys:"]
        def _entry(section, key, value):
            if not value:
                return
            lines.append(f"  {section}:")
            lines.append(f"    {key}: {value}")

        _entry("shodan",         "key",    keys.get("shodan"))
        _entry("virustotal",     "key",    keys.get("virustotal"))
        _entry("hunter",         "key",    keys.get("hunter"))
        _entry("github",         "key",    keys.get("github"))
        _entry("binaryedge",     "key",    keys.get("binaryedge"))
        if keys.get("censys_id") and keys.get("censys_secret"):
            lines.append("  censys:")
            lines.append(f"    id: {keys['censys_id']}")
            lines.append(f"    secret: {keys['censys_secret']}")

        cfg_file.write_text("\n".join(lines) + "\n")
        try: os.chmod(cfg_file, 0o600)
        except Exception: pass
        return str(cfg_file)
    except Exception:
        return ""


def write_all_configs() -> Dict[str, str]:
    """Regenerate every per-tool config. Returns {tool: written_path}."""
    return {
        "subfinder":    write_subfinder_config(),
        "amass":        write_amass_config(),
        "theHarvester": write_theharvester_config(),
    }


def config_arg_for(tool: str) -> str:
    """Return a CLI config argument for tools that support explicit paths."""
    t = (tool or "").lower()
    if t == "subfinder":
        path = _config_file("subfinder", "provider-config.yaml")
        return f"-pc {shlex.quote(str(path))}" if path.exists() else ""
    if t == "amass":
        path = _config_file("amass", "config.ini")
        return f"-config {shlex.quote(str(path))}" if path.exists() else ""
    # theHarvester does not consistently expose a portable API-key config
    # path flag across Kali versions, so HAWK keeps the generated file in
    # hawkc/configs for inspection/export and avoids writing ~/.theHarvester.
    return ""
