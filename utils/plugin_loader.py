# HAWK — Hostile Assessment WorKit
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
HAWK — plugin loader.

Discovers, validates, and loads optional HAWK plugins. The only plugin in
scope today is `hawk_argus`. The loader implements the lifecycle described
in argus/docs/plugin-contract.md §3 and never raises into HAWK.

Public API:
- discover_argus() -> ArgusLoader
- ArgusLoader.state    -> PluginState
- ArgusLoader.plugin   -> HawkPlugin | None
- ArgusLoader.license  -> License | None
- ArgusLoader.error    -> str | None
- ArgusLoader.mount(parent, hawk_api) -> bool
- ArgusLoader.unmount() -> None
"""

from __future__ import annotations
import enum
import importlib
import os
import traceback
from pathlib import Path
from typing import Any, Optional

from utils.config import HAWK_API_VERSION

ARGUS_PACKAGE = "hawk_argus"
DEFAULT_LICENSE_PATH = Path.home() / ".hawk" / "argus_license.bin"

# HAWK_PLUGIN_PATH lets developers point HAWK at an uninstalled plugin tree
# (a sibling repo, an editable checkout). When set and importable, it takes
# precedence over the system-installed package.
ENV_PLUGIN_PATH = "HAWK_PLUGIN_PATH"


class PluginState(enum.Enum):
    NOT_INSTALLED = "not_installed"
    IMPORT_ERROR  = "import_error"
    INCOMPATIBLE  = "incompatible"
    NO_LICENSE    = "no_license"
    EXPIRED       = "expired"
    ACTIVE        = "active"


def _log(msg: str) -> None:
    print(f"[HAWK plugin_loader] {msg}")


def _major_compatible(plugin_api: Optional[str], host_api: str) -> bool:
    """True if plugin's declared major matches host's major."""
    if not plugin_api:
        return False
    try:
        return int(plugin_api.split(".")[0]) == int(host_api.split(".")[0])
    except (ValueError, IndexError):
        return False


class ArgusLoader:
    """One-shot loader for the ARGUS plugin. Construct, then read .state."""

    def __init__(
        self,
        package_name: str = ARGUS_PACKAGE,
        license_path: Path = DEFAULT_LICENSE_PATH,
    ) -> None:
        self._package_name = package_name
        self._license_path = license_path
        self._module: Any = None
        self.plugin: Any = None
        self.license: Any = None
        self.error: Optional[str] = None
        self.state: PluginState = PluginState.NOT_INSTALLED
        self._mounted: bool = False
        self._discover()

    # ── lifecycle ──────────────────────────────────────────────────────

    def _discover(self) -> None:
        """Import + version check + license verify. Never raises."""
        # Optional dev override: prepend HAWK_PLUGIN_PATH to sys.path so an
        # editable checkout takes precedence over a pip-installed wheel.
        dev_path = os.environ.get(ENV_PLUGIN_PATH)
        if dev_path and os.path.isdir(dev_path):
            import sys
            if dev_path not in sys.path:
                sys.path.insert(0, dev_path)
                _log(f"using dev plugin path: {dev_path}")

        try:
            self._module = importlib.import_module(self._package_name)
        except ImportError:
            self.state = PluginState.NOT_INSTALLED
            return
        except Exception as e:
            self.error = f"plugin import error: {e}"
            self.state = PluginState.IMPORT_ERROR
            _log(f"import raised: {e}")
            traceback.print_exc()
            return

        plugin_api = getattr(self._module, "HAWK_API_VERSION", None)
        if not _major_compatible(plugin_api, HAWK_API_VERSION):
            self.error = (
                f"incompatible version: plugin needs HAWK_API_VERSION "
                f"{plugin_api!r}, host is {HAWK_API_VERSION!r}"
            )
            self.state = PluginState.INCOMPATIBLE
            _log(self.error)
            return

        try:
            factory = getattr(self._module, "create_plugin")
            self.plugin = factory()
        except Exception as e:
            self.error = f"plugin factory error: {e}"
            self.state = PluginState.IMPORT_ERROR
            _log(f"create_plugin raised: {e}")
            traceback.print_exc()
            return

        try:
            lic = self.plugin.verify_license(self._license_path)
        except Exception as e:
            # Contract violation: verify_license must NOT raise.
            self.error = f"plugin internal error during license verify: {e}"
            self.state = PluginState.IMPORT_ERROR
            _log(f"verify_license raised (contract violation): {e}")
            traceback.print_exc()
            return

        if lic is None:
            reason = getattr(self.plugin, "last_license_error", None) or "license required"
            self.error = reason
            # Heuristic: substring "expir" → EXPIRED state for UI tone.
            # Anything else (missing, bad signature, malformed) → NO_LICENSE.
            self.state = PluginState.EXPIRED if "expir" in reason.lower() else PluginState.NO_LICENSE
            return

        self.license = lic
        self.state = PluginState.ACTIVE

    def mount(self, parent: Any, hawk_api: Any) -> bool:
        """Mount the plugin UI into `parent`. Returns True on success."""
        if self.state is not PluginState.ACTIVE or self.plugin is None:
            return False
        try:
            self.plugin.mount_in(parent, hawk_api)
            self._mounted = True
            return True
        except Exception as e:
            self.error = f"plugin failed to mount: {e}"
            self.state = PluginState.IMPORT_ERROR
            _log(f"mount_in raised: {e}")
            traceback.print_exc()
            return False

    def unmount(self) -> None:
        """Tear down. Idempotent. Never raises."""
        if not self._mounted or self.plugin is None:
            return
        try:
            self.plugin.unmount()
        except Exception as e:
            _log(f"unmount raised (contract violation): {e}")
        finally:
            self._mounted = False


def discover_argus() -> ArgusLoader:
    """Public entrypoint — always returns a loader, never raises."""
    return ArgusLoader()
