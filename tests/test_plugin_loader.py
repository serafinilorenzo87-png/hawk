import os
import sys
import types
import unittest
from pathlib import Path


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _make_fake_plugin(
    *,
    api_version: str = "1.0.0",
    raise_on_import: bool = False,
    raise_in_factory: bool = False,
    raise_in_verify: bool = False,
    raise_in_mount: bool = False,
    license_result: str = "valid",   # "valid" | "missing" | "expired" | "bad_sig"
):
    """Build a synthetic hawk_argus module and register it in sys.modules."""
    name = "hawk_argus_test_fixture"
    if name in sys.modules:
        del sys.modules[name]

    if raise_on_import:
        raise_module = types.ModuleType(name)
        def _explode():
            raise RuntimeError("boom on import")
        # Trigger by accessing HAWK_API_VERSION? Simpler: simulate by deleting
        # and re-importing via a builtin stub. We instead just register a
        # module whose create_plugin/HAWK_API_VERSION attributes raise.
        sys.modules[name] = raise_module
        raise_module.HAWK_API_VERSION = api_version
        def _factory():
            raise RuntimeError("boom on import (delayed via factory)")
        raise_module.create_plugin = _factory
        return name

    mod = types.ModuleType(name)
    mod.HAWK_API_VERSION = api_version
    mod.NAME = "TestPlugin"
    mod.VERSION = "0.1.0"

    class _Plugin:
        def __init__(self):
            self.last_license_error = None
            self.mounted = False

        def verify_license(self, license_path: Path):
            if raise_in_verify:
                raise RuntimeError("contract violation in verify")
            if license_result == "valid":
                from dataclasses import dataclass
                from datetime import datetime, timedelta, timezone
                now = datetime.now(timezone.utc)
                @dataclass(frozen=True)
                class L:
                    user_id: str = "tester"
                    email: str = "test@example.com"
                    tier: str = "trial"
                    expiry: object = now + timedelta(days=1)
                    issued_at: object = now
                    machine_fingerprint: object = None
                    raw_signature: bytes = b""
                return L()
            if license_result == "missing":
                self.last_license_error = "license file not found"
                return None
            if license_result == "expired":
                self.last_license_error = "license expired on 2020-01-01"
                return None
            if license_result == "bad_sig":
                self.last_license_error = "bad signature"
                return None
            return None

        def mount_in(self, parent, hawk_api):
            if raise_in_mount:
                raise RuntimeError("boom on mount")
            self.mounted = True

        def unmount(self):
            self.mounted = False

    def _factory():
        if raise_in_factory:
            raise RuntimeError("boom on factory")
        return _Plugin()

    mod.create_plugin = _factory
    sys.modules[name] = mod
    return name


class _StubAPI:
    pass


class PluginLoaderTests(unittest.TestCase):
    def setUp(self):
        from utils.plugin_loader import ArgusLoader, PluginState
        self.ArgusLoader = ArgusLoader
        self.PluginState = PluginState

    def _load(self, **kw):
        name = _make_fake_plugin(**kw)
        # nonexistent license path is fine — fake plugin ignores it
        return self.ArgusLoader(package_name=name, license_path=Path("/nonexistent"))

    def test_not_installed(self):
        loader = self.ArgusLoader(
            package_name="definitely_not_installed_xyz",
            license_path=Path("/nonexistent"),
        )
        self.assertEqual(loader.state, self.PluginState.NOT_INSTALLED)
        self.assertIsNone(loader.error)
        self.assertIsNone(loader.plugin)

    def test_active_with_valid_license(self):
        loader = self._load(license_result="valid")
        self.assertEqual(loader.state, self.PluginState.ACTIVE)
        self.assertIsNotNone(loader.license)
        self.assertIsNone(loader.error)

    def test_no_license_state(self):
        loader = self._load(license_result="missing")
        self.assertEqual(loader.state, self.PluginState.NO_LICENSE)
        self.assertIn("not found", loader.error or "")
        self.assertIsNone(loader.license)

    def test_expired_state(self):
        loader = self._load(license_result="expired")
        self.assertEqual(loader.state, self.PluginState.EXPIRED)
        self.assertIn("expired", (loader.error or "").lower())

    def test_bad_signature_is_no_license_not_expired(self):
        loader = self._load(license_result="bad_sig")
        self.assertEqual(loader.state, self.PluginState.NO_LICENSE)

    def test_incompatible_major_version(self):
        loader = self._load(api_version="2.0.0", license_result="valid")
        self.assertEqual(loader.state, self.PluginState.INCOMPATIBLE)
        self.assertIn("incompatible", loader.error or "")

    def test_factory_raises(self):
        loader = self._load(raise_in_factory=True, license_result="valid")
        self.assertEqual(loader.state, self.PluginState.IMPORT_ERROR)

    def test_verify_license_raises_is_contract_violation(self):
        loader = self._load(raise_in_verify=True, license_result="valid")
        self.assertEqual(loader.state, self.PluginState.IMPORT_ERROR)

    def test_mount_when_active(self):
        loader = self._load(license_result="valid")
        self.assertTrue(loader.mount(object(), _StubAPI()))
        self.assertTrue(loader.plugin.mounted)

    def test_mount_when_not_active_returns_false(self):
        loader = self._load(license_result="missing")
        self.assertFalse(loader.mount(object(), _StubAPI()))

    def test_mount_in_raises_transitions_to_import_error(self):
        loader = self._load(license_result="valid", raise_in_mount=True)
        self.assertFalse(loader.mount(object(), _StubAPI()))
        self.assertEqual(loader.state, self.PluginState.IMPORT_ERROR)

    def test_unmount_is_idempotent(self):
        loader = self._load(license_result="valid")
        loader.mount(object(), _StubAPI())
        loader.unmount()
        loader.unmount()  # second call must be silent

    def test_unmount_without_mount_is_noop(self):
        loader = self._load(license_result="valid")
        loader.unmount()  # never mounted — must not raise


if __name__ == "__main__":
    unittest.main()
