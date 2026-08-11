import json
import os
import shutil
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class SelfContainedPolicyTests(unittest.TestCase):
    def test_runtime_dirs_are_inside_hawkc(self):
        from utils import config

        for path in config.RUNTIME_DIRS:
            self.assertTrue(config.is_within_base(path), path)

    def test_session_save_is_atomic_and_backed_up(self):
        from utils.config import is_within_base
        from utils.session import Session

        session = Session("127.0.0.1")
        path = session.save(new_file=True)
        self.assertTrue(is_within_base(path))
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["target_ip"], "127.0.0.1")

        session.notes = "second save"
        session.save(new_file=False)
        self.assertTrue(os.path.exists(path + ".bak"))

        for p in (path, path + ".bak"):
            try:
                os.remove(p)
            except OSError:
                pass

    def test_api_configs_are_generated_inside_hawkc(self):
        from utils import apikeys
        from utils.config import TMP_DIR, is_within_base

        old_keys_path = apikeys.KEYS_PATH
        old_configs_dir = apikeys.CONFIGS_DIR
        test_keys_path = os.path.join(TMP_DIR, "test_apikeys.json")
        test_configs_dir = os.path.join(TMP_DIR, "test_configs")
        apikeys.KEYS_PATH = test_keys_path
        apikeys.CONFIGS_DIR = test_configs_dir
        try:
            self.assertTrue(apikeys.save_keys({"shodan": "dummy"}))
            paths = apikeys.write_all_configs()
            self.assertTrue(paths)
            for path in paths.values():
                self.assertTrue(path)
                self.assertTrue(is_within_base(path), path)
                self.assertTrue(os.path.exists(path), path)
        finally:
            apikeys.KEYS_PATH = old_keys_path
            apikeys.CONFIGS_DIR = old_configs_dir
            for path in [test_keys_path, *(paths.values() if "paths" in locals() else [])]:
                try:
                    if path and os.path.isfile(path):
                        os.remove(path)
                except OSError:
                    pass
            shutil.rmtree(test_configs_dir, ignore_errors=True)

    def test_lhost_detection_prefers_vpn_over_vm_nic_and_bridges(self):
        from utils import runner

        old_run = runner.subprocess.run
        sample = "\n".join([
            "2: ens160    inet 192.168.56.101/24 brd 192.168.56.255 scope global dynamic ens160",
            "3: docker0   inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0",
            "4: tun0      inet 10.10.14.23/23 scope global tun0",
        ])

        class Result:
            stdout = sample

        def fake_run(*_args, **_kwargs):
            return Result()

        runner.subprocess.run = fake_run
        try:
            self.assertEqual(runner.lhost_detect(), "10.10.14.23")
            self.assertEqual(runner.lhost_iface(), "tun0")
        finally:
            runner.subprocess.run = old_run


class RouteToTargetTests(unittest.TestCase):
    """Multi-homed correctness (OBS-2 / #13): the local IP + gateway that
    REACH the target come from `ip route get <target>`, not the default
    route or the ranked global lhost."""

    def _with_route_output(self, sample):
        from utils import runner

        class Result:
            stdout = sample

        old_run = runner.subprocess.run
        runner.subprocess.run = lambda *a, **k: Result()
        self.addCleanup(lambda: setattr(runner.subprocess, "run", old_run))
        return runner

    def test_via_gateway_route_extracts_iface_src_and_gateway(self):
        runner = self._with_route_output(
            "192.168.176.173 via 192.168.176.1 dev eth1 "
            "src 192.168.176.172 uid 0 \n    cache")
        info = runner.route_to_target("192.168.176.173")
        self.assertEqual(info.get("iface"), "eth1")
        self.assertEqual(info.get("src"), "192.168.176.172")
        self.assertEqual(info.get("gateway"), "192.168.176.1")
        self.assertFalse(info.get("on_link"))

    def test_on_link_route_has_no_gateway(self):
        runner = self._with_route_output(
            "10.10.10.5 dev tun0 src 10.10.14.9 uid 0 \n    cache")
        info = runner.route_to_target("10.10.10.5")
        self.assertEqual(info.get("iface"), "tun0")
        self.assertEqual(info.get("src"), "10.10.14.9")
        self.assertIsNone(info.get("gateway"))
        self.assertTrue(info.get("on_link"))

    def test_invalid_target_returns_empty(self):
        from utils import runner
        self.assertEqual(runner.route_to_target("not-an-ip"), {})
        self.assertEqual(runner.route_to_target(""), {})

    def test_missing_ip_command_returns_empty(self):
        from utils import runner
        old_run = runner.subprocess.run

        def boom(*_a, **_k):
            raise FileNotFoundError("ip")

        runner.subprocess.run = boom
        try:
            self.assertEqual(runner.route_to_target("10.0.0.1"), {})
        finally:
            runner.subprocess.run = old_run

    def test_lhost_for_target_prefers_route_src(self):
        runner = self._with_route_output(
            "192.168.176.173 via 192.168.176.1 dev eth1 "
            "src 192.168.176.172 uid 0 \n    cache")
        self.assertEqual(runner.lhost_for_target("192.168.176.173"),
                         "192.168.176.172")

    def test_lhost_for_target_falls_back_when_route_unresolved(self):
        from utils import runner
        old_run = runner.subprocess.run
        old_detect = runner.lhost_detect
        runner.subprocess.run = lambda *a, **k: type("R", (), {"stdout": ""})()
        runner.lhost_detect = lambda: "10.10.14.23"
        try:
            self.assertEqual(runner.lhost_for_target("10.0.0.1"),
                             "10.10.14.23")
        finally:
            runner.subprocess.run = old_run
            runner.lhost_detect = old_detect


if __name__ == "__main__":
    unittest.main()
