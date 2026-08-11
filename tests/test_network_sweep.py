"""Tests for the network sweep feature: discovery parsing, sweep graph
builder, and CIDR helpers."""

import os
import sys
import json
import unittest
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class CidrHelperTests(unittest.TestCase):

    def test_valid_cidr(self):
        from utils.target_validator import parse_cidr
        ok, net, count = parse_cidr("192.168.1.0", "24")
        self.assertTrue(ok)
        self.assertEqual(net, "192.168.1.0/24")
        self.assertEqual(count, 254)

    def test_valid_cidr_16(self):
        from utils.target_validator import parse_cidr
        ok, net, count = parse_cidr("10.0.0.0", "16")
        self.assertTrue(ok)
        self.assertEqual(net, "10.0.0.0/16")
        self.assertEqual(count, 65534)

    def test_invalid_prefix(self):
        from utils.target_validator import parse_cidr
        ok, reason, count = parse_cidr("192.168.1.0", "abc")
        self.assertFalse(ok)
        self.assertIn("number", reason)


class LargeRangeGuardrailTests(unittest.TestCase):
    """#27 — the confirm dialog / forced masscan must cover an EXACT /16.

    A /16 has 65534 usable hosts; the old `> 65534` let it start with no
    warning.  needs_large_range_confirm uses an inclusive comparison.
    """

    def test_exact_slash_16_requires_confirm(self):
        from utils.target_validator import parse_cidr
        from modules.discovery import needs_large_range_confirm
        ok, _net, count = parse_cidr("10.0.0.0", "16")
        self.assertTrue(ok)
        self.assertEqual(count, 65534)
        self.assertTrue(needs_large_range_confirm(count),
                        "an exact /16 must trigger the large-range guardrail")

    def test_slash_17_does_not_require_confirm(self):
        from utils.target_validator import parse_cidr
        from modules.discovery import needs_large_range_confirm
        _ok, _net, count = parse_cidr("10.0.0.0", "17")   # 32766 hosts
        self.assertFalse(needs_large_range_confirm(count))

    def test_slash_15_requires_confirm(self):
        from utils.target_validator import parse_cidr
        from modules.discovery import needs_large_range_confirm
        _ok, _net, count = parse_cidr("10.0.0.0", "15")   # 131070 hosts
        self.assertTrue(needs_large_range_confirm(count))

    def test_out_of_range_prefix(self):
        from utils.target_validator import parse_cidr
        ok, _, _ = parse_cidr("192.168.1.0", "33")
        self.assertFalse(ok)

    def test_empty_input(self):
        from utils.target_validator import parse_cidr
        ok, _, count = parse_cidr("", "24")
        self.assertFalse(ok)
        self.assertEqual(count, 0)

    def test_non_strict_network(self):
        from utils.target_validator import parse_cidr
        ok, net, count = parse_cidr("192.168.1.100", "24")
        self.assertTrue(ok)
        self.assertEqual(net, "192.168.1.0/24")

    def test_is_local_subnet_rfc1918(self):
        from utils.target_validator import is_local_subnet
        self.assertTrue(is_local_subnet("192.168.1.0/24"))
        self.assertTrue(is_local_subnet("10.0.0.0/8"))
        self.assertTrue(is_local_subnet("172.16.0.0/12"))

    def test_is_local_subnet_public(self):
        from utils.target_validator import is_local_subnet
        self.assertFalse(is_local_subnet("8.8.8.0/24"))


class NmapGnmapParserTests(unittest.TestCase):

    def _write_gnmap(self, content):
        fd, path = tempfile.mkstemp(suffix=".gnmap")
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        return path

    def test_parse_status_up(self):
        from modules.discovery import parse_nmap_gnmap
        path = self._write_gnmap(
            "# Nmap 7.94 scan\n"
            "Host: 192.168.1.1 ()\tStatus: Up\n"
            "Host: 192.168.1.2 ()\tStatus: Up\n"
            "# Nmap done\n"
        )
        hosts = parse_nmap_gnmap(path)
        os.unlink(path)
        self.assertEqual(len(hosts), 2)
        ips = {h["ip"] for h in hosts}
        self.assertEqual(ips, {"192.168.1.1", "192.168.1.2"})
        for h in hosts:
            self.assertTrue(h["alive"])

    def test_parse_with_ports(self):
        from modules.discovery import parse_nmap_gnmap
        path = self._write_gnmap(
            "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 445/open/tcp//microsoft-ds///\n"
        )
        hosts = parse_nmap_gnmap(path)
        os.unlink(path)
        self.assertEqual(len(hosts), 1)
        h = hosts[0]
        self.assertEqual(h["ip"], "10.0.0.5")
        self.assertIn(22, h["port_hints"])
        self.assertIn(445, h["port_hints"])
        # 445 wins over 22 — a Windows box with OpenSSH answers both.
        self.assertEqual(h["os_hint"], "windows")

    def test_missing_file_returns_empty(self):
        from modules.discovery import parse_nmap_gnmap
        self.assertEqual(parse_nmap_gnmap("/nonexistent/path.gnmap"), [])


class MasscanListParserTests(unittest.TestCase):

    def test_parse_list(self):
        from modules.discovery import parse_masscan_list
        fd, path = tempfile.mkstemp(suffix=".list")
        with os.fdopen(fd, "w") as fh:
            fh.write(
                "# masscan\n"
                "open tcp 445 192.168.1.10 1627123456\n"
                "open tcp 3389 192.168.1.10 1627123457\n"
                "open tcp 22 192.168.1.20 1627123458\n"
            )
        hosts = parse_masscan_list(path)
        os.unlink(path)
        self.assertEqual(len(hosts), 2)
        by_ip = {h["ip"]: h for h in hosts}
        self.assertIn(445, by_ip["192.168.1.10"]["port_hints"])
        self.assertIn(3389, by_ip["192.168.1.10"]["port_hints"])
        self.assertEqual(by_ip["192.168.1.10"]["os_hint"], "windows")
        self.assertEqual(by_ip["192.168.1.20"]["os_hint"], "linux")


class ArpScanParserTests(unittest.TestCase):

    def test_parse_lines(self):
        from modules.discovery import parse_arp_scan
        lines = [
            "Interface: eth0, type: EN10MB",
            "192.168.176.1\t00:50:56:c0:00:08\tVMware, Inc.",
            "192.168.176.128\t00:0c:29:ab:cd:ef\tVMware, Inc.",
            "",
            "2 packets received.",
        ]
        hosts = parse_arp_scan(lines)
        self.assertEqual(len(hosts), 2)
        self.assertTrue(all(h["alive"] for h in hosts))
        self.assertEqual(hosts[0]["responded_via"], ["arp"])


class OsHintTests(unittest.TestCase):

    def test_windows_ports(self):
        from modules.discovery import infer_os_hint
        self.assertEqual(infer_os_hint([], [445]), "windows")
        self.assertEqual(infer_os_hint([], [3389]), "windows")
        self.assertEqual(infer_os_hint([], [135]), "windows")

    def test_linux_port(self):
        from modules.discovery import infer_os_hint
        self.assertEqual(infer_os_hint([], [22]), "linux")

    def test_smb_rdp_take_precedence_over_ssh(self):
        """445/3389 beat 22: a Windows host running OpenSSH answers both,
        and calling it Linux is the more damaging mistake."""
        from modules.discovery import infer_os_hint
        self.assertEqual(infer_os_hint([], [22, 445]), "windows")
        self.assertEqual(infer_os_hint([], [22, 3389]), "windows")

    def test_probe_tags_are_mined_for_ports(self):
        """Phase 1 has no port_hints — responded_via is the only signal."""
        from modules.discovery import infer_os_hint
        self.assertEqual(infer_os_hint(["tcp:445"], []), "windows")
        self.assertEqual(infer_os_hint(["syn:22"], []), "linux")
        self.assertEqual(infer_os_hint(["arp"], []), "unknown")

    def test_unknown_ports(self):
        from modules.discovery import infer_os_hint
        self.assertEqual(infer_os_hint([], [80, 443]), "unknown")

    def test_no_ports(self):
        from modules.discovery import infer_os_hint
        self.assertEqual(infer_os_hint([], []), "unknown")


class InventoryTests(unittest.TestCase):

    def test_build_and_save(self):
        from modules.discovery import build_inventory, save_inventory, load_inventory
        hosts = [
            {"ip": "10.0.0.1", "alive": True, "responded_via": ["arp"],
             "port_hints": [], "os_hint": "unknown", "session_ref": None},
        ]
        inv = build_inventory("10.0.0.0/24", "nmap-sn", hosts,
                              "2026-07-29T00:00:00Z", "2026-07-29T00:01:00Z")
        self.assertEqual(inv["range"], "10.0.0.0/24")
        self.assertEqual(len(inv["hosts"]), 1)

        path = save_inventory(inv)
        self.assertTrue(os.path.isfile(path))

        loaded = load_inventory(path)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["range"], "10.0.0.0/24")
        os.unlink(path)

    def test_merge_preserves_session_ref(self):
        from modules.discovery import merge_inventory
        existing = {
            "range": "10.0.0.0/24",
            "hosts": [
                {"ip": "10.0.0.1", "alive": True, "responded_via": ["arp"],
                 "port_hints": [], "os_hint": "unknown",
                 "session_ref": {"session_id": "abc", "file": "/x.json"}},
            ],
        }
        new_hosts = [
            {"ip": "10.0.0.1", "alive": True, "responded_via": ["tcp:445"],
             "port_hints": [445], "os_hint": "windows", "session_ref": None},
            {"ip": "10.0.0.2", "alive": True, "responded_via": ["arp"],
             "port_hints": [], "os_hint": "unknown", "session_ref": None},
        ]
        merged = merge_inventory(existing, new_hosts)
        by_ip = {h["ip"]: h for h in merged["hosts"]}
        self.assertIn("10.0.0.1", by_ip)
        self.assertIn("10.0.0.2", by_ip)
        self.assertIsNotNone(by_ip["10.0.0.1"]["session_ref"])
        self.assertEqual(by_ip["10.0.0.1"]["session_ref"]["session_id"], "abc")
        self.assertIn(445, by_ip["10.0.0.1"]["port_hints"])

    def test_aborted_inventory_has_no_finished_time(self):
        from modules.discovery import build_inventory
        inv = build_inventory("10.0.0.0/24", "nmap-sn", [],
                              "2026-08-03T00:00:00Z", "2026-08-03T00:00:30Z",
                              aborted="2026-08-03T00:00:30Z")
        self.assertEqual(inv["finished"], "")
        self.assertEqual(inv["aborted"], "2026-08-03T00:00:30Z")

    def test_complete_sweep_ages_unseen_hosts(self):
        from modules.discovery import merge_inventory
        existing = {
            "range": "10.0.0.0/24",
            "hosts": [
                {"ip": "10.0.0.1", "alive": True, "responded_via": ["arp"],
                 "port_hints": [], "os_hint": "unknown", "session_ref": None},
                {"ip": "10.0.0.9", "alive": True, "responded_via": ["arp"],
                 "port_hints": [], "os_hint": "unknown", "session_ref": None},
            ],
        }
        new_hosts = [
            {"ip": "10.0.0.1", "alive": True, "responded_via": ["arp"],
             "port_hints": [], "os_hint": "unknown", "session_ref": None},
        ]
        merged = merge_inventory(existing, new_hosts,
                                 finished="2026-08-03T00:05:00Z")
        by_ip = {h["ip"]: h for h in merged["hosts"]}
        self.assertFalse(by_ip["10.0.0.9"]["alive"])
        self.assertEqual(merged["finished"], "2026-08-03T00:05:00Z")

    def test_aborted_merge_does_not_age_or_stamp_finished(self):
        """An unprobed host is not "down", and a partial run must not
        leave the file reading as a completed sweep."""
        from modules.discovery import merge_inventory
        existing = {
            "range": "10.0.0.0/24",
            "finished": "2026-08-02T00:00:00Z",
            "hosts": [
                {"ip": "10.0.0.1", "alive": True, "responded_via": ["arp"],
                 "port_hints": [], "os_hint": "unknown", "session_ref": None},
                {"ip": "10.0.0.9", "alive": True, "responded_via": ["arp"],
                 "port_hints": [], "os_hint": "unknown", "session_ref": None},
            ],
        }
        new_hosts = [
            {"ip": "10.0.0.1", "alive": True, "responded_via": ["tcp:445"],
             "port_hints": [445], "os_hint": "windows", "session_ref": None},
        ]
        merged = merge_inventory(existing, new_hosts,
                                 finished="2026-08-03T00:05:00Z",
                                 aborted="2026-08-03T00:05:00Z")
        by_ip = {h["ip"]: h for h in merged["hosts"]}
        self.assertTrue(by_ip["10.0.0.9"]["alive"])
        self.assertEqual(merged["finished"], "")
        self.assertEqual(merged["aborted"], "2026-08-03T00:05:00Z")

    def test_set_session_ref(self):
        from modules.discovery import set_session_ref
        inv = {"hosts": [
            {"ip": "10.0.0.5", "alive": True, "session_ref": None},
        ]}
        set_session_ref(inv, "10.0.0.5", "sess123", "/path.json")
        ref = inv["hosts"][0]["session_ref"]
        self.assertEqual(ref["session_id"], "sess123")
        self.assertEqual(ref["file"], "/path.json")


class SweepGraphTests(unittest.TestCase):

    def test_build_graph_basic(self):
        from utils.sweep_graph import build_graph_data
        inv = {
            "range": "192.168.1.0/24",
            "hosts": [
                {"ip": "192.168.1.1", "alive": True,
                 "responded_via": ["arp"], "port_hints": [],
                 "os_hint": "unknown", "session_ref": None},
                {"ip": "192.168.1.10", "alive": True,
                 "responded_via": ["tcp:445"],
                 "port_hints": [445, 3389],
                 "os_hint": "windows", "session_ref": None},
            ],
        }
        gd = build_graph_data(inv)
        self.assertIsNotNone(gd)
        self.assertIn("nodes", gd)
        self.assertIn("edges", gd)
        self.assertIn("stats", gd)

        node_types = {n["type"] for n in gd["nodes"]}
        self.assertIn("subnet", node_types)
        self.assertIn("host", node_types)
        self.assertIn("service", node_types)

        self.assertEqual(gd["stats"]["alive"], 2)
        self.assertEqual(gd["stats"]["os_windows"], 1)

        host_cats = {n["label"]: n["category"] for n in gd["nodes"]
                     if n["type"] == "host"}
        self.assertEqual(host_cats["192.168.1.10"], "critical")
        self.assertEqual(host_cats["192.168.1.1"], "normal")

    def test_empty_inventory_returns_none(self):
        from utils.sweep_graph import build_graph_data
        self.assertIsNone(build_graph_data(None))
        self.assertIsNone(build_graph_data({}))
        self.assertIsNone(build_graph_data({"hosts": []}))

    def test_session_flag(self):
        from utils.sweep_graph import build_graph_data
        inv = {
            "range": "10.0.0.0/24",
            "hosts": [
                {"ip": "10.0.0.1", "alive": True,
                 "responded_via": [], "port_hints": [],
                 "os_hint": "unknown",
                 "session_ref": {"session_id": "x", "file": "y"}},
            ],
        }
        gd = build_graph_data(inv)
        host = [n for n in gd["nodes"] if n["type"] == "host"][0]
        self.assertIn("has_session", host["flags"])
        self.assertEqual(gd["stats"]["with_session"], 1)


class ChooseMethodTests(unittest.TestCase):

    def test_small_range_uses_nmap(self):
        from modules.discovery import choose_method
        self.assertEqual(choose_method("192.168.1.0/24", 254), "nmap-sn")

    def test_routed_range_uses_nmap(self):
        from modules.discovery import choose_method
        self.assertEqual(choose_method("8.8.8.0/24", 254), "nmap-sn")

    def test_large_range_uses_masscan(self):
        from modules.discovery import choose_method
        self.assertEqual(choose_method("10.0.0.0/16", 65534), "masscan")

    def test_force_masscan(self):
        from modules.discovery import choose_method
        self.assertEqual(
            choose_method("192.168.1.0/24", 254, force_masscan=True),
            "masscan")


if __name__ == "__main__":
    unittest.main()
