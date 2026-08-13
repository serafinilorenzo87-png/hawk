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

    def test_unworked_unseen_host_is_dropped(self):
        """No inheritance: a new sweep must not carry the previous run's
        hosts.  An unworked host not re-found this run is dropped, not
        aged, so a routed false positive cannot ride forward as alive."""
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
        self.assertIn("10.0.0.1", by_ip)
        self.assertNotIn("10.0.0.9", by_ip)
        self.assertEqual(merged["finished"], "2026-08-03T00:05:00Z")

    def test_worked_host_kept_when_unseen(self):
        """Never orphan a worked host: one with a session_ref survives a
        re-sweep that did not re-find it (unlike an unworked stale host)."""
        from modules.discovery import merge_inventory
        existing = {
            "range": "10.0.0.0/24",
            "hosts": [
                {"ip": "10.0.0.5", "alive": True, "responded_via": ["arp"],
                 "port_hints": [], "os_hint": "unknown",
                 "session_ref": {"session_id": "s1", "file": "/a.json"}},
            ],
        }
        new_hosts = [
            {"ip": "10.0.0.6", "alive": True, "responded_via": ["arp"],
             "port_hints": [], "os_hint": "unknown", "session_ref": None},
        ]
        merged = merge_inventory(existing, new_hosts,
                                 finished="2026-08-03T00:05:00Z")
        by_ip = {h["ip"]: h for h in merged["hosts"]}
        self.assertIn("10.0.0.5", by_ip)
        self.assertIn("10.0.0.6", by_ip)
        self.assertIsNotNone(by_ip["10.0.0.5"]["session_ref"])

    def test_aborted_sweep_does_not_inherit_unworked_hosts(self):
        """An aborted sweep starts clean too: the previous run's unworked
        hosts are not carried forward (the confusing "39 alive" bug), and
        no finished time is stamped on a partial run."""
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
        self.assertNotIn("10.0.0.9", by_ip)
        self.assertIn(445, by_ip["10.0.0.1"]["port_hints"])
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


class ScopeTaggingTests(unittest.TestCase):
    """local vs routed banding: a host inside a local interface subnet is
    ARP-confirmable; one outside every local subnet was reached across a
    router and is unverified (can be an nmap false positive)."""

    def test_local_vs_routed(self):
        from modules.discovery import annotate_scope
        hosts = [{"ip": "192.168.176.10"}, {"ip": "192.168.178.5"}]
        annotate_scope(hosts, subnets=["192.168.176.0/24"])
        by_ip = {h["ip"]: h for h in hosts}
        self.assertEqual(by_ip["192.168.176.10"]["scope"], "local")
        self.assertEqual(by_ip["192.168.178.5"]["scope"], "routed")

    def test_multiple_local_subnets(self):
        from modules.discovery import annotate_scope
        hosts = [{"ip": "192.168.177.5"}]
        annotate_scope(hosts,
                       subnets=["192.168.176.0/24", "192.168.177.0/24"])
        self.assertEqual(hosts[0]["scope"], "local")

    def test_invalid_ip_is_unknown(self):
        from modules.discovery import annotate_scope
        hosts = [{"ip": "not-an-ip"}]
        annotate_scope(hosts, subnets=["192.168.176.0/24"])
        self.assertEqual(hosts[0]["scope"], "unknown")

    def test_network_objects_accepted(self):
        import ipaddress
        from modules.discovery import annotate_scope
        nets = [ipaddress.ip_network("10.0.0.0/24")]
        hosts = [{"ip": "10.0.0.7"}, {"ip": "10.0.1.7"}]
        annotate_scope(hosts, subnets=nets)
        by_ip = {h["ip"]: h for h in hosts}
        self.assertEqual(by_ip["10.0.0.7"]["scope"], "local")
        self.assertEqual(by_ip["10.0.1.7"]["scope"], "routed")


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

    def test_routed_collapsed_by_default(self):
        from utils.sweep_graph import build_graph_data
        inv = {
            "range": "192.168.176.0/22",
            "hosts": [
                {"ip": "192.168.176.10", "alive": True,
                 "responded_via": ["arp"], "port_hints": [],
                 "os_hint": "unknown", "session_ref": None,
                 "scope": "local"},
                {"ip": "192.168.178.5", "alive": True,
                 "responded_via": ["tcp:445"], "port_hints": [],
                 "os_hint": "unknown", "session_ref": None,
                 "scope": "routed"},
            ],
        }
        gd = build_graph_data(inv)
        host_labels = {n["label"] for n in gd["nodes"]
                       if n["type"] == "host"}
        # local drawn individually, routed collapsed away
        self.assertIn("192.168.176.10", host_labels)
        self.assertNotIn("192.168.178.5", host_labels)
        summary = [n for n in gd["nodes"] if n["type"] == "routed_summary"]
        self.assertEqual(len(summary), 1)
        self.assertIn("1", summary[0]["label"])
        # counts always report both bands regardless of collapse
        self.assertEqual(gd["stats"]["local"], 1)
        self.assertEqual(gd["stats"]["routed"], 1)

    def test_show_routed_expands_individual_nodes(self):
        from utils.sweep_graph import build_graph_data
        inv = {
            "range": "192.168.176.0/22",
            "hosts": [
                {"ip": "192.168.176.10", "alive": True,
                 "responded_via": ["arp"], "port_hints": [],
                 "os_hint": "unknown", "session_ref": None,
                 "scope": "local"},
                {"ip": "192.168.178.5", "alive": True,
                 "responded_via": ["tcp:445"], "port_hints": [],
                 "os_hint": "unknown", "session_ref": None,
                 "scope": "routed"},
            ],
        }
        gd = build_graph_data(inv, show_routed=True)
        by_label = {n["label"]: n for n in gd["nodes"]
                    if n["type"] == "host"}
        self.assertEqual(by_label["192.168.176.10"]["scope"], "local")
        self.assertEqual(by_label["192.168.178.5"]["scope"], "routed")
        self.assertFalse([n for n in gd["nodes"]
                          if n["type"] == "routed_summary"])


class RoutedFalsePositiveTests(unittest.TestCase):
    """Leva C — the routed-range phantom hosts come from nmap's TCP ACK
    ping (-PA80) drawing RSTs from the stateful gateway that fronts a
    routed range.  The fix removes that probe so the phantoms are never
    generated, while the SYN/ICMP probes that find genuinely-live hosts
    stay and on-link ARP discovery is untouched.  Each test fails on the
    pre-fix command (which carried -PA80)."""

    RANGE = "10.10.0.0/22"        # a /22 that spills past a /24 local subnet
    GNMAP = "/tmp/hawk_routed_test.gnmap"

    def test_ack_ping_removed_from_discovery(self):
        from modules.discovery import build_phase1_cmd
        cmd = build_phase1_cmd(self.RANGE, "nmap-sn", self.GNMAP)
        # -PA (ACK ping) is the phantom source and must be gone.
        self.assertNotIn("-PA", cmd)

    def test_liveness_probes_retained(self):
        # Removing the ACK ping must not gut discovery: the SYN and ICMP
        # probes that detect real hosts stay, so true hosts aren't lost.
        from modules.discovery import build_phase1_cmd
        cmd = build_phase1_cmd(self.RANGE, "nmap-sn", self.GNMAP)
        self.assertIn(" -sn ", cmd)
        self.assertIn("-PE", cmd)
        self.assertIn("-PP", cmd)
        self.assertIn("-PS445,3389,443,80,22", cmd)

    @staticmethod
    def _simulate_routed_gnmap(cmd, local_ip, phantom_routed_ips, path):
        """Model nmap -sn greppable output for a range fronted by a
        stateful gateway.  The gateway RSTs *ACK* probes for every routed
        address (dead or not), so nmap reports them Up ONLY when the
        command sends an ACK ping (-PA...).  The real on-link host answers
        regardless (ARP).  This encodes the exact mechanism the fix
        targets, so the parsed result tracks the command: with -PA80 the
        phantoms appear, without it they don't."""
        lines = [f"Host: {local_ip} ()\tStatus: Up"]
        if "-PA" in cmd:
            lines += [f"Host: {ip} ()\tStatus: Up"
                      for ip in phantom_routed_ips]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def test_routed_range_reports_no_phantoms(self):
        from modules.discovery import build_phase1_cmd, parse_nmap_gnmap
        fd, path = tempfile.mkstemp(suffix=".gnmap")
        os.close(fd)
        try:
            cmd = build_phase1_cmd(self.RANGE, "nmap-sn", path)
            self._simulate_routed_gnmap(
                cmd, "10.10.0.5",
                ["10.10.1.7", "10.10.2.9", "10.10.3.3"], path)
            hosts = parse_nmap_gnmap(path)
        finally:
            os.unlink(path)
        ips = {h["ip"] for h in hosts}
        # The real on-link host is still detected...
        self.assertIn("10.10.0.5", ips)
        # ...and no routed phantom rides along.  Pre-fix, -PA80 in the
        # command makes the simulator emit the phantoms and this fails.
        self.assertEqual(ips, {"10.10.0.5"})

    def test_local_arp_host_still_detected(self):
        # On-link discovery is ARP-based and wholly independent of the
        # probe set the fix touches.
        from modules.discovery import parse_arp_scan
        hosts = parse_arp_scan(
            ["192.168.1.10\t00:11:22:33:44:55\tVendor, Inc."])
        self.assertEqual(len(hosts), 1)
        self.assertTrue(hosts[0]["alive"])
        self.assertEqual(hosts[0]["responded_via"], ["arp"])


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
