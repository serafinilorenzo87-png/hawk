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
HAWK — Network sweep discovery engine.

Builds nmap / masscan / arp-scan commands for host discovery, parses
their machine-readable output, and manages the per-sweep inventory
JSON files under outputs/sweeps/.

This module is pure logic — no tkinter, no ToolRunner.  The UI layer
(target_bar) feeds commands to ToolRunner and calls the parsers here
when the process finishes.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from utils.config import OUTPUTS_DIR, TMP_DIR

SWEEPS_DIR = os.path.join(OUTPUTS_DIR, "sweeps")
os.makedirs(SWEEPS_DIR, exist_ok=True)

# Host count above which we prefer masscan over nmap for Phase 1.
MASSCAN_THRESHOLD = 1024


# ─── Interface resolution ────────────────────────────────────────────────────

def _find_interface_for(cidr: str) -> str:
    """Return the local interface whose subnet contains the target CIDR.

    Falls back to empty string (let the tool pick).
    """
    try:
        import subprocess
        target_net = ipaddress.ip_network(cidr, strict=False)
        r = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=3)
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            iface_idx = 1
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    iface = parts[iface_idx]
                    local_net = ipaddress.ip_network(parts[i + 1], strict=False)
                    if target_net.subnet_of(local_net) or local_net == target_net:
                        return iface
    except Exception:
        pass
    return ""


# ─── Command builders ────────────────────────────────────────────────────────

def choose_method(cidr: str, host_count: int,
                  force_masscan: bool = False) -> str:
    """Pick the best discovery method for the given range.

    Returns one of "arp-scan", "nmap-sn", "masscan".
    """
    if force_masscan or host_count > MASSCAN_THRESHOLD:
        return "masscan"
    return "nmap-sn"


def _is_likely_local(net: ipaddress.IPv4Network) -> bool:
    """Heuristic: the range sits inside RFC1918 / link-local space."""
    private_blocks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
    )
    return any(
        net.network_address in blk and net.broadcast_address in blk
        for blk in private_blocks
    )


def build_phase1_cmd(cidr: str, method: str,
                     gnmap_path: str) -> str:
    """Return the Phase 1 discovery command string.

    gnmap_path: where to write machine-readable output.
    The caller prepends sudo if needed (runner.has_raw_caps decides).
    """
    if method == "arp-scan":
        iface = _find_interface_for(cidr)
        iface_flag = f" -I {iface}" if iface else ""
        return f"sudo arp-scan{iface_flag} {cidr}"

    if method == "masscan":
        list_path = gnmap_path
        return (
            f"sudo masscan {cidr} "
            f"-p445,3389,443,80,22 "
            f"--rate 1000 "
            f"-oL {list_path}"
        )

    # nmap-sn: multi-probe, NO -Pn
    return (
        f"sudo nmap -sn "
        f"-PE -PP -PS445,3389,443,80,22 -PA80 "
        f"-T4 "
        f"-oG {gnmap_path} "
        f"{cidr}"
    )


def build_phase2_cmd(alive_ips: List[str],
                     gnmap_path: str) -> str:
    """Phase 2: light port peek on confirmed-alive hosts.

    -Pn is correct here — hosts are already confirmed up.
    """
    targets_file = os.path.join(TMP_DIR, "sweep_phase2_targets.txt")
    with open(targets_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(alive_ips))
    return (
        f"sudo nmap -Pn --top-ports 100 "
        f"-T4 "
        f"-oG {gnmap_path} "
        f"-iL {targets_file}"
    )


def gnmap_path_for(cidr: str, phase: int) -> str:
    """Return a temp file path for nmap greppable output."""
    safe = cidr.replace("/", "_").replace(".", "-")
    return os.path.join(TMP_DIR, f"sweep_{safe}_p{phase}.gnmap")


def masscan_list_path_for(cidr: str) -> str:
    safe = cidr.replace("/", "_").replace(".", "-")
    return os.path.join(TMP_DIR, f"sweep_{safe}_p1.list")


# ─── Output parsers ──────────────────────────────────────────────────────────

def parse_nmap_gnmap(path: str) -> List[Dict]:
    """Parse nmap greppable output into a list of host dicts.

    Returns list of:
      {"ip": str, "alive": True, "responded_via": [...],
       "port_hints": [...], "os_hint": str, "session_ref": None}
    """
    hosts: Dict[str, Dict] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                m = re.match(r"Host:\s+([\d.]+)\s+", line)
                if not m:
                    continue
                ip = m.group(1)

                if ip not in hosts:
                    hosts[ip] = _blank_host(ip)

                if "Status: Up" in line:
                    hosts[ip]["alive"] = True

                port_match = re.search(r"Ports:\s+(.+?)(?:\t|$)", line)
                if port_match:
                    hosts[ip]["alive"] = True
                    for entry in port_match.group(1).split(","):
                        entry = entry.strip()
                        parts = entry.split("/")
                        if len(parts) >= 2 and parts[1] == "open":
                            try:
                                port = int(parts[0])
                                hosts[ip]["port_hints"].append(port)
                                hosts[ip]["responded_via"].append(
                                    f"tcp:{port}")
                            except ValueError:
                                pass
    except FileNotFoundError:
        return []

    for h in hosts.values():
        h["port_hints"] = sorted(set(h["port_hints"]))
        h["responded_via"] = sorted(set(h["responded_via"]))
        h["os_hint"] = infer_os_hint(h["responded_via"], h["port_hints"])

    return [h for h in hosts.values() if h["alive"]]


def parse_masscan_list(path: str) -> List[Dict]:
    """Parse masscan -oL (list) output.

    Format: open tcp <port> <ip> <timestamp>
    """
    hosts: Dict[str, Dict] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) < 4 or parts[0] != "open":
                    continue
                proto, port_s, ip = parts[1], parts[2], parts[3]
                try:
                    port = int(port_s)
                except ValueError:
                    continue

                if ip not in hosts:
                    hosts[ip] = _blank_host(ip)
                hosts[ip]["alive"] = True
                hosts[ip]["port_hints"].append(port)
                hosts[ip]["responded_via"].append(f"{proto}:{port}")
    except FileNotFoundError:
        return []

    for h in hosts.values():
        h["port_hints"] = sorted(set(h["port_hints"]))
        h["responded_via"] = sorted(set(h["responded_via"]))
        h["os_hint"] = infer_os_hint(h["responded_via"], h["port_hints"])

    return [h for h in hosts.values() if h["alive"]]


def parse_arp_scan(lines: List[str]) -> List[Dict]:
    """Parse arp-scan stdout lines (captured by the output callback).

    arp-scan output looks like:
      192.168.176.1\t00:50:56:c0:00:08\tVMware, Inc.
    """
    hosts = []
    for line in lines:
        m = re.match(r"([\d.]+)\s+([0-9a-fA-F:]{17})", line)
        if m:
            h = _blank_host(m.group(1))
            h["alive"] = True
            h["responded_via"] = ["arp"]
            h["os_hint"] = "unknown"
            hosts.append(h)
    return hosts


# ─── OS hint ──────────────────────────────────────────────────────────────────

_WINDOWS_ONLY_PORTS = {3389, 135, 139}
_LINUX_PORTS = {22}


def infer_os_hint(responded_via: List[str], port_hints: List[int]) -> str:
    """Cheap OS hint from which ports answered — never asserted as fact."""
    ports = set(port_hints)
    has_ssh = bool(ports & _LINUX_PORTS)
    has_win_only = bool(ports & _WINDOWS_ONLY_PORTS)
    has_445 = 445 in ports
    if has_ssh:
        return "linux"
    if has_win_only:
        return "windows"
    if has_445:
        return "windows"
    return "unknown"


# ─── Inventory model §7 ──────────────────────────────────────────────────────

def _blank_host(ip: str) -> Dict:
    return {
        "ip": ip,
        "alive": False,
        "responded_via": [],
        "port_hints": [],
        "os_hint": "unknown",
        "session_ref": None,
    }


def build_inventory(cidr: str, method: str,
                    hosts: List[Dict],
                    started: str, finished: str) -> Dict:
    """Build the inventory dict matching the §7 contract."""
    return {
        "range": cidr,
        "started": started,
        "finished": finished,
        "method": method,
        "hosts": hosts,
    }


def save_inventory(inventory: Dict) -> str:
    """Write inventory to outputs/sweeps/<range>-<ts>.json. Returns path."""
    cidr = inventory["range"]
    safe_range = cidr.replace("/", "_").replace(".", "-")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{safe_range}-{ts}.json"
    path = os.path.join(SWEEPS_DIR, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2)
    return path


def update_inventory(inventory: Dict, path: str) -> None:
    """Overwrite an existing inventory file in place."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2)


def load_inventory(path: str) -> Optional[Dict]:
    """Load an inventory JSON file. Returns None on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_latest_inventory(cidr: str) -> Optional[Dict]:
    """Load the most recent inventory for a given CIDR, if any."""
    safe_range = cidr.replace("/", "_").replace(".", "-")
    candidates = []
    try:
        for name in os.listdir(SWEEPS_DIR):
            if name.startswith(safe_range + "-") and name.endswith(".json"):
                candidates.append(os.path.join(SWEEPS_DIR, name))
    except FileNotFoundError:
        return None
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return load_inventory(candidates[0])


def merge_inventory(existing: Dict, new_hosts: List[Dict]) -> Dict:
    """Merge newly discovered hosts into an existing inventory.

    Preserves session_ref for hosts already worked on.
    """
    by_ip = {h["ip"]: h for h in existing.get("hosts", [])}
    for nh in new_hosts:
        ip = nh["ip"]
        if ip in by_ip:
            old_ref = by_ip[ip].get("session_ref")
            by_ip[ip].update(nh)
            if old_ref:
                by_ip[ip]["session_ref"] = old_ref
        else:
            by_ip[ip] = nh
    existing["hosts"] = sorted(by_ip.values(),
                               key=lambda h: _ip_sort_key(h["ip"]))
    return existing


def _ip_sort_key(ip: str) -> Tuple:
    try:
        return tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


def set_session_ref(inventory: Dict, ip: str,
                    session_id: str, session_file: str) -> None:
    """Record a session reference for a promoted host."""
    for h in inventory.get("hosts", []):
        if h["ip"] == ip:
            h["session_ref"] = {
                "session_id": session_id,
                "file": session_file,
            }
            return
