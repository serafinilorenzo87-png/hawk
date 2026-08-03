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


def build_phase2_cmd(gnmap_path: str, targets_path: str) -> str:
    """Phase 2: light port peek on confirmed-alive hosts.

    -Pn is correct here — hosts are already confirmed up.

    `targets_path` is an -iL list the CALLER has already written.  This
    module stays pure logic: writing the file from here meant doing disk
    I/O on the UI thread with no error path, and a failure left the sweep
    half-dismantled with the phase-1 results already discarded.
    """
    return (
        f"sudo nmap -Pn --top-ports 100 "
        f"-T4 "
        f"-oG {gnmap_path} "
        f"-iL {targets_path}"
    )


def gnmap_path_for(cidr: str, phase: int) -> str:
    """Return a temp file path for nmap greppable output."""
    safe = cidr.replace("/", "_").replace(".", "-")
    return os.path.join(TMP_DIR, f"sweep_{safe}_p{phase}.gnmap")


def phase2_targets_path_for(cidr: str) -> str:
    """Return the temp path for the phase-2 -iL host list.

    Keyed on the range like the gnmap paths so two sweeps of different
    ranges never read each other's list.
    """
    safe = cidr.replace("/", "_").replace(".", "-")
    return os.path.join(TMP_DIR, f"sweep_{safe}_p2_targets.txt")


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

_WINDOWS_PORTS = {445, 3389, 135, 139}
_LINUX_PORTS = {22}

_PROBE_PORT_RE = re.compile(r":(\d{1,5})$")


def infer_os_hint(responded_via: List[str], port_hints: List[int]) -> str:
    """Cheap OS hint from which ports answered — never asserted as fact.

    Per design §4, 445/3389 mean "likely Windows" and win over 22: a
    Windows box running OpenSSH (standard since Server 2019) answers on
    both, and calling it Linux is the more damaging mistake — SMB/RDP are
    only ever served by Windows or by a Samba box that behaves like one.

    In phase 1 `port_hints` is empty by contract (§7) and `responded_via`
    ("tcp:445", "syn:3389", "arp", …) is the ONLY signal, so the probe
    tags are mined for port numbers too.
    """
    ports = set(port_hints or ())
    for entry in responded_via or ():
        m = _PROBE_PORT_RE.search(str(entry))
        if m:
            ports.add(int(m.group(1)))
    if ports & _WINDOWS_PORTS:
        return "windows"
    if ports & _LINUX_PORTS:
        return "linux"
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
                    started: str, finished: str,
                    aborted: str = "") -> Dict:
    """Build the inventory dict matching the §7 contract.

    `aborted` is the ISO time the operator stopped the sweep, empty when
    it ran to the end.  An aborted sweep has NO `finished` time: most of
    the range was never probed, and stamping one makes a partial result
    read as a complete picture of the network days later.
    """
    return {
        "range": cidr,
        "started": started,
        "finished": "" if aborted else finished,
        "aborted": aborted,
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


def merge_inventory(existing: Dict, new_hosts: List[Dict],
                    started: str = "", finished: str = "",
                    aborted: str = "") -> Dict:
    """Merge newly discovered hosts into an existing inventory.

    Preserves session_ref for hosts already worked on (§3: never orphan a
    host the operator already worked).

    A COMPLETE sweep ages the hosts it did not see to `alive: False`.
    Without that a box that answered once stayed alive:true forever and
    the graph kept drawing machines powered off days ago.

    `aborted` (ISO abort time, empty when the sweep completed) says the
    result set is PARTIAL: the silence of a host then means "never
    probed", not "down", so `alive` is left alone — and no `finished`
    time is stamped, because nothing about this range was verified whole.

    `started` is the timestamp of the FIRST sweep of this range and is
    kept as-is; the caller's value only fills it in when the existing
    inventory has none.
    """
    by_ip = {h["ip"]: h for h in existing.get("hosts", [])}
    seen = set()
    for nh in new_hosts:
        ip = nh["ip"]
        seen.add(ip)
        if ip in by_ip:
            old_ref = by_ip[ip].get("session_ref")
            by_ip[ip].update(nh)
            if old_ref:
                by_ip[ip]["session_ref"] = old_ref
        else:
            by_ip[ip] = nh
    if not aborted:
        for ip, h in by_ip.items():
            if ip not in seen:
                h["alive"] = False
    existing["hosts"] = sorted(by_ip.values(),
                               key=lambda h: _ip_sort_key(h["ip"]))
    if started and not existing.get("started"):
        existing["started"] = started
    if aborted:
        existing["finished"] = ""
        existing["aborted"] = aborted
    elif finished:
        existing["finished"] = finished
        existing["aborted"] = ""
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
