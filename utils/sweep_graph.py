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
HAWK — Sweep inventory to graph-data builder.

Mirrors utils/bloodhound_graph.py: pure-data, no tkinter.
Converts a sweep inventory dict into the same {nodes, edges, stats}
shape consumed by the networkx+matplotlib renderer.

Node types:
    subnet  — one root node per sweep range
    host    — one per alive host
    service — one per open-port hint (phase 2 only)

Categories (drive colour in the renderer):
    critical — host exposing 445 / 3389 (RDP/SMB = high attack surface)
    warn     — host exposing 22 (SSH = notable)
    medium   — host with any port hint not in the above sets
    normal   — alive, no port info
"""

from __future__ import annotations

from typing import Dict, List, Optional


_CRITICAL_PORTS = {445, 3389, 135, 139}
_WARN_PORTS = {22}

_PORT_LABELS = {
    22: "SSH", 80: "HTTP", 443: "HTTPS",
    135: "RPC", 139: "NetBIOS", 445: "SMB",
    3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    21: "FTP", 25: "SMTP", 53: "DNS",
    110: "POP3", 143: "IMAP", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
    1433: "MSSQL", 5985: "WinRM", 5986: "WinRM-S",
    6379: "Redis", 27017: "MongoDB",
}


def build_graph_data(inventory: Dict,
                     show_routed: bool = False) -> Optional[Dict]:
    """Convert a sweep inventory into {nodes, edges, stats}.

    Returns None if the inventory is empty or malformed.

    Routed hosts (scope == "routed": off every local subnet, reached via a
    gateway and so unverified) are collapsed into ONE summary node by
    default.  On a wide sweep a router that answers ACK/RST probes for a
    whole range can flag hundreds of dead addresses as up; drawing them all
    buries the handful of real, ARP-confirmed local hosts in noise.  Pass
    ``show_routed=True`` to draw them individually.  The routed COUNT is
    always reported in stats either way.
    """
    if not inventory or not isinstance(inventory, dict):
        return None
    hosts = inventory.get("hosts", [])
    alive = [h for h in hosts if h.get("alive")]
    if not alive:
        return None

    routed = [h for h in alive if h.get("scope") == "routed"]
    local = [h for h in alive if h.get("scope") != "routed"]
    drawn = alive if show_routed else local

    cidr = inventory.get("range", "unknown")
    nodes: List[Dict] = []
    edges: List[Dict] = []

    # Root subnet node
    subnet_id = f"subnet:{cidr}"
    nodes.append({
        "id": subnet_id,
        "label": cidr,
        "type": "subnet",
        "category": "normal",
        "flags": [],
        "details": f"range  {cidr}\nhosts  {len(alive)} alive"
                   f"  ({len(local)} local, {len(routed)} routed)",
    })

    stats = {
        "total": len(hosts),
        "alive": len(alive),
        "os_windows": 0,
        "os_linux": 0,
        "os_unknown": 0,
        "port_445": 0,
        "port_3389": 0,
        "port_22": 0,
        "with_session": 0,
        "local": len(local),
        "routed": len(routed),
    }

    for h in drawn:
        ip = h["ip"]
        host_id = f"host:{ip}"
        port_hints = h.get("port_hints", [])
        os_hint = h.get("os_hint", "unknown")
        session_ref = h.get("session_ref")

        cat = _host_category(port_hints)
        scope = h.get("scope", "unknown")
        flags = []
        if session_ref:
            flags.append("has_session")
            stats["with_session"] += 1

        if os_hint == "windows":
            stats["os_windows"] += 1
        elif os_hint == "linux":
            stats["os_linux"] += 1
        else:
            stats["os_unknown"] += 1

        for p in port_hints:
            key = f"port_{p}"
            if key in stats:
                stats[key] += 1

        nodes.append({
            "id": host_id,
            "label": ip,
            "type": "host",
            "category": cat,
            "scope": scope,
            "flags": flags,
            "details": _host_details(h),
        })
        edges.append({
            "src": subnet_id,
            "dst": host_id,
            "type": "contains",
        })

        for port in port_hints:
            svc_id = f"svc:{ip}:{port}"
            svc_label = _PORT_LABELS.get(port, str(port))
            svc_cat = _service_category(port)
            nodes.append({
                "id": svc_id,
                "label": svc_label,
                "type": "service",
                "category": svc_cat,
                "flags": [],
                "details": f"{ip}:{port} ({svc_label})",
            })
            edges.append({
                "src": host_id,
                "dst": svc_id,
                "type": "runs",
            })

    # Collapse the routed band into one summary node so it never buries
    # the real local hosts; the full list stays in the saved inventory.
    if routed and not show_routed:
        summary_id = "routed:summary"
        nodes.append({
            "id": summary_id,
            "label": f"routed: {len(routed)} (unverified)",
            "type": "routed_summary",
            "category": "routed",
            "scope": "routed",
            "flags": [],
            "details": _routed_summary_details(routed),
        })
        edges.append({
            "src": subnet_id,
            "dst": summary_id,
            "type": "contains",
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": stats,
    }


def _routed_summary_details(routed: List[Dict]) -> str:
    lines = [
        f"{len(routed)} routed host(s) - off your local subnet.",
        "",
        "Reached across a gateway, so a liveness hit here is",
        "UNVERIFIED: a router that answers ACK/RST probes for a",
        "whole range flags dead addresses as up (nmap false",
        "positives).  Collapsed to keep the graph readable; the",
        "full list is in the saved sweep inventory JSON.",
        "",
    ]
    sample = [h.get("ip", "?") for h in routed[:12]]
    lines.append("examples: " + ", ".join(sample))
    if len(routed) > 12:
        lines.append(f"... and {len(routed) - 12} more")
    return "\n".join(lines)


def _host_category(port_hints: List[int]) -> str:
    ports = set(port_hints)
    if ports & _CRITICAL_PORTS:
        return "critical"
    if ports & _WARN_PORTS:
        return "warn"
    if ports:
        return "medium"
    return "normal"


def _service_category(port: int) -> str:
    if port in _CRITICAL_PORTS:
        return "critical"
    if port in _WARN_PORTS:
        return "warn"
    return "medium"


def _host_details(h: Dict) -> str:
    lines = [f"ip             {h['ip']}"]
    scope = h.get("scope", "unknown")
    if scope == "routed":
        lines.append("scope          routed (via gateway - UNVERIFIED)")
    elif scope == "local":
        lines.append("scope          local subnet (ARP-confirmed)")
    if h.get("os_hint", "unknown") != "unknown":
        lines.append(f"os_hint        {h['os_hint']}")
    if h.get("responded_via"):
        lines.append(f"responded_via  {', '.join(h['responded_via'])}")
    if h.get("port_hints"):
        labeled = [f"{p} ({_PORT_LABELS.get(p, '?')})"
                   for p in h["port_hints"]]
        lines.append(f"ports          {', '.join(labeled)}")
    ref = h.get("session_ref")
    if ref:
        lines.append(f"session        {ref.get('session_id', 'yes')}")
    return "\n".join(lines)
