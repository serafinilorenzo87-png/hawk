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
HAWK - Target validator utilities.

Shared helpers for:
 - detecting target type (IP vs domain, IPv4 vs IPv6)
 - detecting private/reserved IP space (RFC1918, CGNAT, loopback, link-local)
 - validating that a target is suitable for a specific class of tool

Used by OSINT guard-rails (whois, theHarvester, subfinder, amass)
and anywhere else we need to reason about the nature of the target.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Tuple


# ─── Detection ────────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$'
)


def is_ip(target: str) -> bool:
    """True if target parses as a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except (ValueError, AttributeError):
        return False


def is_ipv4(target: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(target.strip()),
                          ipaddress.IPv4Address)
    except (ValueError, AttributeError):
        return False


def is_ipv6(target: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(target.strip()),
                          ipaddress.IPv6Address)
    except (ValueError, AttributeError):
        return False


def is_domain(target: str) -> bool:
    """True if target looks like a DNS name (not an IP)."""
    if not target:
        return False
    t = target.strip().rstrip(".")
    if is_ip(t):
        return False
    return bool(_DOMAIN_RE.match(t))


def is_private_ip(target: str) -> bool:
    """
    True for any IP inside RFC1918, CGNAT (100.64/10), loopback,
    link-local, multicast or reserved blocks.
    """
    try:
        ip = ipaddress.ip_address(target.strip())
    except (ValueError, AttributeError):
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def classify_target(target: str) -> str:
    """
    Return one of:
      'private_ip', 'public_ip', 'domain', 'invalid'
    """
    if not target or not target.strip():
        return "invalid"
    t = target.strip()
    if is_ip(t):
        return "private_ip" if is_private_ip(t) else "public_ip"
    if is_domain(t):
        return "domain"
    return "invalid"


def private_block(target: str) -> str:
    """
    Return a human name for the private block that `target` belongs to,
    or '' if not private.
    """
    if not is_private_ip(target):
        return ""
    try:
        ip = ipaddress.ip_address(target.strip())
    except Exception:
        return ""

    if ip.is_loopback:
        return "loopback (127.0.0.0/8)"
    if ip.is_link_local:
        return "link-local (169.254.0.0/16)"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"

    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.ip_network("10.0.0.0/8"):
            return "RFC1918 — 10.0.0.0/8"
        if ip in ipaddress.ip_network("172.16.0.0/12"):
            return "RFC1918 — 172.16.0.0/12"
        if ip in ipaddress.ip_network("192.168.0.0/16"):
            return "RFC1918 — 192.168.0.0/16"
        if ip in ipaddress.ip_network("100.64.0.0/10"):
            return "CGNAT — 100.64.0.0/10 (RFC6598)"
    return "reserved"


# ─── Tool-level validation ────────────────────────────────────────────────────

# Tools that need a public target (IP or domain) — useless on private IPs.
OSINT_TOOLS_PUBLIC_ONLY = {
    "theHarvester", "theharvester",
    "whois",
    "shodan", "censys",
}

# Tools that specifically want a DOMAIN, not an IP.
DOMAIN_ONLY_TOOLS = {
    "subfinder",
    "amass",
    "dnsrecon",
    "assetfinder",
    "fierce",
    "sublist3r",
}

# DNS lookup tools — work fine on domains and public IPs, but against
# public resolvers they cannot resolve RFC1918 PTR records.
DNS_LOOKUP_TOOLS = {
    "nslookup", "dig", "host",
}


# ─── CIDR helpers (network sweep) ────────────────────────────────────────────

def parse_cidr(base_ip: str, prefix: str) -> Tuple[bool, str, int]:
    """Validate a base IP + prefix and return the normalised network.

    Returns (ok, network_str, host_count).
    On failure: (False, reason, 0).
    """
    base_ip = (base_ip or "").strip()
    prefix = (prefix or "").strip()
    if not base_ip or not prefix:
        return (False, "", 0)
    try:
        pfx = int(prefix)
    except ValueError:
        return (False, "prefix must be a number (e.g. 24)", 0)
    if pfx < 1 or pfx > 32:
        return (False, "prefix must be 1-32", 0)
    try:
        net = ipaddress.ip_network(f"{base_ip}/{pfx}", strict=False)
    except ValueError as e:
        return (False, str(e), 0)
    count = max(0, net.num_addresses - 2) if pfx < 31 else net.num_addresses
    return (True, str(net), count)


def is_local_subnet(cidr: str) -> bool:
    """True if the CIDR range sits entirely inside RFC1918 / link-local."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
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


# ─── Tool-level validation ────────────────────────────────────────────────────

def validate_for_tool(target: str, binary: str) -> Tuple[bool, str, str]:
    """
    Check whether `target` is appropriate for tool `binary`.

    Returns:
      (ok, reason, suggestion)
        ok         — True if the target can be used directly
        reason     — short explanation when not ok (empty if ok)
        suggestion — alternative command/tool the user can try

    Example:
      ok, reason, sugg = validate_for_tool("192.168.1.10", "subfinder")
      # (False,
      #  "subfinder needs a domain, not an IP",
      #  "dig -x 192.168.1.10   # reverse DNS")
    """
    kind = classify_target(target)

    # DNS-lookup tools: private IPs have no PTR record on public resolvers.
    if binary.lower() in {b.lower() for b in DNS_LOOKUP_TOOLS}:
        if kind == "private_ip":
            block = private_block(target)
            return (False,
                    f"{binary} queries your DNS resolver for a PTR record of "
                    f"{target}. That IP is private ({block}) — public resolvers "
                    "(8.8.8.8, 1.1.1.1, etc.) do NOT hold reverse records for "
                    "RFC1918 space, so this will fail silently.",
                    f"arp-scan -l  |  nbtscan {target}  |  "
                    f"{binary} {target} <your-LAN-DNS-IP>")
        if kind == "invalid":
            return False, f"Invalid target for {binary}.", ""
        return True, "", ""

    # Domain-only tools
    if binary.lower() in {b.lower() for b in DOMAIN_ONLY_TOOLS}:
        if kind == "domain":
            return True, "", ""
        if kind in ("public_ip", "private_ip"):
            return (False,
                    f"{binary} enumerates subdomains — it needs a DOMAIN, not an IP.",
                    f"dig -x {target}   # reverse DNS, then run on the domain")
        return False, f"Invalid target for {binary}.", ""

    # Public-only OSINT tools
    if binary.lower() in {b.lower() for b in OSINT_TOOLS_PUBLIC_ONLY}:
        if kind == "private_ip":
            block = private_block(target)
            return (False,
                    f"{binary} queries PUBLIC OSINT sources. "
                    f"{target} is a private IP ({block}) — nothing will be indexed.",
                    "Try: arp-scan -l  |  nmap -sV  |  enum4linux  |  nbtscan")
        if kind == "invalid":
            return False, f"Invalid target for {binary}.", ""
        return True, "", ""

    # Unknown tool — permissive
    if kind == "invalid":
        return False, "Invalid target.", ""
    return True, "", ""
