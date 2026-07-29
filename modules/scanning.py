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
HAWK - Phase 2: Port Scanning v1.0
- sudo only where strictly needed (-sS, -sU, -O)
- Service+Scripts and Vuln Scripts run without sudo
- SNMP scan uses --max-retries 1 -T4 for speed
"""
from modules.base import BaseModule, Tool

class ScanningModule(BaseModule):
    PHASE_ID   = "scanning"
    PHASE_NAME = "PORT SCANNING"
    # `desc` strings carry a "Step N — ..." prefix to suggest a recommended
    # workflow order without enforcing it.  Logic-wise nothing depends on
    # the prefix; it's pure UI text shown on the card row.  Order chosen:
    #   1  Fastest port surface (rustscan, masscan as alt)
    #   2  First nmap pass with version+OS (Quick, or Full for deep)
    #   3  Precise OS via NSE smb-os-discovery / NTLM (Service+Scripts)
    #   4  Optional UDP + dedicated -O fallback if OS still ambiguous
    #   5  Vuln NSE scripts after the surface is mapped
    TOOLS = [
        Tool(id="nmap_quick", name="NMAP Quick Top-Ports",
             desc="Step 2 — SYN stealth + versions + OS on top 1000 ports. Best follow-up to Rustscan/Masscan. Requires sudo.",
             cmd_template="sudo nmap -v -Pn -sS -sV -O --top-ports 1000 -T4 --stats-every 2s {target}",
             binary="nmap", category="nmap", requires_sudo=True),
        Tool(id="nmap_full", name="NMAP Full",
             desc="Step 2 (deep) — same as Quick but ALL 65535 ports. Use when Step 2 Quick missed services. Slow. Requires sudo.",
             cmd_template="sudo nmap -v -Pn -sS -sV -O -p- -T3 --stats-every 2s {target}",
             binary="nmap", category="nmap", requires_sudo=True),
        Tool(id="nmap_service", name="NMAP Service+Scripts",
             desc="Step 3 — version + default NSE scripts. Precise OS via smb-os-discovery / NTLM. Run after Step 2. No sudo.",
             cmd_template="nmap -v -Pn -sV -sC --top-ports 1000 -T3 --stats-every 2s {target}",
             binary="nmap", category="nmap", requires_sudo=False),
        Tool(id="nmap_udp", name="NMAP UDP",
             desc="Step 4 (optional) — UDP scan. Finds SNMP/DNS/TFTP that TCP scans miss. Requires sudo.",
             cmd_template="sudo nmap -v -Pn -sU -sV --max-retries 1 -T4 --stats-every 2s {target}",
             binary="nmap", category="nmap", requires_sudo=True),
        Tool(id="nmap_vuln", name="NMAP Vuln Scripts",
             desc="Step 5 — NSE vuln scripts (MS17-010, SMB, SSL, HTTP). Run last, after the surface is mapped. No sudo.",
             cmd_template="nmap -v -Pn --script vuln -T3 --stats-every 2s {target}",
             binary="nmap", category="nmap", requires_sudo=False),
        Tool(id="nmap_os", name="NMAP OS Detection",
             desc="Step 4 (optional) — dedicated -O fingerprinting. Only needed if Step 3 left the OS ambiguous. Requires sudo.",
             cmd_template="sudo nmap -v -Pn -O -sV --top-ports 100 -T3 --stats-every 2s {target}",
             binary="nmap", category="nmap", requires_sudo=True),
        Tool(id="nmap_custom", name="NMAP Custom",
             desc="Power user — build your own nmap command. No fixed step.",
             cmd_template="nmap -v -Pn --stats-every 2s {target}",
             binary="nmap", category="nmap", requires_sudo=False),
        Tool(id="masscan", name="MASSCAN",
             desc="Step 1 (alt) — alternative to Rustscan: full port range at high packet rate. Requires sudo.",
             cmd_template="sudo masscan {target} -p0-65535 --rate=500",
             binary="masscan", category="masscan", requires_sudo=True),
        Tool(id="rustscan", name="RUSTSCAN",
             desc="Step 1 — fastest port discovery (65535 ports in ~3s) then hands off to nmap for details. Best first scan.",
             cmd_template="rustscan -a {target} --ulimit 5000 -- -v -sV -sC --stats-every 2s",
             binary="rustscan", category="rustscan", requires_sudo=False),
    ]
