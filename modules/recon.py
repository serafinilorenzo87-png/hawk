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
HAWK - Phase 1: Reconnaissance
Passive & active information gathering.
"""

from modules.base import BaseModule, Tool


class ReconModule(BaseModule):

    PHASE_ID   = "recon"
    PHASE_NAME = "RECONNAISSANCE"

    TOOLS = [
        Tool(
            id="ping",
            name="PING",
            desc="Check if host is alive",
            cmd_template="ping -c 4 {target}",
            binary="ping",
            category="host-discovery",
        ),
        Tool(
            id="traceroute",
            name="TRACEROUTE",
            desc="Network path to target",
            cmd_template="traceroute {target}",
            binary="traceroute",
            category="host-discovery",
        ),
        Tool(
            id="whois",
            name="WHOIS",
            desc="Domain / IP registration info",
            cmd_template="whois {target}",
            binary="whois",
            category="passive",
        ),
        Tool(
            id="nslookup",
            name="NSLOOKUP",
            desc="DNS forward/reverse lookup",
            cmd_template="nslookup {target}",
            binary="nslookup",
            category="dns",
        ),
        Tool(
            id="dig_any",
            name="DIG (ANY)",
            desc="Full DNS enumeration",
            cmd_template="dig {target} ANY +noall +answer",
            binary="dig",
            category="dns",
        ),
        Tool(
            id="dnsrecon",
            name="DNSRECON",
            desc="Advanced DNS reconnaissance",
            cmd_template="dnsrecon -d {target}",
            binary="dnsrecon",
            category="dns",
        ),
        Tool(
            id="theharvester",
            name="theHarvester",
            desc="Emails, subdomains, IPs from public sources",
            cmd_template="theHarvester -d {target} -b all -l 100",
            binary="theHarvester",
            category="osint",
        ),
        Tool(
            id="whatweb",
            name="WHATWEB",
            desc="Web technology fingerprinting",
            cmd_template="whatweb http://{target}",
            binary="whatweb",
            category="web",
        ),
        Tool(
            id="subfinder",
            name="SUBFINDER",
            desc="Passive subdomain discovery via APIs (Shodan, Censys, VirusTotal)",
            cmd_template="subfinder -d {target} -silent",
            binary="subfinder",
            category="osint",
        ),
        Tool(
            id="amass_enum",
            name="AMASS Enum",
            desc="Deep subdomain enumeration — passive + active, ASN mapping",
            cmd_template="amass enum -passive -d {target}",
            binary="amass",
            category="osint",
        ),
    ]
