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
HAWK - Phase 3: Enumeration v1.0
- crackmapexec replaces smbmap
- All tools are port-aware
- Hydra tools with OS-aware wordlist selection
"""

from modules.base import BaseModule, Tool


class EnumerationModule(BaseModule):
    PHASE_ID   = "enumeration"
    PHASE_NAME = "ENUMERATION"

    TOOLS = [
        Tool(
            id="gobuster_dir",
            name="GOBUSTER Dir",
            desc="Web directory/file brute force. Requires HTTP/HTTPS on target.",
            cmd_template="gobuster dir -u http://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20",
            binary="gobuster",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            id="gobuster_dns",
            name="GOBUSTER DNS",
            desc="Subdomain enumeration. Enter domain when prompted.",
            cmd_template="gobuster dns --domain {target} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20",
            binary="gobuster",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            # The GUI has always shipped a full DIRB route
            # (card_routes_web._route_dirb: wordlist picker, base-path
            # field, wildcard advisory) but no module registered the id,
            # so the branch was unreachable and the card never appeared.
            # dirb is stock on Kali and stays useful where gobuster's
            # HTTP/2 handling or TLS strictness gets in the way, so the
            # tool is registered rather than the route deleted.
            id="dirb",
            name="DIRB",
            desc=("Classic recursive web directory scanner.  No "
                  "response-length filter — prefer GOBUSTER Dir or FFUF "
                  "on SPA / catch-all targets."),
            cmd_template=("dirb http://{target} "
                          "/usr/share/wordlists/dirb/common.txt"),
            binary="dirb",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            id="ffuf",
            name="FFUF",
            desc="Fast web fuzzer. Requires HTTP/HTTPS on target.",
            cmd_template="ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            binary="ffuf",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            id="wafw00f",
            name="WAFW00F",
            desc="Web Application Firewall detection. Requires HTTP/HTTPS.",
            cmd_template="wafw00f http://{target} -a",
            binary="wafw00f",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            id="enum4linux",
            name="ENUM4LINUX",
            desc="SMB/RPC/LDAP enumeration via null session — works on Windows AD and Samba alike (the 'linux' in the name refers to the host that runs the tool, not the target).",
            # enum4linux-ng is the modern Python rewrite: parallel
            # queries + real timeouts, 10× faster than the original
            # Perl enum4linux.  `-A` = run all enumeration, `-r` enables
            # RID cycling with a SANE default range (stock enum4linux
            # -a RID-cycles up to 50000 with no timeout → hangs for
            # minutes on Metasploitable-class targets).
            #
            # Kali doesn't ship enum4linux-ng by default — the tool id
            # is listed in card_widget._INSTALL_FIRST_IDS so clicking
            # the card on a fresh system routes to the install wizard
            # (apt → pipx → pip cascade from base.get_install_strategies).
            cmd_template="enum4linux-ng -A -r 500-1100 {target}",
            binary="enum4linux-ng",
            category="smb",
            requires_sudo=False,
        ),
        Tool(
            id="rpcclient",
            name="RPCCLIENT",
            desc=("Interactive RPC enumeration via SMB null session — "
                  "drops at the rpcclient $> prompt.  Try: srvinfo, "
                  "enumdomusers, enumdomgroups, querydominfo, lsaquery, "
                  "getdompwinfo, netshareenumall, lookupsids "
                  "S-1-5-21-...-500, queryuser <RID>, enumtrusts.  Use "
                  "this when ENUM4LINUX returns nothing OR when you "
                  "need to drill down on a specific user / SID / trust "
                  "(enum4linux is a fixed-query sweep — rpcclient is "
                  "the bisturi)."),
            # Anonymous null session: -U '' -N forces an empty username
            # with no password.  Routed via _open_terminal so the user
            # gets the live `rpcclient $>` prompt — capturing rpcclient
            # output makes no sense, the whole point is iterative
            # interactive querying.
            cmd_template="rpcclient -U '' -N {target}",
            binary="rpcclient",
            category="smb",
            requires_sudo=False,
        ),
        Tool(
            # Id is "netexec", NOT "crackmapexec": every GUI dispatcher
            # keys on "netexec" (card_routes_network._route_tool,
            # card_runtime's intel-parser hop, card_common.SMB_TOOLS),
            # so under the old id this tool matched none of them — the
            # card fell through to the generic raw-run path, never
            # reached its SMB dialog and never ran its intel parser.
            id="netexec",
            name="NETEXEC (CME)",
            desc="SMB/WinRM enumeration — works on Windows and Linux. Requires SMB.",
            # Explicit empty creds force a real null-session bind.
            # Without `-u '' -p ''` netexec skips the auth step on some
            # legacy servers (Win 2008 R2) and Impacket chokes parsing
            # the follow-up share-enum reply, yielding
            #   IndexError: list index out of range
            #   Could not get nt error code 91 (0x5b)
            cmd_template="netexec smb {target} --shares -u '' -p ''",
            binary="netexec",
            category="smb",
            requires_sudo=False,
        ),
        Tool(
            id="smbclient_list",
            name="SMBCLIENT List",
            desc="List SMB shares anonymously. Requires SMB on target.",
            # Three flags, each fixing a different target generation:
            #
            #   -I <ip>
            #     Skip the NetBIOS/DNS server-name resolution step that
            #     otherwise fails with NT_STATUS_RESOURCE_NAME_NOT_FOUND
            #     on modern Windows (Server 2008 R2+) where NetBIOS is
            #     disabled.
            #
            #   --option='client min protocol=NT1'
            #     Allow smbclient to fall back to SMB1/CIFS when the
            #     server doesn't speak SMB2+.  Modern Samba has NT1
            #     disabled by default in the client, which breaks
            #     enumeration of NT4 / 2000 / XP / 2003 targets.  On
            #     modern servers this does nothing — SMB3.1.1 is still
            #     negotiated as the highest common protocol.
            #
            #   --option='client lanman auth=yes'
            #     Re-enable LANMAN authentication for Win 95/98/Me that
            #     only speak LM.  Zero impact on anything NT-based.
            #
            # Net result: single command that works NT4 → Server 2026
            # (and even Win 9x when the LM fallback kicks in).
            cmd_template=(
                "smbclient -L //{target} -N -I {target} "
                "--option='client min protocol=NT1' "
                "--option='client lanman auth=yes'"),
            binary="smbclient",
            category="smb",
            requires_sudo=False,
        ),
        Tool(
            id="snmpwalk",
            name="SNMPWALK",
            desc="SNMP enumeration — finds system info, processes, interfaces. Requires UDP 161.",
            cmd_template="snmpwalk -v2c -c public {target}",
            binary="snmpwalk",
            category="network",
            requires_sudo=False,
        ),
        Tool(
            id="ssh_banner",
            name="SSH Banner Grab",
            desc="Grab SSH banner and version. Requires SSH on target.",
            cmd_template="nc -nv {target} 22 -w 3",
            binary="nc",
            category="network",
            requires_sudo=False,
        ),
        Tool(
            id="db_fingerprint",
            name="DB Fingerprint",
            desc=(
                "Active probe to identify 9 DB protocols on open "
                "ports: Elasticsearch, CouchDB, InfluxDB, "
                "ClickHouse, ArangoDB, Redis, Memcached, MongoDB, "
                "Cassandra.  Sends HTTP probes + binary-protocol "
                "magic, auto-upgrades fp.open_ports with the "
                "detected svc + version.  Re-classifies when nmap "
                "got it wrong (e.g. an Elasticsearch behind 'http')."
            ),
            # Cmd is built dynamically by the dispatcher (target +
            # current open_ports list) — see card_routes_scan.py.
            cmd_template="<dynamic>",
            binary="python3",
            category="network",
            requires_sudo=False,
        ),
        # NOTE: standalone "FTP Anonymous" tool was removed at user
        # request — the integrated Connect → FTP → "Anonymous login"
        # action (target_intel_widget.py action id="anon") covers the
        # same use case and properly verifies + saves the cred via
        # _parse_ftp_connect.  See bug-tracker STEP 0.
        Tool(
            id="kerbrute_userenum",
            name="KERBRUTE Users",
            desc="Enumerate valid AD users via Kerberos. Requires port 88.",
            cmd_template="kerbrute userenum -d {target} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc {target}",
            binary="kerbrute",
            category="ad",
            requires_sudo=False,
        ),
        Tool(
            id="ldapsearch_base",
            name="LDAPSEARCH",
            desc="Query LDAP/AD — anonymous or authenticated. Users, groups, computers, kerberoastable, AS-REP. Requires port 389.",
            cmd_template="ldapsearch -x -H ldap://{target} -s base namingcontexts",
            binary="ldapsearch",
            category="ad",
            requires_sudo=False,
        ),
    ]
