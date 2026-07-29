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
HAWK - Base Module
All kill chain phase modules inherit from this.
Defines the tool structure and check-availability logic.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Callable


# Extra directories HAWK scans when a tool isn't on $PATH. We have no
# idea where the user will install things — could be a Kali pentester
# dropping github releases into /opt, a beginner running as root, a red
# teamer with ~/tools/, someone testing via pipx. So we try every common
# layout we can think of. Hits are cheap (single stat per path) and
# misses are the common case, so false positives aren't a concern.
#
# Category order roughly matches frequency on real pentest workstations:
#   1. Language package managers (pipx / cargo / go / npm)
#   2. Standard system locations (belt-and-suspenders for stripped $PATH)
#   3. /opt — the classic pentester dump for git clones and releases
#   4. Kali / Parrot / BlackArch extras
_EXTRA_BIN_DIRS = [
    # ── Language / package-manager install targets ──────────────────
    os.path.expanduser("~/.local/bin"),       # pipx, pip --user
    os.path.expanduser("~/.cargo/bin"),       # cargo install
    os.path.expanduser("~/go/bin"),           # go install
    os.path.expanduser("~/.go/bin"),          # alternate GOPATH
    os.path.expanduser("~/node_modules/.bin"),# npm local
    os.path.expanduser("~/.npm-global/bin"),  # npm global (user)
    os.path.expanduser("~/.gem/ruby/bin"),    # ruby gems
    os.path.expanduser("~/.poetry/bin"),      # poetry
    os.path.expanduser("~/.pyenv/shims"),     # pyenv
    os.path.expanduser("~/.rbenv/shims"),     # rbenv
    os.path.expanduser("~/.nix-profile/bin"), # nix user profile
    os.path.expanduser("~/.linuxbrew/bin"),   # linuxbrew (user)
    "/home/linuxbrew/.linuxbrew/bin",         # linuxbrew (shared)
    # ── Standard system locations ───────────────────────────────────
    # shutil.which() should already catch these, but cron/desktop
    # shortcuts sometimes launch HAWK with a stripped $PATH.
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/opt/bin",
    # ── /opt (classic pentester dump) ───────────────────────────────
    "/opt",                                   # /opt/<name> bare file
    "/opt/tools",
    "/opt/bin",
    "/opt/pentest",
    "/opt/redteam",
    "/opt/security",
    "/opt/local/bin",
    # ── /srv and /usr/share for packaged extras ─────────────────────
    "/srv/tools",
    "/usr/share/tools",
    # ── Kali / Parrot specifics ─────────────────────────────────────
    "/usr/share/windows-resources",           # impacket scripts etc.
    "/usr/lib/go/bin",
    "/snap/bin",                              # snap packages
    "/var/lib/flatpak/exports/bin",           # flatpak
    # ── Root-run installs ───────────────────────────────────────────
    # Many CTF / lab users actually run as root on Kali. Repeat the home
    # layouts for /root so detection works either way.
    "/root/.local/bin",
    "/root/.cargo/bin",
    "/root/go/bin",
    "/root/bin",
    "/root/tools",
    "/root/opt",
]


# Cache of "last resort" lookups (subprocess-based). We don't want to run
# subprocess for every is_available() call, so we cache positives.
_SUBPROC_POSITIVE_CACHE: dict = {}


# Python-based tools whose apt-packaged /usr/bin/<tool> wrapper is known
# to be broken on modern Kali (Python 3.12+ removed distutils, PEP 632).
# For these we prefer the pipx-installed copy at ~/.local/bin/<tool> even
# if /usr/bin/<tool> exists, because shutil.which() would otherwise return
# the broken apt wrapper and the tool crashes at import time.
#
# Detection is purely prefix-based: any binary whose name starts with one
# of these prefixes (or matches exactly) is considered a "prefer-pipx" tool.
_PREFER_PIPX_PREFIXES = (
    "impacket-",        # apt: python3-impacket, pipx: impacket
    "certipy",          # apt: certipy-ad, pipx: certipy-ad
    "crackmapexec",     # (deprecated; use nxc/netexec)
    "theHarvester",
    "theharvester",
)
_PREFER_PIPX_EXACT = {
    "smbmap", "netexec", "nxc", "pwncat-cs",
}


def _find_binary(name: str) -> Optional[str]:
    """Extended which() — checks $PATH first, then common extra locations,
    several home-directory drop-spots pentesters actually use (~/<name>,
    ~/kerbrute/kerbrute, ~/Downloads/<name>, ~/tools/<name>, ~/bin/<name>),
    and finally a subprocess probe (`name --help`) as a last-resort check.

    Returns absolute path if found, else None.

    Why this matters: tools like kerbrute, rustscan, chisel are often just
    dropped into $HOME from a github release via `wget … -O ~/kerbrute &&
    chmod +x ~/kerbrute`. Users run them as `./kerbrute` from their home
    and never move them into /usr/local/bin. Previously HAWK only looked
    at the git-clone pattern (~/<name>/<name>) and silently claimed the
    tool was missing, forcing the manual-install dialog on every click.

    Special case — "prefer-pipx" tools (impacket-*, certipy, smbmap, nxc,
    pwncat-cs): on modern Kali, /usr/bin/<tool> is the apt wrapper which
    imports distutils and crashes on Python 3.12+. If the user fixed the
    problem with `pipx install`, the working copy lives at ~/.local/bin/
    — but /usr/bin comes first in $PATH, so `shutil.which` returns the
    broken one. We look for the pipx copy FIRST for these tools and only
    fall back to $PATH if it's absent.
    """
    # Prefer-pipx override: check ~/.local/bin before $PATH for tools
    # known to have broken apt wrappers on modern Kali.
    is_pipx_tool = (name in _PREFER_PIPX_EXACT
                    or any(name.startswith(pref)
                           for pref in _PREFER_PIPX_PREFIXES))
    if is_pipx_tool:
        for d in (os.path.expanduser("~/.local/bin"),
                  os.path.expanduser("~/.local/pipx/venvs"),
                  "/root/.local/bin"):
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

    p = shutil.which(name)
    if p:
        return p
    for d in _EXTRA_BIN_DIRS:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    # Home-directory drop-spots. Every pentester has their own filing
    # system — some dump everything in ~, some use ~/tools, ~/pentest,
    # ~/redteam, ~/htb, ~/ctf ... we try all of them. We also look under
    # /root in case HAWK is launched by a different user than the one
    # who installed the binary. Both bare-file (~/kerbrute) and git-clone
    # (~/kerbrute/kerbrute) layouts are checked.
    home       = os.path.expanduser("~")
    user_bases = [home, "/root"]
    sub_dirs   = [
        "",                    # ~/<name>
        "Downloads", "tools", "Tools", "bin", "opt",
        "pentest", "Pentest", "redteam", "RedTeam",
        "htb", "HTB", "thm", "TryHackMe",
        "ctf", "CTF", "labs", "Labs",
        "Desktop", "Documents",
        "work", "workspace", "projects", "src",
        "git", "github",
    ]
    wget_suffixes = ["", "_linux_amd64", "_linux_amd64.bin", "-linux-amd64",
                     "_amd64", "-amd64"]

    home_candidates = []
    for base in user_bases:
        for sub in sub_dirs:
            # Bare-file: ~/<sub>/<name>   (empty sub → ~/<name>)
            d = os.path.join(base, sub) if sub else base
            for suf in wget_suffixes:
                home_candidates.append(os.path.join(d, name + suf))
            # git-clone pattern: ~/<sub>/<name>/<name>
            home_candidates.append(os.path.join(d, name, name))

    for candidate in home_candidates:
        try:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        except OSError:
            # Permission issues stat-ing /root when running unprivileged —
            # just skip and keep looking.
            continue
    # Subprocess fallback — for rare cases where the binary is in a shell
    # alias / function / somewhere os.access can't see. Only run once per
    # binary per HAWK session.
    if name in _SUBPROC_POSITIVE_CACHE:
        return _SUBPROC_POSITIVE_CACHE[name]
    try:
        r = subprocess.run(
            [name, "--help"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=2,
        )
        # Any return code is fine — it ran, so it exists.
        _SUBPROC_POSITIVE_CACHE[name] = name  # use bare name as cmd
        return name
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _resolve_freerdp() -> str:
    """Find the best available xfreerdp binary on this system.

    Modern Kali (2025+) ships ``xfreerdp3`` and no longer provides
    ``xfreerdp``.  Older installs may still have ``xfreerdp`` or
    ``xfreerdp2``.  We probe newest-first and return the first one
    that actually exists on disk (full path if possible, bare name
    as fallback).  If nothing is found we return ``"xfreerdp3"``
    so the user at least gets a meaningful "not found" error.
    """
    for name in ("xfreerdp3", "xfreerdp2", "xfreerdp"):
        hit = _find_binary(name)
        if hit:
            return hit
    return "xfreerdp3"          # sensible default for modern Kali


def _rdp_compat_flags() -> str:
    """Return the TLS/security flags appropriate for the installed xfreerdp.

    Essential for connecting to legacy Windows targets (Server 2008 R2,
    Windows 7) whose TLS ciphers modern OpenSSL 3.x rejects by default.
    Without the seclevel override, Kali 2025 fails the handshake with
    ``BIO_do_handshake failed / ERRCONNECT_TLS_CONNECT_FAILED``.

    Flag name differs across major versions:
      xfreerdp / xfreerdp2     →  /tls-seclevel:0        (dash form)
      xfreerdp3 (FreeRDP 3.x)  →  /tls:seclevel:0        (nested form)

    FreeRDP 3.x refactored a number of flag groups into
    ``/<group>:<subkey>:<value>`` nested syntax (`/tls:`, `/gfx:`, …)
    and flat-out rejects the legacy dash names with:
        Failed at index N [/tls-seclevel:0]: Unexpected keyword

    ``/cert:ignore`` skips self-signed/expired cert checks (almost
    always the case on pentest targets) and works on all versions.

    Returns a string of flags to append after ``/v:... /u:... /p:...``.
    """
    rdp_bin = _resolve_freerdp()
    is_v3 = "xfreerdp3" in rdp_bin
    # /log-level:ERROR suppresses WARN-tier noise that pollutes the
    # captured session output.  The one everyone hits:
    #   [WARN][com.freerdp.client.xfreerdp.utils]
    #     - [run_action_script]: [ActionScript] no such script
    #       '/home/kali/.config/freerdp/action.sh'
    # ActionScript is an opt-in event hook — when the file doesn't
    # exist (99 % of pentesters), xfreerdp prints this on every launch.
    # Setting log-level to ERROR keeps genuine connection failures
    # visible while hiding purely-informational warnings.  Valid on
    # both v2 (xfreerdp/xfreerdp2) and v3 (xfreerdp3).
    if is_v3:
        return ("/sec:rdp,tls,nla /tls:seclevel:0 /cert:ignore "
                "/log-level:ERROR")
    else:
        return ("/sec:tls,rdp,nla /tls-seclevel:0 /cert:ignore "
                "/log-level:ERROR")


@dataclass
class Tool:
    """Represents a single tool/command within a kill chain phase."""
    id:          str           # unique key, e.g. "nmap_quick"
    name:        str           # display name, e.g. "NMAP Quick"
    desc:        str           # short description
    cmd_template: str          # command with {target} placeholder
    binary:      str           # binary to check if installed, e.g. "nmap"
    category:    str = "general"   # grouping within card
    requires_sudo: bool = False
    timeout:     Optional[int] = None  # seconds, None = no limit
    custom_args: str = ""      # user-editable extra args
    os_hint:     str = "any"   # "linux" | "windows" | "any"
    runs_on_target: bool = False  # True = cmd meant to be run ON the target
                                  # (Windows built-ins: reg, wmic, netsh …)
                                  # The tool shows as "COPY" not "RUN",
                                  # and is always clickable regardless of
                                  # whether the binary exists on Kali.

    def build_command(self, target: str, extra_args: str = "") -> str:
        """Build the actual shell command.

        If the binary isn't on $PATH but we located it in a known alt
        directory (e.g. ~/.cargo/bin/rustscan or ~/kerbrute/kerbrute),
        we substitute the absolute path in so the shell doesn't fail
        with 'command not found'.

        Templates may also contain AD-specific placeholders like
        `{user}` / `{password}` / `{domain}` / `{target_computer}` —
        these are left untouched here and resolved by the phase-
        specific dialog (AD pentesting dialog prompts the user for
        them).  We never raise KeyError on unresolved placeholders
        so the command still displays sensibly in UI previews.
        """
        fmt = {
            "target":         target,
            "extra":          extra_args or self.custom_args,
            # AD placeholders default to literal `<field>` labels so
            # the user can see at a glance what's missing before the
            # dialog fills them in.
            "user":            "<user>",
            "password":        "<password>",
            "domain":          "<DOMAIN>",
            "target_computer": "<TARGET_COMPUTER>",
        }
        try:
            cmd = self.cmd_template.format(**fmt)
        except KeyError as e:
            # Unknown placeholder → preserve the literal so the
            # downstream dialog can show the user what still needs
            # filling rather than crashing.
            import re
            missing = str(e).strip("'\"")
            cmd = re.sub(r"\{" + re.escape(missing) + r"\}",
                         f"<{missing}>", self.cmd_template)
            cmd = cmd.format(**fmt)
        # If command starts with the bare binary name and it's not on PATH,
        # rewrite with absolute path.
        if shutil.which(self.binary) is None:
            resolved = _find_binary(self.binary)
            if resolved:
                # Replace only the first whole-word occurrence of the binary
                # name at the start of the command (handles "sudo ..." too).
                parts = cmd.split()
                for i, p in enumerate(parts):
                    if p == self.binary:
                        parts[i] = resolved
                        break
                cmd = " ".join(parts)
        if self.requires_sudo and not cmd.startswith("sudo"):
            cmd = f"sudo {cmd}"
        return cmd

    def is_available(self) -> bool:
        """Check if the tool binary is on PATH or in a known alt dir
        (~/.cargo/bin, ~/go/bin, ~/.local/bin, /usr/local/bin, ~/<name>/)."""
        return _find_binary(self.binary) is not None

    def get_install_hint(self) -> str:
        """Return a cascading install command.

        Single-line shell pipeline using '||' so that the first strategy
        that succeeds wins. Order is apt → package manager alternative →
        build-from-source → prebuilt binary, picking whatever is most
        likely to Just Work on a default Kali install.

        `get_install_strategies()` returns the same information as a
        structured list — prefer that in UIs that want to show the
        user each option separately.
        """
        strategies = self.get_install_strategies()
        # Chain with shell-level OR so the first successful step exits 0.
        return " || ".join(f"({cmd})" for _, cmd in strategies) or \
               f"sudo apt install -y {self.binary}"

    def get_install_strategies(self) -> list:
        """Return ordered list of (label, command) install strategies.

        Each entry is one self-contained shell command. The first that
        exits 0 is considered to have installed the tool. UIs can show
        these as separate options; the CLI hint joins them with '||'.
        """
        # ── Impacket (all entrypoints share one pipx package) ──────────
        # Apt-packaged python3-impacket on Kali still imports distutils
        # (removed in Python 3.12 per PEP 632) so every impacket-* wrapper
        # crashes at startup. pipx gives us an isolated venv with an
        # up-to-date impacket release.
        #
        # The "pipx" strategy ALSO removes the apt package first — if
        # both are installed, /usr/bin/<tool> (apt, broken) shadows
        # ~/.local/bin/<tool> (pipx, working) because /usr/bin comes
        # first in $PATH. Without removing apt the fix looks installed
        # but the tool still crashes.
        #
        # Every impacket-* binary maps to the exact same pair because
        # they all come out of a single `pipx install impacket` → the
        # venv publishes ~10 entrypoints at once.
        _impacket_strategies = [
            ("pipx",
             "(command -v pipx >/dev/null || sudo apt install -y pipx) && "
             "sudo apt remove -y python3-impacket impacket-scripts 2>/dev/null; "
             "pipx uninstall impacket 2>/dev/null; "
             "pipx install impacket && pipx ensurepath"),
            ("apt",
             "sudo apt install -y python3-impacket impacket-scripts"),
        ]
        hints = {
            "nmap":             [("apt", "sudo apt install -y nmap")],
            "masscan":          [("apt", "sudo apt install -y masscan")],
            "gobuster":         [("apt", "sudo apt install -y gobuster")],
            "ffuf":             [("apt", "sudo apt install -y ffuf")],
            "nikto":            [("apt", "sudo apt install -y nikto")],
            "wpscan":           [("apt", "sudo apt install -y wpscan")],
            "sqlmap":           [("apt", "sudo apt install -y sqlmap")],
            "enum4linux":       [("apt", "sudo apt install -y enum4linux")],
            "enum4linux-ng":    [("apt", "sudo apt install -y enum4linux-ng"),
                                  ("pipx", "pipx install enum4linux-ng"),
                                  ("pip",  "pip3 install --break-system-packages enum4linux-ng")],
            "smbmap":           [("pipx", "pipx install smbmap"),
                                 ("pip",  "pip3 install --break-system-packages smbmap")],
            "smbclient":        [("apt", "sudo apt install -y samba-common-bin")],
            "nuclei": [
                ("apt",      "sudo apt install -y nuclei"),
                ("go",       "command -v go >/dev/null 2>&1 && "
                             "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && "
                             "sudo install -m 0755 ~/go/bin/nuclei /usr/local/bin/nuclei"),
                ("prebuilt", "TMP=$(mktemp -d) && "
                             "wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip "
                             "-O $TMP/nuclei.zip && unzip -o $TMP/nuclei.zip -d $TMP && "
                             "sudo install -m 0755 $TMP/nuclei /usr/local/bin/nuclei && rm -rf $TMP"),
            ],
            "hydra":            [("apt", "sudo apt install -y hydra")],
            "msfconsole":       "sudo apt install metasploit-framework",
            "burpsuite":        "sudo apt install burpsuite",
            "searchsploit":     "sudo apt install exploitdb",
            "theHarvester":     "sudo apt install theharvester",
            "dnsrecon":         "sudo apt install dnsrecon",
            "whatweb":          "sudo apt install whatweb",
            "wafw00f":          "sudo apt install wafw00f",
            "pwncat-cs":        "pip3 install pwncat-cs",
            "chisel":           "go install github.com/jpillora/chisel@latest",
            # New tools
            "subfinder":        "sudo apt install subfinder || go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "amass":            "sudo apt install amass",
            "rustscan":         "sudo apt install rustscan || cargo install rustscan || see https://github.com/bee-san/RustScan/releases",
            "kerbrute":         "sudo apt install -y kerbrute || (wget -q https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /tmp/kerbrute && sudo install -m 0755 /tmp/kerbrute /usr/local/bin/kerbrute && rm -f /tmp/kerbrute)",
            "ldapsearch":       "sudo apt install ldap-utils",
            "responder":        "sudo apt install responder",
            # Every impacket-* entrypoint shares the same pipx install.
            "impacket-psexec":          _impacket_strategies,
            "impacket-secretsdump":     _impacket_strategies,
            "impacket-GetNPUsers":      _impacket_strategies,
            "impacket-GetUserSPNs":     _impacket_strategies,
            "impacket-smbclient":       _impacket_strategies,
            "impacket-smbserver":       _impacket_strategies,
            "impacket-wmiexec":         _impacket_strategies,
            "impacket-atexec":          _impacket_strategies,
            "impacket-dcomexec":        _impacket_strategies,
            "impacket-lookupsid":       _impacket_strategies,
            "impacket-samrdump":        _impacket_strategies,
            "impacket-rpcdump":         _impacket_strategies,
            "impacket-ntlmrelayx":      _impacket_strategies,
            "impacket-goldenPac":       _impacket_strategies,
            "impacket-ticketer":        _impacket_strategies,
            "impacket-Get-GPPPassword": _impacket_strategies,
            "impacket-mssqlclient":     _impacket_strategies,
            # AD pentesting module adds these — all ship with impacket.
            "impacket-rbcd":            _impacket_strategies,
            "impacket-findDelegation":  _impacket_strategies,
            "impacket-addcomputer":     _impacket_strategies,

            # Certipy — PyPI `certipy-ad` installs the `certipy` binary.
            "certipy-ad": [
                ("pipx",
                 "(command -v pipx >/dev/null || sudo apt install -y pipx) && "
                 "sudo apt remove -y certipy-ad 2>/dev/null; "
                 "pipx uninstall certipy-ad 2>/dev/null; "
                 "pipx install certipy-ad && pipx ensurepath"),
                ("pip",
                 "pip3 install --break-system-packages certipy-ad"),
            ],
            "certipy": [        # alias used by HAWK's ad_pentesting module
                ("pipx",
                 "(command -v pipx >/dev/null || sudo apt install -y pipx) && "
                 "sudo apt remove -y certipy-ad 2>/dev/null; "
                 "pipx uninstall certipy-ad 2>/dev/null; "
                 "pipx install certipy-ad && pipx ensurepath"),
                ("pip",
                 "pip3 install --break-system-packages certipy-ad"),
            ],

            # BloodHound collector (Python reimplementation of SharpHound).
            "bloodhound-python": [
                ("pipx",
                 "(command -v pipx >/dev/null || sudo apt install -y pipx) && "
                 "pipx install bloodhound && pipx ensurepath"),
                ("apt",
                 "sudo apt install -y bloodhound.py"),
                ("pip",
                 "pip3 install --break-system-packages bloodhound"),
            ],

            # LDAPDomainDump — pure-LDAP AD enumeration → HTML report.
            "ldapdomaindump": [
                ("pipx",
                 "(command -v pipx >/dev/null || sudo apt install -y pipx) && "
                 "pipx install ldapdomaindump && pipx ensurepath"),
                ("apt",
                 "sudo apt install -y ldapdomaindump"),
                ("pip",
                 "pip3 install --break-system-packages ldapdomaindump"),
            ],

            # AD-integrated DNS dump.
            "adidnsdump": [
                ("pipx",
                 "(command -v pipx >/dev/null || sudo apt install -y pipx) && "
                 "pipx install git+https://github.com/dirkjanm/adidnsdump.git "
                 "&& pipx ensurepath"),
                ("pip",
                 "pip3 install --break-system-packages git+"
                 "https://github.com/dirkjanm/adidnsdump.git"),
            ],

            # GPP password decryptor — Kali ships it in-repo.
            "gpp-decrypt": "sudo apt install -y gpp-decrypt",

            # NetExec (used by AD pentesting's LDAP branch).
            "nxc":                 "sudo apt install -y netexec",

            "ligolo-proxy":     "Download from https://github.com/nicocha30/ligolo-ng/releases",
            # Lateral / post-exploit new tools
            "evil-winrm":       [("gem",  "sudo gem install evil-winrm"),
                                 ("apt",  "sudo apt install -y evil-winrm")],
            "sshuttle":         [("apt",  "sudo apt install -y sshuttle"),
                                 ("pip",  "pip3 install --break-system-packages sshuttle")],
            "xfreerdp3":        [("apt",  "sudo apt install -y freerdp2-x11 freerdp3-x11")],
            "getcap":           [("apt",  "sudo apt install -y libcap2-bin")],
            # Windows built-ins — these run on the target, not on Kali.
            # We still need an entry so the install dialog shows a useful
            # message instead of a generic "apt install netstat" hint.
            "netsh":    [("note", "Built-in Windows command — run on the target shell, not on Kali.")],
            "schtasks": [("note", "Built-in Windows command — run on the target shell, not on Kali.")],
            "wmic":     [("note", "Built-in Windows command — run on the target shell, not on Kali.")],
            "whoami":   [("note", "Built-in command (Windows + Linux) — run on the target shell.")],
            "net":      [("note", "Built-in Windows command — run on the target shell, not on Kali.")],
            "netstat":  [("apt",  "sudo apt install -y net-tools"),
                         ("note", "On Windows target: built-in, no install needed.")],
            "reg":      [("note", "Built-in Windows command — run on the target shell, not on Kali.")],
        }
        entry = hints.get(self.binary, f"sudo apt install -y {self.binary}")
        # Backwards-compat: accept legacy plain-string entries.
        if isinstance(entry, str):
            return [("install", entry)]
        return entry


# ─── Brief descriptions keyed by tool.id ─────────────────────────────────────
# Takes precedence over TOOL_BRIEFS when present — useful when several
# distinct HAWK tools share the same underlying binary (e.g. bloody_crawl
# and injection_tester both use curl, but they need their own briefs).
# Also used for tools whose binary has no TOOL_BRIEFS entry (e.g.
# jwt_analyzer's binary is `python3`, which is meaningless to brief).
TOOL_ID_BRIEFS = {
    "web_oracle": (
        "Webapp profiler — fingerprints tech, auth flow, API surface, "
        "exposures and known CVEs.  Recommends what to attack next."),
    "bloody_crawl": (
        "Smart endpoint extractor — reads HTML/forms/JS the app actually "
        "exposes instead of brute-forcing paths.  Detects redirects, "
        "IDOR patterns and JS secrets."),
    "injection_tester": (
        "Parameter injection — tests SQLi / XSS / LFI / SSTI / "
        "command-injection / upload-bypass.  Safe mode with curl, "
        "Aggressive shells out to sqlmap / dalfox / commix."),
    "jwt_analyzer": (
        "JWT decoder + signing-secret brute-force.  Pure Python, no deps. "
        "Detects alg:none acceptance and role-escalation paths."),
}


# ─── Brief descriptions per tool binary ──────────────────────────────────────
# Shown once per unique binary in the kill chain card UI.
TOOL_BRIEFS = {
    # Recon
    "ping":         "Check if host is alive and responding to ICMP. Start here.",
    "traceroute":   "Map the network path to target. Reveals routers and firewalls.",
    "whois":        "Passive lookup — domain owner, registrar, nameservers.",
    "nslookup":     "Quick DNS forward/reverse resolution.",
    "dig":          "Advanced DNS queries — all record types, zone transfers.",
    "dnsrecon":     "Automated DNS recon — brute-force subdomains, zone walks.",
    "theHarvester": "OSINT — scrapes Google, Bing, Shodan for emails, subdomains, IPs.",
    "whatweb":      "Fingerprint web stack — CMS, frameworks, server software.",
    "subfinder":    "Fast passive subdomain discovery via APIs (Shodan, Censys, etc.).",
    "amass":        "Deep subdomain enumeration — passive + active, ASN mapping.",
    # Scanning
    "nmap":         "The standard port scanner. Finds open ports, services, OS. Run Quick first, then Full.",
    "masscan":      "Ultra-fast SYN scanner — scans all 65535 ports in seconds. Use after nmap for speed.",
    "rustscan":     "Fastest port scanner — scans all 65535 ports in ~3s, then pipes results to nmap for service detection. Use when nmap is too slow on large ranges or for a first fast look.",
    # Enumeration
    "gobuster":     "Brute-force web directories and subdomains. Use with a good wordlist.",
    "ffuf":         "Fast web fuzzer — directories, parameters, virtual hosts.",
    "wafw00f":      "Detect WAF (Web Application Firewall) before attacking. Run before Nikto/Nuclei.",
    "enum4linux":   "SMB/NetBIOS enumeration for Samba/Linux. Lists shares, users, groups.",
    "netexec":      "Swiss army knife for AD — SMB, WinRM, LDAP, MSSQL. Replaces CrackMapExec.",
    "smbclient":    "Connect to SMB shares. Use -N for anonymous, or with creds from Credential Store.",
    "snmpwalk":     "Walk SNMP OID tree — reveals system info, processes, interfaces.",
    "nc":           "Netcat — grab banners, test ports, basic connections.",
    "curl":         "HTTP/FTP requests. Used for anonymous FTP check and downloading tools.",
    "kerbrute":     "Kerberos user enumeration + password spraying for Active Directory.",
    "ldapsearch":   "Query LDAP/AD directly — users, groups, GPOs, computer objects.",
    # Vuln scan
    "nikto":        "Web server vulnerability scanner. Noisy — detected by WAFs.",
    "nuclei":       "Template-based CVE scanner. Fast, accurate, updated daily.",
    "gvm-cli":      "Greenbone/OpenVAS — full vulnerability scanner. Heavy but thorough.",
    "wpscan":       "WordPress-specific scanner — plugins, themes, users, CVEs.",
    "sqlmap":       "Automated SQL injection. Give it a URL with parameter to test.",
    "searchsploit": "Offline ExploitDB search. Find public exploits by keyword.",
    # Exploitation
    "msfconsole":   "Metasploit Framework — the exploit toolkit. Use after vuln scan finds targets.",
    "burpsuite":    "Web proxy for intercepting/modifying HTTP requests. Essential for web apps.",
    "hydra":        "Online brute-force — SSH, FTP, HTTP, SMB, RDP. Use with good wordlists.",
    "responder":    "LLMNR/NBT-NS/mDNS poisoner — captures NetNTLMv2 hashes on the network.",
    "impacket-psexec": "Impacket suite — remote execution, hash dumping, Kerberos attacks for AD.",
    "impacket-secretsdump": "Dump SAM/NTDS hashes remotely. Requires admin-level creds or pass-the-hash.",
    "impacket-GetNPUsers": "AS-REP Roasting — find AD users without Kerberos pre-auth.",
    "certipy-ad":   "AD Certificate Services attacks — ESC1-ESC8. Find and exploit cert misconfigs.",
    # AD pentesting module
    "certipy":             "Active Directory Certificate Services attack tool — ESC1-ESC11.",
    "bloodhound-python":   "Python SharpHound — collects AD graph data (users, ACLs, sessions).",
    "ldapdomaindump":      "Dumps the entire AD domain via LDAP — HTML + JSON + grepable.",
    "adidnsdump":          "Dumps DNS records from AD-integrated DNS zone.",
    "gpp-decrypt":         "Decrypt cpassword from SYSVOL Groups.xml (Microsoft leaked the key).",
    "impacket-GetUserSPNs":    "Kerberoasting — request TGS hashes for SPN-bound users.",
    "impacket-rbcd":           "Resource-Based Constrained Delegation abuse (privesc chain).",
    "impacket-findDelegation": "Enumerate accounts with delegation flags (RBCD / unconstrained).",
    "impacket-addcomputer":    "Add a computer account (MachineAccountQuota = 10 by default).",
    "impacket-ticketer":       "Forge Golden / Silver tickets from krbtgt / service hash.",
    # Post-exploit
    "find":         "Find SUID binaries, writable dirs, config files for privilege escalation.",
    "sudo":         "Check sudo permissions — quick win for privesc via sudo -l.",
    "crontab":      "Check scheduled tasks — cron jobs may run as root with writable scripts.",
    "ss":           "Show active connections and listening ports on compromised host.",
    # Post-exploit Linux
    "getcap":       "List file capabilities — alternative privesc vector to SUID.",
    # Post-exploit Windows
    "whoami":       "Show current user privileges (whoami /priv) — spot Potato-able tokens.",
    "wmic":         "WMI command-line — enumerate services, processes, installed software.",
    "reg":          "Query Windows registry — find AlwaysInstallElevated, autoruns, credentials.",
    "schtasks":     "Enumerate Windows scheduled tasks — find tasks running as SYSTEM.",
    "net":          "Windows net command — list users, groups, shares, sessions.",
    "netstat":      "Show active network connections and listening ports (Windows).",
    "powershell":   "PowerShell — run privesc scripts (PowerUp, PrivescCheck) on target.",
    # Lateral Windows
    "evil-winrm":   "WinRM shell — interactive shell over port 5985 with cred or hash.",
    "xfreerdp3":    "RDP client — connect to Windows Remote Desktop. Supports NLA + hash.",
    "netsh":        "Windows network shell — port forwarding and pivoting without extra tools.",
    "sshuttle":     "Transparent SSH proxy — route all traffic through a Linux pivot box.",
    # Lateral
    "pwncat-cs":    "Advanced shell handler — auto-upload, privesc modules, file transfer.",
    "chisel":       "TCP tunnel over HTTP — reverse SOCKS proxy for pivoting through firewalls.",
    "proxychains4": "Route tools through SOCKS proxy — scan internal networks after pivoting.",
    "ssh":          "SSH tunneling — local/dynamic port forwarding for pivoting.",
    "ligolo-proxy": "Modern tunneling agent — easier than chisel, supports multiple agents.",
}


class BaseModule:
    """
    Base class for all kill chain phase modules.
    Subclasses define TOOLS list and optionally override helpers.
    """

    PHASE_ID   = "base"
    PHASE_NAME = "Base Phase"
    TOOLS: list = []

    def __init__(self):
        self._tools = {t.id: t for t in self.TOOLS}

    def get_tools(self) -> list:
        """Return all tools for this phase."""
        return self.TOOLS

    def get_tool(self, tool_id: str) -> Optional[Tool]:
        return self._tools.get(tool_id)

    def get_available_tools(self) -> list:
        """Return only tools whose binary is installed."""
        return [t for t in self.TOOLS if t.is_available()]

    def get_missing_tools(self) -> list:
        """Return tools not yet installed."""
        return [t for t in self.TOOLS if not t.is_available()]

    def check_availability_report(self) -> str:
        """Return a human-readable availability report."""
        lines = [f"[{self.PHASE_NAME}] Tool availability:"]
        for t in self.TOOLS:
            status = "✓" if t.is_available() else "✗"
            lines.append(f"  {status} {t.name:<20} ({t.binary})")
        return "\n".join(lines)
