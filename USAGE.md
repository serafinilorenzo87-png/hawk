# HAWK — Hostile Assessment War-Kit
## User Guide v1.0

---

## Quick Start

```bash
cd ~/hawkc
python3 hawk.py
```

---

## Typical Pentest Workflow

### 1. Start a Session
- Enter target IP in the **TARGET IP** field
- Select platform (Custom, HTB, THM)
- Click **NEW SESSION**

### 2. Reconnaissance
- Run **PING** — discovers if host is alive (ICMP → TCP SYN → TCP ACK)
- If host doesn't respond → try NMAP Quick directly (it uses -Pn)

### 3. Port Scanning
- **NMAP Quick** — fast scan, top 1000 ports (start here)
- **NMAP Full** — all 65535 ports (use if Quick finds nothing)
- **NMAP Service+Scripts** — version detection + NSE scripts
- **NMAP Vuln Scripts** — test for known vulnerabilities (MS17-010, Heartbleed etc.)
- **NMAP OS Detection** — fingerprint OS
- **NMAP UDP** — finds SNMP, DNS, TFTP (slow, be patient)

> After each scan, check **TARGET INTEL** panel — findings auto-populate there.

> **Note on nmap progress bars** — the live % and ETA shown under each nmap
> scan are approximate, not exact. Nmap itself rarely emits detailed stats
> even with `-v`: on fast scans (local VM, quick top-ports) you may see the
> bar jump between phases (SYN Stealth → Service scan → OS detection → NSE)
> rather than flow smoothly, and the `ETC` field is often missing entirely.
> That is a limitation of nmap's own output, not HAWK. The scan itself is
> running correctly — the final results in the terminal and Target Intel
> panel are always the source of truth.

### 4. Enumeration
- Tools only run if the required service was found in Port Scanning
- **GOBUSTER** — web directory brute force (needs HTTP)
- **ENUM4LINUX** — SMB enumeration on Linux/Samba targets
- **CRACKMAPEXEC** — SMB enumeration on Windows
- **SMBCLIENT** — list SMB shares anonymously
- **SNMPWALK** — enumerate SNMP (needs UDP 161)

### 5. Vulnerability Analysis
- **NMAP Vuln Scripts** — already in Port Scanning phase
- **SEARCHSPLOIT** — searches ExploitDB by detected services
- **NIKTO** — web server vulnerability scanner
- **GREENBONE** — full OpenVAS scan

### 6. Exploitation
- Check **TARGET INTEL** for findings with `▶ EXPLOIT WITH MSF` button
- Click `ℹ INFO` to understand what an exploit does before launching
- Click `🔍 SCAN` to verify vulnerability before exploiting
- **METASPLOIT** card — opens msfconsole interactive session

### 7. Post-Exploitation
- After shell obtained → run **WINPEAS** or **LINPEAS**
- Check **CREDENTIAL STORE** — add hashes with **IMPORT**
- Crack hashes with `🔓 CRACK` button → John the Ripper or Hashcat

---

## Copy/Paste in HAWK

### In the GUI (CTkEntry and CTkTextbox fields)
- **Right-click** → Copy / Paste / Cut / Select All
- **Ctrl+C** → Copy selection
- **Ctrl+V** → Paste
- **Ctrl+A** → Select all

### In xterm windows
- **Select text with mouse** → automatically copied to X11 primary clipboard
- **Middle mouse button** (scroll wheel clicked) → paste from primary clipboard
- **Right-click** → paste from clipboard

> **Note:** xterm uses X11 clipboard — separate from Ctrl+C/V clipboard.
> The easiest method is: select text → middle mouse button to paste.

### When HAWK opens xterm for netcat
- The command is automatically copied to clipboard before xterm opens
- In xterm: right-click → Paste (or middle mouse button)

---

## Target Intel Panel

The **TARGET INTEL** panel auto-populates from:
- nmap scan results (ports, services, OS)
- nmap vuln scripts (CVEs, vulnerabilities)
- searchsploit results
- smbclient/nxc (SMB shares)
- NVD API CVE lookup
- Manual netcat verification

### Per-finding buttons
- `ℹ INFO` — explains what the finding is and how to exploit it
- `🔍 SCAN` — runs MSF auxiliary scanner to confirm vulnerability
- `▶ EXPLOIT WITH MSF` — pre-configured MSF dialog (all fields editable)
- `✎ CHANGE SERVICE` — correct service type for a port

### Edit OS Fingerprint
Click `✎ EDIT OS` to manually set the OS if auto-detection is wrong.
Choose from Windows Endpoint/Server, Linux Desktop/Server, macOS.

---

## Credential Store

### Add credentials
- **ADD** button → choose cleartext or hash
- **IMPORT** button → paste hashdump output

### Hashdump format (from Metasploit `hashdump`)
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
```
Format: `username:RID:LM_hash:NTLM_hash:::`

Use **Quick Parse** in IMPORT dialog — paste the line, click 🔍 PARSE.
HAWK extracts the NTLM hash automatically (ignores empty LM hash).

### Crack hashes
Click `🔓 CRACK` → choose John the Ripper or Hashcat → wordlist → START IN XTERM.
- NTLM hashes: John uses `--format=NT`, Hashcat uses `-m 1000`
- rockyou.txt is recommended as first wordlist

### Edit/Delete credentials
Each credential has `✎ EDIT` and `🗑 DELETE` buttons.

---

## Non-Standard Ports

When nmap finds a service on an unexpected port (e.g. HTTP on 5985):
1. HAWK shows a dialog with verification commands
2. Click **🔌 NETCAT** — opens xterm, command pre-copied to clipboard
3. Paste in xterm (middle mouse) to verify the actual service
4. Use **✎ CHANGE SERVICE** to correct the service type

> Port 5985 with `microsoft-httpapi` = **WinRM**, not HTTP.
> HAWK excludes WinRM ports from web tools automatically.

---

## Greenbone / OpenVAS

First time setup:
```bash
sudo gvm-setup    # takes 10-20 minutes
sudo gvm-start
# browser: http://127.0.0.1:9392
```

If gvm-check-setup shows errors, HAWK can fix them automatically
(SCAP data, CERT data etc.) — click **FIX AUTOMATICALLY** in the dialog.

Password reset:
```bash
sudo runuser -u _gvm -- gvmd --user=admin --new-password=admin123
```

---

## Requirements

Install everything:
```bash
sudo apt update && sudo apt install -y \
  xclip xterm nmap masscan \
  smbclient enum4linux netexec onesixtyone \
  nikto gobuster ffuf wafw00f whatweb sqlmap \
  hydra john hashcat seclists wordlists \
  metasploit-framework exploitdb evil-winrm \
  gvm snmp python3-setuptools pipx \
  bloodhound.py ldapdomaindump
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
python3 -m pip install -r requirements.txt --break-system-packages
pipx ensurepath
```

Allow nmap and masscan to use raw sockets without sudo. Prefer Linux
capabilities over sudoers rules:
```bash
sudo ./setup_nmap_caps.sh
```

### Kali 2025 specific — Python env patch

Python 3.13 broke several apt-packaged pentest tools by removing
`distutils`.  Run this one-liner once after install to patch
impacket / netexec / related tools (see `Troubleshooting` below for
the full story):

```bash
pip3 uninstall -y impacket 2>/dev/null
rm -rf ~/.local/lib/python3.*/site-packages/impacket*
sudo pip3 install --break-system-packages --ignore-installed \
     'impacket>=0.12' 'pyasn1<0.5.0' 'pyasn1-modules<0.3.0'
SP=$(python3 -c 'import site; print(site.getsitepackages()[0])')
sudo mkdir -p "$SP/distutils"
sudo tee "$SP/distutils/__init__.py" >/dev/null <<'PYSHIM'
import sys, setuptools._distutils as _d
sys.modules[__name__] = _d
PYSHIM
```

---

## Troubleshooting

**HAWK shows blank screen on startup**
```bash
python3 -c "import customtkinter; print(customtkinter.__version__)"
pip install customtkinter --upgrade --break-system-packages
```

**Copy/paste not working**
```bash
sudo apt install -y xclip
```

**nmap finishes in 1 second with no results**
- Re-run `sudo ./setup_nmap_caps.sh` from the HAWK folder.
- Test: `sudo nmap -Pn -sS --top-ports 10 TARGET`
- If "Network is unreachable": check VM network adapter in your virtualisation environment

**MSF exploit fails — Handler failed to bind**
- Port already in use: `sudo pkill -f msfconsole`
- HAWK auto-selects a free port in the LHOST dialog
- Change LPORT manually if needed (4445, 4446 etc.)

**Greenbone xterm closes without starting**
- Run manually: `sudo gvm-start`
- Check: `sudo gvm-check-setup`
- Browser: `http://127.0.0.1:9392`

---

## Troubleshooting — Python environment on Kali 2025 (Python 3.13)

Kali 2025 ships Python 3.13, which **removed `distutils`** from the
standard library (PEP 632).  At the same time, apt continues to
distribute older versions of `python3-impacket` (0.11) and `netexec`
(1.5.x) that were written against the old stack.  That combination
breaks a handful of HAWK's tools on the first run unless you patch
the interpreter.

HAWK **detects** these failures and pops up a fix dialog with ★★ /
★★★ / ★★★★ strategies.  You can click one and it runs the right
shell commands for you.  This section documents the same fixes so
you can run them by hand from any shell.

### Symptom 1 — `ModuleNotFoundError: No module named 'distutils'`

Any impacket-* tool (psexec, secretsdump, GetUserSPNs …) crashes
with a distutils traceback at import time.

**Fix** — create a shim that redirects `import distutils.*` to the
copy of distutils that setuptools still ships:

```bash
SP=$(python3 -c 'import site; print(site.getsitepackages()[0])')
sudo mkdir -p "$SP/distutils"
sudo tee "$SP/distutils/__init__.py" >/dev/null <<'PYSHIM'
import sys
import setuptools._distutils as _d
sys.modules[__name__] = _d
PYSHIM
```

**HAWK equivalent** — click `IMPACKET PsExec` → fix dialog →
**★★ DEEP FIX — distutils shim**.

### Symptom 2 — `TypeError: init() takes from 0 to 1 positional arguments but 2 were given`

Impacket 0.11 (the apt-shipped version) can't talk to pyasn1 0.5+
(the apt-shipped version as of Kali 2025).  Their ABI diverged.

**Fix** — pin pyasn1 back to 0.4.x in `/usr/local` (side-by-side
with the apt copy, which keeps apt packages happy):

```bash
sudo pip3 install --break-system-packages --ignore-installed \
     'pyasn1<0.5.0' 'pyasn1-modules<0.3.0'
```

**HAWK equivalent** — `★★★ LEGACY DEPS — pin pyasn1/cryptography`
in the fix dialog.

### Symptom 3 — `No module named 'impacket.examples.regsecrets'` (NetExec)

NetExec 1.5.x expects impacket ≥ 0.12 (which added
`examples/regsecrets.py`), but apt ships impacket 0.11.  You also
likely have an older user-local impacket in `~/.local/` from some
previous `pip install --user` that shadows everything else.

**Fix (clean)** — remove the shadow + pin impacket 0.12+ system-wide:

```bash
# Remove any user-site impacket that hijacks the import
pip3 uninstall -y impacket 2>/dev/null
rm -rf ~/.local/lib/python3.*/site-packages/impacket*

# Install impacket 0.12+ (has regsecrets) + compatible pyasn1
sudo pip3 install --break-system-packages --ignore-installed \
     'impacket>=0.12' 'pyasn1<0.5.0' 'pyasn1-modules<0.3.0'

# Verify
python3 -c "import impacket.examples.regsecrets as r; print('✓', r.__file__)"
```

**Fix (alternative — isolated pipx venv)** — if you want NetExec
and its deps off the system Python entirely:

```bash
sudo apt purge -y netexec crackmapexec
sudo rm -f /usr/bin/netexec /usr/bin/nxc /usr/bin/crackmapexec /usr/bin/cme
pipx uninstall netexec 2>/dev/null
pipx install netexec
pipx inject netexec 'pyasn1<0.5.0'
pipx ensurepath && hash -r
```

### Symptom 4 — NetExec "Schema mismatch detected"

NetExec stores state (targets, creds, shares seen) in SQLite DBs
under `~/.nxc/workspaces/default/`.  Upgrading NetExec bumps the
schema.  On the first run after an upgrade you see:

```
[-] Schema mismatch detected for table 'hosts' in protocol 'SMB'
```

**Fix** — move the stale workspace aside. NetExec recreates it with the
new schema on next run, and your old DB remains available as a backup:

```bash
mkdir -p /home/kali/.nxc/workspaces
mv /home/kali/.nxc/workspaces/default \
  /home/kali/.nxc/workspaces/default.bak-$(date +%Y%m%d-%H%M%S)
```

### Symptom 5 — HAWK still shows the error dialog after a manual fix

HAWK caches tool availability on process start.  If you fixed the
environment in a shell while HAWK was already running, close and
reopen HAWK so it re-reads the current Python state.

### One-shot setup for fresh Kali 2025

Run this once after `apt install` to cover every known
environment conflict in one go:

```bash
# 1. Clean any leftover user-site impacket
pip3 uninstall -y impacket 2>/dev/null
rm -rf ~/.local/lib/python3.*/site-packages/impacket*

# 2. System-wide pinned dependencies for impacket + netexec + legacy tools
sudo pip3 install --break-system-packages --ignore-installed \
     'impacket>=0.12' 'pyasn1<0.5.0' 'pyasn1-modules<0.3.0'

# 3. distutils shim (PEP 632 workaround)
SP=$(python3 -c 'import site; print(site.getsitepackages()[0])')
sudo mkdir -p "$SP/distutils"
sudo tee "$SP/distutils/__init__.py" >/dev/null <<'PYSHIM'
import sys, setuptools._distutils as _d
sys.modules[__name__] = _d
PYSHIM

# 4. Smoke test
python3 -c "import impacket.examples.regsecrets; print('✓ impacket OK')"
impacket-psexec --help >/dev/null && echo "✓ impacket-psexec OK"
netexec --help >/dev/null 2>&1 && echo "✓ netexec OK"

# 5. NetExec fresh DBs (only if first run complains about schema)
mv ~/.nxc/workspaces/default ~/.nxc/workspaces/default.bak-$(date +%Y%m%d-%H%M%S)
```

---

*HAWK — Authorized use only on systems you own or have explicit permission to test.*
*Created by Lorenzo Serafini*
