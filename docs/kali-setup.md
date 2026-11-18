# Kali 2025 Setup Notes

HAWK has no installer for now. Review the commands below and run only what you
need on your Kali VM.

## Python packages

Install HAWK's Python dependencies in a virtualenv (isolated from the system
Python; Kali 2025 blocks a direct `pip` via PEP 668). `python3-tk` and
`python3-venv` are system packages — see **Common system tools** below.

```bash
cd ~/hawk
python3 -m venv venv
./venv/bin/python3 -m pip install -r requirements.txt
```

Run with `./venv/bin/python3 hawk.py`.

Quick, non-isolated alternative (installs into the system Python):

```bash
python3 -m pip install -r requirements.txt --break-system-packages
```

## Common system tools

```bash
sudo apt update
sudo apt install -y \
  python3-tk python3-venv \
  xclip xterm qterminal nmap masscan \
  smbclient enum4linux netexec \
  nikto gobuster ffuf wafw00f whatweb sqlmap \
  hydra john hashcat seclists wordlists \
  metasploit-framework exploitdb evil-winrm \
  chisel proxychains4 \
  dnsrecon whois dnsutils theharvester \
  snmp python3-setuptools pipx \
  bloodhound.py ldapdomaindump
```

Rockyou is usually compressed on Kali:

```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
```

## Nmap and masscan without sudo prompts

Prefer capabilities over sudoers rules:

```bash
sudo ./setup_nmap_caps.sh
```

This keeps HAWK from needing a broad sudoers entry and also improves live
progress output for scans.

## Kali 2025 notes

If `netexec`/`nxc` or Impacket tools fail after a Kali upgrade, check `USAGE.md`
for the current compatibility workaround.

## Greenbone credentials

If your Greenbone/GVM account is not the Kali lab default, create:

```json
{
  "username": "admin",
  "password": "your-password"
}
```

as `configs/greenbone.json` inside the HAWK folder, or launch HAWK with:

```bash
HAWK_GVM_USER=admin HAWK_GVM_PASSWORD='your-password' python3 hawk.py
```
