# Security Policy

## Supported Versions

HAWK is developed and tested on **Kali Linux 2025.1** (`kali-rolling`, kernel 6.12.x).
Only the latest released version receives security fixes.

| Version        | Supported |
|----------------|-----------|
| latest (1.0.x) | Yes       |
| older releases | No        |

## Reporting a Vulnerability

Please report security issues **privately** - do not open a public issue.

- **GitHub**: use a private Security Advisory (repository -> *Security* -> *Advisories* -> *Report a vulnerability*).
- **GitLab**: open a **confidential** issue (tick *"This issue is confidential"* when creating it).

Please include the affected version or commit, reproduction steps, and the impact. You will receive an
acknowledgement, and a fix and disclosure timeline will be coordinated with you.

## Scope

HAWK is an **orchestrator** that wraps third-party open-source tools; it does not reimplement them.
Report vulnerabilities in **HAWK's own code** - for example, a flaw that lets a hostile target compromise the
operator's machine through tool output parsed by HAWK. Vulnerabilities in the wrapped tools (nmap, impacket,
netexec, etc.) belong to their respective upstream projects.

## Authorized use only

HAWK is an offensive security tool. Use it only against systems you own or are explicitly authorized to
assess. You are solely responsible for complying with applicable laws and for obtaining proper authorization.
