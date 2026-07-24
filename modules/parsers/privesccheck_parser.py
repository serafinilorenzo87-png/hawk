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
HAWK — PrivescCheck.ps1 output parser.

PrivescCheck (by itm4n) is a modern Windows privesc enumerator that
runs entirely in PowerShell memory.  Its output is structured as a
sequence of named "checks" with a severity tag and a finding
description.  It's deliberately different from winPEAS and can NOT
be parsed by winpeas_parser.

Expected output patterns handled here (the PrivescCheck project has
changed its output formatting a few times across v2021-2025; this
parser accepts the three common variants):

  Variant 1 — "[  KO  ]" + "[HIGH]" side-markers:
      [  KO  ] Get-UserPrivileges          [HIGH]
        Description: The user has the SeImpersonatePrivilege ...
        Result: ...

  Variant 2 — markdown-ish with severity line:
      ## USER_PRIVILEGES
      Severity: High
      The user has SeImpersonatePrivilege, use a Potato variant ...

  Variant 3 — Invoke-PrivescCheck -Extended format:
      [CATEGORY: User]
        [USER_PRIVILEGES] [HIGH] ...

Findings are pushed as CRITICAL / HIGH / MEDIUM / LOW / INFO into
Target Intel.  Check names that look like credential leaks
(e.g. APPLICATIONS_AUTOLOGON, CREDENTIALS_MANAGER) also push a stub
credential into the Credential Store so the UI can link intel ↔ creds
via `linked_run_id`.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from typing import Optional


_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


# Check name → (default severity hint, cred-leaky?).  Used when the
# check emits no explicit severity marker.  cred-leaky checks also
# generate a Credential Store entry so the user sees it in the creds
# tab with a hint about where to look on the target.
_KNOWN_CHECKS = {
    # --- USER ---
    "USER_IDENTITY":             ("info",    False),
    "USER_PRIVILEGES":           ("high",    False),
    "USER_ENV":                  ("medium",  False),
    # --- SERVICES ---
    "SERVICES_UNQUOTED_PATH":    ("high",    False),
    "SERVICES_PERMISSIONS":      ("high",    False),
    "SERVICES_SIMHIJACK_PATH":   ("high",    False),
    "SERVICES_DLL_HIJACKING":    ("high",    False),
    # --- UAC / REGISTRY ---
    "UAC_REGISTRY":              ("low",     False),
    "REGISTRY_WINLOGON":         ("high",    True),   # may leak creds
    "REGISTRY_AUTOLOGON":        ("high",    True),
    "REGISTRY_ALWAYSELEVATED":   ("critical", False),
    "ALWAYS_INSTALL_ELEVATED":   ("critical", False),
    # --- CREDENTIALS ---
    "CREDENTIALS_MANAGER":       ("high",    True),
    "CREDENTIALS_VAULT":         ("high",    True),
    "CREDENTIALS_SAM_BKP":       ("critical", True),
    "CREDENTIALS_KEE":           ("high",    True),
    "APPLICATIONS_AUTOLOGON":    ("high",    True),
    "APPLICATIONS_PUTTY":        ("medium",  True),
    # --- NETWORK ---
    "NETWORK_SHARES":            ("medium",  False),
    "NETWORK_TCP":               ("info",    False),
    "NETWORK_WLAN":              ("medium",  True),   # stored wifi PSK
    # --- MISC ---
    "SCHEDULED_TASKS":           ("medium",  False),
    "HARDENING_LAPS":            ("info",    False),
    "HARDENING_POWERSHELL":      ("low",     False),
}


# ═════════════════════════════════════════════════════════════════════
#  Public entry point
# ═════════════════════════════════════════════════════════════════════

def parse_privesccheck(text: str,
                       app,
                       target: str,
                       source_file: Optional[str] = None) -> dict:
    """Parse ANSI-stripped PrivescCheck.ps1 console output.

    Same contract as the winpeas/linpeas parsers: pushes findings into
    Target Intel, optionally credentials, writes a structured .txt
    sibling, returns a stats dict.
    """
    text = _ANSI_RE.sub("", text)
    run_id = _new_run_id()

    # Parse out individual check blocks.  `blocks` is a list of
    # dicts: {name, severity, body}.  We run THREE passes to cover
    # all three output variants mentioned in the module docstring,
    # then dedup by check name (first wins — variant ordering puts
    # the most structured variant first).
    blocks = (_extract_blocks_variant1(text)
              + _extract_blocks_variant2(text)
              + _extract_blocks_variant3(text))

    seen_names = set()
    unique_blocks = []
    for b in blocks:
        key = b["name"].upper()
        if key in seen_names:
            continue
        seen_names.add(key)
        unique_blocks.append(b)

    # Build findings + creds from the deduped blocks.
    findings: list[dict] = []
    creds:    list[dict] = []

    for b in unique_blocks:
        _emit_finding_and_cred(b, target, findings, creds)

    # Severity tally.
    sev_counts = {"critical": 0, "high": 0, "medium": 0,
                  "low": 0, "info": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    # Structured .txt.
    if source_file:
        try:
            _write_structured_txt(
                source_file, text, unique_blocks,
                findings, creds, sev_counts, target)
        except Exception as e:
            _term_warn(
                app, f"  [!] Could not write structured .txt: {e}")

    # Push to UI.
    for f in findings:
        _push_finding(app, f, run_id)
    for c in creds:
        _push_credential(app, c, run_id)

    # Summary finding.
    summary_desc_lines = [
        f"Parser run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "Severity tally:",
        f"  • CRITICAL : {sev_counts['critical']}",
        f"  • HIGH     : {sev_counts['high']}",
        f"  • MEDIUM   : {sev_counts['medium']}",
        f"  • LOW      : {sev_counts['low']}",
        f"  • INFO     : {sev_counts['info']}",
        "",
        f"Credentials extracted: {len(creds)}",
        f"Checks parsed:         {len(unique_blocks)}",
    ]
    if source_file:
        txt_sibling = os.path.splitext(source_file)[0] + ".txt"
        summary_desc_lines.append("")
        summary_desc_lines.append(f"Readable copy: {txt_sibling}")

    if sev_counts["critical"]:
        summary_sev = "critical"
    elif sev_counts["high"]:
        summary_sev = "high"
    elif sev_counts["medium"]:
        summary_sev = "medium"
    else:
        summary_sev = "info"

    try:
        app.target_intel.add_auto_finding(
            title=f"PrivescCheck parsed — {target}",
            description="\n".join(summary_desc_lines),
            severity=summary_sev,
            source="privesccheck parser",
            linked_run_id=run_id)
    except Exception:
        pass

    return {
        "blocks":          unique_blocks,
        "findings":        findings,
        "creds":           creds,
        "severity_counts": sev_counts,
        "run_id":          run_id,
    }


# ═════════════════════════════════════════════════════════════════════
#  Variant extractors
# ═════════════════════════════════════════════════════════════════════

def _extract_blocks_variant1(text: str) -> list[dict]:
    """Variant 1 — '[ KO/OK/WARN ]' header with '[SEV]' tag.

    Example line:
        [  KO  ] Get-UserPrivileges          [HIGH]
    Body follows indented until the next bracket header.
    """
    blocks = []
    pattern = re.compile(
        r"^\s*\[\s*(KO|NOK|WARN|VULN)\s*\]\s+(\S+)"
        r"(?:\s+.*?)?\s*\[(HIGH|MEDIUM|LOW|INFO|CRITICAL)\]\s*$",
        re.M | re.I)
    matches = list(pattern.finditer(text))
    for i, m in enumerate(matches):
        status = m.group(1).upper()
        name   = m.group(2).strip().lstrip("_").strip()
        sev    = m.group(3).lower()
        start  = m.end()
        end    = matches[i + 1].start() if i + 1 < len(matches) \
                 else len(text)
        body   = text[start:end].strip()
        blocks.append({
            "name":     name,
            "severity": sev,
            "status":   status,
            "body":     body,
        })
    return blocks


def _extract_blocks_variant2(text: str) -> list[dict]:
    """Variant 2 — markdown-ish with 'Severity:' line.

    Example:
        ## USER_PRIVILEGES
        - Severity: High
        - Description: ...
    """
    blocks = []
    pattern = re.compile(
        r"^##\s+(\S[^\n]*?)\s*$", re.M)
    matches = list(pattern.finditer(text))
    for i, m in enumerate(matches):
        name = m.group(1).strip().lstrip("_").strip()
        start = m.end()
        end   = matches[i + 1].start() if i + 1 < len(matches) \
                else len(text)
        body  = text[start:end].strip()
        sev_m = re.search(
            r"Severity:\s*(High|Medium|Low|Info|Critical|None)",
            body, re.I)
        if not sev_m:
            continue  # skip non-check headings
        sev = sev_m.group(1).lower()
        if sev == "none":
            sev = "info"
        blocks.append({
            "name":     name,
            "severity": sev,
            "status":   "KO",
            "body":     body,
        })
    return blocks


def _extract_blocks_variant3(text: str) -> list[dict]:
    """Variant 3 — '[CHECK_NAME] [SEVERITY] ...' inline style emitted
    by Invoke-PrivescCheck -Format txt.

    Example:
        [USER_PRIVILEGES] [HIGH] The user has SeImpersonatePrivilege.
    """
    blocks = []
    pattern = re.compile(
        r"^\s*\[([A-Z_][A-Z0-9_]+)\]\s+"
        r"\[(HIGH|MEDIUM|LOW|INFO|CRITICAL)\]\s*(.*?)$",
        re.M)
    matches = list(pattern.finditer(text))
    for i, m in enumerate(matches):
        name  = m.group(1).lstrip("_").strip()
        sev   = m.group(2).lower()
        first = m.group(3).strip()
        start = m.end()
        end   = matches[i + 1].start() if i + 1 < len(matches) \
                else len(text)
        body  = (first + "\n" + text[start:end]).strip()
        blocks.append({
            "name":     name,
            "severity": sev,
            "status":   "KO",
            "body":     body,
        })
    return blocks


# ═════════════════════════════════════════════════════════════════════
#  Finding / credential builder
# ═════════════════════════════════════════════════════════════════════

def _emit_finding_and_cred(block: dict, target: str,
                            findings: list, creds: list) -> None:
    """Turn one parsed check block into a finding (always) and
    a credential (when the check name suggests a credential leak)."""
    name = block["name"]
    sev  = block["severity"]
    body = block["body"]

    # Trim body to a reasonable length for the description.  linpeas
    # findings cap around 2KB too.
    snippet = body
    if len(snippet) > 1500:
        snippet = snippet[:1500] + "\n  ... (see .txt sibling)"

    findings.append({
        "title":       f"PrivescCheck: {name}",
        "description": (
            f"Target: {target}\n"
            f"Check:  {name}\n"
            f"Severity (as reported by PrivescCheck): {sev.upper()}\n\n"
            f"{snippet}"),
        "severity":    _normalise_severity(sev, name),
        "source":      "privesccheck parser",
    })

    # If this check is in the cred-leaky list, push a stub credential
    # pointing to the target + the check name so the operator can
    # follow up with the right decrypt/dump step.
    check_info = _KNOWN_CHECKS.get(name.upper())
    if check_info and check_info[1]:  # cred-leaky == True
        # Try to pull a username out of the body text.
        usr_m = re.search(
            r"(?:User(?:name)?|Account)\s*[:=]\s*(\S+)", body)
        usr = usr_m.group(1) if usr_m else ""
        pwd_m = re.search(
            r"(?:Password|Secret|Key)\s*[:=]\s*(\S+)", body)
        pwd = pwd_m.group(1) if pwd_m else ""
        creds.append({
            "username":  usr,
            "password":  pwd,
            "host":      target,
            "services":  ["Windows", "PrivescCheck"],
            "cred_type": "cleartext" if pwd else "hash",
            "notes":     (f"{name} reported by PrivescCheck — "
                          f"inspect the finding for details"),
        })


def _normalise_severity(raw: str, check_name: str) -> str:
    """Map PrivescCheck's severity to HAWK's 5-tier scale.  If the
    PrivescCheck severity is missing/none we fall back to the
    `_KNOWN_CHECKS` default for that check name."""
    raw = (raw or "").lower()
    if raw in ("critical", "high", "medium", "low", "info"):
        return raw
    if raw == "none":
        return "info"
    fallback = _KNOWN_CHECKS.get(check_name.upper())
    if fallback:
        return fallback[0]
    return "info"


# ═════════════════════════════════════════════════════════════════════
#  Structured .txt writer
# ═════════════════════════════════════════════════════════════════════

def _write_structured_txt(source_file: str,
                           clean_text: str,
                           blocks: list,
                           findings: list,
                           creds: list,
                           sev_counts: dict,
                           target: str) -> None:
    txt_path = os.path.splitext(source_file)[0] + ".txt"

    rule = "═" * 67
    dash = "─" * 67

    buf: list[str] = []
    def _emit(s: str = ""): buf.append(s)

    _emit(rule)
    _emit(f"  HAWK — PrivescCheck parsed output  —  {target}")
    _emit(f"  Parsed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _emit(f"  Source: {os.path.basename(source_file)}")
    _emit(rule)
    _emit("")
    _emit("  SEVERITY TALLY")
    _emit(dash)
    _emit(f"    CRITICAL : {sev_counts['critical']}")
    _emit(f"    HIGH     : {sev_counts['high']}")
    _emit(f"    MEDIUM   : {sev_counts['medium']}")
    _emit(f"    LOW      : {sev_counts['low']}")
    _emit(f"    INFO     : {sev_counts['info']}")
    _emit(f"    creds    : {len(creds)}")
    _emit("")

    _emit(f"  CHECKS PARSED ({len(blocks)})")
    _emit(dash)
    for b in blocks:
        _emit(f"    [{b['severity'].upper():<8}] {b['name']}")
    _emit("")

    _emit("  CREDENTIALS EXTRACTED")
    _emit(dash)
    if creds:
        for c in creds:
            pw_preview = c.get("password", "") or "(no pass)"
            if len(pw_preview) > 24:
                pw_preview = pw_preview[:20] + "…"
            _emit(f"    • {c.get('username', '?'):<24} : "
                  f"{pw_preview}  ({c.get('notes', '')})")
    else:
        _emit("    (no credentials)")
    _emit("")
    _emit(rule)
    _emit("")

    for i, b in enumerate(blocks, 1):
        _emit(f"[{i}] {b['name']} — "
              f"{b['severity'].upper()}")
        _emit(dash)
        _emit(b["body"].rstrip())
        _emit("")
        _emit("")

    _emit(rule)
    _emit("  RAW (ANSI-stripped) OUTPUT")
    _emit(rule)
    _emit(clean_text)

    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(buf))


# ═════════════════════════════════════════════════════════════════════
#  Small helpers (shared design with winpeas/linpeas parsers)
# ═════════════════════════════════════════════════════════════════════

def _new_run_id() -> str:
    return f"privesccheck-{uuid.uuid4().hex[:10]}"


def _push_finding(app, f: dict, run_id: str):
    try:
        app.target_intel.add_auto_finding(
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            source=f.get("source", "privesccheck parser"),
            linked_run_id=run_id)
    except Exception:
        pass


def _push_credential(app, c: dict, run_id: str):
    try:
        from utils.session import Credential
        cred = Credential(
            username=c.get("username", ""),
            password=c.get("password", ""),
            host=c.get("host", ""),
            services=c.get("services", []) or [],
            cred_type=c.get("cred_type", "cleartext"),
            notes=c.get("notes", ""),
            source_phase="post_exploit",
            linked_run_id=run_id)
        app.cred_store.add_credential(cred)
    except Exception:
        pass


def _term_warn(app, msg: str):
    try:
        app.terminal.write(msg, "warn")
    except Exception:
        pass
