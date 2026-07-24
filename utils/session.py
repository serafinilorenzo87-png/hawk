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
HAWK - Session Manager v1.0
Manages pentest sessions: findings, tool output, credentials, defense alerts.
"""

import json
import os
import re
import shutil
from datetime import datetime
from utils.config import SESSIONS_DIR, is_within_base, require_within_base


# ─── Hash type detector ───────────────────────────────────────────────────────
def detect_hash_type(hash_str: str) -> str:
    """Best-effort hash detector aligned with Credential Store logic."""
    h = hash_str.strip()
    if re.match(r'^[a-f0-9]{32}:[a-f0-9]{32}$', h, re.I):
        return "NTLM"
    if re.match(r'^\$6\$', h):
        return "sha512crypt"
    if re.match(r'^\$5\$', h):
        return "sha256crypt"
    if re.match(r'^\$1\$', h):
        return "md5crypt"
    if re.match(r'^\$2[aby]?\$', h):
        return "bcrypt"
    if h.startswith("$NTLMv2$"):
        return "NTLMv2"
    if re.match(r'^[a-f0-9]{32}$', h, re.I):
        return "NTLM"
    if re.match(r'^[a-f0-9]{40}$', h, re.I):
        return "SHA1"
    if re.match(r'^[a-f0-9]{64}$', h, re.I):
        return "SHA256"
    if re.match(r'^[a-f0-9]{128}$', h, re.I):
        return "SHA512"
    return "Unknown"


def _scrub_for_json(obj):
    """Recursively drop values that would break json.dump.

    Two rules:
      1. Dict keys ending in '_ref' (e.g. '_frame_ref', '_badge_ref',
         '_mark_btn_ref', '_row_ref') are removed — these typically
         hold tkinter/customtkinter widget instances that are not
         JSON-serialisable.
      2. Any value that isn't a JSON-native type (str/int/float/bool/
         None/list/dict) is dropped from the containing dict or list
         — no `repr()` fallback, we'd rather lose the field than
         corrupt the file with a partial dump.

    Return value is a NEW structure (dicts/lists are copies) so the
    caller's live state is never mutated.  The `Session.save()`
    caller writes the cleaned version while the widgets keep their
    references.
    """
    _JSON_SCALARS = (str, int, float, bool, type(None))
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            # Filter widget-ref conventional keys.
            if isinstance(k, str) and k.endswith("_ref"):
                continue
            cleaned = _scrub_for_json(v)
            # _scrub_for_json returns a sentinel when the value is
            # entirely unserialisable (e.g. a bare widget object).
            if cleaned is _UNSAFE:
                continue
            out[k] = cleaned
        return out
    if isinstance(obj, list):
        out_list = []
        for v in obj:
            cleaned = _scrub_for_json(v)
            if cleaned is _UNSAFE:
                continue
            out_list.append(cleaned)
        return out_list
    if isinstance(obj, tuple):
        # json.dump renders tuples as lists — same treatment.
        return _scrub_for_json(list(obj))
    if isinstance(obj, _JSON_SCALARS):
        return obj
    # Unknown type → mark unsafe so callers drop the whole entry.
    return _UNSAFE


# Sentinel for _scrub_for_json — anything unsafe becomes this, callers
# filter it out.
_UNSAFE = object()


def _atomic_write_json(path: str, data: dict) -> str:
    """Write JSON inside HAWK atomically, keeping one best-effort backup.

    VM suspends, power loss, and GUI crashes are exactly the situations
    where direct json.dump(path) can leave a half-written session.  Write
    beside the destination, fsync, then os.replace so readers see either
    the previous valid file or the complete new one.
    """
    path = require_within_base(path, "session save")
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp-{os.getpid()}"
    bak_path = f"{path}.bak"

    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        if os.path.exists(path):
            try:
                shutil.copy2(path, bak_path)
            except OSError:
                pass

        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


class Credential:
    """A single credential entry in the store."""

    def __init__(self, username: str = "", password: str = "",
                 hash_val: str = "", cred_type: str = "cleartext",
                 services: list = None, source_phase: str = "",
                 hash_type: str = "", host: str = "", notes: str = "",
                 linked_run_id: str = "", category: str = "",
                 verified: bool = True):
        self.username     = username
        self.password     = password
        self.hash_val     = hash_val
        self.hash_type    = hash_type or (detect_hash_type(hash_val) if hash_val else "")
        self.cred_type    = cred_type   # cleartext | hash | key
        self.services     = services or []  # SSH, SMB, HTTP, ...
        self.source_phase = source_phase
        self.host         = host        # target host/ip the cred belongs to
        self.notes        = notes       # human-readable hint (e.g. connect cmd)
        self.timestamp    = datetime.now().isoformat()
        self.cracked      = False
        self.cracked_pass = ""
        self.verified     = verified    # False for HTTP brute-force creds pending manual check
        # Cross-navigation between Credential Store and Target Intel.
        # When a tool parser pushes both a credential AND a finding in
        # the same run, it generates one UUID and attaches the same
        # linked_run_id to both.  UI then offers "→ intel" / "🔑 creds"
        # buttons that jump between the two sides.  Empty string = no
        # link (manual credentials, pre-existing imports).
        self.linked_run_id = linked_run_id
        # Optional coarse category for sectioning in the UI.  Values
        # currently in use: "" (default — regular creds) or
        # "ad_result" (credentials produced by AD-pentesting tools,
        # grouped in the "AD RESULTS" box under the main list).
        self.category      = category

    def to_dict(self) -> dict:
        return {
            "username":      self.username,
            "password":      self.password,
            "hash_val":      self.hash_val,
            "hash_type":     self.hash_type,
            "cred_type":     self.cred_type,
            "services":      self.services,
            "source_phase":  self.source_phase,
            "host":          self.host,
            "notes":         self.notes,
            "timestamp":     self.timestamp,
            "cracked":       self.cracked,
            "cracked_pass":  self.cracked_pass,
            "linked_run_id": self.linked_run_id,
            "category":      self.category,
            "verified":      self.verified,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        c = cls(
            username=d.get("username", ""),
            password=d.get("password", ""),
            hash_val=d.get("hash_val", ""),
            cred_type=d.get("cred_type", "cleartext"),
            services=d.get("services", []),
            source_phase=d.get("source_phase", ""),
            hash_type=d.get("hash_type", ""),
            host=d.get("host", ""),
            notes=d.get("notes", ""),
            linked_run_id=d.get("linked_run_id", ""),
            category=d.get("category", ""),
            verified=d.get("verified", True),
        )
        c.timestamp    = d.get("timestamp", c.timestamp)
        c.cracked      = d.get("cracked", False)
        c.cracked_pass = d.get("cracked_pass", "")
        return c

    def display(self) -> str:
        if self.cred_type == "hash":
            val = self.hash_val[:32] + "..." if len(self.hash_val) > 32 else self.hash_val
            cracked = f"  → {self.cracked_pass}" if self.cracked else ""
            return f"[HASH/{self.hash_type}]  {val}{cracked}"
        return f"{self.username}:{self.password}"


class DefenseAlert:
    """A defense/detection finding (honeypot, IDS, firewall, DMZ)."""

    TYPES = ("honeypot", "ids", "ips", "firewall", "waf", "dmz", "unknown")

    def __init__(self, alert_type: str, description: str, confidence: int,
                 recommendation: str = ""):
        self.alert_type     = alert_type   # see TYPES
        self.description    = description
        self.confidence     = confidence   # 0-100
        self.recommendation = recommendation
        self.timestamp      = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "alert_type":     self.alert_type,
            "description":    self.description,
            "confidence":     self.confidence,
            "recommendation": self.recommendation,
            "timestamp":      self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DefenseAlert":
        return cls(
            alert_type=d.get("alert_type", "unknown"),
            description=d.get("description", ""),
            confidence=d.get("confidence", 50),
            recommendation=d.get("recommendation", ""),
        )


class Finding:
    """Canonical finding model unifying the two legacy stores.

    HAWK historically carried two divergent finding shapes:
      1. phase findings   — session.phases[pid]["findings"], dicts of
         {"text", "severity", "timestamp"} written by the manual
         FINDINGS-tab entry;
      2. auto-findings    — session.target_intel["auto_findings"],
         richer dicts pushed by tool parsers via
         target_intel.add_auto_finding (title/description/source/
         occurrences/run_count/port/linked_run_id ...).

    Both producers now construct entries through this class and all
    consumers (reporting, search, summaries) read through
    Session.get_all_findings().  The ON-DISK schema is unchanged:
    phase findings keep the legacy "text" key (plus "title") and
    auto-findings keep their existing dict layout, so old session
    JSON loads untouched and old HAWK builds can still read new
    files.
    """

    SEVERITIES = ("info", "low", "medium", "high", "critical")

    # Operator curation state — set during pre-export report review
    # (pillar C). All optional with safe defaults so auto-generated and
    # pre-curation findings round-trip unchanged. Baked into the model
    # from day 0 to avoid a second session-JSON migration when the
    # curation UI lands.
    _CURATION_KEYS = ("included", "false_positive",
                      "severity_override", "operator_note",
                      "technique_ids")

    # Keys consumed into named attributes by the from_*_dict loaders —
    # anything else lands in self.extra so a load/save round-trip is
    # lossless (occurrences, run_count, first_seen, ... survive).
    _PHASE_KEYS = ("text", "title", "severity", "timestamp",
                   "source", "description") + _CURATION_KEYS
    _AUTO_KEYS  = ("title", "description", "severity", "source",
                   "confidence", "endpoint", "parameter", "method",
                   "impact", "remediation", "linked_run_id", "port"
                   ) + _CURATION_KEYS

    def __init__(self, severity: str = "info", title: str = "",
                 source: str = "", description: str = "",
                 confidence: str = "", endpoint: str = "",
                 parameter: str = "", method: str = "",
                 impact: str = "", remediation: str = "",
                 phase_id: str = "", port: "int | None" = None,
                 linked_run_id: str = "", timestamp: str = "",
                 origin: str = "auto", included: bool = True,
                 false_positive: bool = False,
                 severity_override: str = None, operator_note: str = "",
                 technique_ids: list = None, extra: dict = None):
        self.severity      = self.normalize_severity(severity)
        self.title         = title or ""
        self.source        = source or ""
        self.description   = description or ""
        self.confidence    = confidence or ""
        self.endpoint      = endpoint or ""
        self.parameter     = parameter or ""
        self.method        = method or ""
        self.impact        = impact or ""
        self.remediation   = remediation or ""
        self.phase_id      = phase_id or ""
        self.port          = port if isinstance(port, int) else None
        self.linked_run_id = linked_run_id or ""
        self.timestamp     = timestamp or datetime.now().isoformat()
        # "phase" = manual phase finding, "auto" = Target Intel
        self.origin        = origin if origin in ("phase", "auto") else "auto"
        # ─── Operator curation state ─────────────────────────────────────
        # included: keep in the exported report (operator can exclude
        #   without deleting). false_positive: marked FP, dropped from the
        #   report body. severity_override: report uses this instead of
        #   `severity` — the ORIGINAL severity is never overwritten.
        #   operator_note: free-text added during review.
        self.included         = bool(included) if included is not None else True
        self.false_positive   = bool(false_positive)
        sov = (severity_override or "").strip().lower()
        self.severity_override = sov if sov in self.SEVERITIES else None
        self.operator_note    = operator_note or ""
        # Operator ATT&CK override: when non-empty, the report's ATT&CK
        # provider uses THESE technique ids instead of the curated
        # auto-map. Normalised (upper, stripped, deduped); empty = use
        # auto-map. Serialized only when non-empty (curation convention).
        seen_t: set = set()
        self.technique_ids = []
        for t in (technique_ids or []):
            u = str(t).strip().upper()
            if u and u not in seen_t:
                seen_t.add(u)
                self.technique_ids.append(u)
        self.extra         = dict(extra or {})

    @classmethod
    def normalize_severity(cls, severity: str) -> str:
        s = (severity or "info").strip().lower()
        return s if s in cls.SEVERITIES else "info"

    def effective_severity(self) -> str:
        """Severity the report and any counting/sorting should use:
        the operator's override when set, otherwise the detected
        severity. Never mutates `self.severity`."""
        return self.severity_override or self.severity

    @classmethod
    def from_phase_dict(cls, d: dict, phase_id: str = "") -> "Finding":
        """Legacy phase finding {text, severity, timestamp} → Finding.
        Maps title=text; newer entries carry "title" directly."""
        return cls(
            severity=d.get("severity", "info"),
            title=d.get("title") or d.get("text", ""),
            source=d.get("source", "manual"),
            description=d.get("description", ""),
            phase_id=phase_id,
            timestamp=d.get("timestamp", ""),
            origin="phase",
            included=d.get("included", True),
            false_positive=d.get("false_positive", False),
            severity_override=d.get("severity_override"),
            operator_note=d.get("operator_note", ""),
            technique_ids=d.get("technique_ids"),
            extra={k: v for k, v in d.items()
                   if k not in cls._PHASE_KEYS},
        )

    @classmethod
    def from_auto_dict(cls, d: dict) -> "Finding":
        """Target Intel auto-finding dict → Finding."""
        return cls(
            severity=d.get("severity", "info"),
            title=d.get("title", ""),
            source=d.get("source", ""),
            description=d.get("description", ""),
            confidence=d.get("confidence", ""),
            endpoint=d.get("endpoint", ""),
            parameter=d.get("parameter", ""),
            method=d.get("method", ""),
            impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            port=d.get("port") if isinstance(d.get("port"), int) else None,
            linked_run_id=d.get("linked_run_id", ""),
            timestamp=d.get("first_seen") or d.get("timestamp", ""),
            origin="auto",
            included=d.get("included", True),
            false_positive=d.get("false_positive", False),
            severity_override=d.get("severity_override"),
            operator_note=d.get("operator_note", ""),
            technique_ids=d.get("technique_ids"),
            extra={k: v for k, v in d.items()
                   if k not in cls._AUTO_KEYS},
        )

    def to_phase_dict(self) -> dict:
        """Serialise for phases[pid]["findings"].  Keeps the legacy
        "text" key so pre-unification consumers (and older HAWK builds
        reading a new session JSON) still work."""
        d = {
            "text":      self.title,
            "title":     self.title,
            "severity":  self.severity,
            "timestamp": self.timestamp,
        }
        if self.source and self.source != "manual":
            d["source"] = self.source
        if self.description:
            d["description"] = self.description
        d.update(self._curation_to_dict())
        return d

    def to_auto_dict(self) -> dict:
        """Serialise the canonical core of a Target Intel auto-finding.
        The caller (add_auto_finding) layers its merge bookkeeping
        (occurrences, run_count, first_seen, last_seen, _fresh...) on
        top — those are widget-lifecycle data, not finding identity."""
        d = {
            "title":         self.title,
            "description":   self.description,
            "severity":      self.severity,
            "source":        self.source,
            "linked_run_id": self.linked_run_id,
        }
        for key in ("confidence", "endpoint", "parameter", "method",
                    "impact", "remediation"):
            val = getattr(self, key)
            if val:
                d[key] = val
        if self.port is not None:
            d["port"] = self.port
        d.update(self._curation_to_dict())
        return d

    def _curation_to_dict(self) -> dict:
        """Curation fields, emitted only when they deviate from defaults
        — keeps session JSON minimal and lets older HAWK builds read new
        files (unknown keys are ignored). Symmetric with the from_*_dict
        loaders which apply the same defaults on read."""
        d = {}
        if not self.included:
            d["included"] = False
        if self.false_positive:
            d["false_positive"] = True
        if self.severity_override:
            d["severity_override"] = self.severity_override
        if self.operator_note:
            d["operator_note"] = self.operator_note
        if self.technique_ids:
            d["technique_ids"] = list(self.technique_ids)
        return d


class Session:
    """Represents a single pentest session for one target."""

    @property
    def target(self):
        return self.target_ip

    def __init__(self, target_ip: str, session_id: str = None):
        self.target_ip    = target_ip
        self.target_domain = ""   # optional DNS domain for OSINT tools (subfinder/amass)
        # True when the user TYPED the target_domain manually.  When
        # set, auto-detection from tool output (LDAP, NTLM, PTR,
        # nmap ssl-cert) only surfaces findings + terminal notes —
        # never pops the "replace domain?" dialog.  Cleared on
        # explicit DELETE.
        self.target_domain_pinned: bool = False
        # Stealth Mode toggle — when True, PEAS workflow uses random
        # hex filenames in plausible low-watched target paths, and
        # the binary sent to the target is byte-scrambled so its
        # SHA-256 differs from the vanilla winpeas/linpeas release.
        # Persists per-session so the operator can switch OPSEC
        # posture between engagements without losing state.  See
        # utils/stealth.py for the mechanics.
        self.stealth_mode: bool = False
        self.session_id   = session_id or self._generate_id(target_ip)
        self.created_at   = datetime.now().isoformat()
        self.updated_at   = self.created_at
        self.platform     = ""
        self.notes        = ""
        self.tags         = []
        self.detected_os  = ""   # linux | windows | unknown

        # Phase order matches utils.config.KILL_CHAIN_PHASES — keep in
        # sync when reordering.  AD PENTESTING follows EXPLOITATION so
        # domain-credential attacks (DCSync, Kerberoast, Certipy) run
        # AFTER you've landed an initial foothold.
        self.phases = {
            p: {"status": "ready", "findings": [], "output": []}
            for p in ["recon", "scanning", "enumeration", "web_assault",
                      "vuln_scan", "exploitation", "ad_pentesting",
                      "post_exploit", "lateral", "reporting"]
        }

        self.credentials: list     = []  # list of Credential dicts
        self.defense_alerts: list  = []  # list of DefenseAlert dicts
        self.discovered_users: list = []  # usernames enumerated (enum4linux, kerbrute, ldapsearch…)
        self.discovered_shares: list = []  # SMB shares found
        self.discovered_groups: list = []  # AD/Linux groups found
        # Web paths surfaced by gobuster / ffuf / dirb — kept so that
        # downstream tools (Hydra HTTP-GET / POST-FORM, SQLMap, ...)
        # can offer them as one-click targets instead of forcing the
        # user to retype a URL they already found.
        # Each entry:  {"path": "/admin/login.php", "status": 200, "size": 1234}
        self.discovered_web_paths: list = []

        # ── Full session state so we can resume from disk ──
        # executed_tools: chronological log of every tool run
        #   {tool_id, tool_name, phase_id, command, started_at,
        #    finished_at, returncode, status, output_lines[]}
        self.executed_tools: list = []
        # terminal_lines: every line that appeared in the terminal widget
        #   {ts (ISO), level, text}
        self.terminal_lines: list = []
        # target_intel snapshot: populated at save-time from the intel widget
        #   {fingerprint, open_ports, exploits, auto_findings}
        self.target_intel: dict   = {}
        # saved_at: list of ISO timestamps for each save (last entry is newest)
        self.saved_at: list       = []
        # file_path: absolute path of the last saved JSON (used on re-save)
        self.file_path: str       = ""
        # UI state: collapse/expand per kill-chain card, keyed by phase_id.
        # Loaded on session reopen so the user picks back up with the same
        # layout they had.  Default = expanded for every phase.
        self.card_collapsed: dict = {}
        self.hawk_hosts_entries: list = []

    # ─── Tool execution log ──────────────────────────────────────────────────

    def start_tool_execution(self, tool_id: str, tool_name: str,
                              phase_id: str, command: str) -> str:
        """Record that a tool has started. Returns an execution_id the
        caller should keep and pass to finish_tool_execution()."""
        import uuid as _uuid
        exec_id = _uuid.uuid4().hex[:12]
        self.executed_tools.append({
            "exec_id":      exec_id,
            "tool_id":      tool_id,
            "tool_name":    tool_name,
            "phase_id":     phase_id,
            "command":      command,
            "started_at":   datetime.now().isoformat(),
            "finished_at":  "",
            "returncode":   None,
            "status":       "running",
            "output_lines": [],
        })
        self._touch()
        return exec_id

    def finish_tool_execution(self, exec_id: str, returncode: int,
                               output_lines: list, status: str = ""):
        """Finalize a previously-started execution record."""
        for entry in reversed(self.executed_tools):
            if entry.get("exec_id") == exec_id:
                entry["finished_at"]  = datetime.now().isoformat()
                entry["returncode"]   = returncode
                entry["output_lines"] = list(output_lines or [])
                if not status:
                    status = "done" if returncode == 0 else "error"
                entry["status"] = status
                break
        self._touch()

    def set_tool_status(self, exec_id: str, status: str):
        """Update only the status of an execution record (done/error/aborted)."""
        for entry in reversed(self.executed_tools):
            if entry.get("exec_id") == exec_id:
                entry["status"] = status
                break
        self._touch()

    def last_status_per_tool(self) -> dict:
        """Return {tool_id: last_status} — used to restore card icons
        when the session is reloaded."""
        out = {}
        for e in self.executed_tools:
            tid = e.get("tool_id")
            if tid:
                out[tid] = e.get("status", "done")
        return out

    # ─── Terminal persistence ────────────────────────────────────────────────

    def append_terminal_line(self, text: str, level: str = "info",
                              ts: str = ""):
        """Append a line emitted by the terminal widget. Called from
        TerminalWidget._append so every visible line is retained."""
        self.terminal_lines.append({
            "ts":    ts or datetime.now().isoformat(),
            "level": level,
            "text":  text,
        })
        # No _touch() here — terminal is extremely chatty; the save button
        # is the commit point.

    def set_target_intel(self, intel: dict):
        """Snapshot the Target Intel widget state at save-time."""
        self.target_intel = intel or {}
        self._touch()

    # ─── Credentials ──────────────────────────────────────────────────────────

    def add_credential(self, cred: Credential) -> bool:
        """Append *cred* unless an equivalent entry already exists.

        Dedup key: username (case-insensitive, domain prefix stripped)
        + host + secret value (password for cleartext, hash_val for
        hash).  Returns True if the credential was actually added,
        False if it was a duplicate.
        """
        if self._credential_exists(cred):
            return False
        self.credentials.append(cred.to_dict())
        self._touch()
        return True

    # ── credential dedup helper ──────────────────────────────────────

    @staticmethod
    def _strip_domain(u: str) -> str:
        """Normalise username for dedup: lowercase + drop DOMAIN\\ or
        DOMAIN/ prefix."""
        u = (u or "").strip().lower()
        if "\\" in u:
            u = u.split("\\", 1)[1]
        if "/" in u:
            u = u.split("/", 1)[1]
        return u

    def _credential_exists(self, cred: Credential) -> bool:
        u_new = self._strip_domain(cred.username)
        h_new = (cred.host or "").lower()
        for d in self.credentials:
            if self._strip_domain(d.get("username", "")) != u_new:
                continue
            if (d.get("host", "") or "").lower() != h_new:
                continue
            # Same identity — compare the secret value
            if cred.cred_type == "hash":
                if d.get("cred_type") == "hash" \
                        and d.get("hash_val", "") == cred.hash_val:
                    return True
            else:
                if d.get("password", "") == cred.password:
                    return True
        return False

    def get_credentials(self) -> list:
        return [Credential.from_dict(d) for d in self.credentials]

    def mark_cracked(self, idx: int, plaintext: str):
        if 0 <= idx < len(self.credentials):
            self.credentials[idx]["cracked"]      = True
            self.credentials[idx]["cracked_pass"] = plaintext
            self._touch()

    def delete_credential(self, idx: int) -> bool:
        """Remove credential at idx from the session. Returns True on
        success, False if the index is out of range.

        Note: this mutates the underlying list of dicts directly (which
        is what gets serialised), not the list returned by
        `get_credentials()` — that one is a freshly-built copy each call
        and mutating it is a silent no-op (was causing the 'DELETE button
        does nothing' bug)."""
        if 0 <= idx < len(self.credentials):
            del self.credentials[idx]
            self._touch()
            return True
        return False

    # ─── Discovery (users / shares / groups) ─────────────────────────────────

    def add_discovered_users(self, users: list):
        """Merge a list of usernames, deduplicating case-insensitively."""
        existing = {u.lower() for u in self.discovered_users}
        for u in users:
            u = u.strip()
            if u and u.lower() not in existing:
                self.discovered_users.append(u)
                existing.add(u.lower())
        self._touch()

    def add_discovered_shares(self, shares: list):
        existing = {s.lower() for s in self.discovered_shares}
        for s in shares:
            s = s.strip()
            if s and s.lower() not in existing:
                self.discovered_shares.append(s)
                existing.add(s.lower())
        self._touch()

    def add_discovered_groups(self, groups: list):
        existing = {g.lower() for g in self.discovered_groups}
        for g in groups:
            g = g.strip()
            if g and g.lower() not in existing:
                self.discovered_groups.append(g)
                existing.add(g.lower())
        self._touch()

    def add_discovered_web_paths(self, paths: list):
        """Merge a list of web paths found by gobuster/ffuf/dirb.
        Each entry in *paths* is a dict {path, status, size} — dedup on path."""
        existing = {p.get("path", "").lower()
                    for p in self.discovered_web_paths}
        for entry in paths:
            p = entry.get("path", "").strip()
            if not p or p.lower() in existing:
                continue
            self.discovered_web_paths.append({
                "path":   p,
                "status": int(entry.get("status", 0)),
                "size":   int(entry.get("size", 0)),
            })
            existing.add(p.lower())
        self._touch()

    # ─── Defense Alerts ───────────────────────────────────────────────────────

    def add_defense_alert(self, alert: DefenseAlert):
        self.defense_alerts.append(alert.to_dict())
        self._touch()

    def get_defense_alerts(self) -> list:
        return [DefenseAlert.from_dict(d) for d in self.defense_alerts]

    # ─── Phase Data ───────────────────────────────────────────────────────────

    def add_output(self, phase_id: str, tool_name: str, lines: list):
        if phase_id not in self.phases:
            return
        self.phases[phase_id]["output"].append({
            "tool":      tool_name,
            "timestamp": datetime.now().isoformat(),
            "lines":     lines,
        })
        self._touch()

    def add_finding(self, phase_id: str, finding: str, severity: str = "info"):
        if phase_id not in self.phases:
            return
        f = Finding(severity=severity, title=finding, source="manual",
                    phase_id=phase_id, origin="phase")
        self.phases[phase_id]["findings"].append(f.to_phase_dict())
        self._touch()

    def get_all_findings(self) -> list:
        """Unified read-side view over BOTH finding stores.

        Returns a list of Finding objects: every phase finding
        (origin="phase", phase_id set) followed by every Target Intel
        auto-finding snapshot (origin="auto").  Tolerant of legacy
        on-disk shapes — missing keys default, unknown keys are kept
        in Finding.extra.  This is the single source consumers
        (reporting, summaries, search) should count and render from.
        """
        out = []
        for pid, pdata in (self.phases or {}).items():
            if not isinstance(pdata, dict):
                continue
            for d in (pdata.get("findings") or []):
                if isinstance(d, dict):
                    out.append(Finding.from_phase_dict(d, phase_id=pid))
        intel = self.target_intel if isinstance(self.target_intel, dict) \
            else {}
        for d in (intel.get("auto_findings") or []):
            if isinstance(d, dict):
                out.append(Finding.from_auto_dict(d))
        return out

    def set_phase_status(self, phase_id: str, status: str):
        if phase_id in self.phases:
            self.phases[phase_id]["status"] = status
            self._touch()

    # ─── Persistence ──────────────────────────────────────────────────────────

    def save(self, new_file: bool = False):
        """Persist the session to JSON.

        Default is IN-PLACE overwrite of the current snapshot — used by
        the many auto-save call-sites (credential edits, domain changes,
        intel updates) that must not flood the sessions folder.

        The explicit SAVE button passes `new_file=True` to create a new
        timestamped snapshot so the user ends up with a history of
        point-in-time saves they can roll back to.
        """
        self._touch()
        self.saved_at.append(datetime.now().isoformat())
        data = {
            "session_id":     self.session_id,
            "target_ip":      self.target_ip,
            "target_domain":  self.target_domain,
            "platform":       self.platform,
            "detected_os":    self.detected_os,
            "created_at":     self.created_at,
            "updated_at":     self.updated_at,
            "saved_at":       self.saved_at,
            "notes":          self.notes,
            "tags":           self.tags,
            "phases":         self.phases,
            "credentials":       self.credentials,
            "defense_alerts":    self.defense_alerts,
            "discovered_users":  self.discovered_users,
            "discovered_shares": self.discovered_shares,
            "discovered_groups": self.discovered_groups,
            "discovered_web_paths": self.discovered_web_paths,
            "executed_tools":   self.executed_tools,
            "terminal_lines":   self.terminal_lines,
            "target_intel":     self.target_intel,
            "card_collapsed":   self.card_collapsed,
            # Online crack API keys persisted per-session only when the
            # user explicitly ticks the "save to session" checkbox in
            # the api-key prompt.  Never auto-populated — that dict is
            # set on the Session instance at runtime by the dialog.
            "_online_crack_keys": getattr(
                self, "_online_crack_keys", {}),
            "target_domain_pinned": getattr(
                self, "target_domain_pinned", False),
            "stealth_mode": getattr(self, "stealth_mode", False),
            "hawk_hosts_entries": getattr(
                self, "hawk_hosts_entries", []),
        }
        if new_file or not self.file_path or not is_within_base(self.file_path):
            path = self._make_snapshot_path()
        else:
            path = self.file_path

        # ── Defensive deep-scrub of non-serialisable widget refs ──
        # A Target Intel finding dict can carry "_frame_ref",
        # "_badge_ref", "_mark_btn_ref" (and any *_ref field) that
        # point at Tk/customtkinter widgets.  Those widgets aren't
        # JSON-serialisable, and json.dump fails MID-WRITE, leaving
        # a truncated file on disk (last seen at the user's session
        # 12:05:52.json — broken at line 29405 "col 23").  The
        # target_bar strip helpers are SUPPOSED to remove those keys
        # pre-snapshot, but belt-and-suspenders: walk the data tree
        # here, delete any key whose name ends with "_ref" before
        # serialising.  Also filter out any value that isn't one of
        # the JSON-native types.
        data = _scrub_for_json(data)

        path = _atomic_write_json(path, data)
        self.file_path = path
        return path

    def delete_files(self) -> list:
        """Permanently erase every JSON snapshot on disk that belongs
        to this session (same session_id).  Returns the list of deleted
        paths — empty list means nothing was found.

        Scope rationale: explicit SAVE creates timestamped snapshots
        that all share this session's `session_id`.  A user clicking
        DELETE expects ALL of them gone, not just the most recent one
        still referenced by `self.file_path` — otherwise the session
        silently reappears on next HAWK launch with slightly older data.

        Safety: we only remove files we can positively attribute to this
        session (session_id match inside the JSON) or the current
        `file_path`.  Foreign JSON in SESSIONS_DIR is never touched.

        Also removes the matching ``<path>.bak`` left behind by
        ``_atomic_write_json`` — without this, DELETE leaves a stale
        backup that the user has to reap by hand and that can resurrect
        the session if they later restore it manually.
        """
        deleted = []

        def _remove_with_bak(path: str):
            """Remove `path` plus its `<path>.bak` sibling. Append every
            file actually removed to `deleted`."""
            for p in (path, f"{path}.bak"):
                if not p or not os.path.isfile(p):
                    continue
                try:
                    os.remove(p)
                    deleted.append(p)
                except OSError:
                    pass

        # 1. The current file_path — always try this first.
        if (self.file_path and is_within_base(self.file_path)
                and os.path.isfile(self.file_path)):
            _remove_with_bak(self.file_path)
        # 2. Legacy-path filename pattern (old-style save, if any).
        legacy = self._legacy_path()
        if os.path.isfile(legacy) and legacy not in deleted:
            _remove_with_bak(legacy)
        # 3. Scan SESSIONS_DIR for additional snapshots that carry the
        # same session_id.  This catches explicit SAVE history.
        if os.path.isdir(SESSIONS_DIR):
            for fname in os.listdir(SESSIONS_DIR):
                if not fname.endswith(".json") or fname.startswith("."):
                    continue
                full = os.path.join(SESSIONS_DIR, fname)
                if full in deleted:
                    continue
                try:
                    with open(full, encoding="utf-8") as f:
                        d = json.load(f)
                    if d.get("session_id") == self.session_id:
                        _remove_with_bak(full)
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
        # 4. Mop up any orphan `.bak` whose adjacent `.json` was already
        # removed (rare but possible if a previous DELETE crashed mid-way
        # leaving the bak behind).  Match by filename prefix → safe
        # because we only run inside SESSIONS_DIR and the prefix has to
        # match a file we just deleted in this very call.
        deleted_set = set(deleted)
        if os.path.isdir(SESSIONS_DIR):
            for fname in os.listdir(SESSIONS_DIR):
                if not fname.endswith(".json.bak"):
                    continue
                full = os.path.join(SESSIONS_DIR, fname)
                # The adjacent .json must have been one of ours.
                stem = full[: -len(".bak")]   # strip ".bak" → ".json"
                if stem in deleted_set and full not in deleted_set:
                    try:
                        os.remove(full)
                        deleted.append(full)
                    except OSError:
                        pass
        # Detach the object from the filesystem so a stray save() after
        # delete doesn't resurrect it at the same path.
        self.file_path = ""
        return deleted

    def load(self, path: str = ""):
        """Load session state from disk. If `path` is given, read exactly
        that file. Otherwise fall back to the legacy id-based path."""
        if not path:
            path = self.file_path or self._legacy_path()
        if not path or not os.path.exists(path):
            return False
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.file_path      = path
        self.target_ip      = data.get("target_ip", self.target_ip)
        self.target_domain  = data.get("target_domain", "")
        self.platform       = data.get("platform", "")
        self.detected_os    = data.get("detected_os", "")
        self.created_at     = data.get("created_at", self.created_at)
        self.updated_at     = data.get("updated_at", self.updated_at)
        self.saved_at       = data.get("saved_at", [])
        self.notes          = data.get("notes", "")
        self.tags           = data.get("tags", [])
        self.phases         = data.get("phases", self.phases)
        self.credentials       = data.get("credentials", [])
        self.defense_alerts    = data.get("defense_alerts", [])
        self.discovered_users  = data.get("discovered_users", [])
        self.discovered_shares = data.get("discovered_shares", [])
        self.discovered_groups = data.get("discovered_groups", [])
        self.discovered_web_paths = data.get("discovered_web_paths", [])
        self.executed_tools    = data.get("executed_tools", [])
        self.terminal_lines    = data.get("terminal_lines", [])
        self.target_intel      = data.get("target_intel", {})
        self.card_collapsed    = data.get("card_collapsed", {}) or {}
        self.target_domain_pinned = bool(
            data.get("target_domain_pinned", False))
        self.stealth_mode = bool(data.get("stealth_mode", False))
        self.hawk_hosts_entries = data.get("hawk_hosts_entries", [])
        # Re-hydrate session-persisted online-crack API keys (if the
        # user ticked "save to session" in an earlier run).  Kept as a
        # "private" attribute so it's clearly separate from the public
        # `Credential` store.
        keys = data.get("_online_crack_keys")
        if isinstance(keys, dict):
            self._online_crack_keys = keys
        return True

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _make_snapshot_path(self) -> str:
        """Build a new snapshot filename using the current date+time.

        Format: ``{target}-{YYYY-MM-DD}-{HH-MM-SS}.json``
        Example: ``192.168.156.162-2026-04-15-17-45-12.json``

        Dashes everywhere (no underscore mix) so the name is easy to read
        and sort. If the exact same second is already taken, append
        ``(1)``, ``(2)`` … to disambiguate."""
        safe = self._safe_target_slug()
        ts   = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        base = f"{safe}-{ts}"
        candidate = os.path.join(SESSIONS_DIR, f"{base}.json")
        n = 1
        while os.path.exists(candidate):
            candidate = os.path.join(SESSIONS_DIR, f"{base}({n}).json")
            n += 1
        return candidate

    def _safe_target_slug(self) -> str:
        raw = self.target_ip or "target"
        # Keep hostnames readable (replace only filesystem-hostile chars)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", raw)
        return safe or "target"

    def _legacy_path(self) -> str:
        """Old-style path: {target}_{id[:8]}.json — kept for back-compat
        so pre-existing saves still resolve when only the session_id is
        known."""
        safe = self._safe_target_slug()
        return os.path.join(SESSIONS_DIR, f"{safe}_{self.session_id[:8]}.json")

    def _get_path(self) -> str:
        """Deprecated — retained only for legacy call-sites."""
        return self.file_path or self._legacy_path()

    def _touch(self):
        self.updated_at = datetime.now().isoformat()

    @staticmethod
    def _generate_id(target_ip: str) -> str:
        from hashlib import md5
        return md5(f"{target_ip}:{datetime.now().isoformat()}".encode()).hexdigest()

    def summary(self) -> dict:
        done  = sum(1 for p in self.phases.values() if p["status"] == "done")
        # Unified count — phase findings + Target Intel auto-findings,
        # matching what the report's Executive Summary shows.
        finds = len(self.get_all_findings())
        last_save = self.saved_at[-1] if self.saved_at else self.updated_at
        return {
            "target_ip":      self.target_ip,
            "target_domain":  self.target_domain,
            "session_id":     self.session_id[:8],
            "platform":       self.platform,
            "phases_done":    done,
            "total_findings": finds,
            "creds_found":    len(self.credentials),
            "alerts":         len(self.defense_alerts),
            "tools_run":      len(self.executed_tools),
            "terminal_lines": len(self.terminal_lines),
            "created_at":     self.created_at[:16].replace("T", " "),
            "updated_at":     self.updated_at[:16].replace("T", " "),
            "last_saved":     last_save[:19].replace("T", " ") if last_save else "",
            "file_path":      self.file_path,
            "file_name":      os.path.basename(self.file_path) if self.file_path else "",
        }


class SessionManager:
    def __init__(self):
        self.current: Session = None
        self._sessions: list  = []

    def new_session(self, target_ip: str, platform: str = "") -> Session:
        session = Session(target_ip)
        session.platform = platform
        session.save(new_file=True)
        self.current = session
        self._sessions.append(session)
        return session

    def load_all(self) -> list:
        """Scan the sessions directory and return one Session per JSON
        snapshot. Each snapshot is treated as an independent entry so the
        user can load any point-in-time save.

        Every skip now logs a reason to stderr so the user can diagnose
        "my file is there but HAWK doesn't see it" problems — previously
        the bare `except Exception: continue` swallowed every failure
        mode (wrong permissions, corrupted JSON, missing keys, symlink
        loop, ...) with zero hint to the user."""
        import sys as _sys
        sessions = []
        if not os.path.isdir(SESSIONS_DIR):
            print(f"[HAWK] SESSIONS_DIR does not exist: {SESSIONS_DIR}",
                  file=_sys.stderr)
            return []
        try:
            entries = sorted(os.listdir(SESSIONS_DIR))
        except OSError as e:
            print(f"[HAWK] listdir({SESSIONS_DIR}) failed: {e}",
                  file=_sys.stderr)
            return []
        scanned = skipped = loaded = 0
        for fname in entries:
            scanned += 1
            if not fname.endswith(".json"):
                continue            # silently ignore non-JSON (expected)
            if fname.startswith("."):
                print(f"[HAWK] session load: skipped '{fname}' "
                      f"(starts with '.')", file=_sys.stderr)
                skipped += 1
                continue
            full = os.path.join(SESSIONS_DIR, fname)
            try:
                with open(full, encoding="utf-8") as f:
                    data = json.load(f)
            except PermissionError as e:
                print(f"[HAWK] session load: skipped '{fname}' "
                      f"(permission denied — check `ls -l` and "
                      f"`chmod 644`): {e}", file=_sys.stderr)
                skipped += 1
                continue
            except json.JSONDecodeError as e:
                print(f"[HAWK] session load: skipped '{fname}' "
                      f"(invalid JSON at line {e.lineno}, col {e.colno}: "
                      f"{e.msg})", file=_sys.stderr)
                skipped += 1
                continue
            except (OSError, UnicodeDecodeError) as e:
                print(f"[HAWK] session load: skipped '{fname}' "
                      f"({type(e).__name__}: {e})", file=_sys.stderr)
                skipped += 1
                continue
            # Skip non-session JSON (preference files, user-edited blobs).
            missing = [k for k in ("target_ip", "session_id")
                       if k not in data]
            if missing:
                print(f"[HAWK] session load: skipped '{fname}' "
                      f"(missing required key(s): {', '.join(missing)})",
                      file=_sys.stderr)
                skipped += 1
                continue
            try:
                s = Session(data["target_ip"], data["session_id"])
                s.file_path = full
                s.load(full)
                sessions.append(s)
                loaded += 1
            except Exception as e:
                print(f"[HAWK] session load: '{fname}' parsed as JSON "
                      f"but Session.load() raised: "
                      f"{type(e).__name__}: {e}", file=_sys.stderr)
                skipped += 1
                continue
        if scanned == 0:
            print(f"[HAWK] SESSIONS_DIR is empty: {SESSIONS_DIR}",
                  file=_sys.stderr)
        else:
            print(f"[HAWK] session scan: {loaded} loaded, {skipped} "
                  f"skipped, dir={SESSIONS_DIR}", file=_sys.stderr)
        # Newest first by last saved_at (fallback updated_at)
        def _key(s):
            return s.saved_at[-1] if s.saved_at else s.updated_at
        sessions.sort(key=_key, reverse=True)
        self._sessions = sessions
        return sessions

    def set_current(self, session: Session):
        self.current = session

    def delete(self, session: Session = None) -> list:
        """Hard-delete a session: wipe ALL its JSON snapshots from disk
        and drop the object from the manager's cache.  If `session` is
        None we delete `self.current` (the normal UI path).

        Returns the list of deleted file paths so the caller can log /
        display a confirmation.  Safe to call with no active session —
        returns [] and logs nothing."""
        if session is None:
            session = self.current
        if session is None:
            return []
        deleted = []
        try:
            deleted = session.delete_files()
        except Exception as e:
            import sys as _s
            print(f"[HAWK] delete_files() failed: {e}", file=_s.stderr)
        # Evict from the in-memory cache.
        try:
            if session in self._sessions:
                self._sessions.remove(session)
        except Exception:
            pass
        if self.current is session:
            self.current = None
        return deleted
