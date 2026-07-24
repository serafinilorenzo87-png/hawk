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

"""Structured findings for the WEB ASSAULT pipeline.

Every class here produces a formatted description string for
add_auto_finding() (backward compat) AND stores structured data
for ReportForge export and inter-module pipeline.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ── Confidence & Severity ────────────────────────────────────────

class Confidence(Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ── Base Finding ─────────────────────────────────────────────────

@dataclass
class WebFinding:
    """A structured finding from the WEB ASSAULT pipeline.

    Every tool (Crawl, Injection, JWT) creates WebFinding instances.
    Each finding can render itself as plain text (for the current
    Target Intel UI) or as a dict (for ReportForge / JSON export).
    """
    title:         str
    severity:      Severity
    confidence:    Confidence
    source:        str
    endpoint:      str = ""
    parameter:     str = ""
    method:        str = ""
    evidence:      list[str] = field(default_factory=list)
    # Optional un-masked counterpart of `evidence`.  Populated only by
    # producers that DO mask values in the public `evidence` list (see
    # `deduplicate_secrets`).  Consumed by the Target Intel Info
    # dialog's "🔓 SHOW RAW" toggle.  Never persisted to disk: it sits
    # in memory only, stripped during session-save.
    raw_evidence:  list[str] = field(default_factory=list)
    impact:        str = ""
    remediation:   str = ""
    tags:          list[str] = field(default_factory=list)
    timestamp:     str = field(
        default_factory=lambda: datetime.now().isoformat())
    linked_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "title":       self.title,
            "severity":    self.severity.value,
            "confidence":  self.confidence.value,
            "source":      self.source,
            "endpoint":    self.endpoint,
            "parameter":   self.parameter,
            "method":      self.method,
            "evidence":    self.evidence,
            "impact":      self.impact,
            "remediation": self.remediation,
            "tags":        self.tags,
            "timestamp":   self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> WebFinding:
        return cls(
            title=d.get("title", ""),
            severity=Severity(d.get("severity", "info")),
            confidence=Confidence(d.get("confidence", "medium")),
            source=d.get("source", ""),
            endpoint=d.get("endpoint", ""),
            parameter=d.get("parameter", ""),
            method=d.get("method", ""),
            evidence=d.get("evidence", []),
            impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            tags=d.get("tags", []),
            timestamp=d.get("timestamp", ""),
        )

    def render_description(self, *, raw: bool = False) -> str:
        """Formatted text for add_auto_finding() backward compat.

        When ``raw=True`` and ``self.raw_evidence`` is populated, the
        EVIDENCE block is rendered using the un-masked values instead
        of the masked ones in ``self.evidence``.  Used by the Target
        Intel Info dialog's "SHOW RAW" toggle on CTF / lab targets
        where the operator wants to see the actual hardcoded value.
        """
        lines = []
        if self.endpoint:
            ep = (f"{self.method} {self.endpoint}"
                  if self.method else self.endpoint)
            lines.append(f"Endpoint: {ep}")
        if self.parameter:
            lines.append(f"Parameter: {self.parameter}")
        lines.append(f"Confidence: {self.confidence.value.upper()}")
        ev_list = (self.raw_evidence
                   if (raw and self.raw_evidence)
                   else self.evidence)
        if ev_list:
            lines.append(f"\n{'─' * 50}")
            lines.append("EVIDENCE:")
            for ev in ev_list[:10]:
                lines.append(f"  {ev}")
        if self.impact:
            lines.append(f"\n{'─' * 50}")
            lines.append(f"IMPACT: {self.impact}")
        if self.remediation:
            lines.append(f"\n{'─' * 50}")
            lines.append(f"REMEDIATION: {self.remediation}")
        return "\n".join(lines)


# ── JS Secrets ───────────────────────────────────────────────────

@dataclass
class JsSecret:
    """A secret found in a JavaScript file."""
    pattern_name:  str
    severity:      Severity
    matched_value: str
    source_file:   str
    line_number:   int = 0
    context:       str = ""


# Pattern registry: (name, regex, severity, impact)
JS_SECRET_PATTERNS = [
    # ── API Keys (HIGH+) ────────────────────────────────────
    ("AWS Access Key",
     r'AKIA[0-9A-Z]{16}',
     Severity.HIGH,
     "AWS account compromise, data exfiltration, resource abuse"),
    ("AWS Secret Key",
     r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key'
     r'[\s:=\"\']+([A-Za-z0-9/+=]{40})',
     Severity.HIGH,
     "Full AWS API access"),
    ("Google API Key",
     r'AIza[0-9A-Za-z\-_]{35}',
     Severity.HIGH,
     "Google Cloud service abuse, billing fraud"),
    ("Stripe Live Key",
     r'sk_live_[0-9a-zA-Z]{24,}',
     Severity.CRITICAL,
     "Direct payment processing, financial fraud"),
    ("Stripe Publishable Key",
     r'pk_live_[0-9a-zA-Z]{24,}',
     Severity.MEDIUM,
     "Payment form abuse (limited without secret key)"),
    ("GitHub Token",
     r'gh[pousr]_[A-Za-z0-9_]{36,}',
     Severity.HIGH,
     "Repository access, code theft, supply chain attack"),
    ("Slack Token",
     r'xox[baprs]-[0-9A-Za-z\-]{10,}',
     Severity.HIGH,
     "Slack workspace access, message exfiltration"),
    ("Generic Bearer Token",
     r'(?i)bearer\s+[a-z0-9\-_.~+/]{20,}',
     Severity.MEDIUM,
     "Authenticated API access"),
    ("Azure/MS Client Secret",
     r'(?i)(?:client[_\-]?secret|azure[_\-]?secret)'
     r'[\s:=\"\']+([A-Za-z0-9~._\-]{30,})',
     Severity.HIGH,
     "Azure AD app compromise, tenant access"),
    ("Mailgun API Key",
     r'key-[0-9a-zA-Z]{32}',
     Severity.HIGH,
     "Email sending abuse, phishing from trusted domain"),
    ("Twilio API Key",
     r'SK[0-9a-fA-F]{32}',
     Severity.HIGH,
     "SMS/voice abuse, account takeover via phone"),
    ("SendGrid API Key",
     r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
     Severity.HIGH,
     "Email sending abuse, phishing"),
    ("Firebase URL",
     r'https://[a-z0-9-]+\.firebaseio\.com',
     Severity.MEDIUM,
     "Firebase database access if rules misconfigured"),
    ("Heroku API Key",
     r'(?i)heroku[_\-]?api[_\-]?key[\s:=\"\']+([0-9a-f-]{36})',
     Severity.HIGH,
     "Heroku app deployment, environment variable access"),

    # ── Private Keys / Secrets (CRITICAL) ────────────────────
    ("Private Key",
     r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
     Severity.CRITICAL,
     "TLS impersonation, SSH access, code signing"),
    ("JWT Secret Hardcoded",
     r'(?i)(?:jwt[_\-]?secret|signing[_\-]?key)'
     r'[\s:=\"\']+([A-Za-z0-9/+=]{8,})',
     Severity.HIGH,
     "JWT forgery, authentication bypass"),

    # ── Credentials (HIGH) ───────────────────────────────────
    ("Hardcoded Password",
     r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']',
     Severity.HIGH,
     "Direct authentication, lateral movement"),
    ("Database Connection String",
     r'(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\'<>]{10,}',
     Severity.CRITICAL,
     "Direct database access, data exfiltration"),
    ("Basic Auth Header",
     r'(?i)authorization[\s:]*basic\s+[A-Za-z0-9+/=]{10,}',
     Severity.HIGH,
     "Authenticated access with hardcoded credentials"),

    # ── Internal Endpoints (MEDIUM) ──────────────────────────
    ("Internal API Endpoint",
     r'(?i)["\']/(api|internal|admin|debug|private|staging'
     r'|v[0-9])/[a-z0-9/_-]+["\']',
     Severity.MEDIUM,
     "Hidden attack surface, privilege escalation paths"),
    ("Internal IP Address",
     r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
     r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
     r'|192\.168\.\d{1,3}\.\d{1,3})',
     Severity.LOW,
     "Network topology disclosure"),

    # ── Info Leak (LOW) ──────────────────────────────────────
    ("Email Address",
     r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
     Severity.LOW,
     "Phishing targets, username enumeration"),
    ("Source Map Reference",
     r'//# sourceMappingURL=\S+\.map',
     Severity.LOW,
     "Source code disclosure via source maps"),
]

# Quick lookup: pattern_name → impact string
PATTERN_IMPACT: dict[str, str] = {
    name: impact
    for name, _regex, _severity, impact in JS_SECRET_PATTERNS
}

# Remediation templates per pattern type
_REMEDIATION_TEMPLATES: dict[str, str] = {
    "AWS Access Key":
        "Rotate the key in AWS IAM immediately. Remove from frontend "
        "code. Use server-side proxy for AWS API calls.",
    "AWS Secret Key":
        "Rotate the key in AWS IAM immediately. Remove from frontend "
        "code. Use server-side proxy for AWS API calls.",
    "Google API Key":
        "Restrict the key to specific APIs and referrers in Google "
        "Cloud Console. Rotate if unrestricted.",
    "Stripe Live Key":
        "Rotate the key in the Stripe Dashboard immediately. Never "
        "expose secret keys in frontend code.",
    "Stripe Publishable Key":
        "Restrict the key to specific domains. Consider if exposure "
        "is intentional (publishable keys are designed for frontend).",
    "GitHub Token":
        "Revoke the token on GitHub immediately. Audit repository "
        "access logs for unauthorized actions.",
    "Slack Token":
        "Revoke the token in Slack admin. Audit workspace for "
        "unauthorized message access.",
    "Private Key":
        "Revoke and rotate the associated certificate/key pair. "
        "Never embed private keys in frontend code.",
    "JWT Secret Hardcoded":
        "Rotate the signing key. Move JWT validation server-side. "
        "Use asymmetric keys (RS256) instead of shared secrets.",
    "Hardcoded Password":
        "Remove the password from source code. Use environment "
        "variables or a secrets manager. Rotate the credential.",
    "Database Connection String":
        "Remove the connection string from frontend code immediately. "
        "Rotate the database credentials. Restrict network access.",
    "Internal API Endpoint":
        "Review access controls on the internal endpoint. Consider "
        "whether it should be exposed to the frontend at all.",
    "Internal IP Address":
        "Remove internal IPs from client-side code to prevent "
        "network topology disclosure.",
    "Source Map Reference":
        "Remove source map references from production builds. "
        "Configure bundler to skip sourcemap generation for prod.",
    "Firebase URL":
        "Review Firebase Security Rules. Ensure authentication is "
        "required for read/write operations.",
    "Basic Auth Header":
        "Remove hardcoded credentials from frontend code. Use "
        "session-based auth or OAuth tokens.",
    "Azure/MS Client Secret":
        "Rotate the client secret in Azure AD. Move auth flow "
        "server-side.",
    "Mailgun API Key":
        "Rotate the key in Mailgun dashboard. Move email sending "
        "to a server-side endpoint.",
    "Twilio API Key":
        "Rotate the key in Twilio console. Move API calls "
        "server-side.",
    "SendGrid API Key":
        "Rotate the key in SendGrid dashboard. Move email sending "
        "to a server-side endpoint.",
    "Heroku API Key":
        "Rotate the key via Heroku CLI. Move deployment operations "
        "to CI/CD pipelines.",
}


# ── Secret masking ───────────────────────────────────────────────

def mask_secret(value: str) -> str:
    """Mask a secret value for safe display in findings/reports."""
    if not value:
        return ""
    if len(value) <= 12:
        return value[:3] + "***"
    return f"{value[:6]}...{value[-4:]}"


# ── Deduplication ────────────────────────────────────────────────

def deduplicate_secrets(secrets: list[JsSecret]) -> list[WebFinding]:
    """Group by (pattern_name, value_hash).
    Same key in 5 files → 1 finding with 5 evidence lines."""
    groups: dict[tuple, dict] = {}
    for s in secrets:
        secret_hash = hashlib.sha256(
            s.matched_value.encode()).hexdigest()
        key = (s.pattern_name, secret_hash)
        if key not in groups:
            groups[key] = {
                "pattern":  s.pattern_name,
                "severity": s.severity,
                "value":    s.matched_value,
                "impact":   PATTERN_IMPACT.get(
                    s.pattern_name,
                    "Potential information disclosure or "
                    "unauthorized access."),
                "files":    [],
            }
        location = (f"{s.source_file}:{s.line_number}"
                    if s.line_number else s.source_file)
        if location not in groups[key]["files"]:
            groups[key]["files"].append(location)

    findings = []
    for (pattern_name, _), group in groups.items():
        evidence = [f"Masked value: {mask_secret(group['value'])}"]
        evidence += [f"Found in: {f}" for f in group["files"]]
        # Same shape as `evidence` but with the un-masked value.  Kept
        # in `raw_evidence` so the Info-dialog SHOW RAW toggle can
        # swap the rendered block without re-fetching anything.
        raw_evidence = [f"Raw value: {group['value']}"]
        raw_evidence += [f"Found in: {f}" for f in group["files"]]
        findings.append(WebFinding(
            title=f"Hardcoded {group['pattern']} in JavaScript",
            severity=group["severity"],
            confidence=Confidence.HIGH,
            source="Bloody Crawl",
            endpoint=(group["files"][0].split(":")[0]
                      if group["files"] else ""),
            evidence=evidence,
            raw_evidence=raw_evidence,
            impact=group["impact"],
            remediation=_REMEDIATION_TEMPLATES.get(
                pattern_name,
                "Remove the secret from frontend code, rotate "
                "the exposed value, and move sensitive API calls "
                "server-side."),
            tags=["js-secret",
                  pattern_name.lower().replace(" ", "-")],
        ))
    return findings


# ── Assault State (shared pipeline data) ─────────────────────────

@dataclass
class AssaultState:
    """Shared state between WEB ASSAULT tools on a card.

    Each tool reads results from previous steps here.
    Example: Injection Tester reads assault_state.forms to know
    which forms to test.
    """
    # Oracle results
    oracle_done:     bool = False
    tech_stack:      list[str] = field(default_factory=list)
    framework:       str = ""
    api_endpoints:   list[dict] = field(default_factory=list)
    graphql_schema:  dict = field(default_factory=dict)

    # Bloody Crawl results
    crawl_done:      bool = False
    endpoints:       dict = field(default_factory=dict)
    forms:           list[dict] = field(default_factory=list)
    parameters:      list[dict] = field(default_factory=list)
    upload_forms:    list[dict] = field(default_factory=list)
    js_secrets:      list[JsSecret] = field(default_factory=list)
    jwt_tokens:      list[str] = field(default_factory=list)
    idor_findings:   list[dict] = field(default_factory=list)
    redirect_chains: dict = field(default_factory=dict)

    # Injection Tester results
    injection_done:  bool = False
    confirmed_vulns: list[WebFinding] = field(default_factory=list)

    # JWT Analyzer results
    jwt_done:        bool = False
    jwt_findings:    list[WebFinding] = field(default_factory=list)

    def summary(self) -> dict:
        """Quick status for the pipeline UI."""
        return {
            "oracle":    {"done": self.oracle_done,
                          "count": len(self.tech_stack)},
            "crawl":     {"done": self.crawl_done,
                          "forms": len(self.forms),
                          "params": len(self.parameters),
                          "secrets": len(self.js_secrets)},
            "injection": {"done": self.injection_done,
                          "vulns": len(self.confirmed_vulns)},
            "jwt":       {"done": self.jwt_done,
                          "vulns": len(self.jwt_findings)},
        }

    def get_injectable_targets(self) -> list[dict]:
        """Return targets ready for Injection Tester.
        Merges forms + GET parameters found by Crawl."""
        targets = []
        for form in self.forms:
            for fld in form.get("fields", []):
                targets.append({
                    "url":          form["action"],
                    "method":       form["method"],
                    "parameter":    fld,
                    "source":       "form",
                    "has_password": form.get("has_password", False),
                })
        for p in self.parameters:
            targets.append({
                "url":       p["url"],
                "method":    p.get("method", "GET"),
                "parameter": p["param"],
                "source":    "query_string",
            })
        return targets

    def to_dict(self) -> dict:
        """Serialize for session save."""
        return {
            "oracle_done":     self.oracle_done,
            "tech_stack":      self.tech_stack,
            "framework":       self.framework,
            "api_endpoints":   self.api_endpoints,
            "crawl_done":      self.crawl_done,
            "forms":           self.forms,
            "parameters":      self.parameters,
            "upload_forms":    self.upload_forms,
            "js_secrets":      [{"pattern_name": s.pattern_name,
                                 "severity": s.severity.value,
                                 "matched_value": mask_secret(s.matched_value),
                                 "source_file": s.source_file,
                                 "line_number": s.line_number}
                                for s in self.js_secrets],
            "jwt_tokens":      ["***masked***" for _ in self.jwt_tokens],
            "idor_findings":   self.idor_findings,
            "injection_done":  self.injection_done,
            "confirmed_vulns": [v.to_dict() for v in self.confirmed_vulns],
            "jwt_done":        self.jwt_done,
            "jwt_findings":    [v.to_dict() for v in self.jwt_findings],
        }
