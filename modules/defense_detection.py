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
HAWK - Defense Detection Module
Analyzes scan output to detect:
  - Honeypots
  - IDS/IPS
  - Firewalls / WAF
  - DMZ placement
Produces DefenseAlert objects saved in the session.
"""

import re
from utils.session import DefenseAlert


class DefenseDetector:
    """
    Analyzes raw output lines from recon/scanning tools
    and produces DefenseAlert findings.
    """

    # ── Honeypot heuristics ──────────────────────────────────────────────────

    HONEYPOT_BANNERS = [
        "welcome to vulnerable",
        "honeypot",
        "cowrie",
        "dionaea",
        "kippo",
        "glastopf",
        "amun",
    ]

    HONEYPOT_PORT_PATTERNS = [
        # Too many well-known ports open at once is suspicious
        # checked dynamically
    ]

    # ── IDS/IPS heuristics ───────────────────────────────────────────────────

    IDS_PATTERNS = [
        r"connection reset by peer",
        r"connection refused after \d+ attempt",
        r"rst.*flood",
        r"rate.limit",
        r"too many connection",
        r"blocked",
        r"forbidden.*ids",
        r"intrusion",
    ]

    # ── Firewall heuristics ───────────────────────────────────────────────────

    # Specific signals of an active packet filter rejecting traffic.
    # Bare \bfiltered\b used to live here but matched nmap's harmless
    # summary "Not shown: 994 filtered ports", which appears on every
    # scan — turning the alert into noise that fired on every target,
    # including clean HTB boxes.  Each pattern below corresponds to a
    # firewall behaviour that is genuinely informative (ICMP-based
    # rejection or TTL anomaly).
    FIREWALL_PATTERNS = [
        r"admin-prohibited",
        r"host.*prohibited",
        r"net.*prohibited",
        r"packet filtered",
        r"no route to host",
        r"time.?to.?live exceeded",
    ]

    # ── WAF heuristics ────────────────────────────────────────────────────────

    # Vendor-specific signals ONLY.  Earlier iterations also matched
    # `403 forbidden`, `406 not acceptable`, the bare `waf` token,
    # and the phrase `web application firewall` — all four matched
    # legitimate output of unrelated tools (a single 403 on /rpc,
    # the literal word "WAFW00F" in tool banners, nuclei template
    # names like "WAF Detection", and the tagline `The Web
    # Application Firewall Fingerprinting Toolkit` that wafw00f
    # prints on every run) and produced spurious "WAF detected —
    # 80%" alerts on targets where wafw00f itself correctly
    # reported NO WAF (e.g. vanilla IIS 7.5 on Metasploitable3).
    # We trust wafw00f for the "is there a WAF?" question;
    # HAWK's role here is just to surface vendor identification
    # when it leaks through other tools' output.
    WAF_PATTERNS = [
        r"cloudflare",
        r"mod_security",
        r"sucuri",
        r"incapsula",
        r"akamai",
        r"barracuda",
    ]

    # ── DMZ heuristics ────────────────────────────────────────────────────────

    DMZ_PATTERNS = [
        r"ttl.*6[0-4]",         # low hop TTL suggests 1-2 hops
        r"1 hop",
        r"2 hops",
    ]

    def analyze(self, lines: list, target: str) -> list:
        """
        Analyze a list of output lines and return DefenseAlert objects.
        lines: list of (level, text) or plain str
        """
        alerts = []
        text_lines = []
        for l in lines:
            if isinstance(l, tuple):
                text_lines.append(l[1].lower())
            else:
                text_lines.append(str(l).lower())

        full_text = "\n".join(text_lines)

        alerts += self._check_honeypot(text_lines, full_text)
        alerts += self._check_ids(full_text)
        alerts += self._check_firewall(full_text)
        alerts += self._check_waf(full_text)
        alerts += self._check_dmz(full_text)

        return alerts

    def _check_honeypot(self, lines: list, full_text: str) -> list:
        alerts = []

        # Banner check
        for banner in self.HONEYPOT_BANNERS:
            if banner in full_text:
                alerts.append(DefenseAlert(
                    alert_type="honeypot",
                    description=f"Suspicious banner detected: '{banner}'",
                    confidence=75,
                    recommendation=(
                        "Target may be a honeypot. Proceed with extreme caution. "
                        "Verify with other tools before continuing exploitation."
                    ),
                ))

        # Too many open ports
        open_ports = len(re.findall(r'\bopen\b', full_text))
        if open_ports > 50:
            alerts.append(DefenseAlert(
                alert_type="honeypot",
                description=f"Detected {open_ports} open ports — unusually high number.",
                confidence=60,
                recommendation=(
                    "A very high number of open ports is typical of honeypots emulating "
                    "services. Consider whether to proceed or flag it in the report."
                ),
            ))

        # Identical responses pattern
        responses = re.findall(r'(\d+)/tcp\s+open\s+(\w+)', full_text)
        if len(responses) > 5:
            services = [s[1] for s in responses]
            if len(set(services)) == 1:
                alerts.append(DefenseAlert(
                    alert_type="honeypot",
                    description="All ports report the same service — possible emulation.",
                    confidence=70,
                    recommendation=(
                        "Identical responses on different ports suggest a honeypot. "
                        "Verify manually before proceeding."
                    ),
                ))

        return alerts

    def _check_ids(self, full_text: str) -> list:
        alerts = []
        for pattern in self.IDS_PATTERNS:
            if re.search(pattern, full_text, re.I):
                alerts.append(DefenseAlert(
                    alert_type="ids",
                    description=f"Possible IDS/IPS detected: pattern '{pattern}'",
                    confidence=65,
                    recommendation=(
                        "An IDS/IPS appears to be active. Consider reducing scan speed "
                        "(-T1 or -T2 with nmap) and increasing delays between requests. "
                        "Avoid noisy tools like masscan at high speed."
                    ),
                ))
                break
        return alerts

    def _check_firewall(self, full_text: str) -> list:
        # Only fire on EXPLICIT active-rejection signals (ICMP
        # admin/host/net-prohibited, "packet filtered", "no route to
        # host", TTL exceeded).  We deliberately do NOT alert on the
        # mere presence of filtered ports — every CTF/lab host and
        # every Windows target with the default firewall enabled shows
        # filtered ports, so a ratio-based alert is indistinguishable
        # noise.  The filtered-port count is already visible in the
        # raw nmap output; surfacing it again here added nothing.
        alerts = []
        fw_matches = []
        for pattern in self.FIREWALL_PATTERNS:
            if re.search(pattern, full_text, re.I):
                fw_matches.append(pattern)

        if fw_matches:
            desc = (
                f"Network-level firewall actively rejecting traffic "
                f"({len(fw_matches)} indicator(s): "
                f"{', '.join(fw_matches)}). This is a LAYER 3/4 "
                f"packet filter — iptables, Windows Firewall, pfSense, "
                f"router ACL, cloud security group, etc."
            )
            alerts.append(DefenseAlert(
                alert_type="firewall",
                description=desc,
                confidence=70,
                recommendation=(
                    "NOTE — this is NOT a Web Application Firewall (WAF).\n"
                    "Wafw00f will not detect this because wafw00f only "
                    "inspects HTTP/HTTPS layer 7. A target can have a "
                    "network firewall AND no WAF at the same time — "
                    "that's actually the common case (e.g. any Windows "
                    "server has Windows Firewall enabled by default).\n\n"
                    "What to do:\n"
                    "  • nmap --script firewalk <target>     # map ACL rules\n"
                    "  • nmap -f -T2 <target>                # fragmented, slow\n"
                    "  • Try source port 53/udp or 80/tcp (often allowed out):\n"
                    "      nmap --source-port 53 -sU <target>\n"
                    "  • Pivot through a compromised host inside the perimeter."
                ),
            ))
        return alerts

    def _check_waf(self, full_text: str) -> list:
        # Graduated confidence based on how many DISTINCT vendor
        # signals show up in the output.  More converging fingerprints
        # = stronger evidence.  Caveats:
        #   • This is still a keyword scan on flat text — no notion
        #     of "this match came from an HTTP response header vs
        #     a tool banner".  See `feedback_waf_detect_future.md`
        #     for the planned structured-line refactor that would
        #     enable Option-2 context-aware weighting.
        #   • The previous implementation hard-coded confidence=80
        #     for every match (cloudflare-as-CDN and a tangential
        #     mention in nuclei output got the same label).
        # Scoring:
        #   1 vendor matched  -> 70
        #   2 vendor matched  -> 90
        #   3+ vendor matched -> 95 (capped — never claim 100%
        #                            without a real verification step)
        matched = []
        for pattern in self.WAF_PATTERNS:
            if re.search(pattern, full_text, re.I):
                matched.append(pattern)
        if not matched:
            return []

        if   len(matched) >= 3: conf = 95
        elif len(matched) == 2: conf = 90
        else:                   conf = 70

        vendors_str = ", ".join(matched)
        return [DefenseAlert(
            alert_type="waf",
            description=(
                f"Web Application Firewall (WAF) detected — "
                f"{len(matched)} vendor signal(s): {vendors_str}.  "
                f"LAYER 7 control inspecting HTTP/HTTPS bodies and "
                f"headers (Cloudflare, AWS WAF, ModSecurity, F5 ASM, "
                f"Imperva, etc.).  Separate from any network firewall "
                f"that may also be present."
            ),
            confidence=conf,
            recommendation=(
                "NOTE — a WAF only matters if you're attacking "
                "the HTTP(S) surface. It does NOT stop network "
                "scans on non-web ports (SMB, RDP, SSH, ...).\n\n"
                "What to do:\n"
                "  • Run wafw00f -a <url>          # identify WAF vendor\n"
                "  • Try encoding tricks (URL, double-URL, unicode)\n"
                "  • Case variation: `SeLeCt` instead of `select`\n"
                "  • Custom Host header or X-Forwarded-For bypass\n"
                "  • Origin-IP direct-connect (skip the CDN/WAF)"
            ),
        )]

    def _check_dmz(self, full_text: str) -> list:
        alerts = []
        # Low hop count from traceroute
        if re.search(r'^\s*[12]\s+\d+\.\d+', full_text, re.M):
            alerts.append(DefenseAlert(
                alert_type="dmz",
                description="Low hop count (1-2 hops) — target may be in a DMZ.",
                confidence=55,
                recommendation=(
                    "Target appears to be separated by few routers. May be in a DMZ. "
                    "Traffic to/from this host is likely logged. "
                    "Verify with traceroute and gateway analysis."
                ),
            ))

        # Subnet typical of DMZ
        if re.search(r'172\.16\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+', full_text):
            if re.search(r'gateway|router|dmz|perimeter', full_text, re.I):
                alerts.append(DefenseAlert(
                    alert_type="dmz",
                    description="Private IP with gateway/DMZ references detected.",
                    confidence=50,
                    recommendation=(
                        "Possible target in segmented network. "
                        "Analyze network topology before proceeding with exploitation."
                    ),
                ))

        return alerts


# ─── OpSec Notes Generator ────────────────────────────────────────────────────

class OpSecNotesGenerator:
    """
    Generates operational security awareness notes for each phase.
    These are general-purpose educational notes, not operational attack guides.
    """

    @staticmethod
    def get_notes(phase_id: str) -> list:
        from utils.config import OPSEC_NOTES
        return OPSEC_NOTES.get(phase_id, [])

    @staticmethod
    def format_for_terminal(phase_id: str) -> list:
        """Returns list of (level, text) tuples for terminal display."""
        notes = OpSecNotesGenerator.get_notes(phase_id)
        if not notes:
            return []
        lines = [
            ("section", "  ┌─ OPSEC NOTES — what this phase generated ─────────────"),
            ("dim",     "  Useful information for the final report."),
            ("dim",     "  The Blue Team could have detected:"),
            ("dim",     ""),
        ]
        for artifact, general_countermeasure in notes:
            lines.append(("warn", f"  ⚠  {artifact}"))
            lines.append(("dim",  f"     Countermeasure category: {general_countermeasure}"))
            lines.append(("dim",  ""))
        return lines
