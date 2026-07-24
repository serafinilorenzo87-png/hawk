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
HAWK — Web Assault phase.

Two-tool phase:
  • ORACLE — webapp profiling engine (tech stack, auth, API, CVEs)
  • BLOODY CRAWL — passive HTML endpoint extraction + active probing
    (redirects, IDOR detection, recursive crawl)

Orchestration logic lives in utils.web_oracle.WebOracleRunner — this
module just registers the Tools so the Kill Chain card picks them up.
"""

from modules.base import BaseModule, Tool


class WebOracleModule(BaseModule):
    PHASE_ID   = "web_assault"
    PHASE_NAME = "WEB ASSAULT"

    TOOLS = [
        Tool(
            id="web_oracle",
            name="ORACLE",
            desc=("Fingerprints tech, maps auth & API surface, "
                  "detects exposures & known CVEs — then recommends "
                  "what to attack."),
            cmd_template="",
            binary="whatweb",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            id="bloody_crawl",
            name="BLOODY CRAWL",
            desc=("Extracts real endpoints from HTML (href, form, JS), "
                  "probes each one, follows redirects, detects IDOR "
                  "patterns — smarter than brute-force."),
            cmd_template="",
            binary="curl",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            id="injection_tester",
            name="INJECTION",
            desc=("Tests parameters for SQLi / XSS / LFI / SSTI / "
                  "command-injection / upload-bypass — Safe mode is "
                  "pure curl; Aggressive uses sqlmap / dalfox / commix "
                  "if installed.  Auto-fed from Bloody Crawl."),
            cmd_template="",
            binary="curl",
            category="web",
            requires_sudo=False,
        ),
        Tool(
            id="jwt_analyzer",
            name="JWT ANALYZER",
            desc=("Decodes JWTs and tests for weak signing secrets, "
                  "alg:none acceptance, and role-escalation paths.  "
                  "Pure Python — no external dependencies.  "
                  "Auto-fed from Bloody Crawl's captured tokens."),
            cmd_template="",
            binary="python3",
            category="web",
            requires_sudo=False,
        ),
    ]

    def get_tools(self):
        return self.TOOLS
