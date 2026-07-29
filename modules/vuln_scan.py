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
HAWK - Phase 4: Vulnerability Analysis
Includes Greenbone/OpenVAS integration with install/skip flow.
"""

from modules.base import BaseModule, Tool


class VulnScanModule(BaseModule):

    PHASE_ID   = "vuln_scan"
    PHASE_NAME = "VULNERABILITY ANALYSIS"

    TOOLS = [
        Tool(
            id="nikto",
            name="NIKTO",
            desc="Web server vulnerability scanner",
            cmd_template="nikto -h http://{target}",
            binary="nikto",
            category="web",
        ),
        Tool(
            id="nikto_ssl",
            name="NIKTO (SSL)",
            desc="HTTPS web server scan",
            cmd_template="nikto -h https://{target} -ssl",
            binary="nikto",
            category="web",
        ),
        Tool(
            id="nuclei",
            name="NUCLEI",
            desc="Template-based CVE scanner (medium/high/critical)",
            cmd_template="nuclei -u http://{target} -severity medium,high,critical",
            binary="nuclei",
            category="web",
        ),
        Tool(
            id="greenbone",
            name="GREENBONE / OpenVAS",
            desc="Full vulnerability scan — install wizard included",
            cmd_template="gvm-cli socket --xml '<get_version/>'",
            binary="gvm-cli",
            category="openvas",
        ),
        Tool(
            id="wpscan",
            name="WPSCAN",
            desc="WordPress vulnerability scanner",
            cmd_template="wpscan --url http://{target} --enumerate u,p,t",
            binary="wpscan",
            category="cms",
        ),
        Tool(
            id="sqlmap",
            name="SQLMAP",
            desc="Automated SQL injection detection",
            cmd_template="sqlmap -u http://{target} --dbs --batch",
            binary="sqlmap",
            category="web",
        ),
        # Searchsploit removed from this card on user request — it now
        # lives only as the Target Intel "SEARCH EXPLOITS" button
        # (target_intel_widget._run_exploit_search), which feeds it
        # context-aware queries built from current findings.  Running
        # it as a generic vuln-scan tool produced thousands of unrelated
        # hits and duplicated functionality.
    ]

    def get_tool_display_state(self, tool_id: str) -> tuple:
        """
        Returns (available: bool, state_label: str) for UI display.
        For Greenbone, shows NOT INSTALLED but still enabled so
        the install wizard can be launched.
        """
        from modules.base import Tool
        tool = self.get_tool(tool_id)
        if tool is None:
            return False, "MISSING"
        if tool_id == "greenbone":
            import shutil
            if shutil.which("gvm-cli"):
                from utils.runner import GreenBoneRunner
                if GreenBoneRunner.is_running():
                    return True, "RUNNING"
                return True, "INSTALLED"
            return False, "NOT INSTALLED"  # still show as clickable
        return tool.is_available(), ("INSTALLED" if tool.is_available()
                                     else "NOT INSTALLED")
