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
HAWK - Phase 10: Reporting.

Thin facade over the unified report engine (modules.report).  The engine
is the single source for every output format; this module keeps the
historical ``ReportingModule.generate_report(session) -> path`` entry
point the GUI button calls.
"""

from modules.base import BaseModule, Tool


class ReportingModule(BaseModule):

    PHASE_ID   = "reporting"
    PHASE_NAME = "REPORTING"

    TOOLS = []  # Reporting has no runnable tools; it uses generate_report()

    @staticmethod
    def generate_report(session) -> str:
        """Generate the client report and return the path to the PRIMARY
        deliverable (self-contained HTML).

        Reconciliation: the report engine (modules.report) is now the
        single serializer for ALL formats.  This method used to hand-build
        a Markdown file in SESSIONS_DIR; it now delegates to the engine,
        which writes HTML + CSV + Markdown into the dedicated REPORTS_DIR
        from the unified Finding model — honouring curation
        (included / false_positive) and effective_severity, and sourcing
        phase metadata from config.KILL_CHAIN_PHASES.  The GUI button
        keeps its one-path contract: it receives the HTML path.
        """
        from modules.report import generate
        paths = generate(session)
        return (paths.get("html") or paths.get("md")
                or next(iter(paths.values()), ""))
