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
HAWK — Report engine (pillar C).

Pipeline:  Unified Finding model  ->  [Section Providers]  ->  [Render Targets]

* A *section provider* returns STRUCTURED DATA (a Section made of typed
  Blocks), never rendered markup.  Rendering belongs to the render
  target, so adding a provider that reuses the existing Block vocabulary
  needs zero changes to any render target.
* A *render target* (HTML / CSV / Markdown) consumes the same ordered
  list of Sections plus the shared ReportContext, so all formats report
  identical numbers (same effective_severity, same curation applied).
* The ReportContext applies curation ONCE: findings with included=False
  or false_positive=True are dropped from both the counts and the body,
  and every count uses Finding.effective_severity() — never raw
  severity.  The curation UI is a later fast-follow; today overrides are
  None so this is a no-op, but the engine already honours them.

See engine.generate() for the entry point.
"""

from modules.report.engine import generate, result_summary, REPORT_FORMATS

__all__ = ["generate", "result_summary", "REPORT_FORMATS"]
