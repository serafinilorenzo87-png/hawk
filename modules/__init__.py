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

"""HAWK modules package"""
from modules.recon         import ReconModule
from modules.scanning      import ScanningModule
from modules.enumeration   import EnumerationModule
from modules.web_oracle    import WebOracleModule
from modules.vuln_scan     import VulnScanModule
from modules.ad_pentesting import ADPentestingModule
from modules.exploitation  import ExploitationModule
from modules.post_exploit  import PostExploitModule
from modules.lateral       import LateralModule
from modules.reporting     import ReportingModule

# Order here drives the Kill Chain panel.  WEB ASSAULT sits between
# enumeration and vulnerability analysis: once enum surfaces HTTP/S
# services, Oracle profiles them into a structured attack plan
# (tech, auth, API, exposures, CVEs) and Bloody Crawl maps the real
# endpoint surface — cheaper and quieter than blind vuln scans.
# AD PENTESTING still follows EXPLOITATION (see ad_pentesting.py).
ALL_MODULES = [
    ReconModule, ScanningModule, EnumerationModule, WebOracleModule,
    VulnScanModule, ADPentestingModule,
    ExploitationModule, PostExploitModule, LateralModule, ReportingModule,
]
MODULE_MAP = {m.PHASE_ID: m for m in ALL_MODULES}
