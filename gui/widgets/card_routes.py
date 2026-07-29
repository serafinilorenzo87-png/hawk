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
HAWK - Kill Chain Card Widget v1.0
- Port-aware routing for all tools
- Hydra: wordlist dropdown from metasploit/seclists + browse
- MSF card: check DB + guide user
- Nmap custom: free command field
- Right-click context menu on all entries
- smbclient/crackmapexec → auto-populate intel
- ssh_banner/ftp_anon port-aware fix
- No popup for 0 ports found
- WinRM excluded from HTTP tools
"""

from gui.widgets.card_routes_access import CardAccessRoutesMixin
from gui.widgets.card_routes_scan import CardScanRoutesMixin
from gui.widgets.card_routes_oracle_hydra import CardOracleHydraRoutesMixin
from gui.widgets.card_routes_responder import CardResponderRoutesMixin
from gui.widgets.card_routes_web import CardWebRoutesMixin
from gui.widgets.card_routes_network import CardNetworkRoutesMixin
from gui.widgets.card_routes_assault import CardAssaultRoutesMixin


class CardRoutesMixin(
    CardAccessRoutesMixin,
    CardScanRoutesMixin,
    CardOracleHydraRoutesMixin,
    CardResponderRoutesMixin,
    CardWebRoutesMixin,
    CardNetworkRoutesMixin,
    CardAssaultRoutesMixin,
):
    """Composed route mixin for KillChainCard."""
    pass
