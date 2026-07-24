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

from gui.widgets.card_parsers_service import CardServiceParserMixin
from gui.widgets.card_parsers_web import CardWebParserMixin
from gui.widgets.card_parsers_ad import CardADParserMixin
from gui.widgets.card_parsers_post import CardPostParserMixin


class CardIntelParserMixin(
    CardServiceParserMixin,
    CardWebParserMixin,
    CardADParserMixin,
    CardPostParserMixin,
):
    """Composed parser mixin for KillChainCard."""
    pass
