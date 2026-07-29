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
HAWK - Dialogs v1.0
- Greenbone install: 10-second countdown popup watching xterm for password
- Selectable text: CTkTextbox (disabled) for all technical content
- OS detection dialog fixed (grab_set)
- Netcat with service-specific verification commands
"""

# Compatibility facade.  Keep importing from gui.dialogs exactly as before;
# implementation is split by domain in dialogs_*.py.
from gui.dialogs_common import *
from gui.dialogs_core import *
from gui.dialogs_privesc import *
from gui.dialogs_bloodhound import *
from gui.dialogs_ops import *
