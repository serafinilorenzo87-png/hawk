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
HAWK parsers — post-processing of enumeration tool output.

Each parser consumes ANSI-stripped text and pushes auto-findings into
`app.target_intel` and credentials into `app.cred_store`, producing the
same user-visible effect as a tool run (blink animation + fresh-badge).
"""
