# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0

"""
HAWK — Crack strategy recommendation engine.

Pure function: given the hash + its context (type, username, session
domain, device info, past attempts), return a ranked list of
strategies HAWK thinks are worth trying FIRST.  The CRACK dialog
surfaces the top recommendation as a big banner at the top plus a
USE-THIS-STRATEGY button.

No GUI imports, no subprocess — plug into any dialog.
"""

from __future__ import annotations

from typing import Optional


def recommend(cred: dict,
              device_info: dict,
              session_ctx: Optional[dict] = None,
              past_attempts: Optional[list] = None) -> list:
    """Return a ranked list of recommendation dicts.

    Args:
        cred:          a Credential-like dict with keys
                        username / hash_type / services / host
        device_info:   output of utils.crack_runner.detect_devices()
        session_ctx:   optional dict, e.g. {target_domain, company_name,
                        discovered_users}
        past_attempts: optional list of strategy names already tried
                        unsuccessfully on this hash

    Each recommendation:
        {
            "strategy":    "FAST"|"RULE-BASED"|"HYBRID"|"TARGET"|
                            "MASK"|"FULL STACK"|"CRACK ONLINE",
            "reason":      short one-liner (shown in the banner),
            "priority":    float 0-100 (higher = more recommended),
            "est_time":    human-readable estimate,
        }

    Ordered by priority descending — top is what HAWK shows first.
    """
    session_ctx = session_ctx or {}
    past = set(past_attempts or [])
    recs = []

    ht = (cred.get("hash_type") or "").lower()
    uname = (cred.get("username") or "").lower()
    has_gpu = device_info.get("has_gpu", False)
    cpu_only = not has_gpu
    has_hashcat = device_info.get("has_hashcat", False)

    # ── Rule 1: super-slow algorithms — don't bother offline ─────────
    if ht in ("bcrypt", "argon2", "scrypt", "pbkdf2"):
        recs.append({
            "strategy": "CRACK ONLINE",
            "reason":   (f"{cred.get('hash_type')} is designed to be "
                         "slow to brute — even GPU cracks are rare.  "
                         "Online breach DBs are your realistic shot."),
            "priority": 95,
            "est_time": "seconds (if in breach DB)",
        })
        recs.append({
            "strategy": "MASK",
            "reason":   "Only attempt offline if you know the "
                        "structure (e.g. 4-digit PIN, short fixed "
                        "length).",
            "priority": 20,
            "est_time": "hours-days",
        })
        return _rank(recs)

    # ── Rule 2: fast-hash types with online quick-win ─────────────────
    # MD5/SHA1 are instantly cracked by crackstation.net (huge
    # rainbow table), saves the user the hassle of local cracking.
    if ht in ("md5", "sha1", "sha256") and cpu_only:
        recs.append({
            "strategy": "CRACK ONLINE",
            "reason":   (f"{cred.get('hash_type')} + no GPU → "
                         "crackstation finds these in 2 sec (free, no "
                         "signup)."),
            "priority": 90,
            "est_time": "seconds",
        })

    # ── Rule 3: NetNTLMv2 + CPU-only (the user's typical setup) ──────
    if ht == "netntlmv2" and cpu_only:
        if "RULE-BASED" not in past:
            recs.append({
                "strategy": "RULE-BASED",
                "reason":   ("NetNTLMv2 + CPU-only VM → RULE-BASED is "
                             "the sweet spot.  Finds Admin123!, "
                             "Welcome1, P@ssw0rd1 in 9-14 min."),
                "priority": 88,
                "est_time": "9-14 min CPU",
            })
        else:
            recs.append({
                "strategy": "HYBRID",
                "reason":   ("RULE-BASED already tried — HYBRID adds "
                             "numeric+symbol suffixes on top-100k "
                             "words.  Different candidate set."),
                "priority": 82,
                "est_time": "5-10 min CPU",
            })

    # ── Rule 4: NetNTLMv2 + GPU available ────────────────────────────
    if ht == "netntlmv2" and has_gpu and "RULE-BASED" not in past:
        recs.append({
            "strategy": "RULE-BASED",
            "reason":   "GPU available — RULE-BASED (best64 + "
                        "rockyou) gets done in ~30 sec.",
            "priority": 92,
            "est_time": "30s-2 min GPU",
        })

    # ── Rule 5: service account hint (username = svc_* / Service) ────
    # These rarely change password — TARGET dict is gold.
    is_service = (
        "svc" in uname or
        uname.startswith("service") or
        uname.endswith("$") or
        uname in ("sqlservice", "iisservice"))
    has_domain = bool(session_ctx.get("target_domain"))
    if is_service and has_domain:
        recs.append({
            "strategy": "TARGET",
            "reason":   (f"'{cred.get('username')}' looks like a "
                         "service account — password likely themed "
                         "around company/domain, rarely rotated.  "
                         "TARGET profile dict often nails these."),
            "priority": 85,
            "est_time": "1-3 min after dict build",
        })

    # ── Rule 6: admin-set hashes (username = admin*, Administrator) ──
    is_admin = (
        uname == "administrator" or
        uname.startswith("admin") or
        "domain admin" in uname)
    if is_admin and "RULE-BASED" not in past:
        recs.append({
            "strategy": "RULE-BASED",
            "reason":   ("Admin-set password: usually a capitalized "
                         "common word + digits + symbol.  "
                         "best64.rule catches ~80% of this pattern."),
            "priority": 86,
            "est_time": "9-14 min CPU / 30s GPU",
        })

    # ── Rule 7: 2+ attempts already failed → try FULL STACK or online
    if len(past) >= 2:
        recs.append({
            "strategy": "CRACK ONLINE",
            "reason":   (f"{len(past)} local attempts failed — this "
                         "password is either truly random or not in "
                         "common wordlists.  Breach DBs (hashes.com) "
                         "may still hit."),
            "priority": 87,
            "est_time": "seconds-minutes",
        })
        if has_domain:
            recs.append({
                "strategy": "TARGET",
                "reason":   ("Last local shot before going online: "
                             "TARGET profile with full company/domain/"
                             "year context.  If this fails the "
                             "password is likely truly random."),
                "priority": 80,
                "est_time": "5-10 min incl. dict build",
            })

    # ── Rule 8: nothing matched → safe default recommendation ───────
    if not recs:
        if not has_hashcat:
            recs.append({
                "strategy": "FAST",
                "reason":   "hashcat not installed — FAST (john) is "
                            "your only local option.",
                "priority": 50,
                "est_time": "3-8 min CPU",
            })
        else:
            recs.append({
                "strategy": "RULE-BASED",
                "reason":   "Good general-purpose starting point for "
                            "most modern hashes.",
                "priority": 70,
                "est_time": ("9-14 min CPU"
                             if cpu_only else "30s-2 min GPU"),
            })

    # FULL STACK — always offered as a secondary "just-let-it-run" suggestion
    if "FULL STACK" not in past and len(past) < 2:
        recs.append({
            "strategy": "FULL STACK",
            "reason":   ("Runs FAST → RULE-BASED → HYBRID → TARGET in "
                         "sequence, stops at first hit.  ~25-35 min on "
                         "CPU, much less on GPU.  Set and forget."),
            "priority": 60,
            "est_time": ("25-35 min CPU" if cpu_only
                         else "2-5 min GPU"),
        })

    return _rank(recs)


def _rank(recs: list) -> list:
    """Sort descending by priority, dedup by strategy (keep highest)."""
    seen = {}
    for r in recs:
        s = r["strategy"]
        if s not in seen or r["priority"] > seen[s]["priority"]:
            seen[s] = r
    return sorted(seen.values(),
                  key=lambda r: r["priority"], reverse=True)
