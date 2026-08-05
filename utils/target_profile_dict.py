# HAWK — Hostile Assessment War-Kit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0

"""
HAWK — Target profile dict builder.

CUPP-style candidate list for the TARGET crack strategy.  Given a
handful of context strings about the target (company name, domain,
usernames already enumerated, a year range, optional cewl-scraped
homepage), produce a wordlist in <HAWK>/dicts/dict-<target>.txt that a
human pentester would actually type: capitalised variants, common
password-policy suffixes, year/season appends, l33t substitutions,
and a few classic stems (Welcome / Password / Admin / letmein).

No network I/O, no GUI — pass it a dict of strings, get a file path
back.
"""

from __future__ import annotations

import os
import re
import itertools


# ─── Static seeds ─────────────────────────────────────────────────────

# Classic stems that end up in >half of admin-set passwords in any
# industry, any region.  Expanded with capitalised forms because
# password policies typically require at least one capital.
_CLASSIC_STEMS = [
    "admin", "administrator", "password", "passwd", "welcome",
    "letmein", "changeme", "hello", "qwerty", "abc", "default",
    "secret", "master", "login", "company", "corp", "office",
]

_SEASONS = ["Winter", "Spring", "Summer", "Autumn", "Fall"]

# Common suffix sets appended to any base word.  Ordered by real-
# world frequency on cracked AD hashes.
_CLASSIC_SUFFIXES = [
    "!", ".", "?", "@",
    "1", "12", "123", "1234",
    "!1", "!2", "!3",
    "2024", "2025", "2023", "2022",
    "2024!", "2025!", "2023!",
    "!2024", "!2025",
    "123!", "1!",
]

# A small l33t table — enough to double a ~10k seed dict to ~25k
# without exploding combinatorically.  Every base word gets ONE
# l33t variant; we don't permute every possible substitution.
_LEET_MAP = {
    "a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7",
}


# ─── Helpers ─────────────────────────────────────────────────────────

def _cap_variants(word: str) -> list:
    """Return canonical capitalisation variants for a seed word."""
    if not word:
        return []
    word = word.strip()
    variants = {word.lower(), word.upper(), word.capitalize()}
    # Toggle first-and-last (e.g. admin → adminA, adminX is too
    # noisy — skip).  Only the three above are high-signal.
    return [v for v in variants if v]


def _leet_one(word: str) -> str:
    """Return a single l33t variant where the MOST COMMON leetable
    char is substituted.  One variant per word is enough — don't
    permute every vowel or the dict explodes."""
    for ch, sub in _LEET_MAP.items():
        if ch in word.lower():
            # Substitute the first occurrence only.
            idx = word.lower().find(ch)
            return word[:idx] + sub + word[idx + 1:]
    return ""


def _year_range(from_year: int, to_year: int) -> list:
    if from_year > to_year:
        from_year, to_year = to_year, from_year
    return [str(y) for y in range(from_year, to_year + 1)]


# ─── Public builder ──────────────────────────────────────────────────

def build_dict(
        out_path: str,
        company: str = "",
        domain: str = "",
        usernames: list = None,
        extra_seeds: list = None,
        year_from: int = 2020,
        year_to: int = 2025,
        include_leet: bool = True,
        max_lines: int = 60000,
) -> tuple:
    """Generate a TARGET profile wordlist and write it to `out_path`.

    Returns (path, n_lines).

    The generated list is deterministic for the same inputs so
    re-opening HAWK and re-running on the same target won't cycle
    through different candidates — the user can paste the dict
    elsewhere if they want.

    `max_lines` caps the output.  Real-world AD engagements almost
    never need more than ~50k candidates from a TARGET dict; a bigger
    dict just becomes a slower scan.
    """
    seeds = set()

    # 1. Company stem.
    if company:
        cbase = re.sub(r"[^A-Za-z0-9]", "", company)
        if cbase:
            seeds.update(_cap_variants(cbase))
            # Just the first word (drop "Corp", "Inc", etc. suffixes).
            tokens = re.split(r"[^A-Za-z0-9]+", company)
            if tokens:
                seeds.update(_cap_variants(tokens[0]))

    # 2. Domain — strip the TLD, take just the label.
    if domain:
        label = domain.split(".")[0]
        if label:
            seeds.update(_cap_variants(label))

    # 3. Usernames — each contributes its name part (before @ or $).
    for u in (usernames or []):
        u = (u or "").strip()
        if not u:
            continue
        name = re.split(r"[@$\\/]", u)[0]
        if name and len(name) >= 3:
            seeds.update(_cap_variants(name))

    # 4. User-supplied extra seeds.
    for s in (extra_seeds or []):
        s = (s or "").strip()
        if s and len(s) >= 2:
            seeds.update(_cap_variants(s))

    # 5. Always include classic stems (as-is and capitalised).
    for s in _CLASSIC_STEMS:
        seeds.update(_cap_variants(s))

    # ── Expand seeds into the final list ────────────────────────────
    out = set()

    # 5a. Base seeds (bare words).
    out.update(seeds)

    # 5b. Season + year (one of the most common admin patterns).
    years = _year_range(year_from, year_to)
    for season, year in itertools.product(_SEASONS, years):
        out.add(f"{season}{year}")
        out.add(f"{season}{year}!")
        out.add(f"{season}{year}@")
        out.add(f"{season}{year[-2:]}!")

    # 5c. Seed + suffix cross-product.
    for seed, suffix in itertools.product(seeds, _CLASSIC_SUFFIXES):
        out.add(f"{seed}{suffix}")

    # 5d. Seed + year (without season).
    for seed, year in itertools.product(seeds, years):
        out.add(f"{seed}{year}")
        out.add(f"{seed}{year}!")
        out.add(f"{seed}@{year}")

    # 5e. l33t variants (only on seeds — not on derived forms).
    if include_leet:
        leet_seeds = set()
        for seed in seeds:
            l = _leet_one(seed)
            if l:
                leet_seeds.add(l)
                leet_seeds.add(l + "!")
                leet_seeds.add(l + "1")
                leet_seeds.add(l + "2024")
        out.update(leet_seeds)

    # Sort for determinism + take the cap.
    final = sorted(out)
    if len(final) > max_lines:
        final = final[:max_lines]

    # Write.  `out_path` is a parameter, so the containment rule is
    # enforced here rather than trusted: the single caller builds it
    # from DICTS_DIR and catches the ValueError.
    from utils.config import require_writable
    out_path = require_writable(out_path, "target dict")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)),
                    exist_ok=True)
    except Exception:
        pass
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(final) + "\n")

    return out_path, len(final)
