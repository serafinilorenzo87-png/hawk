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
HAWK - CVE Lookup via NVD API v1.0
Queries National Vulnerability Database for CVEs by software/version.
Respects rate limits: 5 req/30s (no key) or 50 req/30s (with key).
Caches results per session to avoid duplicate calls.
"""

import re
import time
import threading
import urllib.request
import urllib.parse
import json
from dataclasses import dataclass, field
from datetime import datetime


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class CVEEntry:
    cve_id:      str
    description: str
    cvss_score:  float
    severity:    str       # CRITICAL / HIGH / MEDIUM / LOW / NONE
    cwe:         str       # CWE-xxx
    published:   str
    references:  list = field(default_factory=list)
    msf_module:  str  = ""   # filled in if MSF module exists
    # CISA KEV membership — a utils.cisa_kev.KevEntry when this CVE is on
    # the Known Exploited Vulnerabilities catalog (actively exploited in
    # the wild), else None.  Set at parse time; see _enrich_kev.
    kev:         object = None

    SEVERITY_ORDER = {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4
    }

    def severity_score(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity.upper(), 99)

    def is_kev(self) -> bool:
        """True when this CVE is on the CISA KEV catalog."""
        return self.kev is not None

    def kev_ransomware(self) -> bool:
        """True when KEV flags known ransomware-campaign use."""
        return bool(getattr(self.kev, "known_ransomware", False))

    def short_desc(self, max_len: int = 120) -> str:
        d = self.description.strip().replace("\n", " ")
        return d[:max_len] + "..." if len(d) > max_len else d

    def severity_color(self) -> str:
        from utils.config import COLORS
        return {
            "CRITICAL": COLORS["text_red"],
            "HIGH":     COLORS["text_orange"],
            "MEDIUM":   COLORS["text_yellow"],
            "LOW":      COLORS["text_green"],
            "NONE":     COLORS["text_dim"],
        }.get(self.severity.upper(), COLORS["text_dim"])


# ─── Rate limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket — respects NVD limits."""

    def __init__(self, calls: int, period: float):
        self._calls  = calls
        self._period = period
        self._lock   = threading.Lock()
        self._times  = []

    def wait(self):
        with self._lock:
            now = time.time()
            self._times = [t for t in self._times if now - t < self._period]
            if len(self._times) >= self._calls:
                sleep_for = self._period - (now - self._times[0]) + 0.1
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._times.append(time.time())


# ─── NVD Client ───────────────────────────────────────────────────────────────

class NVDClient:
    """
    Queries NVD REST API v2.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    TIMEOUT  = 15

    def __init__(self, api_key: str = ""):
        self._api_key     = api_key.strip()
        self._cache: dict = {}   # query_key → list[CVEEntry]
        self._lock        = threading.Lock()

        # Rate limiter: 5/30s without key, 50/30s with key
        if self._api_key:
            self._limiter = RateLimiter(calls=50, period=30.0)
        else:
            self._limiter = RateLimiter(calls=5,  period=30.0)

    def set_api_key(self, key: str):
        self._api_key = key.strip()
        if self._api_key:
            self._limiter = RateLimiter(calls=50, period=30.0)
        else:
            self._limiter = RateLimiter(calls=5, period=30.0)

    def has_key(self) -> bool:
        return bool(self._api_key)

    def search_by_keyword(self, keyword: str,
                          min_score: float = 7.0,
                          max_results: int = 20) -> list:
        """
        Search CVEs by keyword (software name + version).
        Returns list of CVEEntry sorted by CVSS score desc.
        """
        cache_key = f"kw:{keyword}:{min_score}"
        with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 100),
        }
        results = self._fetch(params)
        filtered = [r for r in results if r.cvss_score >= min_score]
        # KEV CVEs first (actively exploited in the wild beats a higher
        # CVSS that nobody is using), then CVSS desc, then severity.
        filtered.sort(key=lambda r: (0 if r.is_kev() else 1,
                                     -r.cvss_score, r.severity_score()))

        with self._lock:
            self._cache[cache_key] = filtered
        return filtered

    def search_by_cve(self, cve_id: str) -> list:
        """Fetch a specific CVE by ID."""
        cache_key = f"cve:{cve_id}"
        with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        params = {"cveId": cve_id.upper()}
        results = self._fetch(params)
        with self._lock:
            self._cache[cache_key] = results
        return results

    def search_recent(self, days: int = 30,
                      min_score: float = 7.0) -> list:
        """Fetch recent high-severity CVEs."""
        from datetime import timedelta
        now  = datetime.utcnow()
        then = now - timedelta(days=days)
        params = {
            "pubStartDate": then.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate":   now.strftime("%Y-%m-%dT23:59:59.999"),
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": 50,
        }
        results = self._fetch(params)
        return [r for r in results if r.cvss_score >= min_score]

    def _fetch(self, params: dict) -> list:
        self._limiter.wait()
        url = self.BASE_URL + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        if self._api_key:
            req.add_header("apiKey", self._api_key)

        try:
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return self._parse(data)
        except Exception as e:
            return []

    def _parse(self, data: dict) -> list:
        entries = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # Description (English)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS score
            score    = 0.0
            severity = "NONE"
            metrics  = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    if "cvssData" in m:
                        score    = float(m["cvssData"].get("baseScore", 0))
                        severity = m["cvssData"].get(
                            "baseSeverity",
                            m.get("baseSeverity", "NONE"))
                    break

            # CWE
            cwe = ""
            for w in cve.get("weaknesses", []):
                for d in w.get("description", []):
                    if d.get("lang") == "en":
                        cwe = d.get("value", "")
                        break
                if cwe:
                    break

            # Published date
            published = cve.get("published", "")[:10]

            # References
            refs = [r.get("url", "")
                    for r in cve.get("references", [])[:5]]

            entries.append(CVEEntry(
                cve_id=cve_id,
                description=desc,
                cvss_score=score,
                severity=severity.upper(),
                cwe=cwe,
                published=published,
                references=refs,
            ))
        self._enrich_kev(entries)
        return entries

    @staticmethod
    def _enrich_kev(entries: list) -> None:
        """Tag each CVEEntry with its CISA KEV membership (offline lookup
        against the bundled snapshot).  Best-effort: any failure leaves
        ``kev`` as None so a missing/corrupt KEV catalog never breaks an
        NVD lookup."""
        try:
            from utils.cisa_kev import is_kev as _is_kev
        except Exception:
            return
        for e in entries:
            try:
                e.kev = _is_kev(e.cve_id)
            except Exception:
                e.kev = None


# ─── Global client singleton ──────────────────────────────────────────────────

_client: NVDClient = None
_client_lock = threading.Lock()


def get_client() -> NVDClient:
    global _client
    with _client_lock:
        if _client is None:
            _client = NVDClient(api_key=_load_stored_key())
    return _client


def set_api_key(key: str):
    get_client().set_api_key(key)
    _save_key(key)


def _env_path() -> str:
    import os
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, ".env")


def _scrub_legacy_key_from_env() -> None:
    """Remove any legacy ``NVD_API_KEY=...`` line from the project .env.

    Older HAWK builds persisted the NVD API key on disk so it auto-loaded
    on every launch.  Sensitive data — should never have been written.
    On every import we rewrite the .env without that line so a stale key
    from a previous version doesn't keep travelling with the project
    folder.  The .env file itself is preserved (other vars stay intact);
    only the NVD line is dropped.  Idempotent and silent on missing/empty
    files.
    """
    import os
    path = _env_path()
    try:
        if not os.path.exists(path):
            return
        with open(path) as f:
            lines = f.readlines()
        new_lines = [ln for ln in lines
                     if not ln.lstrip().startswith("NVD_API_KEY=")]
        if len(new_lines) != len(lines):
            with open(path, "w") as f:
                f.writelines(new_lines)
    except Exception:
        pass


# Run the cleanup once at import time so the user's first interaction
# with HAWK after this fix wipes the previously-persisted key.
_scrub_legacy_key_from_env()


def _load_stored_key() -> str:
    """Return the persisted NVD API key, or "" if none is set.

    NVD is now a managed key like the OSINT providers: it lives in the
    0600 ``sessions/.apikeys.json`` under the ``nvd`` id (utils.apikeys),
    so ``get_client()`` picks it up at boot and the operator sets it once
    instead of re-typing it every launch.  This is a deliberate reversal
    of the earlier "ephemeral, never on disk" stub: NVD is the least
    sensitive key HAWK holds — free, read-only, its only effect a higher
    rate limit (50 vs 5 requests / 30 s) — so keeping it next to the other
    API keys is the right trade.  (The legacy ``.env`` persistence, which
    could leak the key into the project folder, is still scrubbed on
    import; only the storage location moved, to the guarded apikeys file.)
    """
    try:
        from utils.apikeys import load_keys
        return load_keys().get("nvd", "")
    except Exception:
        return ""


def _save_key(key: str) -> None:
    """Persist the NVD key into ``sessions/.apikeys.json`` (utils.apikeys).

    Counterpart of _load_stored_key: an empty key clears the stored one
    (save_keys drops empty values).  The in-memory NVDClient is updated
    separately via ``set_api_key`` so a change takes effect without a
    restart."""
    try:
        from utils.apikeys import load_keys, save_keys
        keys = load_keys()
        keys["nvd"] = (key or "").strip()
        save_keys(keys)
    except Exception:
        pass


# ─── Async search helper ──────────────────────────────────────────────────────

def search_async(keyword: str, callback, min_score: float = 7.0):
    """Run NVD search in background thread, call callback(results) when done."""
    def _run():
        results = get_client().search_by_keyword(keyword, min_score)
        callback(results)
    threading.Thread(target=_run, daemon=True).start()


def enrich_with_msf(entries: list, callback=None):
    """
    For each CVEEntry, check if a Metasploit module exists.
    Fills entry.msf_module. Calls callback(entries) when done.
    """
    def _run():
        import subprocess
        for entry in entries:
            try:
                result = subprocess.run(
                    ["msfconsole", "-q", "-x",
                     f"search cve:{entry.cve_id}; exit"],
                    capture_output=True, text=True, timeout=20)
                out = result.stdout
                # Find first exploit/ line
                m = re.search(r'(exploit/\S+|auxiliary/\S+)', out)
                if m:
                    entry.msf_module = m.group(1)
            except Exception:
                pass
        if callback:
            callback(entries)
    threading.Thread(target=_run, daemon=True).start()
