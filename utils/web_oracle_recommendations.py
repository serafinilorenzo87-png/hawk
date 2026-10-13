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
HAWK — Web Oracle recommendations engine.

Pure-Python profile → list-of-actions mapping.  No GUI imports, no
subprocess — the runner calls recommend(profile) and gets back a list
of recommendation dicts ready to render.

Also emits "regional_flags" — authentication / stack patterns common
to specific market segments (federated identity providers, local CMS
choices, ERP suites).  No country names in the flags: the user knows
where the target is; HAWK just tells them what pattern it sees and
which next-step tool handles it.

Recommendation dict shape (identical to the Phase 1 stub):
    {
      "action":   short verb (e.g. "RUN WPSCAN"),
      "reason":   one-liner why HAWK suggests it,
      "tool_id":  HAWK tool id if action opens one (None = external),
      "prefill":  dict passed to launch_tool_prefilled,
      "command":  optional shell command template for manual run,
      "severity": "info"|"low"|"medium"|"high"|"critical",
    }

Regional flag shape:
    {
      "tag":    short label (e.g. "SAML federation IdP"),
      "detail": what HAWK saw + why it matters,
      "hint":   next-step tool / technique,
    }
"""

from __future__ import annotations

import re
from typing import Iterable


# ─── Helpers ─────────────────────────────────────────────────────────

def _tech_contains(profile: dict, *needles) -> bool:
    """True if any tech name/version in profile matches any needle
    (case-insensitive substring)."""
    names = " ".join(
        f"{t.get('name', '')} {t.get('version', '')}"
        for t in (profile.get("tech") or [])).lower()
    return any(n.lower() in names for n in needles)


def _any_path(profile: dict, needles: Iterable[str]) -> list:
    """Return the exposures whose path contains any needle."""
    out = []
    for e in (profile.get("exposures") or []):
        p = (e.get("path") or "").lower()
        if any(n.lower() in p for n in needles):
            out.append(e)
    return out


def _header_has(profile: dict, header_name: str, needle: str) -> bool:
    v = (profile.get("headers") or {}).get(header_name, "")
    if isinstance(v, list):
        v = " ".join(str(x) for x in v)
    return needle.lower() in str(v).lower()


# ─── Recommendation rules ────────────────────────────────────────────

def recommend(profile: dict) -> list:
    """Return a prioritised list of recommendation dicts.

    Order:
      1. Critical exposures (.env, /.git, admin panels with default
         creds found)
      2. Known CVEs (already flagged by nuclei — we just echo them
         as actions)
      3. CMS-specific paths (WordPress, Typo3, PrestaShop, Magento,
         Joomla, Drupal)
      4. Framework-specific (Laravel, Django, Rails, Node/Express,
         Spring)
      5. API surface (GraphQL, Swagger, SOAP/WSDL)
      6. Auth mechanism (JWT, SAML, OIDC, Basic)
      7. Generic attack surface (login form → hydra, content
         discovery hints)
    """
    recs: list = []
    url = profile.get("url", "")
    expos = profile.get("exposures") or []
    cves = profile.get("cves") or []
    apis = profile.get("apis") or []
    tech = profile.get("tech") or []
    auth = profile.get("auth") or {}

    # ── 1. Critical exposures ──────────────────────────────────────
    for e in _any_path(profile, ["/.env"]):
        if e.get("status") == "200":
            recs.append({
                "action":   "FETCH .env",
                "reason":   ".env reachable — likely holds DB creds, "
                            "API keys, APP_KEY, JWT secrets.",
                "tool_id":  None,
                "prefill":  {},
                "command":  f"curl -s {url.rstrip('/')}/.env "
                            f"| tee loot/env.leak",
                "severity": "critical",
            })
    for e in _any_path(profile, ["/.git/"]):
        if e.get("status") == "200":
            recs.append({
                "action":   "DUMP GIT REPO",
                "reason":   "/.git/ reachable — full source + history "
                            "reconstructable with git-dumper.",
                "tool_id":  None,
                "prefill":  {},
                "command":  f"git-dumper {url.rstrip('/')}/.git "
                            f"loot/git-dump",
                "severity": "high",
            })
    for e in _any_path(profile, ["/.DS_Store"]):
        if e.get("status") == "200":
            recs.append({
                "action":   "HARVEST .DS_Store",
                "reason":   "macOS .DS_Store leaks directory listing "
                            "— useful for path enumeration.",
                "tool_id":  None,
                "prefill":  {},
                "command":  f"ds_store_exp {url}",
                "severity": "low",
            })
    for e in _any_path(profile, ["/server-status", "/server-info"]):
        if e.get("status") == "200":
            recs.append({
                "action":   "READ /server-status",
                "reason":   "Apache mod_status exposed — live "
                            "request table, client IPs, internal "
                            "URLs in real time.",
                "tool_id":  None,
                "prefill":  {},
                "command":  f"curl -s {url.rstrip('/')}/server-status "
                            f"| less",
                "severity": "medium",
            })
    for e in _any_path(profile, ["/phpinfo.php"]):
        if e.get("status") == "200":
            recs.append({
                "action":   "READ phpinfo",
                "reason":   "phpinfo() exposed — PHP version, loaded "
                            "modules, environment variables, "
                            "session paths, full disk paths.",
                "tool_id":  None,
                "prefill":  {},
                "command":  f"curl -s {url.rstrip('/')}/phpinfo.php "
                            f"| grep -iE "
                            f"'(version|path|secret|key|passwd)'",
                "severity": "medium",
            })

    # ── 2. CVEs from nuclei ────────────────────────────────────────
    for c in cves[:5]:
        cid = c.get("id", "?")
        sev = c.get("severity", "medium")
        recs.append({
            "action":   f"VERIFY {cid}",
            "reason":   f"nuclei matched: {c.get('name', '')} "
                        f"({sev}).  Re-verify with a targeted probe, "
                        f"then pivot to searchsploit / MSF.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"searchsploit {cid}",
            "severity": sev,
        })

    # ── 3. CMS-specific ────────────────────────────────────────────
    if _tech_contains(profile, "wordpress") or _any_path(
            profile, ["/wp-login", "/wp-admin", "/wp-json"]):
        recs.append({
            "action":   "RUN WPSCAN",
            "reason":   "WordPress fingerprinted — wpscan enumerates "
                        "users, plugins, themes, known CVEs.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"wpscan --url {url} "
                        f"--enumerate u,vp,vt --random-user-agent",
            "severity": "medium",
        })
        # xmlrpc.php is almost always enabled on a default WP and
        # still useful for login brute + pingback amplification.
        recs.append({
            "action":   "TEST xmlrpc.php",
            "reason":   "WordPress xmlrpc is usually enabled.  "
                        "Check system.listMethods → pingback + "
                        "wp.getUsersBlogs login brute.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"curl -s -X POST "
                        f"{url.rstrip('/')}/xmlrpc.php "
                        f"-d '<?xml version=\"1.0\"?><methodCall>"
                        f"<methodName>system.listMethods"
                        f"</methodName></methodCall>'",
            "severity": "low",
        })
    if _tech_contains(profile, "typo3"):
        recs.append({
            "action":   "RUN TYPO3SCAN",
            "reason":   "Typo3 fingerprinted — typo3scan enumerates "
                        "extensions and maps known CVEs per version.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"typo3scan.py -u {url}",
            "severity": "medium",
        })
    if _tech_contains(profile, "joomla"):
        recs.append({
            "action":   "RUN JOOMSCAN",
            "reason":   "Joomla fingerprinted — joomscan enumerates "
                        "components and misconfigurations.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"joomscan --url {url}",
            "severity": "medium",
        })
    if _tech_contains(profile, "drupal"):
        recs.append({
            "action":   "RUN DROOPESCAN",
            "reason":   "Drupal fingerprinted — droopescan enumerates "
                        "modules + CVEs (Drupalgeddon lineage).",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"droopescan scan drupal -u {url}",
            "severity": "medium",
        })
    if _tech_contains(profile, "magento"):
        recs.append({
            "action":   "RUN MAGESCAN",
            "reason":   "Magento fingerprinted — magescan maps "
                        "installed modules + known vulns (Magmi, "
                        "SUPEE bypasses).",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"magescan scan:all {url}",
            "severity": "medium",
        })
    if _tech_contains(profile, "prestashop"):
        recs.append({
            "action":   "PROBE PRESTASHOP MODULES",
            "reason":   "PrestaShop fingerprinted — older module "
                        "versions have chained SQLi/RCE.  Enumerate "
                        "installed modules via /modules/.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"ffuf -u {url.rstrip('/')}/modules/"
                        f"FUZZ/config.xml -w "
                        f"/usr/share/seclists/Discovery/Web-Content/"
                        f"CMS/prestashop-modules.txt -mc 200",
            "severity": "medium",
        })

    # ── 4. Framework-specific ──────────────────────────────────────
    if _tech_contains(profile, "laravel"):
        recs.append({
            "action":   "PROBE LARAVEL DEBUG",
            "reason":   "Laravel detected — test /telescope, /horizon, "
                        "/_ignition/execute-solution (CVE-2021-3129 "
                        "RCE if debug=on).",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"curl -s -X POST "
                        f"{url.rstrip('/')}/_ignition/"
                        f"execute-solution -H 'Content-Type: "
                        f"application/json'",
            "severity": "high",
        })
    if _tech_contains(profile, "django"):
        recs.append({
            "action":   "TEST DJANGO DEBUG",
            "reason":   "Django detected — DEBUG=True leaks settings, "
                        "source paths, SECRET_KEY.  Try forcing an "
                        "error and reading the trace.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"curl -s {url.rstrip('/')}/"
                        f"<random-404-path>",
            "severity": "medium",
        })
    if _tech_contains(profile, "spring", "springboot"):
        recs.append({
            "action":   "PROBE SPRING ACTUATORS",
            "reason":   "Spring Boot detected — /actuator/* endpoints "
                        "commonly unauth in dev: /env, /heapdump, "
                        "/trace leak secrets and memory.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"ffuf -u "
                        f"{url.rstrip('/')}/actuator/FUZZ -w "
                        f"/usr/share/seclists/Discovery/Web-Content/"
                        f"spring-boot.txt -mc 200,401",
            "severity": "high",
        })
    if _tech_contains(profile, "rails"):
        recs.append({
            "action":   "PROBE RAILS SECRETS",
            "reason":   "Rails detected — test /rails/info/routes, "
                        "CVE chain around secret_key_base "
                        "(deserialization → RCE).",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"curl -s {url.rstrip('/')}/rails/info/routes",
            "severity": "medium",
        })

    # ── 5. API surface ─────────────────────────────────────────────
    if any(a.get("kind") == "GraphQL" for a in apis) or _any_path(
            profile, ["/graphql"]):
        recs.append({
            "action":   "GRAPHQL FINGERPRINT",
            "reason":   "GraphQL endpoint responsive — graphw00f "
                        "identifies the engine (Apollo, Hasura, "
                        "Relay) which dictates which attacks work.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"graphw00f -t {url.rstrip('/')}/graphql -d",
            "severity": "medium",
        })
        recs.append({
            "action":   "GRAPHQL INTROSPECTION",
            "reason":   "If introspection is on → full schema dump "
                        "with clairvoyance, then read every type "
                        "and mutation.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"clairvoyance {url.rstrip('/')}/graphql "
                        f"-o schema.json",
            "severity": "medium",
        })
    if any(a.get("kind") == "OpenAPI" for a in apis) or _any_path(
            profile, ["/swagger", "/openapi", "/api-docs"]):
        recs.append({
            "action":   "GRAB OPENAPI SPEC",
            "reason":   "OpenAPI/Swagger spec reachable — every "
                        "endpoint + required params + auth type "
                        "in one JSON.  Feed to kiterunner or ffuf.",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"curl -s "
                        f"{url.rstrip('/')}/openapi.json "
                        f"| tee loot/openapi.json",
            "severity": "medium",
        })
    if any(a.get("kind") == "SOAP" for a in apis):
        recs.append({
            "action":   "ENUM SOAP METHODS",
            "reason":   "WSDL endpoint reached — enumerate operations, "
                        "test per-op injection (SOAP/XML body).",
            "tool_id":  None,
            "prefill":  {},
            "command":  f"wsdler {url}  "
                        f"# or: python3 -m zeep {url}",
            "severity": "medium",
        })

    # ── 6. Auth mechanism ──────────────────────────────────────────
    if auth.get("type") == "form":
        login_path = auth.get("login_path", "/")
        fields = auth.get("fields") or []
        recs.append({
            "action":   "RUN HYDRA HTTP-POST-FORM",
            "reason":   f"Login form detected at {login_path} "
                        f"(fields: {', '.join(fields[:4]) or '?'}). "
                        f"Hydra wizard pre-checks CSRF/JSON "
                        f"compatibility.",
            "tool_id":  "hydra_http_form",
            "prefill":  {"_origin": f"Web Oracle ({login_path})"},
            "command":  "",
            "severity": "info",
        })
    # JWT tokens leaked in HTML or sent in Authorization header.
    if any(e.get("status") == "jwt-leak" for e in expos) \
       or _header_has(profile, "Authorization", "Bearer"):
        recs.append({
            "action":   "CRACK JWT",
            "reason":   "JWT token observed — test alg=none, weak "
                        "HMAC secret, key confusion (RS→HS), "
                        "malformed kid.",
            "tool_id":  None,
            "prefill":  {},
            "command":  "jwt_tool <paste-token-here> -M at",
            "severity": "medium",
        })
    # Basic Auth via WWW-Authenticate header.
    if _header_has(profile, "WWW-Authenticate", "Basic"):
        recs.append({
            "action":   "RUN HYDRA HTTP-GET",
            "reason":   "Server challenged with WWW-Authenticate: "
                        "Basic — HTTP-GET brute is the right tool.",
            "tool_id":  "hydra_http",
            "prefill":  {"_origin": "Web Oracle (Basic Auth detected)"},
            "command":  "",
            "severity": "info",
        })

    return recs


# ─── Regional / federation flags ────────────────────────────────────

def regional_flags(profile: dict) -> list:
    """Surface authentication / stack patterns common in specific
    markets.  Output is deliberately country-name-free: if HAWK sees
    a federation redirect it says "federated identity redirect to
    provider-X.gov" and lets the user (who knows where the target
    is) take it from there.

    Each flag is a hint, not a recommendation — it doesn't get a
    "RUN" button.  The operator is supposed to read it, recognise
    the environment, and pivot accordingly.
    """
    flags: list = []
    url = (profile.get("url") or "").lower()
    html = (profile.get("raw", {}).get("html-home") or "").lower()
    endpoints = [e.lower() for e in (profile.get("endpoints") or [])]
    all_text = url + "\n" + html + "\n" + "\n".join(endpoints)

    # ── Federated identity / SSO providers ─────────────────────────
    # The user knows where the target is; we only say "this goes
    # out to provider X" and let them decide.
    FED_PATTERNS = [
        # (regex, tag, detail, hint)
        (r"spid\.[a-z0-9.-]+",
         "Federated identity — SPID",
         "Login redirects through a national SPID IdP federation. "
         "No direct brute viable — the IdP owns the credential store. "
         "Pivot to SAML assertion tampering or IdP metadata abuse.",
         "Inspect /metadata, test XSW signature wrapping with SAMLRaider."),
        (r"digid\.nl|digid-assertion",
         "Federated identity — DigID",
         "Redirect to DigID IdP (OIDC).  Credential store is "
         "centralised and out of scope for direct brute.",
         "Focus on post-callback flaws: audience confusion, "
         "PKCE downgrade, id_token validation."),
        (r"cie\.id|cie-auth",
         "Federated identity — Electronic ID card",
         "National eID card auth flow (SAML/OIDC over smartcard).",
         "Attack surface is the application's session handling "
         "post-callback, not the IdP itself."),
        (r"shibboleth|/shibsso/|/saml2/idp/ssoservice",
         "Federated identity — Shibboleth SAML",
         "Common on university / research / gov SSO.",
         "Test XSW, XXE in metadata; check for unsigned "
         "response acceptance."),
        (r"adfs|/adfs/|federationmetadata",
         "Federated identity — ADFS",
         "Microsoft ADFS federation detected.",
         "ADFSpray for spray attacks, test /adfs/ls/IdpInitiated"
         "SignOn.aspx enumeration."),
        (r"azuread|login\.microsoftonline|microsoftonline\.com",
         "Federated identity — Entra ID / AAD",
         "Microsoft Entra ID (Azure AD) federation.",
         "Use AADInternals, ROPC on /common/oauth2/token, "
         "device-code flow abuse."),
        (r"okta\.com|/app/okta|okta-idp",
         "Federated identity — Okta",
         "Okta IdP federation — check for org slug leak, "
         "authorization server misconfig.",
         "Test /api/v1/authn spray, /app/<slug>/sso/saml."),
        (r"auth0\.com|oidc\.auth0",
         "Federated identity — Auth0",
         "Auth0 federation — management API is separate from "
         "login.  Public clients sometimes leak keys in JS bundles.",
         "Grep JS bundles for `AUTH0_DOMAIN` and `clientId` — "
         "combine with jwt_tool for ID-token forgery."),
        (r"keycloak|/auth/realms/",
         "Federated identity — Keycloak",
         "Keycloak realm detected.  Known CVEs in older versions "
         "(SAML XSW, admin JWT forgery).",
         "Grab /.well-known/openid-configuration, test "
         "/realms/<realm>/protocol/openid-connect/token spray."),
    ]

    # ── Payment / e-commerce flows (per-market popular stacks) ─────
    PAYMENT_PATTERNS = [
        (r"/ideal|psp-ideal|mollie|adyen",
         "Payment gateway redirect — iDEAL family",
         "Payment redirect out of scope — do NOT brute the PSP "
         "(triggers anti-fraud immediately).  The app's own "
         "callback handler is the attack surface.",
         "Fuzz the return URL / status parameters; test forced "
         "success via replay + HMAC downgrade."),
        (r"stripe\.com/v1|js\.stripe",
         "Payment gateway — Stripe",
         "Stripe.js integration.  Publishable key is public by "
         "design; look for SECRET key leak in JS bundles.",
         "Grep bundles for `sk_live_` / `sk_test_` — "
         "account takeover if found."),
        (r"paypal\.com|braintree-api",
         "Payment gateway — PayPal / Braintree",
         "Classic PSP — IPN signature validation is the usual "
         "weak point.",
         "Fuzz /ipn callbacks with forged TXN states."),
    ]

    # ── Enterprise / ERP stacks ────────────────────────────────────
    ENTERPRISE_PATTERNS = [
        (r"/irj/portal|/sap/bc/|netweaver|sap-webdynpro",
         "Enterprise ERP — SAP NetWeaver",
         "SAP NetWeaver surface detected — long list of CVEs "
         "(10KBLAZE, RECON, ICMAD) against unauth endpoints.",
         "erpscan-pentest / pysap, target /sap/public/info."),
        (r"/liferay|liferay-portal",
         "Enterprise CMS — Liferay",
         "Liferay portal — check /api/jsonws unauth and "
         "lr-admin default creds (test:test).",
         "nuclei -tags liferay,  msf module liferay_json_rpc."),
        (r"/profitwebservices|afas-online",
         "Business ERP — AFAS",
         "AFAS Profit SOAP surface.  Unauth WSDL dump leaks "
         "operation list + data types.",
         "wsdler <url>, test AppConnector token replay."),
        (r"jboss|jmx-console|jbossas",
         "Enterprise app server — JBoss",
         "JBoss / WildFly console surface.  Classic default-pwd + "
         "RMI deserialization vectors.",
         "msfconsole → exploit/multi/http/jboss_*"),
        (r"jenkins|/jnlpJars/|jenkins-build",
         "CI/CD — Jenkins",
         "Jenkins detected — script console = RCE with valid "
         "creds, /asynchPeople/ leaks user enum.",
         "nuclei -tags jenkins,  hydra http-get /script/."),
        (r"/gitlab|gitlab-workhorse",
         "CI/CD — GitLab",
         "GitLab CE/EE.  Check for unauth /api/v4/users, CVE-"
         "2023-7028 password-reset hijack.",
         "hawk searchsploit gitlab.  Also check snippets/*.raw."),
    ]

    # ── GDPR / cookie walls (purely advisory — they break crawls) ──
    GDPR_PATTERNS = [
        (r"cookieyes|cookiebot|cookie-consent|usercentrics|"
         r"onetrust-banner",
         "GDPR cookie wall",
         "Cookie consent layer in the DOM.  Deep crawlers "
         "(katana, gobuster) may trip on the consent modal and "
         "miss behind-login paths.",
         "Pre-inject Cookie: cookieyes-consent=... in katana -H, "
         "or Burp match-replace the wall before scanning."),
    ]

    ALL = (FED_PATTERNS + PAYMENT_PATTERNS +
           ENTERPRISE_PATTERNS + GDPR_PATTERNS)

    # Walk patterns.  Match against url + html + endpoints + all
    # exposure paths.
    hay = all_text
    for e in (profile.get("exposures") or []):
        hay += "\n" + (e.get("path") or "").lower()
    for h in (profile.get("headers") or {}).values():
        hay += "\n" + str(h).lower()

    seen_tags = set()
    for regex, tag, detail, hint in ALL:
        if re.search(regex, hay, re.I):
            if tag in seen_tags:
                continue
            seen_tags.add(tag)
            flags.append({
                "tag":    tag,
                "detail": detail,
                "hint":   hint,
            })

    # ── Stack-shape flags derived from tech (no redirect clues) ────
    tech_text = " ".join(
        f"{t.get('name', '')} {t.get('version', '')}"
        for t in (profile.get("tech") or [])).lower()
    STACK = [
        ("typo3", "Local-market CMS — Typo3",
         "Typo3 has regional market share concentration; less "
         "covered by generic web scanners.",
         "typo3scan.py + nuclei -tags typo3 — check installed "
         "extensions (typo3conf/ext/ path)."),
        ("sitecore", "Enterprise CMS — Sitecore",
         "Sitecore surface — recurring CVEs in debug.aspx and "
         "the item editor.",
         "nuclei -tags sitecore, test /sitecore/admin."),
        ("umbraco", "Enterprise CMS — Umbraco",
         "Umbraco portal — look for /umbraco login + 0day "
         "plugin chain.",
         "nuclei -tags umbraco, test /umbraco/backoffice."),
    ]
    for needle, tag, detail, hint in STACK:
        if needle in tech_text and tag not in seen_tags:
            seen_tags.add(tag)
            flags.append({
                "tag":    tag,
                "detail": detail,
                "hint":   hint,
            })

    return flags
