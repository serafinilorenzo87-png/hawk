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

"""AssaultState — single source of truth for the WEB ASSAULT pipeline.

The four tools in WEB ASSAULT (ORACLE → CRAWL → INJECT → JWT) are
runnable independently but feed each other when chained:

    ORACLE produces tech_stack, api_endpoints, exposures
    CRAWL  produces parameters, forms, upload_forms, jwt_tokens
    INJECT consumes parameters + upload_forms
    JWT    consumes jwt_tokens

Each tool reads what's already in AssaultState before opening its
config dialog (auto-fed) and writes its own results back when done.
A user may also run any tool with empty state (manual input).

Invariants:
  • All state lives on `app.assault_state` (singleton on the app
    object), not on individual cards/widgets.
  • Cancellation is cooperative via `cancel_event` — workers must
    check it on every network step.
  • Serializable via `to_dict()` / `from_dict()` so a half-finished
    pipeline survives a session save/restore.
  • Scope is enforced via `target_host` — workers never make requests
    to a host other than the one Oracle was pointed at.

Concurrency: writes use `_lock`; reads return shallow copies of the
mutable lists/dicts so workers can iterate safely without holding
the lock.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse


# ─── Atomic data carriers ────────────────────────────────────────────

@dataclass
class ApiEndpoint:
    """One discoverable API surface (Swagger doc, GraphQL, REST root)."""
    url:        str
    kind:       str = "rest"      # rest | graphql | swagger | openapi | actuator | wsdl | other
    method:     str = "GET"
    status:     int = 0
    title:      str = ""
    framework:  str = ""          # "spring" / "flask" / "express" / ...
    notes:      str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ApiEndpoint":
        return cls(**{k: d.get(k, getattr(cls, k, ""))
                      for k in ("url","kind","method","status","title",
                                "framework","notes")})


@dataclass
class Param:
    """One injectable parameter on a given URL+method."""
    url:        str
    name:       str
    method:     str = "GET"        # GET | POST
    where:      str = "query"      # query | body | path | header | cookie
    sample:     str = ""           # example value seen during crawl
    source:     str = "crawl"      # crawl | oracle | manual

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Param":
        return cls(**{k: d.get(k, "") for k in
                      ("url","name","method","where","sample","source")})


@dataclass
class UploadForm:
    """A <form> with at least one <input type='file'>."""
    url:           str           # form action URL (absolute)
    method:        str = "POST"
    file_field:    str = ""      # name= of the file input
    other_fields:  list = field(default_factory=list)
    enctype:       str = "multipart/form-data"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "UploadForm":
        return cls(**{k: d.get(k, "" if k != "other_fields" else [])
                      for k in ("url","method","file_field",
                                "other_fields","enctype")})


@dataclass
class JwtToken:
    """A captured JWT (cookie, header, response body)."""
    token:       str
    source:      str = "cookie"  # cookie | header | body | manual
    where:       str = ""        # e.g. "Set-Cookie: session"
    seen_at:     str = ""        # URL where it was observed
    timestamp:   str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "JwtToken":
        return cls(**{k: d.get(k, "") for k in
                      ("token","source","where","seen_at","timestamp")})


# ─── Container ───────────────────────────────────────────────────────

class AssaultState:
    """Mutable shared state for the WEB ASSAULT pipeline.

    Attached to the app once at startup as `app.assault_state`.
    Reset on target change via `bind_target(url)`.
    """

    PIPELINE_STEPS = ("oracle", "crawl", "inject", "jwt")

    def __init__(self):
        self._lock         = threading.RLock()

        # Scope: every worker compares against this host before any
        # network request.  Empty = no scope enforced (worker should
        # refuse to run if scope is required and target_host is empty).
        self.target_url:    str = ""
        self.target_host:   str = ""

        # Oracle outputs.
        self.tech_stack:    list[str] = []          # ["Flask","gunicorn","Bootstrap"]
        self.api_endpoints: list[ApiEndpoint] = []
        self.exposures:     list[dict] = []         # {path,severity,note}

        # Crawl outputs.
        self.parameters:    list[Param] = []
        self.forms:         list[dict] = []         # raw form metadata
        self.upload_forms:  list[UploadForm] = []
        self.jwt_tokens:    list[JwtToken] = []
        self.cookies:       dict[str, str] = {}

        # Pipeline progress: per-step status string.
        self._steps:        dict[str, str] = {
            s: "pending" for s in self.PIPELINE_STEPS
        }
        # Per-step metadata: timestamps + last error message.
        # Populated automatically by `set_step()` based on transitions:
        #   pending → running:  started_at = now,  finished_at/error cleared
        #   running → done:     finished_at = now
        #   running → error:    finished_at = now, error = caller-supplied
        # Workers don't have to track this themselves — calling
        # `set_step("crawl","running")` followed later by
        # `set_step("crawl","done")` is enough.
        self._step_info:    dict[str, dict] = {
            s: {"started_at": None, "finished_at": None, "error": ""}
            for s in self.PIPELINE_STEPS
        }
        # Pipeline-level wall-clock — first-step start to last-step
        # finish.  Useful for the "Total: 4m 18s" line in the dialog
        # without recomputing from step_info every refresh.
        self.pipeline_started_at:  Optional[str] = None
        self.pipeline_updated_at:  Optional[str] = None

        # Cooperative cancellation — workers must call `is_cancelled()`
        # on each request loop iteration and abort gracefully.
        self.cancel_event:  threading.Event = threading.Event()

        # Subscribers for UI updates (pipeline bar polls this).
        self._subscribers:  list = []

    # ── Scope management ────────────────────────────────────────────
    def bind_target(self, url: str):
        """Pin scope to a URL.  Resets all collected data — call this
        when the user changes target so a stale pipeline doesn't bleed
        cross-target results.
        """
        with self._lock:
            self.target_url = url or ""
            try:
                self.target_host = (urlparse(url).hostname or "").lower()
            except Exception:
                self.target_host = ""
            # Reset payloads but keep cancel_event slot (recreate fresh
            # so a previous cancel doesn't bleed into the new target).
            self.tech_stack    = []
            self.api_endpoints = []
            self.exposures     = []
            self.parameters    = []
            self.forms         = []
            self.upload_forms  = []
            self.jwt_tokens    = []
            self.cookies       = {}
            for s in self.PIPELINE_STEPS:
                self._steps[s] = "pending"
                self._step_info[s] = {"started_at": None,
                                       "finished_at": None,
                                       "error": ""}
            self.pipeline_started_at = None
            self.pipeline_updated_at = None
            self.cancel_event = threading.Event()
        self._notify()

    def in_scope(self, url: str) -> bool:
        """True if the given URL is on the same host as the bound
        target.  Workers should call this BEFORE every request and
        skip out-of-scope URLs.  Returns True when scope is unbound
        (caller is responsible for not calling this in that case)."""
        if not self.target_host:
            return True
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        return host == self.target_host

    # ── Cancellation ────────────────────────────────────────────────
    def cancel(self):
        """Request cooperative cancellation of running workers."""
        self.cancel_event.set()
        self._notify()

    def reset_cancel(self):
        """Clear the cancel flag — call before starting a new run."""
        with self._lock:
            self.cancel_event = threading.Event()

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    # ── Pipeline step status ────────────────────────────────────────
    def set_step(self, step: str, status: str, error: str = ""):
        """Set a pipeline step's status and auto-stamp timing.

        status ∈ {pending, ready, running, done, error, skipped}

        Side effects (atomic under `_lock`):
          • running   → started_at = now, finished_at = None, error = ""
          • done      → finished_at = now (started_at preserved)
          • error     → finished_at = now, error = `error` arg
          • pending   → all info cleared

        Also tracks `pipeline_started_at` / `pipeline_updated_at` so
        the dialog can show a single wall-clock for the whole run.
        """
        if step not in self._steps:
            return
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self._steps[step] = status
            info = self._step_info.setdefault(step, {})
            if status == "running":
                info["started_at"]  = now
                info["finished_at"] = None
                info["error"]       = ""
                if not self.pipeline_started_at:
                    self.pipeline_started_at = now
            elif status in ("done", "error", "skipped"):
                info["finished_at"] = now
                if status == "error":
                    info["error"] = error or info.get("error", "") or ""
            elif status == "pending":
                info["started_at"]  = None
                info["finished_at"] = None
                info["error"]       = ""
            self.pipeline_updated_at = now
        self._notify()

    def step(self, step: str) -> str:
        with self._lock:
            return self._steps.get(step, "pending")

    def steps(self) -> dict[str, str]:
        with self._lock:
            return dict(self._steps)

    def step_info(self, step: str) -> dict:
        """Return a snapshot of `{status, started_at, finished_at,
        error, duration_s}` for a single step.  duration_s is computed
        from started/finished and falls back to live elapsed when the
        step is currently running."""
        with self._lock:
            status = self._steps.get(step, "pending")
            info = dict(self._step_info.get(step, {}))
        info["status"] = status
        info["duration_s"] = self._compute_duration(info, status)
        return info

    @staticmethod
    def _compute_duration(info: dict, status: str) -> float:
        sa = info.get("started_at")
        fa = info.get("finished_at")
        if not sa:
            return 0.0
        try:
            start = datetime.fromisoformat(sa)
        except Exception:
            return 0.0
        if fa:
            try:
                end = datetime.fromisoformat(fa)
            except Exception:
                end = datetime.now()
        elif status == "running":
            end = datetime.now()
        else:
            return 0.0
        return max(0.0, (end - start).total_seconds())

    # ── Add helpers (idempotent) ────────────────────────────────────
    def add_tech(self, *items: str):
        with self._lock:
            seen = {t.lower() for t in self.tech_stack}
            for it in items:
                t = (it or "").strip()
                if t and t.lower() not in seen:
                    self.tech_stack.append(t)
                    seen.add(t.lower())
        self._notify()

    def add_api_endpoint(self, ep: ApiEndpoint):
        with self._lock:
            key = (ep.url, ep.method)
            for e in self.api_endpoints:
                if (e.url, e.method) == key:
                    return
            self.api_endpoints.append(ep)
        self._notify()

    def add_exposure(self, path: str, severity: str = "info", note: str = ""):
        with self._lock:
            for e in self.exposures:
                if e.get("path") == path:
                    return
            self.exposures.append({"path": path, "severity": severity,
                                   "note": note})
        self._notify()

    def add_parameter(self, param: Param):
        with self._lock:
            key = (param.url, param.name, param.method, param.where)
            for p in self.parameters:
                if (p.url, p.name, p.method, p.where) == key:
                    return
            self.parameters.append(param)
        self._notify()

    def add_form(self, form: dict):
        """Add a raw form descriptor (compatible with what Bloody Crawl
        already collects: {action, method, fields, has_password})."""
        with self._lock:
            key = (form.get("action",""), form.get("method","GET"))
            for f in self.forms:
                if (f.get("action",""), f.get("method","GET")) == key:
                    return
            self.forms.append(dict(form))
        self._notify()

    def add_upload_form(self, uf: UploadForm):
        with self._lock:
            for u in self.upload_forms:
                if (u.url, u.file_field) == (uf.url, uf.file_field):
                    return
            self.upload_forms.append(uf)
        self._notify()

    def add_jwt(self, jwt: JwtToken):
        with self._lock:
            if any(t.token == jwt.token for t in self.jwt_tokens):
                return
            self.jwt_tokens.append(jwt)
        self._notify()

    def update_cookies(self, mapping: dict):
        with self._lock:
            for k, v in (mapping or {}).items():
                if k:
                    self.cookies[k] = v
        self._notify()

    # ── Read helpers (return copies) ────────────────────────────────
    def get_parameters(self) -> list[Param]:
        with self._lock:
            return list(self.parameters)

    def get_upload_forms(self) -> list[UploadForm]:
        with self._lock:
            return list(self.upload_forms)

    def get_jwt_tokens(self) -> list[JwtToken]:
        with self._lock:
            return list(self.jwt_tokens)

    def get_api_endpoints(self) -> list[ApiEndpoint]:
        with self._lock:
            return list(self.api_endpoints)

    def get_tech(self) -> list[str]:
        with self._lock:
            return list(self.tech_stack)

    def summary(self) -> dict:
        """One-line snapshot for the pipeline UI bar + details dialog.

        Includes per-step timing/error so the dialog can render
        durations without a second call.
        """
        with self._lock:
            steps_copy   = dict(self._steps)
            info_copy    = {
                k: {**v,
                    "duration_s": self._compute_duration(v, steps_copy.get(k, "pending"))}
                for k, v in self._step_info.items()
            }
            return {
                "target":               self.target_url,
                "host":                 self.target_host,
                "tech":                 len(self.tech_stack),
                "api":                  len(self.api_endpoints),
                "params":               len(self.parameters),
                "uploads":              len(self.upload_forms),
                "jwts":                 len(self.jwt_tokens),
                "exposures":            len(self.exposures),
                "cancelled":            self.cancel_event.is_set(),
                "steps":                steps_copy,
                "step_info":            info_copy,
                "pipeline_started_at":  self.pipeline_started_at,
                "pipeline_updated_at":  self.pipeline_updated_at,
            }

    # ── Subscriptions (UI) ──────────────────────────────────────────
    def subscribe(self, callback):
        """Register a no-arg callback fired after every mutation.

        The pipeline UI bar uses this to refresh the step icons in real
        time without polling.  Callback runs synchronously on the
        thread that mutated the state — UI consumers must marshal back
        to the Tk thread themselves (use `app.after(0, ...)`).
        """
        with self._lock:
            self._subscribers.append(callback)

    def _notify(self):
        with self._lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb()
            except Exception:
                pass

    # ── Serialization ───────────────────────────────────────────────
    def to_dict(self) -> dict:
        with self._lock:
            return {
                "target_url":    self.target_url,
                "target_host":   self.target_host,
                "tech_stack":    list(self.tech_stack),
                "api_endpoints": [e.to_dict() for e in self.api_endpoints],
                "exposures":     list(self.exposures),
                "parameters":    [p.to_dict() for p in self.parameters],
                "forms":         list(self.forms),
                "upload_forms":  [u.to_dict() for u in self.upload_forms],
                "jwt_tokens":    [t.to_dict() for t in self.jwt_tokens],
                "cookies":       dict(self.cookies),
                "steps":         dict(self._steps),
                "step_info":     {k: dict(v) for k, v in
                                  self._step_info.items()},
                "pipeline_started_at": self.pipeline_started_at,
                "pipeline_updated_at": self.pipeline_updated_at,
            }

    def load_dict(self, d: dict):
        if not d:
            return
        with self._lock:
            self.target_url    = d.get("target_url", "")
            self.target_host   = d.get("target_host", "")
            self.tech_stack    = list(d.get("tech_stack", []))
            self.api_endpoints = [ApiEndpoint.from_dict(x)
                                  for x in d.get("api_endpoints", [])]
            self.exposures     = list(d.get("exposures", []))
            self.parameters    = [Param.from_dict(x)
                                  for x in d.get("parameters", [])]
            self.forms         = list(d.get("forms", []))
            self.upload_forms  = [UploadForm.from_dict(x)
                                  for x in d.get("upload_forms", [])]
            self.jwt_tokens    = [JwtToken.from_dict(x)
                                  for x in d.get("jwt_tokens", [])]
            self.cookies       = dict(d.get("cookies", {}))
            steps              = d.get("steps", {})
            info_loaded        = d.get("step_info", {}) or {}
            for s in self.PIPELINE_STEPS:
                self._steps[s] = steps.get(s, "pending")
                self._step_info[s] = {
                    "started_at":  (info_loaded.get(s, {}) or {}).get("started_at"),
                    "finished_at": (info_loaded.get(s, {}) or {}).get("finished_at"),
                    "error":       (info_loaded.get(s, {}) or {}).get("error", ""),
                }
            self.pipeline_started_at = d.get("pipeline_started_at")
            self.pipeline_updated_at = d.get("pipeline_updated_at")
        self._notify()
