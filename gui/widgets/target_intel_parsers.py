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
HAWK - Target Intel Widget v1.0
- Nmap vuln scripts findings → auto-populate intel
- Per-finding MSF launch button with pre-configured editable dialog
- OS Detection merge (don't overwrite existing ports)
- Single nonstandard port popup (flag)
- Spinner on all operations
"""

import customtkinter as ctk
import tkinter as tk
import os
import re
import time
import threading
import subprocess
import shlex
import json
import socket
import tempfile
import shutil
from datetime import datetime

from gui.widgets.target_intel_common import *

# `Name: value` on its own line.  Same shape as
# TargetIntelWidget._HTTP_HEADER_RE, kept here so the header extractor
# below is importable without the widget.
_HTTP_HEADER_LINE_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9\-]*):\s*([^\r\n]+)", re.MULTILINE)
_HTTP_STATUS_LINE_RE = re.compile(r"^HTTP/[\d.]+\s+\d{3}")


def extract_http_headers(text: str) -> dict:
    """Return {lowercased header name: value} from an HTTP transcript.

    Only the HEADER BLOCKS are read.  The old code ran the header
    regex over the whole captured text, body included, so any body line
    shaped like `Name: value` became a header — a page that merely
    TALKS about `Strict-Transport-Security: max-age=...` (a docs page,
    a <pre> block, a security.txt) made HAWK report the security header
    as PRESENT on a server that never sent it.

    A block runs from an `HTTP/x.y NNN` status line to the first blank
    line.  A redirect chain has several; the last one wins, matching
    what curl -v prints and what the operator cares about.

    When the text has no HTTP status line at all (a whatweb report, a
    raw nc transcript) there is nothing to scope to, so the legacy
    whole-text scan is used rather than losing the data outright.
    """
    headers = {}
    in_headers = False
    saw_status = False
    for line in (text or "").splitlines():
        if _HTTP_STATUS_LINE_RE.match(line):
            in_headers = True
            saw_status = True
            continue
        if not in_headers:
            continue
        if not line.strip():
            in_headers = False
            continue
        m = _HTTP_HEADER_LINE_RE.match(line)
        if m:
            headers[m.group(1).strip().lower()] = m.group(2).strip()
    if not saw_status:
        for m in _HTTP_HEADER_LINE_RE.finditer(text or ""):
            headers.setdefault(m.group(1).strip().lower(),
                               m.group(2).strip())
    return headers


class TargetIntelParserMixin:
    def _sess(self):
        try:
            return self.app.session_manager.current
        except Exception:
            return None

    def _persist_and_refresh_store(self) -> None:
        """Save the session and repaint the Credential Store.

        In-place promotions (unverified -> verified) mutate the raw
        ``sess.credentials`` dicts, so neither ``Session.save`` nor the
        widget refresh happen on their own: without this the promotion
        is lost on restart and the row keeps showing the UNVERIFIED
        badge until something else triggers a repaint.
        """
        sess = self._sess()
        if sess:
            try:
                sess.save()
            except Exception as e:
                print(f"[HAWK] session save after cred promotion: {e}")
        store = getattr(self.app, "cred_store", None)
        if store:
            try:
                store.refresh()
            except Exception as e:
                print(f"[HAWK] cred store refresh after promotion: {e}")

    @staticmethod
    def _promote_cred_dict(cdict: dict, note: str) -> bool:
        """Flip an existing credential dict to verified and append the
        evidence note.  Returns True when something actually changed."""
        changed = False
        if not cdict.get("verified", False):
            cdict["verified"] = True
            changed = True
        old_notes = (cdict.get("notes") or "").strip()
        if note and note not in old_notes:
            cdict["notes"] = (f"{old_notes}\n{note}".strip()
                              if old_notes else note)
            changed = True
        return changed

    def _mark_creds_verified(self, used_creds, host: str, service_tag: str,
                              evidence: str) -> bool:
        """Save a credential to the Credential Store when a captured
        CONNECT parser detects login success.

        Save-on-launch was removed (no more "[unverified]" entries) —
        this function is now the ONLY path that adds connect-typed
        credentials to the store.  Behaviour:
          • If a matching ``(user, password|hash, host, service)`` entry
            already exists → PROMOTE it to verified (the login we just
            observed is the proof), persist and repaint.
          • Otherwise → add a brand-new ``[verified by <evidence>]`` entry.

        Parameters
        ----------
        used_creds : tuple | None
            ``(user, password, hash)`` from the dialog, or None.
        host : str
            Target IP / hostname the credential belongs to.
        service_tag : str
            Service tag for the cred store (``SMB``, ``WINRM``, …).
        evidence : str
            Short string describing how we verified, e.g.
            ``"SMB share enumeration"`` or ``"WinRM netexec Pwn3d!"``.

        Returns
        -------
        bool
            True if a cred was added, False otherwise (already present
            — possibly promoted in place — or no usable input).
        """
        if not used_creds:
            return False
        try:
            user, password, hash_val = used_creds
        except Exception:
            return False
        user = (user or "").strip()
        if not user:
            return False
        password = password or ""
        hash_val = (hash_val or "").strip()

        sess = self._sess()
        store = getattr(self.app, "cred_store", None)
        if not store:
            return False

        cred_type = "hash" if (hash_val and not password) else "cleartext"
        secret = hash_val if cred_type == "hash" else password
        note_verified = f"[verified by {evidence}]"

        # Dedup: matching entry already in store → promote it in place.
        try:
            if sess:
                for cdict in sess.credentials:
                    if cdict.get("username") != user:
                        continue
                    if cdict.get("host") != host:
                        continue
                    if service_tag not in (cdict.get("services") or []):
                        continue
                    if cred_type == "cleartext":
                        if cdict.get("password") != secret:
                            continue
                    else:
                        if cdict.get("hash_val") != secret:
                            continue
                    # Already in the store — promote it to verified.
                    # This used to be a silent no-op, which left a
                    # credential the operator had just authenticated
                    # with stuck behind the UNVERIFIED badge.
                    if self._promote_cred_dict(cdict, note_verified):
                        sess._touch()
                        self._persist_and_refresh_store()
                        try:
                            self.app.terminal.write(
                                f"  [+] Cred promoted to verified: "
                                f"{user} → {service_tag}@{host}  "
                                f"({evidence})", "success")
                        except Exception:
                            pass
                    return False
        except Exception as e:
            print(f"[HAWK] _mark_creds_verified dedup error: {e}")

        # Not in store → add as new verified credential.
        try:
            from utils.session import Credential
            store.add_credential(Credential(
                username=user,
                password=(secret if cred_type == "cleartext" else ""),
                hash_val=(secret if cred_type == "hash"      else ""),
                cred_type=cred_type,
                services=[service_tag],
                source_phase="exploitation",
                host=host,
                notes=note_verified,
                # Only reached when a captured parser observed the
                # login succeed — that is the proof.
                verified=True,
            ))
            try:
                self.app.terminal.write(
                    f"  [+] Cred saved (verified): "
                    f"{user} → {service_tag}@{host}  ({evidence})",
                    "success")
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[HAWK] _mark_creds_verified add error: {e}")
            return False

    def _parse_hydra_output(self, target: str, port: int,
                             svc_key: str, text: str,
                             cmd: str = "") -> None:
        """Parse Hydra captured output for valid-credential hits and push
        them into the Credential Store as VERIFIED entries.

        Behaviour:
          • Adds a brand-new credential when no matching entry exists.
          • UPGRADES an existing `[unverified]` save-on-launch entry for
            the same (user, host, service, password) combo by rewriting
            its notes to `[verified by Hydra …]` — avoids duplication.
          • Adds a Target Intel finding so the user sees the win on the
            main panel, not just buried in the Credential Store.
          • When ``cmd`` is supplied and the hydra module is an HTTP/S
            one (``http-get``/``http-post``/``http-form`` + ``https``
            variants), runs the false-positive cascade check via
            ``utils.hydra_verify.detect_false_positive_cascade``.
            Misconfigured web apps return 200/302 to ANY credential and
            hydra happily flags every (user, pass) pair — without this
            check the Credential Store fills up with garbage like
            ``root:123456`` on a target that has no auth at all.
        """
        import re as _re
        hits = list(self._HYDRA_HIT_RE.finditer(text or ""))
        if not hits:
            return

        from utils.session import Credential
        sess = self._sess()
        store = getattr(self.app, "cred_store", None)
        if not store:
            return

        svc_tag = self._SVC_TAG_MAP.get(
            (svc_key or "").lower(), (svc_key or "").upper())

        # Verification pass.  Two layers:
        #   • the batch cascade guard, scoped to HTTP/HTTPS as before
        #     (a web endpoint that answers the same to any password);
        #   • a per-credential probe, which is the ONLY thing that can
        #     mark a cred verified.  A cred our own probe rejects is
        #     dropped even though hydra reported it.
        # Only fires when we have the launching cmd (Connect-dialog
        # brute path); without it nothing can be probed and every hit
        # is stored unverified.
        cred_note = "[unverified - no HAWK probe]"
        probe_by_pair = {}
        if cmd:
            try:
                from utils.hydra_verify import (
                    parse_hydra_cmd, verify_creds, unverified_note)
                cmd_info = parse_hydra_cmd(cmd)
                cred_note = unverified_note(cmd_info)
                is_http = (cmd_info.is_http or cmd_info.is_https or
                           cmd_info.proto.startswith(("http-", "https-")))
                extracted = [
                    (m.group(4), (m.group(5) or "").strip())
                    for m in hits]
                if is_http:
                    self.app.terminal.write(
                        f"  [*] Hydra HTTP cascade check: probing "
                        f"{cmd_info.proto}://{cmd_info.host}:"
                        f"{cmd_info.port}{cmd_info.path} with a "
                        f"fake password to validate "
                        f"{len(extracted)} reported cred(s)…",
                        "dim")
                kept, rejected, reason, is_cascade = verify_creds(
                    extracted, cmd_info, run_cascade=is_http)
                if is_cascade:
                    self.app.terminal.write(
                        f"  [!] HYDRA FALSE-POSITIVE CASCADE on "
                        f"{cmd_info.proto}://{cmd_info.host}:"
                        f"{cmd_info.port}{cmd_info.path} — "
                        f"dropping all {len(extracted)} reported "
                        f"cred(s).",
                        "error")
                    for ln in (reason or "").splitlines():
                        self.app.terminal.write(f"      {ln}",
                                                 "warn")
                    try:
                        self.add_auto_finding(
                            title=(f"HYDRA false-positive cascade "
                                    f"on {cmd_info.proto}://"
                                    f"{cmd_info.host}:"
                                    f"{cmd_info.port}"),
                            description=(reason or "")
                                + "\n\nNo credentials were saved.",
                            severity="high",
                            source="Hydra brute force "
                                   "(cascade guard)")
                    except Exception:
                        pass
                    return
                for _u, _p in rejected:
                    self.app.terminal.write(
                        f"  [!] hydra reported {_u} but HAWK's own "
                        f"{cmd_info.proto or 'auth'} probe was "
                        f"REJECTED — credential dropped, not saved.",
                        "error")
                probe_by_pair = {(u, p): v for u, p, v in kept}
                if len(kept) < len(extracted):
                    keep_set = set(probe_by_pair)
                    hits = [m for m in hits
                            if (m.group(4),
                                (m.group(5) or "").strip())
                            in keep_set]
                    self.app.terminal.write(
                        f"  [hawk] Hydra verification kept "
                        f"{len(hits)}/{len(extracted)} cred(s) "
                        f"after counter-probe.", "dim")
            except Exception as _e:
                # Verifier failure → keep the creds (dropping real
                # ones silently would be worse) but none of them can
                # claim to be verified.
                print(f"[HAWK] hydra-verify in connect path failed: {_e}")
                probe_by_pair = {}

        new_count = 0
        upgraded  = 0
        for m in hits:
            hit_port  = m.group(1)
            hit_proto = m.group(2)
            hit_host  = m.group(3)
            hit_user  = m.group(4)
            hit_pass  = (m.group(5) or "").strip()

            # Hydra reporting a hit is not proof — only HAWK's own
            # probe is (see utils/hydra_verify).
            probe = probe_by_pair.get((hit_user, hit_pass))
            if probe is True:
                hit_note = (
                    f"[verified by Hydra brute force + HAWK probe] "
                    f"{svc_tag}@{hit_host}:{hit_port} ({hit_proto})"
                )
            else:
                hit_note = (
                    f"[hydra reported valid] "
                    f"{svc_tag}@{hit_host}:{hit_port} ({hit_proto})  "
                    f"{cred_note}"
                )

            # Existing entry for the same cred?  Promote it only when
            # the probe proved it; otherwise leave it untouched (we
            # learned nothing new) and don't add a duplicate.
            upgraded_this_hit = False
            try:
                if sess:
                    for cdict in sess.credentials:
                        if (cdict.get("username") == hit_user
                                and cdict.get("host") == hit_host
                                and cdict.get("password") == hit_pass
                                and svc_tag in (cdict.get("services") or [])):
                            if probe is True and \
                                    self._promote_cred_dict(cdict, hit_note):
                                sess._touch()
                                # Promotion lives in the raw dict, so it
                                # only reaches disk / the UI if we save
                                # and repaint here.
                                self._persist_and_refresh_store()
                                upgraded += 1
                            upgraded_this_hit = True
                            break
            except Exception:
                pass

            if upgraded_this_hit:
                continue

            try:
                store.add_credential(Credential(
                    username=hit_user,
                    password=hit_pass,
                    cred_type="cleartext",
                    services=[svc_tag],
                    source_phase="exploitation",
                    host=hit_host,
                    notes=hit_note,
                    verified=(probe is True),
                ))
                new_count += 1
            except Exception as e:
                print(f"[HAWK] hydra parser cred add failed: {e}")

        if new_count or upgraded:
            try:
                bits = []
                if new_count:
                    bits.append(f"{new_count} new")
                if upgraded:
                    bits.append(f"{upgraded} upgraded → verified")
                self.app.terminal.write(
                    f"  [+] Hydra brute force: "
                    f"{', '.join(bits)} cred(s) saved to store.",
                    "success")
            except Exception:
                pass

            # Also surface the win on the Target Intel panel so the user
            # doesn't have to switch to the Credential Store to see it.
            try:
                first = hits[0]
                desc_parts = [
                    f"Hydra found {len(hits)} valid credential"
                    f"{'s' if len(hits) != 1 else ''} on "
                    f"{svc_tag} {target}:{port}.",
                    "",
                ]
                for m in hits[:5]:
                    desc_parts.append(
                        f"  • {m.group(4)} : {(m.group(5) or '').strip()}")
                if len(hits) > 5:
                    desc_parts.append(f"  • … and {len(hits) - 5} more")
                desc_parts.append("")
                n_proven = sum(1 for v in probe_by_pair.values()
                               if v is True)
                desc_parts.append(
                    f"Saved to the Credential Store: {n_proven} of "
                    f"{len(hits)} confirmed by HAWK's own auth probe; "
                    f"the rest are marked UNVERIFIED "
                    f"({cred_note}).")
                self.add_auto_finding(
                    title=f"{svc_tag} brute force: valid credentials found",
                    description="\n".join(desc_parts),
                    severity="critical",
                    source="Hydra brute force")
            except Exception:
                pass

    def _parse_netexec_brute_output(self, target: str, port: int,
                                     svc_key: str, text: str) -> None:
        """Parse netexec brute / spray output for valid credentials and
        lockout indicators.  Used for WinRM brute (netexec) and for any
        ``nxc <svc> -u <list> -p '<pw>' --continue-on-success`` style
        spray launched from the lockout-warning popup."""
        import re as _re
        from utils.session import Credential

        sess = self._sess()
        store = getattr(self.app, "cred_store", None)
        if not store:
            return

        svc_tag = self._SVC_TAG_MAP.get(
            (svc_key or "").lower(), (svc_key or "").upper())

        hits = list(self._NXC_HIT_RE.finditer(text or ""))
        locked = list(self._NXC_LOCKED_RE.finditer(text or ""))

        new_count = 0
        admin_count = 0
        for m in hits:
            dom    = (m.group(1) or "").strip()
            usr    = m.group(2).strip()
            pw     = (m.group(3) or "").strip()
            pwn3d  = bool(m.group(4))
            note   = (f"[verified by netexec brute/spray] "
                      f"{svc_tag}@{target}:{port}"
                      + (f" (Pwn3d! → local admin)" if pwn3d else "")
                      + (f"  domain={dom}" if dom else ""))
            try:
                # Dedup-aware add: if same (user, password, host, svc)
                # already in store, skip silently.
                if sess:
                    found_dup = any(
                        c.get("username") == usr
                        and c.get("password") == pw
                        and c.get("host") == target
                        and svc_tag in (c.get("services") or [])
                        for c in sess.credentials
                    )
                    if found_dup:
                        continue
                store.add_credential(Credential(
                    username=usr, password=pw, cred_type="cleartext",
                    services=[svc_tag], source_phase="exploitation",
                    host=target, notes=note,
                    # netexec prints [+] only after the login was
                    # accepted by the service.
                    verified=True,
                ))
                new_count += 1
                if pwn3d:
                    admin_count += 1
            except Exception as e:
                print(f"[HAWK] nxc parser cred add failed: {e}")

        if new_count:
            try:
                self.app.terminal.write(
                    f"  [+] netexec brute/spray: {new_count} cred"
                    f"{'s' if new_count != 1 else ''} saved"
                    + (f" ({admin_count} local admin)"
                       if admin_count else ""),
                    "success")
            except Exception:
                pass
            # Surface as a Target Intel finding too
            try:
                desc_parts = [
                    f"netexec brute/spray found {new_count} valid "
                    f"credential{'s' if new_count != 1 else ''} on "
                    f"{svc_tag} {target}:{port}"
                    + (f" ({admin_count} local admin)"
                       if admin_count else "")
                    + ".",
                    "",
                ]
                for m in hits[:5]:
                    dom = (m.group(1) or "").strip()
                    usr = m.group(2).strip()
                    pw  = (m.group(3) or "").strip()
                    pwn = " (admin)" if m.group(4) else ""
                    desc_parts.append(
                        f"  • {dom + chr(92) if dom else ''}{usr} : {pw}{pwn}")
                if len(hits) > 5:
                    desc_parts.append(f"  • … and {len(hits) - 5} more")
                self.add_auto_finding(
                    title=f"{svc_tag} brute/spray: valid credentials",
                    description="\n".join(desc_parts),
                    severity="critical" if admin_count else "high",
                    source="netexec brute/spray")
            except Exception:
                pass

        # Lockout diagnostic finding (info-severity, doesn't block flow)
        if locked:
            uniq_locked = sorted({m.group(2).strip() for m in locked})
            self.add_auto_finding(
                f"{svc_tag} brute: {len(uniq_locked)} accounts hit lockout",
                f"netexec reported lockout on {len(uniq_locked)} "
                f"account(s) during the brute on {target}:{port}:\n\n  • "
                + "\n  • ".join(uniq_locked[:20])
                + (f"\n  • … and {len(uniq_locked) - 20} more"
                   if len(uniq_locked) > 20 else "")
                + "\n\nConsider switching to password spraying "
                "(1 password × many users) to avoid further lockouts.",
                severity="medium",
                source="netexec brute/spray")

    def _parse_kerbrute_output(self, target: str, port: int,
                                svc_key: str, text: str) -> None:
        """Parse kerbrute output for valid LOGIN lines.  Saves cracked
        creds with note ``[verified by kerbrute pre-auth spray]``.
        ``svc_key`` here is informational — the actual service-tag for
        the cred store is always LDAP/AD because kerbrute talks to
        the KDC.  We use SMB as the default tag since most operators
        will follow up with SMB attempts after a kerbrute hit."""
        from utils.session import Credential

        store = getattr(self.app, "cred_store", None)
        sess = self._sess()
        if not store:
            return

        hits = list(self._KERBRUTE_HIT_RE.finditer(text or ""))
        if not hits:
            return

        # Multi-tag: kerb-validated creds work on any AD service.  Tag
        # them broadly so the cred-picker shows them everywhere it
        # makes sense.
        services = ["SMB", "WINRM", "LDAP", "RDP", "MSSQL"]

        new_count = 0
        for m in hits:
            usr    = m.group(1).strip()
            domain = m.group(2).strip()
            pw     = (m.group(3) or "").strip()
            note = (f"[verified by kerbrute pre-auth spray] "
                    f"{usr}@{domain} on KDC {target}")
            try:
                if sess:
                    found_dup = any(
                        c.get("username") == usr
                        and c.get("password") == pw
                        and c.get("host") == target
                        for c in sess.credentials
                    )
                    if found_dup:
                        continue
                store.add_credential(Credential(
                    username=usr, password=pw, cred_type="cleartext",
                    services=services, source_phase="exploitation",
                    host=target, notes=note,
                    # kerbrute VALID LOGIN = Kerberos pre-auth
                    # succeeded with this password.
                    verified=True,
                ))
                new_count += 1
            except Exception as e:
                print(f"[HAWK] kerbrute parser cred add failed: {e}")

        if new_count:
            try:
                self.app.terminal.write(
                    f"  [+] kerbrute spray: {new_count} valid AD "
                    f"credential{'s' if new_count != 1 else ''} saved.",
                    "success")
            except Exception:
                pass
            desc_parts = [
                f"Kerberos pre-auth spray found {len(hits)} valid AD "
                f"credential{'s' if len(hits) != 1 else ''} on KDC "
                f"{target}.",
                "",
            ]
            for m in hits[:5]:
                desc_parts.append(
                    f"  • {m.group(1)}@{m.group(2)} : {m.group(3)}")
            if len(hits) > 5:
                desc_parts.append(f"  • … and {len(hits) - 5} more")
            self.add_auto_finding(
                title="Kerberos pre-auth spray: valid AD credentials",
                description="\n".join(desc_parts),
                severity="critical",
                source="kerbrute passwordspray")

    def _parse_patator_output(self, target: str, port: int,
                               svc_key: str, text: str) -> None:
        """Parse patator output for successful logins.  Patator prints a
        progress table + per-row results.  We grep the rows whose code
        column is in the success set for the given module and that
        weren't tagged as locked-out."""
        import re as _re
        from utils.session import Credential

        store = getattr(self.app, "cred_store", None)
        sess = self._sess()
        if not store:
            return

        svc_tag = self._SVC_TAG_MAP.get(
            (svc_key or "").lower(), (svc_key or "").upper())

        # Patator emits a final summary block — use that as ground truth
        # when present.  Falls back to row-scan when summary missing.
        summary_block = _re.search(
            r"Hits/Done/Skip/Fail/Size:[^\n]+\n[\s\S]+?(?=\n\n|\Z)",
            text)
        # Hit rows look like:
        #   1 | 200 |  1234 |   2.5 | user:password
        hits_raw = list(self._PATATOR_HIT_RE.finditer(
            (summary_block.group(0) if summary_block else text) or ""))
        if not hits_raw:
            return

        new_count = 0
        for m in hits_raw:
            usr = m.group("user").strip()
            pw  = m.group("pwd").strip()
            if not usr or not pw:
                continue
            note = (f"[verified by patator brute] "
                    f"{svc_tag}@{target}:{port}")
            try:
                if sess:
                    found_dup = any(
                        c.get("username") == usr
                        and c.get("password") == pw
                        and c.get("host") == target
                        and svc_tag in (c.get("services") or [])
                        for c in sess.credentials
                    )
                    if found_dup:
                        continue
                store.add_credential(Credential(
                    username=usr, password=pw, cred_type="cleartext",
                    services=[svc_tag], source_phase="exploitation",
                    host=target, notes=note,
                    # A patator hit row is a login the module drove to
                    # success against the service.
                    verified=True,
                ))
                new_count += 1
            except Exception as e:
                print(f"[HAWK] patator parser cred add failed: {e}")

        if new_count:
            try:
                self.app.terminal.write(
                    f"  [+] patator brute: {new_count} cred"
                    f"{'s' if new_count != 1 else ''} saved.",
                    "success")
            except Exception:
                pass
            self.add_auto_finding(
                title=f"{svc_tag} patator brute: valid credentials",
                description=(
                    f"patator found {new_count} valid credential"
                    f"{'s' if new_count != 1 else ''} on "
                    f"{svc_tag} {target}:{port} (lockout-aware run)."),
                severity="critical",
                source="patator brute")

    def _parse_pass_policy_output(self, target: str, port: int,
                                    svc_key: str, text: str) -> None:
        """Parse netexec ``--pass-pol`` output.  Records the policy as a
        Target Intel finding so the operator can size subsequent brute
        attempts safely."""
        threshold_m = self._PASSPOL_THRESHOLD_RE.search(text or "")
        duration_m  = self._PASSPOL_DURATION_RE.search(text or "")
        if not (threshold_m or duration_m):
            return

        bits = []
        if threshold_m:
            bits.append(f"  • Lockout Threshold: {threshold_m.group(1)} "
                        f"failed attempts before lockout")
        if duration_m:
            unit = duration_m.group(2) or "minutes"
            bits.append(f"  • Lockout Duration: {duration_m.group(1)} "
                        f"{unit}")

        # Risk indicator
        thr_value = threshold_m.group(1) if threshold_m else ""
        if thr_value.isdigit() and int(thr_value) > 0 and int(thr_value) <= 5:
            risk = (f"\n⚠  Threshold is low ({thr_value}) — wordlist "
                    f"brute will lock accounts almost immediately.  "
                    f"Use spray/kerbrute instead.")
        elif thr_value in ("0", "None", "Never"):
            risk = ("\n✓  Threshold is 0 / disabled — wordlist brute "
                    "is safe (no lockout enforced).")
        else:
            risk = ""

        self.add_auto_finding(
            title=f"AD password policy on {target}",
            description=(
                f"Password / lockout policy retrieved from "
                f"{target}:{port}:\n\n"
                + "\n".join(bits)
                + (risk if risk else "")),
            severity="info",
            source="netexec --pass-pol")

    def _parse_smb_connect(self, aid, target, port, lines, text,
                            used_creds=None):
        import re as _re
        low = text.lower()

        # Hard denial (no finding).
        if ("nt_status_access_denied" in low and
                "sharename" not in low):
            return

        if aid in ("enum_anon", "enum_guest", "enum_auth", "enum_hash"):
            # smbclient -L table:  "<name>   Disk    <comment>"
            shares = []
            in_table = False
            for ln in lines:
                if _re.search(r"^\s*Sharename\s+Type", ln):
                    in_table = True
                    continue
                if in_table:
                    if not ln.strip() or ln.strip().startswith("---"):
                        continue
                    # End of shares block.
                    if (ln.strip().startswith("Server") or
                            ln.strip().startswith("Workgroup") or
                            ln.lower().startswith("reconnecting")):
                        in_table = False
                        continue
                    m = _re.match(
                        r"^\s*(\S+)\s+(Disk|IPC|Printer)\b",
                        ln, _re.IGNORECASE)
                    if m:
                        shares.append(m.group(1))

            # netexec/smbmap  "READ ONLY", "READ, WRITE", etc.
            nxc = _re.findall(
                r"^\s*(\S+)\s+(READ ONLY|READ, WRITE|READ|WRITE)",
                text, _re.MULTILINE | _re.IGNORECASE)
            for s, _perm in nxc:
                if s and s not in shares:
                    shares.append(s)

            # Did the login itself succeed?  smbclient prints
            # "Anonymous login successful" even when the share list
            # is empty (e.g. RestrictAnonymous, no Disk shares).
            anon_login_ok = "anonymous login successful" in low

            if shares:
                sess = self._sess()
                if sess:
                    try:
                        sess.add_discovered_shares(shares)
                    except Exception:
                        pass
                title_mode = {
                    "enum_anon":  "SMB anonymous share enumeration allowed",
                    "enum_guest": "SMB guest login enumeration allowed",
                    "enum_auth":  "SMB authenticated share enumeration",
                    "enum_hash":  "SMB pass-the-hash share enumeration",
                }.get(aid, "SMB share enumeration")
                sev = "high" if aid in ("enum_anon", "enum_guest") else "info"
                self.add_auto_finding(
                    title_mode,
                    f"Host {target}:{port} exposed {len(shares)} share(s): "
                    f"{', '.join(shares)}",
                    severity=sev, source="CONNECT / SMB")

                # Login proven by share listing → upgrade [unverified]
                # save-on-launch entry to [verified], or add new if absent.
                if aid in ("enum_auth", "enum_hash"):
                    self._mark_creds_verified(
                        used_creds, target, "SMB",
                        f"SMB share enumeration ({len(shares)} share"
                        f"{'s' if len(shares) != 1 else ''} listed)")

            elif anon_login_ok and aid in ("enum_anon", "enum_guest"):
                # Login succeeded but no shares were listed — still a
                # significant finding: the null session is accepted.
                mode_label = ("Anonymous" if aid == "enum_anon"
                              else "Guest")
                self.add_auto_finding(
                    f"SMB {mode_label.lower()} login accepted (no shares)",
                    f"{target}:{port} accepted the {mode_label.lower()} "
                    f"null-session but returned no share list. The "
                    f"credential is valid — try deeper enumeration:\n"
                    f"  enum4linux -a {target}\n"
                    f"  nxc smb {target} -u '' -p '' --rid-brute\n"
                    f"  rpcclient -U '' -N {target}",
                    severity="medium", source="CONNECT / SMB")

            # ── Auto-add anonymous/guest credential to Cred Store ────
            # When an anonymous or guest null-session succeeds we want
            # the credential visible in the Credential Store so the
            # user can USE it later (smbclient, enum4linux, rpcclient…).
            # This fires whether or not shares were found — the login
            # itself is the valuable piece of intel.
            if anon_login_ok and aid in ("enum_anon", "enum_guest"):
                try:
                    from utils.session import Credential
                    uname = ("anonymous" if aid == "enum_anon"
                             else "guest")
                    if shares:
                        share_list = ", ".join(shares[:6])
                        if len(shares) > 6:
                            share_list += " ..."
                        note_shares = (
                            f"{len(shares)} share(s): {share_list}")
                    else:
                        note_shares = "no shares listed (try enum4linux)"
                    cred = Credential(
                        username=uname,
                        password="",
                        cred_type="cleartext",
                        services=["SMB"],
                        source_phase="enumeration",
                        host=target,
                        notes=(
                            f"Null-session on {target}:{port} — "
                            f"{note_shares}\n"
                            f"smbclient //{target}/<SHARE> -N\n"
                            f"nxc smb {target} -u '{uname}' -p '' "
                            f"--shares\n"
                            f"enum4linux -a {target}\n"
                            f"rpcclient -U '' -N {target}"),
                        # Guarded by anon_login_ok: smbclient reported
                        # "Anonymous login successful".
                        verified=True,
                    )
                    if hasattr(self.app, "cred_store"):
                        self.app.cred_store.add_credential(cred)
                except Exception as e:
                    print(f"[HAWK] SMB anon cred-store: {e}")

        if aid == "check_creds":
            # netexec smb  "[+] DOM\\user:pass (Pwn3d!)"
            m = _re.search(
                r"\[\+\]\s+(\S+)\\(\S+):(\S+)(\s+\(Pwn3d!\))?",
                text)
            if m:
                dom, usr, _pw, pwn = m.groups()
                admin = bool(pwn)
                title = ("Valid SMB credential — local admin"
                         if admin else "Valid SMB credential")
                self.add_auto_finding(
                    title,
                    f"Credential succeeded on {target}:{port} "
                    f"({dom}\\{usr}).",
                    severity="critical" if admin else "high",
                    source="CONNECT / SMB")
                # Upgrade existing [unverified] save-on-launch entry if
                # the user matches; netexec confirms the cred works.
                self._mark_creds_verified(
                    used_creds, target, "SMB",
                    "netexec smb check_creds"
                    + (" (Pwn3d! → local admin)" if admin else ""))
                if hasattr(self.app, "cred_store"):
                    from utils.session import Credential
                    self.app.cred_store.add_credential(Credential(
                        username=usr, password=_pw,
                        cred_type="cleartext", services=["SMB"],
                        source_phase="enumeration", host=target,
                        notes=f"Validated via netexec smb ({dom}\\{usr})"
                              + (" — LOCAL ADMIN" if admin else ""),
                        verified=True))

    def _parse_winrm_connect(self, aid, target, port, lines, text,
                              used_creds=None):
        import re as _re
        m = _re.search(
            r"\[\+\]\s+(\S+)\\(\S+):(\S+)(\s+\(Pwn3d!\))?",
            text)
        if m:
            dom, usr, _pw, pwn = m.groups()
            admin = bool(pwn)
            self.add_auto_finding(
                "Valid WinRM credential — remote shell"
                + (" (admin)" if admin else ""),
                f"{dom}\\{usr} authenticates on WinRM {target}:{port}.",
                severity="critical" if admin else "high",
                source="CONNECT / WinRM")
            # Upgrade existing [unverified] save-on-launch entry.
            self._mark_creds_verified(
                used_creds, target, "WINRM",
                "netexec winrm validation"
                + (" (Pwn3d! → admin)" if admin else ""))
            if hasattr(self.app, "cred_store"):
                from utils.session import Credential
                self.app.cred_store.add_credential(Credential(
                    username=usr, password=_pw,
                    cred_type="cleartext", services=["WINRM"],
                    source_phase="enumeration", host=target,
                    notes=f"Validated via netexec winrm ({dom}\\{usr})"
                          + (" — ADMIN" if admin else ""),
                    verified=True))
        # evil-winrm shell-success heuristic — must see the actual
        # PowerShell prompt ("*Evil-WinRM* PS C:\\Users\\..."), which
        # evil-winrm prints ONLY after auth succeeds.  The plain
        # "Evil-WinRM" substring is the startup banner ("Evil-WinRM
        # shell v3.x") and is emitted before auth is attempted, so
        # matching it would flag every failed login as a success and
        # silently save the wrong credentials to the store.
        # Belt-and-suspenders: bail out if evil-winrm explicitly
        # reported an auth error or non-zero exit, since the prompt
        # could in principle scroll past alongside a later error.
        elif aid in ("shell_pw", "shell_hash") \
                and "*Evil-WinRM* PS" in text \
                and "WinRMAuthorizationError" not in text \
                and "Error: Exiting with code" not in text:
            self.add_auto_finding(
                "WinRM shell opened — credentials valid",
                f"evil-winrm authenticated on WinRM {target}:{port}.",
                severity="high", source="CONNECT / WinRM")
            self._mark_creds_verified(
                used_creds, target, "WINRM",
                "evil-winrm shell opened")

    def _parse_rdp_connect(self, aid, target, port, lines, text):
        low = text.lower()
        if "nla" in low and ("disabled" in low or "not enforced" in low):
            self.add_auto_finding(
                "RDP without Network Level Authentication",
                f"{target}:{port} exposes RDP without NLA — credential "
                "hunt attacks (hydra, ncrack) are feasible.",
                severity="medium", source="CONNECT / RDP")

    def _parse_ssh_connect(self, aid, target, port, lines, text,
                            used_creds=None):
        import re as _re
        m = _re.search(
            r"Authentications that can continue:\s*([^\r\n]+)", text)
        if m:
            methods = m.group(1).strip()
            self.add_auto_finding(
                "SSH authentication methods enumerated",
                f"{target}:{port} advertises: {methods}",
                severity="info", source="CONNECT / SSH")
        banner = _re.search(r"^(SSH-\d\.\d-[^\r\n]+)", text, _re.MULTILINE)
        if banner:
            self.add_auto_finding(
                "SSH banner captured",
                f"{target}:{port} — {banner.group(1).strip()}",
                severity="info", source="CONNECT / SSH")

        # ── Silent-failure diagnostic ─────────────────────────────────
        # When the user picked a cred-supplying action (Password
        # authentication, sshpass) but the captured trace has neither
        # a banner, an auth challenge, nor an explicit error — the
        # ssh client exited before reaching the auth layer.  This is
        # the pattern observed on Metasploitable2's OpenSSH 4.7p1
        # (last_linux.json #547-#551, rc=255 with empty output) where
        # the server drops new connections under load or refuses
        # password auth, and `LogLevel=ERROR` suppresses the warning.
        # Emit a single actionable hint so the user knows what to do
        # next instead of staring at a silent rc=255.
        low = text.lower()
        useful_lines = [
            ln for ln in lines
            if ln.strip()
            and not ln.strip().startswith("[")  # HAWK terminal markers
            and "warning:" not in ln.lower()   # SSH/sshpass warnings
        ]
        looks_silent = (
            not banner
            and "permission denied" not in low
            and "authentications that can continue" not in low
            and "connection refused" not in low
            and "connection closed" not in low
            and "no route to host" not in low
            and "host key verification failed" not in low
            and "could not connect" not in low
            and "socket error" not in low
            and len(useful_lines) <= 4
        )
        # Only fire when an auth action supplied creds — banner-only
        # / info-style actions are NOT supposed to print auth output.
        auth_action = (
            used_creds is not None
            and any((c or "").strip() for c in used_creds)
        )
        if looks_silent and auth_action:
            self.add_auto_finding(
                "SSH connect ended silently "
                "(no banner, no auth response)",
                f"{target}:{port} — the SSH client exited without "
                f"a banner, an auth challenge, or an error message. "
                f"`LogLevel=ERROR` on the client side suppresses the "
                f"warning text, so the rc=255 looks unexplained in "
                f"the terminal.\n\n"
                f"Likely causes (in order of frequency on lab / "
                f"legacy targets):\n"
                f"  • Server dropped the TCP connection before auth — "
                f"legacy OpenSSH 4.x with low MaxStartups under "
                f"concurrent probes (Metasploitable2 when hydra and "
                f"ssh run in parallel triggers exactly this).\n"
                f"  • Server refuses password auth "
                f"(`PasswordAuthentication no` in sshd_config — only "
                f"publickey / keyboard-interactive accepted).\n"
                f"  • Protocol-compat negotiation failed and the "
                f"matching error was silenced by LogLevel=ERROR.\n\n"
                f"Diagnostic next steps:\n"
                f"  • Try ncrack: `ncrack -p {port} --user <u> "
                f"--pass '<p>' ssh://{target}` — ncrack uses its own "
                f"SSH stack and is immune to client-side compat "
                f"issues. (On the same JSON trace, ncrack succeeded "
                f"on a target where ssh + hydra both failed silently.)\n"
                f"  • Enumerate auth methods: `ssh -vv "
                f"-o PreferredAuthentications=none -o BatchMode=yes "
                f"-p {port} <user>@{target}` — the resulting "
                f"'Permission denied' line lists the server's "
                f"accepted methods (publickey, password, ...).\n"
                f"  • If you ran hydra in parallel: wait 5-10 s "
                f"before retrying so the server's MaxStartups "
                f"counter recovers.",
                severity="medium", source="CONNECT / SSH")

    def _parse_ftp_connect(self, aid, target, port, lines, text,
                            used_creds=None):
        low = text.lower()
        # 230 = login successful in FTP. Anonymous case keeps its
        # special treatment, but ANY 230 with a logged-in user means
        # the typed creds worked → upgrade [unverified] → [verified].
        # 230 = login successful in FTP.  Different daemons phrase the
        # message differently:
        #   • vsftpd:    "230 Login successful."
        #   • ProFTPD:   "230 User <name> logged in"
        #   • Microsoft IIS FTP (5.0–10): "230 User logged in."
        #   • Pure-FTPd: "230 Anonymous user logged in"
        # Accept any of these phrasings; the older "login" substring
        # check alone missed IIS and ProFTPD because "logged in" does
        # not contain the contiguous string "login".
        login_ok = "230 " in text and (
            "login" in low or "logged in" in low)
        # Detect anonymous mode robustly. Three signals, any one matches:
        #   (1) action id is one of the anon-mode actions  ("anon",
        #       "list_anon", "download_anon"). The "anon" action uses
        #       `ftp -n` which suppresses prompt echo, so the typed
        #       `user anonymous` line is NEVER in the captured text.
        #   (2) the dialog passed username == "anonymous" via used_creds
        #       (covers any future anon-style action with a different id).
        #   (3) the literal "anonymous" string is present in the captured
        #       text (original heuristic, kept for backward compat with
        #       curl/wget-based anon actions that DO echo the user).
        aid_anon = aid in ("anon", "list_anon", "download_anon")
        creds_anon = False
        if used_creds:
            try:
                _u = (used_creds[0] or "").strip().lower()
                creds_anon = _u == "anonymous"
            except Exception:
                creds_anon = False
        is_anon = aid_anon or creds_anon or ("anonymous" in low)
        if login_ok and is_anon:
            self.add_auto_finding(
                "FTP anonymous login allowed",
                f"{target}:{port} accepts anonymous FTP login.",
                severity="high", source="CONNECT / FTP")
            if hasattr(self.app, "cred_store"):
                from utils.session import Credential
                self.app.cred_store.add_credential(Credential(
                    username="anonymous", password="anonymous",
                    cred_type="cleartext", services=["FTP"],
                    source_phase="enumeration", host=target,
                    notes=f"FTP anonymous login on {target}:{port}",
                    # Guarded by login_ok: the server answered 230.
                    verified=True))
        elif login_ok:
            # Authenticated login confirmed by 230 → verify the cred.
            self.add_auto_finding(
                "FTP login successful",
                f"{target}:{port} accepted authenticated FTP login.",
                severity="high", source="CONNECT / FTP")
            self._mark_creds_verified(
                used_creds, target, "FTP",
                "FTP 230 Login successful")
        # Collect file names from LIST output.
        import re as _re
        files = []
        for ln in lines:
            m = _re.match(
                r"^[-d][rwx\-]{9}\s+\d+\s+\S+\s+\S+\s+\d+\s+"
                r"\S+\s+\S+\s+\S+\s+(\S+)$", ln)
            if m:
                files.append(m.group(1))
        if files and aid in ("list_anon", "download_anon"):
            self.add_auto_finding(
                "FTP anonymous file listing",
                f"{target}:{port} — {len(files)} entries: "
                f"{', '.join(files[:12])}"
                + (" …" if len(files) > 12 else ""),
                severity="medium", source="CONNECT / FTP")

    def _parse_telnet_connect(self, aid, target, port, lines, text,
                               used_creds=None):
        """Parse captured CONNECT output for Telnet actions.

        Telnet was unparsed before — valid logins from the auth_creds
        action were never marked verified in the Credential Store, and
        the nmap `banner` script's raw IAC option-negotiation bytes
        (RFC 854: \\xFF\\xFB/\\xFC/\\xFD/\\xFE) were left in the
        terminal as backslash-x hex garbage with no explanation.

        Detects:
          • Successful login via the auth_creds action — strong markers
            are "Last login:" (Linux/BSD post-auth record), Linux
            kernel banner, Ubuntu/Debian MOTD copyright, or the cmd.exe
            banner on Windows telnet servers.
          • Failed login ("Login incorrect").
          • IAC option-negotiation bytes from nmap `--script banner`.
          • Empty/weak creds accepted by the telnet-brute no_auth scan.

        Works on:
          • Linux/BSD/Solaris telnetd (Metasploitable2, legacy Unix)
          • Windows Telnet Server (2000/2003/2008, Services for Unix)
          • Cisco/embedded-device telnet (banner text first, no IAC)
        """
        import re as _re
        low = text.lower()

        # ── IAC banner detection (nmap --script banner) ──────────────
        # Telnet starts every session with RFC 854 option negotiation:
        # \xFF + verb (\xFB WILL / \xFC WON'T / \xFD DO / \xFE DON'T)
        # + option-id byte.  nmap's `banner` script dumps the first
        # received bytes verbatim, so on telnet the captured banner
        # line is ALWAYS this IAC sequence — never plaintext.  We
        # surface a useful explanation instead of leaving the user
        # staring at `\xFF\xFD\x18\xFF\xFD ...` hex literals.
        # Match only when the banner line begins with IAC (\xFF) —
        # devices that send plaintext first (Cisco, some IoT) are
        # not affected.
        if aid == "banner":
            iac_line_m = _re.search(
                r"\|_banner:\s*(\\x[Ff][Ff][^\r\n]*)",
                text)
            if iac_line_m:
                iac_raw = iac_line_m.group(1).strip()
                # Token-by-token decode.  After each \xFF verb byte
                # the option-id is either an escaped \x.. hex literal
                # OR a single printable character (nmap prints byte
                # 0x20..0x7E literally — that's why " " and "#" and
                # "'" appear in the Metasploitable2 capture).
                TELNET_OPTS = {
                    0x01: "ECHO", 0x03: "SUPPRESS-GO-AHEAD",
                    0x05: "STATUS", 0x06: "TIMING-MARK",
                    0x18: "TERMINAL-TYPE", 0x1F: "NAWS (window-size)",
                    0x20: "TERMINAL-SPEED",
                    0x21: "REMOTE-FLOW-CONTROL",
                    0x22: "LINEMODE", 0x23: "X-DISPLAY-LOCATION",
                    0x24: "ENVIRON-OLD", 0x27: "NEW-ENVIRON",
                    0x2A: "CHARSET", 0x25: "AUTHENTICATION",
                    0x26: "ENCRYPT",
                }
                VERB = {0xFB: "WILL", 0xFC: "WON'T",
                        0xFD: "DO",   0xFE: "DON'T"}
                # Walk the string: every IAC verb followed by either
                # \x.. or a single printable char.
                idx = 0
                tokens = []
                while idx < len(iac_raw):
                    m = _re.match(
                        r"\\x[Ff][Ff]\\x([Ff][BbCcDdEe])"
                        r"(?:\\x([0-9A-Fa-f]{2})|(.))",
                        iac_raw[idx:])
                    if not m:
                        idx += 1
                        continue
                    verb = int(m.group(1), 16)
                    if m.group(2):
                        opt = int(m.group(2), 16)
                    else:
                        opt = ord(m.group(3))
                    tokens.append(
                        f"{VERB.get(verb, '?')} "
                        f"{TELNET_OPTS.get(opt, f'opt 0x{opt:02X}')}")
                    idx += m.end()
                decoded = ", ".join(tokens) if tokens else "(unparseable)"
                self.add_auto_finding(
                    "Telnet banner: IAC option negotiation "
                    "(no plaintext banner)",
                    f"{target}:{port} — nmap captured Telnet "
                    f"option-negotiation bytes, not a human-readable "
                    f"banner.  Telnet starts every session with RFC "
                    f"854 option exchange BEFORE any login prompt — "
                    f"this is normal protocol behaviour, not an "
                    f"error.\n\n"
                    f"Decoded options: {decoded}\n\n"
                    f"Raw IAC: {iac_raw}\n\n"
                    f"To get the login banner, connect interactively "
                    f"(`telnet {target} {port}`) and the issue-net / "
                    f"MOTD prints AFTER negotiation.",
                    severity="info", source="CONNECT / Telnet")

        # ── Login outcome (auth_creds, connect interactive) ──────────
        # Strong success markers — post-auth only:
        #   • "Last login:"             Linux/BSD post-auth login record
        #   • Linux kernel banner       e.g. "Linux <host> 2.6.x..."
        #   • Ubuntu/Debian MOTD        "absolutely no warranty"
        #   • Windows cmd.exe banner    "Microsoft Windows [Version"
        #   • Win cmd prompt            "C:\\... >"
        #   • Unix shell prompt         user@host:~$ / ~#
        # Pre-auth markers (issue-net banner, login prompts) are
        # NOT in this list — they appear on every connect attempt
        # regardless of auth outcome.
        success = (
            "last login:" in low
            or "absolutely no warranty" in low
            or "microsoft windows [version" in low
            or _re.search(
                r"^Linux\s+\S+\s+\d+\.\d+",
                text, _re.MULTILINE) is not None
            or _re.search(
                r"^[A-Z]:\\[^>\r\n]*>\s*$",
                text, _re.MULTILINE) is not None
            or _re.search(
                r"^[\w.\-]+@[\w.\-]+:[~\w./\-]*[#$]\s*$",
                text, _re.MULTILINE) is not None
        )
        failure = "login incorrect" in low or "authentication failed" in low

        if success:
            # Telnet IS cleartext by design — flag the protocol
            # property regardless of which cred was used.
            self.add_auto_finding(
                "Telnet cleartext authentication accepted",
                f"{target}:{port} accepted telnet login.  Username, "
                f"password and the full session travel UNENCRYPTED on "
                f"the wire — anyone with packet-capture access "
                f"(Wireshark, tcpdump, span port) recovers both "
                f"credentials and command output in plaintext.",
                severity="high", source="CONNECT / Telnet")
            self._mark_creds_verified(
                used_creds, target, "TELNET",
                "Telnet login successful (Last login / shell prompt)")
        elif failure and used_creds:
            # Don't push a finding for failed creds (noise), but tell
            # the user via the terminal so the dialog outcome is clear.
            try:
                u = (used_creds[0] or "?") if used_creds else "?"
                self.app.terminal.write(
                    f"  [*] Telnet login REJECTED for "
                    f"{u}@{target}:{port}", "warn")
            except Exception:
                pass

        # ── telnet-brute (no_auth empty-creds scan) ──────────────────
        # nmap script output (success):
        #   |   Accounts: <user>:<pass>   - Valid credentials
        #   |_  Statistics: Performed N guesses ...
        # On failure: "Accounts: No valid accounts found"
        if aid == "no_auth":
            m = _re.search(
                r"Accounts:\s+(\S+):(\S*)\s+-\s+Valid", text)
            if m:
                u, p = m.group(1), m.group(2)
                self.add_auto_finding(
                    "Telnet empty/weak credentials accepted",
                    f"{target}:{port} accepted telnet login: "
                    f"{u}:{p or '(empty password)'}",
                    severity="critical", source="CONNECT / Telnet")
                if hasattr(self.app, "cred_store"):
                    from utils.session import Credential
                    self.app.cred_store.add_credential(Credential(
                        username=u, password=p,
                        cred_type="cleartext", services=["TELNET"],
                        source_phase="enumeration", host=target,
                        notes=f"Telnet weak/empty creds from nmap "
                              f"telnet-brute on {target}:{port}",
                        # nmap telnet-brute prints the pair only after
                        # a successful login.
                        verified=True))

    def _parse_http_connect(self, aid, target, port, lines, text,
                            scheme="http", used_creds=None):
        """Rich HTTP/HTTPS captured-output parser.

        Pushes structured, multi-line findings into Target Intel covering:
          • Server fingerprint  (status / Server / X-Powered-By / Content-Type / title)
          • Cookies + backend stack inference
          • Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
          • Allowed methods (Allow header — flags PUT/DELETE as risky)
          • Redirects (Location header — exposes internal hostnames / vhosts)
          • CMS / framework body markers (WordPress / Drupal / Joomla / DVWA / Tomcat / …)
          • TLS certificate (HTTPS only — CN / issuer / SANs / validity)
          • WAF / CDN detection (Cf-Ray / X-Akamai / Server: cloudflare)
          • whatweb plugin output
          • Basic-auth verdict + auto-save credentials on success
        """
        import re as _re
        SCHEME = scheme.upper()

        # ── Status / core headers ─────────────────────────────────────────
        status_m = _re.search(r"^HTTP/[\d\.]+\s+(\d{3})\s+([^\r\n]*)",
                               text, _re.MULTILINE)
        status_code = status_m.group(1) if status_m else ""
        status_text = status_m.group(2).strip() if status_m else ""

        # Build a normalised header dict (last wins on dup keys — matches
        # how curl -v / curl -I dump headers, last response in a redirect
        # chain is what the user cares about).
        # Header BLOCKS only — see extract_http_headers() for why the
        # body must not be scanned.
        header_dict = extract_http_headers(text)

        def _h(name: str) -> str:
            return header_dict.get(name.lower(), "")

        server     = _h("Server")
        powered    = _h("X-Powered-By")
        ctype      = _h("Content-Type")
        location   = _h("Location")
        allow      = _h("Allow")
        www_auth   = _h("WWW-Authenticate")

        # Page title from HTML body (only present on full GET, not HEAD)
        title_m = _re.search(r"<title[^>]*>(.*?)</title>",
                              text, _re.IGNORECASE | _re.DOTALL)
        title = (title_m.group(1).strip().replace("\n", " ").replace("\r", "")
                 if title_m else "")
        if len(title) > 120:
            title = title[:117] + "…"

        # ── Cookies ───────────────────────────────────────────────────────
        cookie_lines = _re.findall(
            r"^Set-Cookie:\s*([^=;\r\n]+)=([^;\r\n]*)",
            text, _re.MULTILINE | _re.IGNORECASE)
        cookies     = []
        stack_hints = []
        for cname, cval in cookie_lines:
            cn = cname.strip()
            cookies.append(f"{cn} = {cval.strip()[:40]}"
                           + ("…" if len(cval.strip()) > 40 else ""))
            for needle, hint in self._COOKIE_STACK.items():
                if needle.lower() in cn.lower():
                    if hint not in stack_hints:
                        stack_hints.append(hint)

        # ── Security headers (presence/absence on production servers) ────
        SEC_HEADERS = [
            ("Strict-Transport-Security",  "HSTS"),
            ("Content-Security-Policy",    "CSP"),
            ("X-Frame-Options",            "X-Frame-Options"),
            ("X-Content-Type-Options",     "X-Content-Type-Options"),
            ("Referrer-Policy",            "Referrer-Policy"),
            ("Permissions-Policy",         "Permissions-Policy"),
        ]
        sec_present = []
        sec_missing = []
        for hname, label in SEC_HEADERS:
            v = _h(hname)
            if v:
                sec_present.append(f"{label}: {v[:80]}")
            else:
                sec_missing.append(label)

        # ── WAF / CDN detection from headers ─────────────────────────────
        waf_hits = []
        if _h("Cf-Ray") or "cloudflare" in server.lower():
            waf_hits.append("Cloudflare (CDN/WAF)")
        if _h("X-Akamai-Transformed") or "akamai" in server.lower():
            waf_hits.append("Akamai")
        if "x-sucuri-id" in header_dict:
            waf_hits.append("Sucuri WAF")
        if "x-cdn" in header_dict:
            waf_hits.append(f"CDN: {_h('X-CDN')}")
        if "x-amz-cf-id" in header_dict:
            waf_hits.append("AWS CloudFront")

        # ── CMS / framework body markers ─────────────────────────────────
        cms_hits = []
        for pat, label in self._CMS_MARKERS:
            mm = _re.search(pat, text, _re.IGNORECASE)
            if mm:
                resolved = label
                # Resolve back-reference \\1 if present
                if "\\1" in resolved:
                    g1 = mm.group(1) if mm.groups() else ""
                    resolved = resolved.replace("\\1", g1.strip())
                if resolved not in cms_hits:
                    cms_hits.append(resolved)

        # ── HTML comments (often leak version / dev paths) ───────────────
        # Cap length and count to avoid dumping minified blobs.
        comments = [c.strip() for c in
                    _re.findall(r"<!--\s*(.*?)\s*-->", text, _re.DOTALL)
                    if c.strip() and len(c.strip()) < 200
                    and not c.strip().startswith("[if")  # IE conditionals
                    ]
        comments = comments[:6]

        # ── Login forms (action= attribute) ──────────────────────────────
        login_forms = []
        for fm in _re.finditer(
                r"<form[^>]*action=['\"]([^'\"]+)['\"][^>]*>",
                text, _re.IGNORECASE):
            action_url = fm.group(1).strip()
            # Heuristic: forms whose action mentions login/auth/signin
            if _re.search(r"login|auth|signin|sign-in|admin",
                          action_url, _re.IGNORECASE):
                if action_url not in login_forms:
                    login_forms.append(action_url)

        # ── TLS cert (HTTPS only — extracted on ANY action via curl -vk) ─
        cert_bits = {}
        if scheme == "https":
            cn = _re.search(r"subject:[^\n]*CN\s*=\s*([^\r\n,]+)",
                            text, _re.IGNORECASE)
            iss = _re.search(r"issuer:[^\n]*CN\s*=\s*([^\r\n,]+)",
                             text, _re.IGNORECASE)
            sans = _re.findall(
                r"DNS:([\w\-\.\*]+)", text, _re.IGNORECASE)
            valid_from = _re.search(
                r"start date:\s*([^\r\n]+)", text, _re.IGNORECASE)
            valid_to = _re.search(
                r"expire date:\s*([^\r\n]+)", text, _re.IGNORECASE)
            if cn:         cert_bits["CN"]      = cn.group(1).strip()
            if iss:        cert_bits["Issuer"]  = iss.group(1).strip()
            if sans:       cert_bits["SANs"]    = sorted(set(sans))[:10]
            if valid_from: cert_bits["From"]    = valid_from.group(1).strip()
            if valid_to:   cert_bits["Until"]   = valid_to.group(1).strip()

        # ─────────────────────────────────────────────────────────────────
        #  Compose the multi-line "fingerprint" finding
        # ─────────────────────────────────────────────────────────────────
        if aid in ("head", "get", "basic_auth"):
            sections = []

            # 1) Server fingerprint
            srv_lines = []
            if status_code:
                srv_lines.append(f"Status: {status_code} {status_text}")
            if server:
                srv_lines.append(f"Server: {server}")
            if powered:
                srv_lines.append(f"X-Powered-By: {powered}")
            if ctype:
                srv_lines.append(f"Content-Type: {ctype}")
            if title:
                srv_lines.append(f"Page title: {title}")
            if location:
                srv_lines.append(f"Location (redirect): {location}")
            if srv_lines:
                sections.append(("Server fingerprint", srv_lines))

            # 2) Cookies + stack hints
            if cookies:
                ck_lines = list(cookies[:8])
                if len(cookies) > 8:
                    ck_lines.append(f"… and {len(cookies) - 8} more")
                if stack_hints:
                    ck_lines.append("")
                    ck_lines.append("Backend stack inferred:")
                    for h in stack_hints:
                        ck_lines.append(f"  → {h}")
                sections.append(("Cookies", ck_lines))

            # 3) Security headers
            sec_lines = []
            if sec_present:
                sec_lines.append("Present:")
                for s in sec_present:
                    sec_lines.append(f"  ✓ {s}")
            if sec_missing:
                if sec_lines:
                    sec_lines.append("")
                sec_lines.append("Missing:")
                for s in sec_missing:
                    sec_lines.append(f"  ✗ {s}")
            if sec_lines:
                sections.append(("Security headers", sec_lines))

            # 4) Allowed methods (only if explicitly returned)
            if allow:
                methods = [m.strip().upper()
                           for m in allow.split(",") if m.strip()]
                m_lines = [f"Allow: {', '.join(methods)}"]
                risky = [m for m in methods
                         if m in ("PUT", "DELETE", "PATCH", "TRACE",
                                   "CONNECT")]
                if risky:
                    m_lines.append(
                        f"⚠  Risky methods enabled: {', '.join(risky)}")
                sections.append(("HTTP methods", m_lines))

            # 5) WAF / CDN
            if waf_hits:
                sections.append(("WAF / CDN detected",
                                  [f"• {h}" for h in waf_hits]))

            # 6) CMS / framework markers (only on GET — body required)
            if cms_hits:
                sections.append(("CMS / framework",
                                  [f"• {c}" for c in cms_hits]))

            # 7) Login forms
            if login_forms:
                sections.append(("Login forms (action attribute)",
                                  [f"• {f}" for f in login_forms[:5]]))

            # 8) HTML comments (truncated, only if any)
            if comments:
                sections.append(("HTML comments (first 6)",
                                  [f"• {c[:160]}" for c in comments]))

            # 9) WWW-Authenticate
            if www_auth:
                sections.append(("Auth challenge",
                                  [f"WWW-Authenticate: {www_auth}"]))

            # 10) TLS cert (HTTPS)
            if cert_bits:
                tls_lines = []
                for k in ("CN", "Issuer", "From", "Until"):
                    if k in cert_bits:
                        tls_lines.append(f"{k}: {cert_bits[k]}")
                if "SANs" in cert_bits:
                    sans_v = cert_bits["SANs"]
                    tls_lines.append(
                        f"SANs: {', '.join(sans_v)}"
                        + (" …" if len(sans_v) >= 10 else ""))
                sections.append(("TLS certificate", tls_lines))

            # 11) Risk indicators (computed from collected facts)
            risk = []
            # EOL software heuristics
            eol_patterns = [
                (r"PHP/[45]\.",            "PHP 4.x / 5.x — EOL since 2008-2018, many CVEs"),
                (r"Apache/2\.[02]\.",      "Apache 2.0 / 2.2 — EOL since 2017"),
                (r"Apache/2\.4\.[0-9]\b",  "Apache 2.4.x (single-digit minor) — likely outdated"),
                (r"OpenSSL/0\.",           "OpenSSL 0.x — Heartbleed-era, EOL"),
                (r"OpenSSL/1\.0\.",        "OpenSSL 1.0.x — EOL since 2019"),
                (r"nginx/1\.[0-9]\.",      "nginx 1.0.x-1.9.x — outdated"),
                (r"IIS/[5-7]\.",           "IIS 5/6/7 — Windows 2003/2008 era"),
                (r"Apache Tomcat/[5-7]\.", "Apache Tomcat 5/6/7 — EOL"),
                (r"Microsoft-IIS/[5-7]\.", "IIS 5-7 — outdated, often Windows 2003/2008"),
            ]
            for pat, msg in eol_patterns:
                if _re.search(pat,
                              f"{server} {powered}", _re.IGNORECASE):
                    risk.append(msg)
            if not sec_present and not waf_hits:
                risk.append("Zero security headers + no WAF — likely "
                            "unhardened or default install")
            if "PUT" in (allow or "").upper() or \
               "DELETE" in (allow or "").upper():
                risk.append("PUT/DELETE method exposed — potential file "
                            "upload or destructive call")
            if cms_hits and any("vulnerable testbed" in c.lower()
                                for c in cms_hits):
                risk.append("Vulnerable testbed app detected — "
                            "likely Metasploitable / similar lab target")
            if risk:
                sections.append(("Risk indicators",
                                  [f"⚠  {r}" for r in risk]))

            # ── Render finding ────────────────────────────────────────────
            if sections:
                out = []
                for title_, body in sections:
                    out.append(f"{title_}:")
                    for ln in body:
                        if ln.startswith("  ") or ln == "":
                            out.append(ln)
                        else:
                            out.append(f"  • {ln}" if not ln.startswith("•")
                                       and not ln.startswith("✓")
                                       and not ln.startswith("✗")
                                       and not ln.startswith("⚠")
                                       and not ln.startswith("→")
                                       else f"  {ln}")
                    out.append("")
                desc = (f"{scheme}://{target}:{port}/  fingerprint\n\n"
                        + "\n".join(out).rstrip())

                # Severity escalates with risk indicators present
                if risk and any("EOL" in r or "PUT/DELETE" in r
                                 or "Vulnerable testbed" in r for r in risk):
                    sev = "high"
                elif risk:
                    sev = "medium"
                else:
                    sev = "info"

                self.add_auto_finding(
                    f"{SCHEME} fingerprint :{port}",
                    desc,
                    severity=sev,
                    source=f"CONNECT / {SCHEME}")
            elif aid in ("head", "get"):
                # Reachable but nothing distinctive — still log
                reach = (_re.search(r"Connected to ", text) or
                         _re.search(r"HTTP/", text))
                if reach:
                    self.add_auto_finding(
                        f"{SCHEME} endpoint reachable",
                        f"{target}:{port} responded but no distinctive "
                        f"headers/body were returned. Try whatweb / "
                        f"nikto / gobuster for deeper enumeration.",
                        severity="info", source=f"CONNECT / {SCHEME}")

        # ── whatweb output ────────────────────────────────────────────────
        if aid == "whatweb":
            plugins = _re.findall(r"([A-Z][A-Za-z0-9\-]+)\[([^\]]+)\]", text)
            if plugins:
                # Multi-line presentation, not crammed key=value
                lines_out = [f"• {n}: {v}" for n, v in plugins[:20]]
                if len(plugins) > 20:
                    lines_out.append(f"… and {len(plugins) - 20} more")
                self.add_auto_finding(
                    "Web technology fingerprint (whatweb)",
                    f"{scheme}://{target}:{port}/\n\n"
                    + "\n".join(lines_out),
                    severity="info", source="CONNECT / whatweb")

        # ── Standalone TLS-cert finding for the dedicated cert_info action
        # (the fingerprint block above already includes cert details on
        # head/get; this is the more verbose openssl x509 output).
        if aid == "cert_info" and cert_bits:
            tls_lines = []
            for k in ("CN", "Issuer", "From", "Until"):
                if k in cert_bits:
                    tls_lines.append(f"• {k}: {cert_bits[k]}")
            if "SANs" in cert_bits:
                sans_v = cert_bits["SANs"]
                tls_lines.append(
                    f"• SANs: {', '.join(sans_v)}"
                    + (" …" if len(sans_v) >= 10 else ""))
                # SANs frequently leak vhost names — surface as
                # subdomain-discovery hint
                vhosts = [s for s in sans_v
                          if s != target and "*" not in s]
                if vhosts:
                    tls_lines.append("")
                    tls_lines.append("Possible vhosts/subdomains from SANs:")
                    for v in vhosts[:8]:
                        tls_lines.append(f"  → {v}")
            if tls_lines:
                self.add_auto_finding(
                    "TLS certificate details",
                    f"{target}:{port}\n\n" + "\n".join(tls_lines),
                    severity="info", source="CONNECT / HTTPS")

        # ── Basic-auth verdict + cred capture on success ──────────────────
        if aid == "basic_auth":
            # Dual-probe protocol: probe-A goes WITHOUT auth to detect
            # whether the endpoint actually enforces Basic auth, and
            # probe-B sends the typed credentials.  Without probe-A,
            # any public endpoint (Apache root, CTF homepage,
            # /index.html on any non-protected URL) returns 200 OK
            # for EVERY request — including a credentialled one —
            # and the legacy parser declared "credentials valid"
            # even though the server ignored the Authorization
            # header entirely.  See last_linux.json #885-#911 for
            # the exact false-positive trace on Metasploitable2.
            PROBE_A_HDR = "=== HAWK probe-A (no auth) ==="
            PROBE_B_HDR = "=== HAWK probe-B (typed creds, verbose) ==="
            stat_a, wwa_a, stat_b = "", "", status_code
            if PROBE_A_HDR in text and PROBE_B_HDR in text:
                try:
                    pre, post = text.split(PROBE_B_HDR, 1)
                    txt_a = pre.split(PROBE_A_HDR, 1)[-1]
                    txt_b = post
                except Exception:
                    txt_a, txt_b = "", text
                m_a = _re.search(
                    r"^HTTP/[\d\.]+\s+(\d{3})",
                    txt_a, _re.MULTILINE)
                stat_a = m_a.group(1) if m_a else ""
                m_wa = _re.search(
                    r"^WWW-Authenticate:\s*(\S+)",
                    txt_a, _re.MULTILINE | _re.IGNORECASE)
                wwa_a = m_wa.group(1) if m_wa else ""
                m_b = _re.search(
                    r"^HTTP/[\d\.]+\s+(\d{3})",
                    txt_b, _re.MULTILINE)
                stat_b = m_b.group(1) if m_b else ""
            # Decision tree.
            endpoint_public = (
                stat_a in ("200", "301", "302") and not wwa_a)
            endpoint_protected = (
                stat_a == "401" or wwa_a.lower() == "basic")
            if endpoint_public:
                # FALSE-POSITIVE GUARD: endpoint returned 2xx/3xx to
                # the no-auth probe and never sent WWW-Authenticate.
                # The server is NOT enforcing Basic auth — the typed
                # credentials were silently ignored.  Emit an info
                # finding instead of the misleading "credentials
                # valid" one, and do NOT save the cred.
                self.add_auto_finding(
                    f"{SCHEME} basic-auth probe: endpoint is PUBLIC "
                    "(no auth required)",
                    f"{target}:{port} returned HTTP {stat_a} for the "
                    f"no-auth pre-probe — the endpoint does NOT "
                    f"require Basic authentication.  Any credentials "
                    f"supplied to curl are silently ignored by the "
                    f"server, so HAWK does NOT mark the typed creds "
                    f"as valid.\n\n"
                    f"Action: try a path that actually requires auth "
                    f"(e.g. /admin, /phpmyadmin, /manager/html, "
                    f"WebDAV mount points, /.well-known/...), or use "
                    f"the Hydra brute action which uses a "
                    f"counter-probe to detect this case.",
                    severity="info", source=f"CONNECT / {SCHEME}")
            elif endpoint_protected and stat_b in ("200", "301", "302"):
                # Real success: endpoint demanded auth (probe-A 401 +
                # WWW-Authenticate: Basic), credentials made probe-B
                # succeed.
                self.add_auto_finding(
                    f"{SCHEME} basic-auth credentials valid",
                    f"{target}:{port} accepted Basic credentials "
                    f"(status {stat_b}; pre-probe returned "
                    f"{stat_a or '?'} with WWW-Authenticate: "
                    f"{wwa_a or 'Basic'}). Credentials saved to the "
                    f"Credential Store as verified.",
                    severity="high", source=f"CONNECT / {SCHEME}")
                self._mark_creds_verified(
                    used_creds, target, SCHEME,
                    f"HTTP basic-auth probe returned {stat_b} "
                    f"(endpoint confirmed protected)")
                up = _re.search(r"-u\s+(\S+?):(\S+)", text)
                if up and not used_creds and hasattr(self.app, "cred_store"):
                    from utils.session import Credential
                    self.app.cred_store.add_credential(Credential(
                        username=up.group(1), password=up.group(2),
                        cred_type="cleartext",
                        services=[SCHEME],
                        source_phase="enumeration", host=target,
                        notes=(f"[verified by HTTP basic-auth probe] "
                               f"{scheme}://{target}:{port} returned "
                               f"{stat_b} with credentials "
                               f"(endpoint confirmed protected)"),
                        # Dual probe: 401 without creds, 2xx/3xx with
                        # them — the credentials did authenticate.
                        verified=True))
            elif endpoint_protected and stat_b == "401":
                self.add_auto_finding(
                    f"{SCHEME} basic-auth rejected",
                    f"{target}:{port} returned 401 Unauthorized to "
                    f"the typed credentials — they were not "
                    f"accepted.  (Endpoint was confirmed protected "
                    f"by the no-auth pre-probe: {stat_a} + "
                    f"WWW-Authenticate: {wwa_a or 'Basic'}.)",
                    severity="info", source=f"CONNECT / {SCHEME}")
            elif not stat_a and not (PROBE_A_HDR in text):
                # Legacy single-curl trace (no HAWK probe markers).
                # Preserve the old behaviour so HAWK keeps working if
                # the user runs an older action template.  Note: this
                # is the FP-prone path — kept ONLY for back-compat.
                if status_code in ("200", "301", "302"):
                    self.add_auto_finding(
                        f"{SCHEME} basic-auth credentials valid "
                        "(legacy probe, FP risk)",
                        f"{target}:{port} accepted Basic credentials "
                        f"(status {status_code}). NOTE: legacy "
                        f"single-probe template was used — this "
                        f"verdict cannot distinguish a real success "
                        f"from a public endpoint.  Re-run with the "
                        f"updated 'HTTP Basic auth request' action "
                        f"for the dual-probe verdict.",
                        severity="info", source=f"CONNECT / {SCHEME}")
                    self._mark_creds_verified(
                        used_creds, target, SCHEME,
                        f"HTTP basic-auth probe returned "
                        f"{status_code} (legacy single-probe)")
                elif status_code == "401":
                    self.add_auto_finding(
                        f"{SCHEME} basic-auth rejected",
                        f"{target}:{port} returned 401 Unauthorized "
                        f"— the supplied credentials were not "
                        f"accepted.",
                        severity="info", source=f"CONNECT / {SCHEME}")
            else:
                # Inconclusive: pre-probe response is unusual (5xx,
                # network error, redirect away).  Tell the user we
                # can't decide and let them retry on a known-good
                # path.
                self.add_auto_finding(
                    f"{SCHEME} basic-auth pre-probe inconclusive",
                    f"{target}:{port} pre-probe returned "
                    f"{stat_a or '<no status>'} "
                    f"(WWW-Authenticate: {wwa_a or '<none>'}).  Cred "
                    f"probe returned {stat_b or '<no status>'}.  "
                    f"HAWK cannot decide whether the endpoint "
                    f"enforces Basic auth.  Try a different URL "
                    f"path (e.g. /admin or /protected) and re-run.",
                    severity="info", source=f"CONNECT / {SCHEME}")

    def _parse_mysql_connect(self, aid, target, port, lines, text,
                              used_creds=None):
        low = text.lower()
        if aid == "empty_root" and ("mysql>" in low or
                                    "information_schema" in low):
            self.add_auto_finding(
                "MySQL root login with empty password",
                f"{target}:{port} — root connected without a password.",
                severity="critical", source="CONNECT / MySQL")
            if hasattr(self.app, "cred_store"):
                from utils.session import Credential
                self.app.cred_store.add_credential(Credential(
                    username="root", password="",
                    cred_type="cleartext", services=["MYSQL"],
                    source_phase="enumeration", host=target,
                    notes=f"MySQL root:empty on {target}:{port}",
                    # The mysql> prompt / information_schema output is
                    # only reachable after the login succeeded.
                    verified=True))
        if aid == "list_dbs":
            import re as _re
            dbs = _re.findall(
                r"^\s*\|\s*(\w+)\s*\|\s*$", text, _re.MULTILINE)
            dbs = [d for d in dbs if d.lower() not in
                   ("database", "information_schema",
                    "performance_schema", "mysql", "sys")]
            if dbs:
                self.add_auto_finding(
                    "MySQL application databases discovered",
                    f"{target}:{port} — {', '.join(dbs[:10])}"
                    + (" …" if len(dbs) > 10 else ""),
                    severity="medium", source="CONNECT / MySQL")
                # SHOW DATABASES output proves the typed creds worked.
                self._mark_creds_verified(
                    used_creds, target, "MYSQL",
                    "MySQL SHOW DATABASES succeeded")

    def _parse_postgres_connect(self, aid, target, port, lines, text,
                                 used_creds=None):
        low = text.lower()
        if "postgres=" in low or "list of databases" in low:
            self.add_auto_finding(
                "PostgreSQL login succeeded",
                f"{target}:{port} — psql session established.",
                severity="high", source="CONNECT / PostgreSQL")
            # The credential that opened this session is whatever the
            # operator typed in the dialog, and _mark_creds_verified
            # below stores exactly that.  This used to ALSO fabricate a
            # `<user>:<empty password>` row from the psql -U flag —
            # a credential nobody ever authenticated with, which then
            # sat in the store looking real.  Service tag kept aligned
            # with the connect dialog's ("POSTGRES").
            self._mark_creds_verified(
                used_creds, target, "POSTGRES",
                "PostgreSQL psql session opened")

    def _parse_mssql_connect(self, aid, target, port, lines, text,
                              used_creds=None):
        import re as _re
        m = _re.search(
            r"\[\+\]\s+(\S+)\\(\S+):(\S+)(\s+\(Pwn3d!\))?",
            text)
        if m:
            dom, usr, _pw, pwn = m.groups()
            admin = bool(pwn)
            self.add_auto_finding(
                "Valid MSSQL credential"
                + (" — sysadmin" if admin else ""),
                f"{dom}\\{usr} authenticates on MSSQL {target}:{port}.",
                severity="critical" if admin else "high",
                source="CONNECT / MSSQL")
            self._mark_creds_verified(
                used_creds, target, "MSSQL",
                "netexec mssql validation"
                + (" (Pwn3d! → sysadmin)" if admin else ""))
            if hasattr(self.app, "cred_store"):
                from utils.session import Credential
                self.app.cred_store.add_credential(Credential(
                    username=usr, password=_pw,
                    cred_type="cleartext", services=["MSSQL"],
                    source_phase="enumeration", host=target,
                    notes=f"Validated via netexec mssql ({dom}\\{usr})"
                          + (" — SYSADMIN" if admin else ""),
                    verified=True))

    def _parse_ldap_connect(self, aid, target, port, lines, text,
                             used_creds=None):
        import re as _re
        if aid in ("anon_base", "anon_dump", "auth_dump", "ad_users"):
            if "result: 0 Success" in text or "numEntries:" in text:
                dnc = _re.search(
                    r"defaultNamingContext:\s*([^\r\n]+)", text)
                rdn = _re.search(
                    r"rootDomainNamingContext:\s*([^\r\n]+)", text)
                desc = f"{target}:{port}"
                if dnc:
                    desc += f" — defaultNamingContext={dnc.group(1).strip()}"
                elif rdn:
                    desc += f" — domain={rdn.group(1).strip()}"
                is_anon = aid in ("anon_base", "anon_dump")
                self.add_auto_finding(
                    "LDAP anonymous bind allowed"
                    if is_anon else "LDAP bind succeeded",
                    desc,
                    severity="high" if is_anon else "info",
                    source="CONNECT / LDAP")
                if is_anon and hasattr(self.app, "cred_store"):
                    from utils.session import Credential
                    self.app.cred_store.add_credential(Credential(
                        username="anonymous", password="anonymous",
                        cred_type="cleartext", services=["LDAP"],
                        source_phase="enumeration", host=target,
                        notes=f"LDAP anonymous bind on {target}:{port}",
                        # "result: 0 Success" / numEntries — the
                        # anonymous bind was accepted.
                        verified=True))
                # Authenticated bind succeeded → upgrade typed creds.
                if not is_anon:
                    self._mark_creds_verified(
                        used_creds, target, "LDAP",
                        "LDAP authenticated bind succeeded")

            # Pull sAMAccountName entries for AD user dumps.
            users = _re.findall(
                r"sAMAccountName:\s*([^\r\n]+)", text)
            users = [u.strip() for u in users if u.strip()
                     and not u.strip().endswith("$")]
            if users:
                sess = self._sess()
                if sess:
                    try:
                        sess.add_discovered_users(users)
                    except Exception:
                        pass
                self.add_auto_finding(
                    "LDAP domain user accounts enumerated",
                    f"{target}:{port} — {len(users)} users "
                    f"(sample: {', '.join(users[:8])}"
                    + (" …" if len(users) > 8 else "") + ")",
                    severity="medium", source="CONNECT / LDAP")

    def _parse_redis_connect(self, aid, target, port, lines, text):
        import re as _re
        ver = _re.search(r"redis_version:([^\r\n]+)", text)
        role = _re.search(r"role:([^\r\n]+)", text)
        if ver:
            bits = [f"version={ver.group(1).strip()}"]
            if role:
                bits.append(f"role={role.group(1).strip()}")
            self.add_auto_finding(
                "Redis unauthenticated access",
                f"{target}:{port} answers INFO without AUTH — "
                + ", ".join(bits),
                severity="high", source="CONNECT / Redis")
            if hasattr(self.app, "cred_store"):
                from utils.session import Credential
                self.app.cred_store.add_credential(Credential(
                    username="(no auth)", password="",
                    cred_type="cleartext", services=["REDIS"],
                    source_phase="enumeration", host=target,
                    notes=f"Redis no-auth on {target}:{port} — "
                          + ", ".join(bits),
                    # INFO returned real data without AUTH: the
                    # unauthenticated access is proven, not inferred.
                    verified=True))

    def _parse_vnc_connect(self, aid, target, port, lines, text):
        """Parse `nmap --script vnc-info,realvnc-auth-bypass` output and
        push a structured fingerprint to Target Intel.

        Extracted facts:
          • Protocol version (3.3 / 3.7 / 3.8)
          • Full security-types list (with human labels)
          • Tight auth subtypes (when present)
          • realvnc-auth-bypass verdict (CVE-2006-2369)

        Risk indicators are auto-derived and set the finding severity:
          • None (1) accepted    → critical (no auth at all)
          • CVE-2006-2369 hit    → critical (pre-auth bypass)
          • VNC Authentication only → high (DES-8 password is weak)
          • Protocol 3.3         → medium (legacy, no extension support)
          • Otherwise            → info
        """
        import re as _re
        low = text.lower()

        # ── Protocol version ──────────────────────────────────────────────
        proto_m = _re.search(
            r"Protocol version:\s*([\d.]+)", text, _re.IGNORECASE)
        proto = proto_m.group(1).strip() if proto_m else ""

        # ── Security types ────────────────────────────────────────────────
        # Locate the "Security types:" block and pick out every indented
        # line until we hit a line that doesn't start with the pipe-and-
        # spaces continuation prefix.  Each entry is something like:
        #   |     VNC Authentication (2)
        #   |     Tight (16)
        sec_block = _re.search(
            r"Security types:\s*\n((?:\s*\|[^\n]*\n)+)",
            text, _re.IGNORECASE)
        sec_types = []
        if sec_block:
            for ln in sec_block.group(1).splitlines():
                # Strip nmap's "|   " or "|_  " prefix
                clean = _re.sub(r"^\s*\|[_\s]*", "", ln).strip()
                if not clean:
                    continue
                if ":" in clean and not _re.match(r"^[A-Za-z]", clean):
                    continue
                # Stop at the next sub-section header
                if clean.lower().startswith(("tight auth subtypes",
                                              "vendor:")):
                    break
                # Keep the entry verbatim so the type code (e.g. "(2)")
                # stays visible for the user.
                if _re.search(r"\(\d+\)", clean):
                    sec_types.append(clean)
                elif clean and clean[0].isupper():
                    sec_types.append(clean)

        # Fallback: simpler line-by-line scan if the block regex missed
        # (some nmap versions emit slightly different formatting).
        if not sec_types:
            for m in _re.finditer(
                    r"^\s*\|[_\s]*\s*([A-Z][\w\s\-]+?)\s*\((\d+)\)\s*$",
                    text, _re.MULTILINE):
                sec_types.append(f"{m.group(1).strip()} ({m.group(2)})")

        # ── Tight auth subtypes ──────────────────────────────────────────
        tight_block = _re.search(
            r"Tight auth subtypes:\s*\n((?:\s*\|[^\n]*\n)+)",
            text, _re.IGNORECASE)
        tight_subtypes = []
        if tight_block:
            for ln in tight_block.group(1).splitlines():
                clean = _re.sub(r"^\s*\|[_\s]*", "", ln).strip()
                if clean and _re.search(r"\(\d+\)", clean):
                    tight_subtypes.append(clean)

        # ── realvnc-auth-bypass verdict (CVE-2006-2369) ──────────────────
        bypass_vuln  = bool(_re.search(
            r"realvnc-auth-bypass[\s\S]{0,500}?VULNERABLE\b",
            text, _re.IGNORECASE))
        bypass_safe  = bool(_re.search(
            r"realvnc-auth-bypass[\s\S]{0,500}?NOT\s+VULNERABLE",
            text, _re.IGNORECASE))

        # ── No-auth detection ────────────────────────────────────────────
        # nmap may emit any of these phrasings depending on script version.
        no_auth = bool(
            "no authentication" in low or
            "auth types: 1" in low or
            any(_re.match(r"^\s*None\s*\(1\)", s) for s in sec_types) or
            "none (1)" in " ".join(s.lower() for s in sec_types))

        # ── Risk indicators (set severity at the same time) ──────────────
        risk = []
        if no_auth:
            risk.append("None (1) accepted — VNC reachable without ANY "
                        "credentials")
        if bypass_vuln:
            risk.append("RealVNC auth bypass (CVE-2006-2369) — pre-auth "
                        "RCE-equivalent over default port 5900")
        only_vnc_auth = (
            sec_types and all("vnc authentication" in s.lower()
                              for s in sec_types))
        if only_vnc_auth and not no_auth:
            risk.append("VNC Authentication is the only mechanism — "
                        "8-char DES password (brute-forceable, no salt)")
        if proto == "3.3":
            risk.append("Protocol 3.3 — legacy, no extensions, "
                        "vulnerable to downgrade attacks")

        # Severity logic — most severe wins.
        if no_auth or bypass_vuln:
            sev = "critical"
        elif only_vnc_auth:
            sev = "high"
        elif proto == "3.3":
            sev = "medium"
        else:
            sev = "info"

        # ── Compose multi-line finding ───────────────────────────────────
        # If we have nothing to report at all, log a "scan ran but no
        # info" hint instead of staying silent — the previous bug was
        # that the parser only fired on no-auth and silently dropped
        # every other case.
        if not (proto or sec_types or tight_subtypes or
                bypass_vuln or bypass_safe or no_auth):
            # Scan ran but the script returned nothing parseable —
            # surface a short note so the user isn't left wondering.
            self.add_auto_finding(
                f"VNC enumeration: no fingerprint",
                f"{target}:{port} — vnc-info / realvnc-auth-bypass "
                f"returned no parseable data. The server may be "
                f"non-VNC, behind a wrapper, or refusing the script "
                f"probe. Try `vncviewer {target}::{port}` directly.",
                severity="info", source="CONNECT / VNC")
            return

        sections = []

        fp_lines = []
        if proto:
            fp_lines.append(f"Protocol version: {proto}")
        if sec_types:
            fp_lines.append("Security types:")
            for s in sec_types:
                fp_lines.append(f"  • {s}")
        if tight_subtypes:
            fp_lines.append("")
            fp_lines.append("Tight auth subtypes:")
            for s in tight_subtypes:
                fp_lines.append(f"  • {s}")
        if fp_lines:
            sections.append(("VNC fingerprint", fp_lines))

        verdict_lines = []
        if no_auth:
            verdict_lines.append("✗ No authentication required — anyone "
                                  "can connect")
        if bypass_vuln:
            verdict_lines.append("✗ Vulnerable to CVE-2006-2369 "
                                  "(realvnc-auth-bypass)")
        if bypass_safe:
            verdict_lines.append("✓ Not vulnerable to CVE-2006-2369")
        if verdict_lines:
            sections.append(("Auth bypass verdict", verdict_lines))

        if risk:
            sections.append(("Risk indicators",
                              [f"⚠  {r}" for r in risk]))

        out = []
        for title_, body in sections:
            out.append(f"{title_}:")
            for ln in body:
                if ln.startswith(("  •", "  ⚠", "  ✓", "  ✗")) or ln == "":
                    out.append(ln)
                else:
                    out.append(f"  {ln}")
            out.append("")
        desc = (f"VNC {target}:{port}\n\n"
                + "\n".join(out).rstrip())

        self.add_auto_finding(
            f"VNC fingerprint :{port}",
            desc,
            severity=sev, source="CONNECT / VNC")

        # Save no-auth credential to store (existing behaviour preserved).
        if no_auth and hasattr(self.app, "cred_store"):
            from utils.session import Credential
            self.app.cred_store.add_credential(Credential(
                username="(no auth)", password="",
                cred_type="cleartext", services=["VNC"],
                source_phase="enumeration", host=target,
                notes=(f"VNC no-auth on {target}:{port} — advertised "
                       f"by the server's security-types list; no "
                       f"session was established"),
                # nmap read the advertised security types, it did not
                # open a VNC session: not proven.
                verified=False))

    def _parse_smtp_connect(self, aid, target, port, lines, text):
        import re as _re
        # swaks / nc wrappers prefix SMTP responses with "<- " — the
        # response code isn't at the physical line start.  Anchor on
        # "start-of-line OR a swaks arrow" so all layouts match.
        # Example swaks success: "<-  220 metasploitable.localdomain ESMTP ..."
        # Example swaks error:   "<** 501 5.1.7 Bad sender address syntax"
        # Example nc raw line:   "220 metasploitable.localdomain ESMTP ..."
        _RESP_PREFIX = r"(?:^|<-\s+|<\*\*\s+)"
        banner = _re.search(
            _RESP_PREFIX + r"220[ -]([^\r\n]+)",
            text, _re.MULTILINE)
        # Banner is useful evidence on EVERY action (open_relay, vrfy,
        # banner, …) — every SMTP exchange begins with 220, so we always
        # surface it once per run.  Previously this was gated on
        # aid == "banner" which meant the open-relay test's banner line
        # never made it to Target Intel.
        if banner:
            ban_text = banner.group(1).strip()
            self.add_auto_finding(
                "SMTP banner",
                f"{target}:{port} — {ban_text}",
                severity="info", source="CONNECT / SMTP")

        # FQDN/hostname harvesting — Postfix/Sendmail/Exim echo the server
        # hostname in the 220 banner AND in every 250- EHLO line.  Both
        # are valuable: they give us the target's self-reported FQDN even
        # when reverse-DNS from our side says nothing (CTF lab networks,
        # NAT'd boxes, HTB).  Example hits on Metasploitable2:
        #   <-  220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
        #   <-  250-metasploitable.localdomain
        # Require AT LEAST ONE dot in the captured label so we don't
        # false-match SMTP keywords like "PIPELINING", "VRFY", "DSN".
        # Skipped: bare IPs, protocol keywords, and the user's own
        # target string (would create a useless self-referential suggestion).
        fqdn_hit = _re.search(
            _RESP_PREFIX + r"2(?:20|50)[ -]"
            r"([A-Za-z0-9][\w-]{0,62}(?:\.[A-Za-z0-9][\w-]{0,62})+)\b",
            text, _re.MULTILINE)
        if fqdn_hit:
            host = fqdn_hit.group(1).strip().rstrip(".")
            # Reject obvious non-hostnames
            is_ip   = bool(_re.match(r"^\d+\.\d+\.\d+\.\d+$", host))
            is_kw   = host.lower() in ("esmtp", "smtp", "smtpd", "postfix",
                                        "sendmail", "exim", "qmail")
            is_self = host.lower() == (target or "").lower()
            if host and not is_ip and not is_kw and not is_self:
                # Update the fingerprint with what we learned — cheap,
                # non-destructive (only fills empty fields).
                fp = self._get_fingerprint()
                if fp is not None:
                    if not fp.fqdn and "." in host:
                        fp.fqdn = host
                    if not fp.computer_name:
                        fp.computer_name = host.split(".")[0]
                    # Domain = everything after the first label.  For a
                    # 2-label name like "metasploitable.localdomain" we
                    # DO NOT fill fp.domain (single TLD is rarely a real
                    # AD domain), but the suggestion below still fires
                    # with the full FQDN so the user can edit if needed.
                    if not fp.domain and host.count(".") >= 2:
                        fp.domain = host.split(".", 1)[1]
                # Push as a suggestion to the app — it handles dedup,
                # dialog rendering, session persistence, and target-bar
                # update.  suggest_target_domain() silently drops names
                # without a dot, so we only bother for real FQDNs.
                if "." in host:
                    try:
                        self.app.suggest_target_domain(
                            host, f"SMTP banner / EHLO :{port}",
                            confidence=85,
                            evidence=(banner.group(0).strip()
                                      if banner else
                                      f"250-{host}"))
                    except Exception as e:
                        try:
                            self.app.terminal.write(
                                f"  [!] domain suggest error: {e}", "dim")
                        except Exception:
                            pass
                    # Also surface as an auto-finding so the evidence
                    # sticks around in Target Intel even if the user
                    # dismisses the dialog.
                    self.add_auto_finding(
                        "Target FQDN / hostname from SMTP",
                        f"{target}:{port} self-reports as '{host}'",
                        severity="info", source="CONNECT / SMTP")

        # ── EHLO capabilities ─────────────────────────────────────────────
        # Always parse 250-<keyword> lines if present in output. These
        # tell us the server feature set — VRFY enabled (enum risk),
        # STARTTLS support, AUTH methods (login mechs), PIPELINING,
        # message size limit, etc. Every SMTP capture sees them so we
        # extract on any aid that includes the EHLO exchange.
        cap_lines = _re.findall(
            _RESP_PREFIX + r"250[- ]([A-Z0-9][A-Z0-9 _\-]*[A-Z0-9 ]*)",
            text, _re.MULTILINE)
        if cap_lines:
            # Normalise: keep only the keyword (first token) when the line
            # carries args ("SIZE 10240000" → "SIZE", "AUTH PLAIN LOGIN" →
            # "AUTH PLAIN LOGIN" — keep AUTH args because they matter).
            seen = []
            risky = []
            for raw in cap_lines:
                cap = raw.strip()
                if not cap:
                    continue
                kw = cap.split()[0].upper()
                # Drop FQDN echoes that look like "metasploitable.localdomain"
                if "." in kw:
                    continue
                # Skip non-capability words that may slip through (rare)
                if kw in ("OK", "BYE"):
                    continue
                if cap not in seen:
                    seen.append(cap)
                # Risk-flag specific capabilities
                if kw == "VRFY":
                    risky.append("VRFY enabled — username enumeration possible")
                elif kw == "EXPN":
                    risky.append("EXPN enabled — mailing list enumeration possible")
                elif kw == "ETRN":
                    risky.append("ETRN enabled — queue flush via remote command (ESMTP relay)")
                elif kw == "AUTH" and len(cap.split()) > 1:
                    methods = " ".join(cap.split()[1:])
                    risky.append(f"AUTH methods exposed: {methods}")
            if seen:
                desc = ("Capabilities advertised by the EHLO response:\n  • "
                        + "\n  • ".join(seen))
                if risky:
                    desc += "\n\nRisk indicators:\n  • " + "\n  • ".join(risky)
                # Severity: risky if VRFY/EXPN/AUTH-cleartext present
                sev = "low"
                risky_low = " ".join(risky).lower()
                if "vrfy" in risky_low or "expn" in risky_low:
                    sev = "medium"
                self.add_auto_finding(
                    "SMTP capabilities (EHLO)",
                    f"{target}:{port}\n\n{desc}",
                    severity=sev, source="CONNECT / SMTP")

        # ── VRFY user enumeration results ─────────────────────────────────
        # smtp-user-enum prints lines like:
        #   192.168.176.138: root exists
        #   192.168.176.138: msfadmin exists
        # The previous regex matched any "250 xxx" line, which would also
        # match the 250 OK MAIL FROM responses from open-relay tests.
        # Anchor specifically on smtp-user-enum's "<host>: <user> exists"
        # output to avoid cross-action false positives.
        if aid in ("vrfy", "vrfy_single"):
            # RFC 2142 (Mailbox Names For Common Services, Roles And
            # Functions) MANDATES certain mailbox names at every
            # domain that handles mail.  These are virtual aliases
            # routed to a real account by the MTA — they almost never
            # correspond to a login user.  Flag them so the operator
            # doesn't waste brute-force passes on names that aren't
            # password-protected accounts.  Conservative list: only
            # the names that are virtually never login users.  Names
            # like `ftp`, `news`, `www`, `mail` are excluded because
            # on Linux/BSD they ARE often real system accounts.
            RFC2142_ALIASES = {
                "postmaster", "abuse", "webmaster", "hostmaster",
                "noc", "security", "info", "mailer-daemon",
            }
            # Case-insensitive dedup — smtp-user-enum with a wordlist
            # containing both "root" and "ROOT" hit the same Postfix
            # account TWICE and we previously listed both forms.  Keep
            # the first-seen casing for display.
            uniq_users = []
            seen_low = set()
            for m in _re.finditer(
                r"^\s*\S+:\s+(\S+)\s+exists\s*$",
                text, _re.MULTILINE,
            ):
                u = m.group(1).strip()
                if not u:
                    continue
                lu = u.lower()
                if lu in seen_low:
                    continue
                seen_low.add(lu)
                uniq_users.append(u)
            if uniq_users:
                # Split into login candidates vs RFC-2142 aliases.
                login_users = [u for u in uniq_users
                               if u.lower() not in RFC2142_ALIASES]
                alias_users = [u for u in uniq_users
                               if u.lower() in RFC2142_ALIASES]
                sess = self._sess()
                if sess:
                    try:
                        # Only push real login candidates to the
                        # discovered_users list — aliases pollute
                        # brute-force wordlists and other downstream
                        # tools.
                        sess.add_discovered_users(login_users)
                    except Exception:
                        pass
                parts = [
                    f"{len(uniq_users)} user(s) confirmed via "
                    f"VRFY on {target}:{port}."
                ]
                if login_users:
                    parts.append(
                        "\n\nLogin candidates:\n  • "
                        + "\n  • ".join(login_users[:50]))
                    if len(login_users) > 50:
                        parts.append(
                            f"\n  • … and {len(login_users) - 50} more")
                if alias_users:
                    parts.append(
                        "\n\nRFC 2142 mailbox aliases (mandated by RFC, "
                        "usually NOT login accounts — excluded from "
                        "discovered-users list):\n  • "
                        + "\n  • ".join(alias_users))
                self.add_auto_finding(
                    "SMTP VRFY enumeration: valid users",
                    "".join(parts),
                    severity="high", source="CONNECT / SMTP")

        # ── Open-relay verdict ────────────────────────────────────────────
        # Always report a verdict (positive or negative) so the user has
        # confirmation that the test ran.  Positive verdict = the server
        # accepted RCPT TO an external address with 250 OK after MAIL FROM
        # was accepted too.  Negative = the server refused at MAIL FROM
        # (sender-validation) OR at RCPT TO (relay-denied).  We disambiguate
        # those failure modes so the user knows WHY it failed.
        if aid == "open_relay":
            relay_open = bool(_re.search(
                _RESP_PREFIX + r"250\s+(?:Ok|2\.\d\.\d\s+Ok|"
                r"queued as|accepted)", text, _re.IGNORECASE))
            sender_rejected = bool(_re.search(
                _RESP_PREFIX + r"5\d\d[ -].*?"
                r"(sender|MAIL FROM|address syntax)",
                text, _re.IGNORECASE))
            relay_denied = bool(_re.search(
                _RESP_PREFIX + r"(?:550|554)[ -].*?"
                r"(relay|relaying|not permitted|access denied)",
                text, _re.IGNORECASE))

            if relay_open:
                self.add_auto_finding(
                    "SMTP open relay (CRITICAL)",
                    f"{target}:{port} accepted RCPT TO an external address "
                    f"and queued the message — this is a fully open relay. "
                    f"Abusable for spam, phishing, and identity spoofing.",
                    severity="critical", source="CONNECT / SMTP")
            elif relay_denied:
                self.add_auto_finding(
                    "SMTP open-relay test: blocked at relay",
                    f"{target}:{port} refused to relay an external "
                    f"recipient (550/554 relay denied). The server is "
                    f"NOT an open relay — this is the safe default.",
                    severity="info", source="CONNECT / SMTP")
            elif sender_rejected:
                self.add_auto_finding(
                    "SMTP open-relay test: blocked at sender validation",
                    f"{target}:{port} rejected the spoofed envelope "
                    f"sender (5xx during MAIL FROM). The relay test could "
                    f"not progress to RCPT — try a sender that the server "
                    f"considers locally valid (e.g. user@<server-fqdn>) "
                    f"to test relay behaviour properly.",
                    severity="info", source="CONNECT / SMTP")

    def _quick_probe(self, port: int, svc: str):
        """Open the QuickServiceProbeDialog to send a tailored payload."""
        target = self.app.get_target()
        if not target:
            return
        try:
            from gui.dialogs import QuickServiceProbeDialog
            QuickServiceProbeDialog(self, target, port, svc)
        except Exception as e:
            self.app.terminal.write(f"  [!] Probe dialog error: {e}", "error")

    def _open_cheatsheet(self, port: int, svc: str) -> None:
        """Open the floating cheatsheet dialog for this service.

        Invoked by the per-port "📋 CMDS" button in the Ports panel.
        Non-modal — the dialog stays open alongside the Connect
        xterm so the operator can copy commands as they work.
        Only reachable when ``_cheatsheet_key_for(svc)`` resolves
        to a curated entry (button is hidden otherwise).
        """
        target = self.app.get_target()
        if not target:
            return
        try:
            from gui.widgets.cheatsheet_dialog import (
                open_cheatsheet_dialog)
            open_cheatsheet_dialog(
                self, svc, target, port, app=self.app)
        except Exception as e:
            try:
                self.app.terminal.write(
                    f"  [!] Cheatsheet dialog error: {e}", "error")
            except Exception:
                pass

