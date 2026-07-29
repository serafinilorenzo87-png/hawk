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
HAWK - Network Health Indicator

Standalone clickable widget that probes the default gateway and the current
target host every ~15s off the UI thread. Rendered as a bordered button so
it is unambiguously visible regardless of theme.

Originally lived inside the bottom status bar; moved here as a reusable
widget so it can be mounted anywhere (target bar, side panel, etc.) and so
users can actually spot it.

States (shown as the button's text + colour):
    ●  NET     green   — gateway + target both reachable
    ⚠  TGT     amber   — our network fine, target unreachable
    ✗  NET     red     — we lost our own gateway / interface
    ?  NET     dim     — first probe still in flight / unknown
    …  NET     dim     — an on-demand re-check is running
"""

import customtkinter as ctk
import platform as _platform
import re
import socket
import subprocess
import threading
from utils.config import COLORS


# ─── Helpers (off the UI thread) ────────────────────────────────────────────
def _ping(host: str, count: int = 1, timeout_s: int = 1) -> bool:
    try:
        if _platform.system() == "Windows":
            cmd = ["ping", "-n", str(count),
                   "-w", str(int(timeout_s*1000)), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout_s),
                   "-n", host]
        r = subprocess.run(cmd, capture_output=True,
                            timeout=count + timeout_s + 2)
        return r.returncode == 0
    except Exception:
        return False


def _tcp_probe(host: str, port: int, timeout_s: float = 1.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout_s)
        s.close()
        return True
    except Exception:
        return False


def _read_default_route():
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=2)
        m = re.search(r'default via (\S+) dev (\S+)', r.stdout or "")
        if m:
            return m.group(1), m.group(2)
    except Exception:
        pass
    return None, None


def _read_iface_ip(iface: str) -> str:
    if not iface:
        return ""
    try:
        r = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=2)
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', r.stdout or "")
        return m.group(1) if m else ""
    except Exception:
        return ""


def _systemctl_active(unit: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=2)
        return (r.stdout or "").strip() == "active"
    except Exception:
        return False


# ─── Widget ─────────────────────────────────────────────────────────────────
class NetHealthIndicator(ctk.CTkFrame):
    """A self-contained network-health pill. Click to open a diagnostic
    dialog with copyable fix commands.

    Pass `app` so the widget can:
      * read `app.get_target()` and probe TCP fallback ports from
        `app.target_intel._fp.open_ports`
      * write status lines back into `app.terminal` (optional — only for
        the initial hello log)
    """

    NET_CHECK_INTERVAL_MS = 15_000
    NET_CHECK_INITIAL_MS  = 1_200

    # ─── Drift detection ───────────────────────────────────────────────────
    # When a target was previously reachable and then becomes
    # unreachable for N consecutive checks, HAWK suspects the target
    # IP drifted (classic HTB-after-reset symptom: the box gets a new
    # IP but the user has the old one in /etc/hosts and in the
    # session).  We emit a single terminal warning + flag the
    # diagnostic dialog so the operator sees it explicitly instead
    # of staring at "tgt down" for hours.  Reset as soon as a probe
    # succeeds again.
    DRIFT_FAIL_THRESHOLD = 5   # 5 × 15s = 75s of continuous failure

    def __init__(self, parent, app=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.app = app
        self._net_status  = "unknown"
        self._net_details = {}
        self._net_probe_inflight = False
        # Drift tracking — "was OK" is sticky once we've seen ONE
        # successful probe in this session, so a target that's been
        # down forever doesn't flap into drift just because the
        # operator restarts HAWK.
        self._target_ever_ok      = False
        self._consec_target_fail  = 0
        self._drift_warned        = False
        self._drift_last_ip       = ""   # last seen target value when ok

        # Label (left of the pill) → describes what the indicator is.
        self._title_lbl = ctk.CTkLabel(
            self,
            text="NETWORK HEALTH:",
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            text_color=COLORS["text_dim"],
        )
        self._title_lbl.pack(side="left", padx=(0, 6))

        # Pill itself — a button so it has a proper border + hover + cursor.
        self._btn = ctk.CTkButton(
            self,
            text="?  NET",
            width=130, height=30,
            font=ctk.CTkFont(family="Courier New", size=14, weight="bold"),
            fg_color="transparent",
            hover_color=COLORS.get("bg_card_hover", "#1a2430"),
            border_color=COLORS["text_dim"],
            border_width=1,
            text_color=COLORS["text_dim"],
            corner_radius=4,
            cursor="hand2",
            command=self._on_click,
        )
        self._btn.pack(side="left")

        # Small secondary label showing the resolved gateway/target once
        # the first probe completes. Purely informational.
        self._info_lbl = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(family="Courier New", size=13),
            text_color=COLORS["text_muted"],
        )
        self._info_lbl.pack(side="left", padx=(8, 0))

        # Kick off the first probe after the main window is drawn.
        self._check_id = self.after(self.NET_CHECK_INITIAL_MS, self._tick)

    # ─── Probe loop ────────────────────────────────────────────────────────
    def _tick(self):
        if self._net_probe_inflight:
            self._check_id = self.after(self.NET_CHECK_INTERVAL_MS, self._tick)
            return
        self._net_probe_inflight = True

        def _worker():
            result = self._probe_network()
            def _apply():
                self._net_probe_inflight = False
                self._apply_result(result)
                self._check_id = self.after(self.NET_CHECK_INTERVAL_MS,
                                             self._tick)
            try:
                self.after(0, _apply)
            except Exception:
                self._net_probe_inflight = False

        threading.Thread(target=_worker, daemon=True).start()

    def _probe_network(self) -> dict:
        out = {
            "iface": None, "ip": None,
            "gateway": None, "gateway_ok": None,
            "target": None, "target_ok": None, "target_via": None,
            "nm_running": None,
        }
        gw, iface = _read_default_route()
        out["iface"]   = iface
        out["gateway"] = gw
        if iface:
            out["ip"] = _read_iface_ip(iface)
        if gw:
            out["gateway_ok"] = _ping(gw, count=1, timeout_s=1)

        try:
            tgt = self.app.get_target() if self.app else ""
        except Exception:
            tgt = ""
        tgt = (tgt or "").strip()
        if tgt:
            out["target"] = tgt
            if _ping(tgt, count=1, timeout_s=1):
                out["target_ok"]  = True
                out["target_via"] = "icmp"
            else:
                ports = self._known_open_ports()
                if not ports:
                    ports = [445, 80, 443, 22, 3389, 139, 135]
                for p in ports:
                    if _tcp_probe(tgt, p, timeout_s=1.0):
                        out["target_ok"]  = True
                        out["target_via"] = f"tcp/{p}"
                        break
                if out["target_ok"] is None:
                    out["target_ok"] = False

        if _platform.system() != "Windows":
            out["nm_running"] = _systemctl_active("NetworkManager")
        return out

    def _known_open_ports(self) -> list:
        try:
            fp = getattr(self.app, "target_intel", None)
            fp = getattr(fp, "_fp", None) if fp else None
            if fp and fp.open_ports:
                return [p for p, proto, *_ in fp.open_ports
                        if proto == "tcp"]
        except Exception:
            pass
        return []

    def _apply_result(self, r: dict):
        gw_ok  = r.get("gateway_ok")
        tg_ok  = r.get("target_ok")
        has_tg = r.get("target") is not None

        # ── Target IP drift detection ─────────────────────────────
        # Counts consecutive target failures, but only after we've
        # observed at least one success (otherwise a target that's
        # been down forever — wrong IP entered, target VM never on
        # — would flap into drift mode pointlessly).
        if has_tg and gw_ok:
            if tg_ok:
                self._target_ever_ok = True
                self._consec_target_fail = 0
                self._drift_last_ip = (r.get("target") or "").strip()
                # Successful probe clears the drift warning so it can
                # re-fire if the target drops AGAIN later (a second
                # HTB reset in the same session).
                self._drift_warned = False
                r["drift_suspected"] = False
            else:
                if self._target_ever_ok:
                    self._consec_target_fail += 1
                drift = (self._consec_target_fail
                         >= self.DRIFT_FAIL_THRESHOLD)
                r["drift_suspected"] = drift
                if drift and not self._drift_warned:
                    self._drift_warned = True
                    self._emit_drift_warning(r)
        else:
            r["drift_suspected"] = False

        if gw_ok is False or gw_ok is None:
            state, text, color = "down", "✗  NET", COLORS["text_red"]
        elif gw_ok and has_tg and tg_ok is False:
            # Drift suspected gets its own visual: the standard amber
            # "target down" indicator becomes a more alarming label
            # so the operator notices something CHANGED rather than
            # the target just being briefly flaky.
            if r.get("drift_suspected"):
                state, text, color = (
                    "drift", "⚠  IP?",
                    COLORS.get("text_red", "#FF6B6B"))
            else:
                state, text, color = "degraded", "⚠  TGT", "#FFB600"
        elif gw_ok and (not has_tg or tg_ok):
            state, text, color = "ok", "●  NET", COLORS["text_green"]
        else:
            state, text, color = "unknown", "?  NET", COLORS["text_dim"]

        self._net_status  = state
        self._net_details = r
        try:
            self._btn.configure(text=text, text_color=color,
                                  border_color=color)
        except Exception:
            pass
        # Info line (iface / gateway / target status)
        bits = []
        if r.get("iface"):
            bits.append(r["iface"])
        if r.get("ip"):
            bits.append(r["ip"])
        if r.get("gateway"):
            bits.append(f"gw {r['gateway']}")
        if r.get("target"):
            via = r.get("target_via") or ("?" if tg_ok is None else "down")
            bits.append(f"tgt {r['target']} ({via})")
        try:
            self._info_lbl.configure(text="  ·  ".join(bits))
        except Exception:
            pass

    # ─── Drift warning ─────────────────────────────────────────────────────
    def _emit_drift_warning(self, r: dict):
        """One-shot terminal warning when target drift is suspected.

        Called exactly once per drift episode (cleared on next
        successful probe).  Writes to the HAWK terminal so the
        operator sees it even if the network-health pill is
        scrolled off-screen on a small monitor.
        """
        try:
            tgt = r.get("target") or self._drift_last_ip or "(target)"
            secs = self._consec_target_fail * (
                self.NET_CHECK_INTERVAL_MS // 1000)
            msg = (
                f"  [NET-HEALTH] target {tgt} unreachable for "
                f"{secs}s ({self._consec_target_fail} consecutive "
                f"checks).  POSSIBLE IP DRIFT — if this is HTB and "
                f"the box was reset, the IP may have changed.  "
                f"Check the HTB dashboard and update the target IP "
                f"on the target bar if needed."
            )
            if self.app and hasattr(self.app, "terminal"):
                self.app.terminal.write(msg, "warn")
        except Exception:
            pass

    # ─── Click → dialog ────────────────────────────────────────────────────
    def _on_click(self):
        from gui.dialogs import (_make_win, _note_box, _btn_row, _btn,
                                  _safe_destroy)
        d = self._net_details
        win = _make_win(self, "Network Health", 620, 600)
        ctk.CTkLabel(
            win, text="⟐  HAWK Network Health",
            font=ctk.CTkFont(family="Courier New", size=16, weight="bold"),
            text_color=COLORS.get("text_cyan", COLORS["text_green"]),
        ).pack(pady=(14, 8))

        def _line(label, ok, extra=""):
            if ok is True:
                glyph, color = "✓", COLORS["text_green"]
            elif ok is False:
                glyph, color = "✗", COLORS["text_red"]
            else:
                glyph, color = "·", COLORS["text_dim"]
            rf = ctk.CTkFrame(win, fg_color="transparent")
            rf.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(
                rf, text=f"  {glyph}  {label}",
                font=ctk.CTkFont(family="Courier New", size=14,
                                  weight="bold"),
                text_color=color, width=230, anchor="w",
            ).pack(side="left")
            _selectable_line(rf, extra)

        def _selectable_line(parent, text):
            """Right-hand value rendered as a read-only Entry so the
            operator can select and copy IPs/interfaces from the dialog."""
            from utils.clipboard import add_context_menu
            e = ctk.CTkEntry(
                parent,
                font=ctk.CTkFont(family="Courier New", size=14),
                fg_color="transparent",
                text_color=COLORS["text_dim"],
                border_width=0,
                height=22,
            )
            e.pack(side="left", fill="x", expand=True)
            e.insert(0, text)
            e.configure(state="readonly")
            add_context_menu(e)
            return e

        _line("Default gateway",
              d.get("gateway_ok"),
              f"{d.get('gateway') or '(none)'}  via {d.get('iface') or '-'}")
        _line("Local IP assigned",
              True if d.get("ip") else False,
              d.get("ip") or "(no IPv4 on interface)")
        if d.get("target"):
            via = d.get("target_via") or "-"
            _line("Target reachable",
                  d.get("target_ok"),
                  f"{d.get('target')}  ({via})")
        else:
            _line("Target reachable", None, "(no target set)")
        if d.get("nm_running") is not None:
            _line("NetworkManager",
                  d.get("nm_running"),
                  "systemd unit active" if d.get("nm_running")
                  else "not active — network is probably unmanaged")

        state = self._net_status

        # Distinguish "DOWN, DHCP failed" (no default route at all → the
        # virtualisation environment's DHCP service on the host is dead /
        # VM got no lease) from "DOWN, gateway unreachable" (route
        # present but gateway silent → host-side NAT saturated / NAT
        # service crashed). The fix procedure is completely different
        # for the two cases so we route them separately.
        no_route   = (state == "down" and d.get("gateway") is None)
        gw_silent  = (state == "down" and d.get("gateway") is not None)

        if state == "ok":
            diag, color = (
                "All probes green. If a scan still fails, it is the TARGET\n"
                "that has changed (rebooted, firewalled, crashed) — not\n"
                "your own network.", COLORS["text_green"])
        elif state == "drift":
            secs = self._consec_target_fail * (
                self.NET_CHECK_INTERVAL_MS // 1000)
            diag, color = (
                f"TARGET IP DRIFT SUSPECTED — {d.get('target') or '(target)'} "
                f"has been unreachable for {secs}s "
                f"({self._consec_target_fail} consecutive failed probes).\n\n"
                "Most common cause on HTB / lab platforms: the box was\n"
                "reset and got a new IP.  /etc/hosts and the HAWK session\n"
                "still have the OLD IP, so every probe from now on is\n"
                "talking to a dead address.\n\n"
                "Fix:\n"
                "  1. Open the HTB dashboard and copy the current IP.\n"
                "  2. On the HAWK target bar, click the IP field and update.\n"
                "  3. If you used ADD HOSTS for vhosts, re-run it so\n"
                "     /etc/hosts is rewritten with the new IP.\n"
                "  4. Hit RE-CHECK NOW below.",
                COLORS.get("text_red", "#FF6B6B"))
        elif state == "degraded":
            diag, color = (
                "Kali's network is fine — only the target is unreachable.\n"
                "Nothing to do on Kali side.",
                "#FFB600")
        elif no_route:
            diag, color = (
                "No default route — Kali has no DHCP lease.\n"
                "Recover Kali's networking with the commands below.",
                COLORS["text_red"])
        elif gw_silent:
            diag, color = (
                "Default route is set but the gateway is silent —\n"
                "Kali's NetworkManager is stuck (typical post-nmap\n"
                "flood). Restart it with the commands below.",
                COLORS["text_red"])
        else:
            diag, color = (
                "Status not yet determined — the first probe may still\n"
                "be in flight. Hit RE-CHECK NOW to force one.",
                COLORS["text_dim"])
        _note_box(win, diag, color, selectable=True, text_color=color)

        # ── Single Kali-side fix box for any down/stuck state ──
        if no_route or gw_silent:
            iface = d.get("iface") or "eth0"
            _note_box(win, self._kali_fixes(iface), COLORS["text_yellow"],
                      selectable=True, text_color=COLORS["text_yellow"])

        row = _btn_row(win)

        def _recheck():
            try:
                self._btn.configure(text="…  NET",
                                      text_color=COLORS["text_dim"],
                                      border_color=COLORS["text_dim"])
            except Exception:
                pass
            self._net_probe_inflight = False
            self._tick()
            _safe_destroy(win)

        def _copy_fixes():
            """Copy the Kali-side one-liner (NM restart + nmcli
            reconnect).  Hypervisor-agnostic — works regardless of
            what's running underneath Kali."""
            try:
                from utils.clipboard import clipboard_copy
                iface = d.get("iface") or "eth0"
                clipboard_copy(self._kali_oneliner(iface))
            except Exception:
                pass

        _btn(row, "RE-CHECK NOW", _recheck, primary=True, w=160)
        if state == "down":
            _btn(row, "COPY FIX CMDS", _copy_fixes, w=160)
        _btn(row, "CLOSE", lambda: _safe_destroy(win), w=100)

    # ─── Kali-side fix registry ────────────────────────────────────────────
    #
    # HAWK is hypervisor-agnostic.  It runs on Kali under VMware,
    # VirtualBox, Hyper-V, KVM, Proxmox, Parallels, UTM, Qubes, bare
    # metal — anything.  We never know what's underneath, and we never
    # need to: when Kali's network locks up (typical cause: nmap -T5
    # or a Metasploit module saturating the conntrack / ARP cache /
    # NM's internal queues), the fix is INSIDE Kali, not on the host.
    #
    # Even when the actual root cause IS on the host (host DHCP service
    # crashed, host NAT process saturated), we can't help — the user
    # may not have shell access on the host, the host may be a
    # completely different OS, the host may be a corporate locked-down
    # appliance.  All we can do is reset Kali's networking and let it
    # re-DHCP / reconnect.  That recovers ~95% of incidents in practice.

    def _kali_fixes(self, iface: str) -> str:
        """Return the unified Kali-side recovery commands, ordered from
        soft to hard.  Same set regardless of host / hypervisor."""
        return (
            "# 1) Soft restart — handles ~90% of post-nmap flood lockups\n"
            "sudo systemctl restart NetworkManager\n\n"
            "# 2) Bounce the interface via NetworkManager\n"
            f"sudo nmcli device disconnect {iface}\n"
            f"sudo nmcli device connect {iface}\n\n"
            "# 3) If NM is unresponsive: release/renew DHCP manually\n"
            f"sudo dhclient -r {iface}\n"
            f"sudo dhclient {iface}\n\n"
            "# 4) Last resort: L2 bounce + NM restart\n"
            f"sudo ip link set {iface} down\n"
            f"sudo ip link set {iface} up\n"
            "sudo systemctl restart NetworkManager"
        )

    def _kali_oneliner(self, iface: str) -> str:
        """One-liner copied by the COPY FIX CMDS button.  Combines the
        two most-effective steps (NM restart + nmcli reconnect) so the
        user can paste-and-go in the Kali terminal."""
        return (f"sudo systemctl restart NetworkManager && sleep 2 && "
                f"sudo nmcli device disconnect {iface} && "
                f"sudo nmcli device connect {iface}")

    # ─── Teardown ──────────────────────────────────────────────────────────
    def destroy(self):
        try:
            tid = getattr(self, "_check_id", None)
            if tid is not None:
                self.after_cancel(tid)
        except Exception:
            pass
        super().destroy()
