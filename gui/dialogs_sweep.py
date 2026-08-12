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
HAWK — Network sweep graph viewer.

Reuses the same networkx + matplotlib (TkAgg) renderer pattern as the
BloodHound attack graph in gui/dialogs_bloodhound.py.  Opens a
CTkToplevel with an interactive graph of discovered hosts.

Click a host node → detail panel + SELECT AS TARGET button.
"""

import customtkinter as ctk
from utils.config import COLORS
from gui.dialogs_common import (
    _f, _make_win, _title, _sub, _divider,
    _btn_row, _btn, _safe_destroy,
)


_CAT_COLOR = {
    "critical": "#FF4A4A",
    "warn":     "#FFA030",
    "medium":   "#E8D020",
    "normal":   "#55708A",
}

_LEGEND = [
    ("#FF4A4A", "SMB/RDP"),
    ("#FFA030", "SSH"),
    ("#E8D020", "ports found"),
    ("#55708A", "alive"),
]


def show_sweep_graph_window(parent, cidr, graph_data,
                            on_select_host=None):
    """Open the sweep graph in a Toplevel.

    Args:
      parent:         Tk parent widget.
      cidr:           str — range label for the title.
      graph_data:     dict from utils.sweep_graph.build_graph_data().
      on_select_host: callable(ip: str) — fired when the operator
                      clicks SELECT AS TARGET on a host node.

    Returns the Toplevel, or None when the graph could not be drawn.
    The caller keeps the handle so it can close the window after a
    promotion — the layout is a snapshot and never redraws itself.
    """
    try:
        import matplotlib
        matplotlib.use("TkAgg")
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import (
            FigureCanvasTkAgg, NavigationToolbar2Tk)
        import networkx as nx
    except ImportError as e:
        _show_missing_deps(parent, str(e))
        return

    nodes = (graph_data or {}).get("nodes") or []
    edges = (graph_data or {}).get("edges") or []
    stats = (graph_data or {}).get("stats") or {}
    if not nodes:
        _show_empty(parent)
        return

    # ── Window ────────────────────────────────────────────────────────
    win = ctk.CTkToplevel(parent)
    win.withdraw()
    win.title(f"Network Sweep — Host Graph — {cidr}")
    win.configure(fg_color=COLORS["bg_primary"])
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    w = min(1300, int(sw * 0.92))
    h = min(850, int(sh * 0.92))
    win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
    win.minsize(900, 600)

    ctk.CTkFrame(win, fg_color=COLORS["border_green"],
                 height=2, corner_radius=0).pack(fill="x")

    # ── Header + legend + stats ───────────────────────────────────────
    header = ctk.CTkFrame(win, fg_color="transparent")
    header.pack(fill="x", padx=18, pady=(10, 4))
    ctk.CTkLabel(
        header,
        text=f"NETWORK SWEEP — {cidr}  "
             f"({stats.get('alive', 0)}/{stats.get('total', 0)} alive)",
        font=_f("xl", True),
        text_color=COLORS["text_bright"], anchor="w",
    ).pack(side="left")

    legend = ctk.CTkFrame(header, fg_color="transparent")
    legend.pack(side="right")
    for color, label in _LEGEND:
        chip = ctk.CTkFrame(legend, fg_color="transparent")
        chip.pack(side="left", padx=6)
        ctk.CTkLabel(chip, text="●", font=_f("lg", True),
                     text_color=color).pack(side="left")
        ctk.CTkLabel(chip, text=label, font=_f("sm"),
                     text_color=COLORS["text_dim"]).pack(side="left",
                                                          padx=(2, 0))
    _divider(win)

    # ── Main: graph (left) + detail panel (right) ─────────────────────
    main = ctk.CTkFrame(win, fg_color="transparent")
    main.pack(fill="both", expand=True, padx=8, pady=(0, 6))

    graph_fr = ctk.CTkFrame(main, fg_color=COLORS["bg_primary"],
                            border_color=COLORS["border_dim"],
                            border_width=1, corner_radius=4)
    graph_fr.pack(side="left", fill="both", expand=True, padx=(4, 4))

    detail_fr = ctk.CTkFrame(main, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_dim"],
                             border_width=1, corner_radius=4, width=340)
    detail_fr.pack(side="right", fill="y", padx=(0, 4))
    detail_fr.pack_propagate(False)

    ctk.CTkLabel(
        detail_fr, text="  HOST DETAILS",
        font=_f("md", True), text_color=COLORS["text_green"], anchor="w",
    ).pack(fill="x", padx=8, pady=(8, 4))
    _divider(detail_fr)

    detail_box = ctk.CTkTextbox(
        detail_fr, font=_f("md"),
        fg_color="transparent",
        text_color=COLORS["text_bright"],
        border_width=0, corner_radius=0, wrap="word")
    detail_box.pack(fill="both", expand=True, padx=8, pady=(4, 4))
    detail_box.insert("1.0",
                      "Click any host node to see its details.\n\n"
                      "Colored nodes have open ports or known\n"
                      "services. Click SELECT AS TARGET to\n"
                      "promote a host to the active session.")
    detail_box.configure(state="disabled")

    action_fr = ctk.CTkFrame(detail_fr, fg_color="transparent")
    action_fr.pack(fill="x", padx=8, pady=(0, 10), side="bottom")

    def _set_details(text):
        try:
            detail_box.configure(state="normal")
            detail_box.delete("1.0", "end")
            detail_box.insert("1.0", text)
            detail_box.configure(state="disabled")
        except Exception:
            pass

    def _clear_actions():
        for w in action_fr.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass

    def _add_action_button(text, cmd, primary=False):
        bc = COLORS["border_green"] if primary else COLORS["border_dim"]
        tc = COLORS["text_green"]   if primary else COLORS["text_dim"]
        ctk.CTkButton(
            action_fr, text=text, width=320, height=34,
            font=_f("md", primary),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=bc, border_width=1, text_color=tc,
            corner_radius=4, command=cmd,
        ).pack(fill="x", pady=3)

    # ── Build networkx graph (hosts only, no service nodes) ─────────
    vis_nodes = [n for n in nodes
                 if n.get("type") in ("subnet", "host", "routed_summary")]
    vis_ids = {n["id"] for n in vis_nodes}

    G = nx.DiGraph()
    for n in vis_nodes:
        G.add_node(n["id"], data=n)
    for e in edges:
        if e["src"] in vis_ids and e["dst"] in vis_ids:
            G.add_edge(e["src"], e["dst"], type=e.get("type", ""))

    n_count = G.number_of_nodes()
    try:
        if n_count <= 200:
            pos = nx.spring_layout(G, k=1.6, iterations=80, seed=42)
        else:
            pos = nx.kamada_kawai_layout(G)
    except Exception:
        pos = nx.spring_layout(G, k=1.6, iterations=60, seed=42)

    # ── Figure ────────────────────────────────────────────────────────
    fig = Figure(figsize=(10, 6.5), dpi=100,
                 facecolor=COLORS["bg_primary"])
    ax = fig.add_subplot(111, facecolor=COLORS["bg_primary"])

    subnet_ids = [n["id"] for n in vis_nodes if n.get("type") == "subnet"]
    labels = {n["id"]: n["label"] for n in vis_nodes}

    def _paint(preserve_view: bool = False):
        """(Re)draw the whole figure from the CURRENT node flags on the
        fixed layout ``pos``.  The has_session cyan ring is recomputed here
        every call, so marking a host promoted and repainting makes the ring
        appear without reopening the window (carry-over graph-redraw fix).
        ``preserve_view`` keeps the operator's current zoom/pan across a
        repaint triggered by a promotion."""
        if preserve_view:
            xl, yl = ax.get_xlim(), ax.get_ylim()
        ax.clear()

        nx.draw_networkx_edges(
            G, pos, ax=ax,
            edge_color="#2A3642",
            width=0.7, arrows=False, alpha=0.55)

        for cat in ("normal", "medium", "warn", "critical"):
            ids = [n["id"] for n in vis_nodes
                   if n.get("category") == cat and n.get("type") == "host"]
            if not ids:
                continue
            nx.draw_networkx_nodes(
                G, pos, nodelist=ids, ax=ax,
                node_color=_CAT_COLOR.get(cat, "#55708A"),
                node_size=350,
                edgecolors=COLORS["bg_primary"],
                linewidths=0.9,
                node_shape="o",
                alpha=1.0 if cat != "normal" else 0.7)

        if subnet_ids:
            nx.draw_networkx_nodes(
                G, pos, nodelist=subnet_ids, ax=ax,
                node_color="#55708A",
                node_size=500,
                edgecolors=COLORS["bg_primary"],
                linewidths=0.9,
                node_shape="p",
                alpha=0.7)

        # Collapsed routed band: one amber square standing in for every
        # off-subnet (unverified) host, so the graph stays readable.
        summary_ids = [n["id"] for n in vis_nodes
                       if n.get("type") == "routed_summary"]
        if summary_ids:
            nx.draw_networkx_nodes(
                G, pos, nodelist=summary_ids, ax=ax,
                node_color="#3A2A10",
                node_size=900,
                edgecolors="#E0A030",
                linewidths=2.0,
                node_shape="s",
                alpha=0.95)

        if labels:
            nx.draw_networkx_labels(
                G, pos, labels=labels, ax=ax,
                font_size=9, font_color="#E8F0F8",
                font_family="monospace")

        session_ids = [n["id"] for n in vis_nodes
                       if n.get("type") == "host"
                       and "has_session" in (n.get("flags") or [])]
        if session_ids:
            nx.draw_networkx_nodes(
                G, pos, nodelist=session_ids, ax=ax,
                node_color="none",
                node_size=420,
                edgecolors=COLORS["text_cyan"],
                linewidths=2.0,
                node_shape="o",
                alpha=0.9)

        # Routed band: hosts outside every local subnet were reached across
        # a gateway, so a liveness hit is unverified (nmap -PA/-PS can flag a
        # dead routed address up).  Ring them amber so they read as plainly
        # separate from the ARP-confirmed local hosts.
        routed_ids = [n["id"] for n in vis_nodes
                      if n.get("type") == "host"
                      and n.get("scope") == "routed"]
        if routed_ids:
            nx.draw_networkx_nodes(
                G, pos, nodelist=routed_ids, ax=ax,
                node_color="none",
                node_size=540,
                edgecolors="#E0A030",
                linewidths=1.8,
                node_shape="o",
                alpha=0.95)

        n_local = stats.get("local", 0)
        n_routed = stats.get("routed", 0)
        if n_local or n_routed:
            ax.text(
                0.01, 0.01,
                f"{n_local} in your subnet   -   {n_routed} routed "
                f"(unverified)",
                transform=ax.transAxes, fontsize=8.5, color="#C8B070",
                family="monospace", va="bottom", ha="left")

        ax.set_axis_off()
        if preserve_view:
            ax.set_xlim(xl)
            ax.set_ylim(yl)
        else:
            ax.margins(0.05)

    _paint()

    # ── Embed in tk ───────────────────────────────────────────────────
    canvas = FigureCanvasTkAgg(fig, master=graph_fr)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

    tbar_fr = ctk.CTkFrame(win, fg_color=COLORS["bg_secondary"],
                           height=32, corner_radius=0)
    tbar_fr.pack(fill="x")
    try:
        toolbar = NavigationToolbar2Tk(canvas, tbar_fr)
        toolbar.update()
    except Exception:
        pass

    # ── Scroll zoom ───────────────────────────────────────────────────
    def _on_scroll(event):
        if event.inaxes is None or event.xdata is None:
            return
        scale = 0.85 if getattr(event, "button", "") == "up" else 1.18
        xlim = ax.get_xlim()
        ylim = ax.get_ylim()
        xd, yd = event.xdata, event.ydata
        nw = (xlim[1] - xlim[0]) * scale
        nh = (ylim[1] - ylim[0]) * scale
        rx = (xlim[1] - xd) / (xlim[1] - xlim[0]) if (xlim[1] - xlim[0]) else 0.5
        ry = (ylim[1] - yd) / (ylim[1] - ylim[0]) if (ylim[1] - ylim[0]) else 0.5
        ax.set_xlim([xd - nw * (1 - rx), xd + nw * rx])
        ax.set_ylim([yd - nh * (1 - ry), yd + nh * ry])
        canvas.draw_idle()
    canvas.mpl_connect("scroll_event", _on_scroll)

    # ── Click node → detail + action ──────────────────────────────────
    node_by_id = {n["id"]: n for n in nodes}
    all_ids = [nid for nid in node_by_id if nid in pos]

    def _on_click(event):
        if event.inaxes is None or event.xdata is None:
            return
        try:
            tb_mode = canvas.toolbar.mode if canvas.toolbar else ""
        except Exception:
            tb_mode = ""
        if tb_mode:
            return

        min_d2 = float("inf")
        closest = None
        for nid in all_ids:
            x, y = pos[nid]
            d2 = (x - event.xdata) ** 2 + (y - event.ydata) ** 2
            if d2 < min_d2:
                min_d2 = d2
                closest = nid

        xlim = ax.get_xlim()
        thr = ((xlim[1] - xlim[0]) * 0.025) ** 2
        if closest is None or min_d2 > thr:
            return

        n = node_by_id[closest]
        lines = [
            f"{n['type'].upper()}  ·  {n['label']}",
            f"category: {n.get('category', 'normal')}",
            "",
            n.get("details", "") or "(no properties)",
        ]
        _set_details("\n".join(lines))

        _clear_actions()
        if n.get("type") == "host" and on_select_host:
            ip = n["label"]
            has_sess = "has_session" in (n.get("flags") or [])
            btn_text = (f"LOAD SESSION — {ip}" if has_sess
                        else f"SELECT AS TARGET — {ip}")

            def _select(target_ip=ip):
                on_select_host(target_ip)
            _add_action_button(btn_text, _select, primary=True)

    canvas.mpl_connect("button_press_event", _on_click)

    # Let the caller mark a host promoted and repaint IN PLACE, so the cyan
    # has_session ring appears the moment the session materialises instead of
    # only on a reopen.  The click handler reads flags from these same node
    # dicts, so a later click on the promoted node correctly offers LOAD.
    def _mark_session_ring(ip: str):
        touched = False
        for n in vis_nodes:
            if n.get("type") == "host" and n.get("label") == ip:
                flags = n.setdefault("flags", [])
                if "has_session" not in flags:
                    flags.append("has_session")
                    touched = True
        if not touched:
            return
        try:
            _paint(preserve_view=True)
            canvas.draw_idle()
        except Exception:
            pass
    win.mark_session_ring = _mark_session_ring

    # ── Footer ────────────────────────────────────────────────────────
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True, w=120)

    def _reveal():
        try:
            if win.winfo_exists():
                win.deiconify()
                win.lift()
                win.focus_force()
        except Exception:
            pass
    win.after(180, _reveal)

    return win


def _show_missing_deps(parent, err):
    win = _make_win(parent, "Graph — missing dependencies", 620, 300)
    _title(win, "Network sweep graph needs matplotlib + networkx")
    _sub(win,
         "The sweep completed and the inventory is saved, but the "
         "graph viewer needs these optional packages.\n\n"
         f"Import error: {err}",
         COLORS["text_dim"])

    from gui.dialogs_common import _selectable_text
    _selectable_text(
        win,
        "pip install matplotlib networkx --break-system-packages",
        color=COLORS["text_green"], height=34)
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True, w=120)


def _show_empty(parent):
    win = _make_win(parent, "Graph — no data", 540, 220)
    _title(win, "Network sweep graph — nothing to draw")
    _sub(win,
         "The sweep did not find any alive hosts to graph. Check the "
         "HAWK terminal for scan output and errors.",
         COLORS["text_dim"], wrap=460)
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True, w=120)
