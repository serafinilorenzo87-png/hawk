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
HAWK - Dialogs v1.0
- Greenbone install: 10-second countdown popup watching xterm for password
- Selectable text: CTkTextbox (disabled) for all technical content
- OS detection dialog fixed (grab_set)
- Netcat with service-specific verification commands
"""

import os
import re
import time
import threading
import subprocess
import shlex
import json
import tempfile
import shutil
import socket
import pathlib
import urllib.request

from gui.dialogs_common import *


# ── BloodHound CE install guide ──────────────────────────────────────
# Rendered step-by-step by show_bloodhound_ce_setup_dialog() and copied
# as one script by its "COPY ALL COMMANDS" button.  Embedded rather than
# fetched so the guide still works on an air-gapped Kali.
#
# Step numbering is referenced from the dialog's own text — the
# credentials block points at step 7 for the password reset and the
# troubleshooting appendix points at steps 1 and 2 — so keep the order
# stable when editing.
_BHCE_SETUP_STEPS = [
    ("1. Install the Docker engine",
     "# Kali ships docker.io in the standard repo.  If you already run\n"
     "# Docker Desktop or docker-ce, skip this step.\n"
     "sudo apt update && sudo apt install -y docker.io\n"
     "sudo systemctl enable --now docker\n"
     "docker --version"),

    ("2. Install the Docker Compose plugin",
     "# BH CE ships a compose file and needs compose v2 (the plugin,\n"
     "# invoked as `docker compose`, NOT the old `docker-compose`).\n"
     "sudo apt install -y docker-compose-v2 || sudo apt install -y docker-compose-plugin\n"
     "docker compose version"),

    ("3. Let your user talk to the Docker socket",
     "# Without this every docker call needs sudo and the compose file\n"
     "# writes root-owned volumes into your home.\n"
     "sudo usermod -aG docker \"$USER\"\n"
     "\n"
     "# Group membership only applies to NEW logins — load it in the\n"
     "# current shell instead of logging out:\n"
     "newgrp docker\n"
     "docker ps"),

    ("4. Fetch the official compose file",
     "mkdir -p ~/bloodhound-ce && cd ~/bloodhound-ce\n"
     "\n"
     "# SpecterOps publish the current compose file behind a short URL.\n"
     "curl -L https://ghst.ly/getbhce -o docker-compose.yml\n"
     "\n"
     "# Sanity-check what you just downloaded before running it.\n"
     "head -40 docker-compose.yml"),

    ("5. Pull the images",
     "# Four images: postgres, neo4j, the bloodhound API and the UI.\n"
     "# ~2 GB on a cold cache — do this before you're on the clock.\n"
     "cd ~/bloodhound-ce && docker compose pull"),

    ("6. Start the stack",
     "cd ~/bloodhound-ce && docker compose up -d\n"
     "\n"
     "# Give neo4j ~30s on first boot to initialise its store, then:\n"
     "cd ~/bloodhound-ce && docker compose ps"),

    ("7. First login — read the one-time password and change it",
     "# The initial admin password is printed ONCE, in the API logs.\n"
     "cd ~/bloodhound-ce && docker compose logs bloodhound 2>&1 | "
     "grep -i 'Initial Password'\n"
     "\n"
     "# Username is always:  admin\n"
     "# BH CE forces a password change on first login — do it there.\n"
     "\n"
     "# Locked out later?  Reset to a known value without losing data:\n"
     "cd ~/bloodhound-ce && docker compose exec bloodhound python3 -c \"\n"
     "import bcrypt, psycopg2, os\n"
     "c = psycopg2.connect(os.environ['BHE_DATABASE_CONNECTION'])\n"
     "h = bcrypt.hashpw(b'HawkRecovered123!', bcrypt.gensalt()).decode()\n"
     "cur = c.cursor()\n"
     "cur.execute(\\\"UPDATE auth_secrets SET digest=%s WHERE \\\n"
     "  user_id=(SELECT id FROM users WHERE principal_name='admin');\\\", (h,))\n"
     "c.commit(); print('OK - admin reset to HawkRecovered123!')\""),

    ("8. Verify the web UI",
     "# The compose file binds the UI to loopback only.\n"
     "curl -s -o /dev/null -w '%{http_code}\\n' http://localhost:8080/ui/login\n"
     "\n"
     "xdg-open http://localhost:8080  ||  firefox http://localhost:8080  &"),

    ("9. Collect data and upload it",
     "# Remote collection from Kali (no agent on the DC):\n"
     "bloodhound-python -u USER -p PASS -d DOMAIN.LOCAL -dc DC01.DOMAIN.LOCAL "
     "-c All --zip\n"
     "\n"
     "# Or run SharpHound.exe on the target:\n"
     "#   SharpHound.exe -c All --zipfilename bh.zip\n"
     "\n"
     "# Then in the UI:  Administration > File Ingest > Upload Files\n"
     "# and drop the .zip.  HAWK's own BLOODHOUND card produces the\n"
     "# same .zip — the path is shown in the run summary."),

    ("10. Day-to-day: stop, update, wipe",
     "# Stop the stack (data on disk is preserved):\n"
     "cd ~/bloodhound-ce && docker compose down\n"
     "\n"
     "# Update to the latest BH CE release:\n"
     "cd ~/bloodhound-ce && docker compose pull && docker compose up -d\n"
     "\n"
     "# Wipe EVERYTHING including the graph (new engagement, clean DB):\n"
     "cd ~/bloodhound-ce && docker compose down -v"),
]

# One-shot version of the steps above, for the COPY ALL COMMANDS button.
# Deliberately stops before step 7: the initial password has to be read
# from the logs by a human, so the script prints it and hands over.
_BHCE_SETUP_SCRIPT = "\n".join([
    "#!/usr/bin/env bash",
    "# BloodHound CE — install + first start (Kali).  Generated by HAWK.",
    "# Run it, then read the admin password it prints at the end.",
    "set -euo pipefail",
    "",
    "sudo apt update",
    "sudo apt install -y docker.io",
    "sudo apt install -y docker-compose-v2 || sudo apt install -y docker-compose-plugin",
    "sudo systemctl enable --now docker",
    "sudo usermod -aG docker \"$USER\"",
    "",
    "mkdir -p ~/bloodhound-ce",
    "cd ~/bloodhound-ce",
    "curl -L https://ghst.ly/getbhce -o docker-compose.yml",
    "",
    "# `sg docker` runs the compose calls with the new group without",
    "# needing a fresh login for the rest of this script.",
    "sg docker -c 'docker compose pull'",
    "sg docker -c 'docker compose up -d'",
    "",
    "echo '[*] Waiting 45s for neo4j / postgres to initialise...'",
    "sleep 45",
    "sg docker -c 'docker compose ps'",
    "",
    "echo '[*] Initial admin password (user: admin):'",
    "sg docker -c 'docker compose logs bloodhound' 2>&1 | grep -i 'Initial Password' || \\",
    "  echo '[!] Not found - run: docker compose logs bloodhound | grep -i password'",
    "echo '[*] UI: http://localhost:8080'",
])


def show_bloodhound_summary_dialog(parent, target, stats, zip_path,
                                   graph_data=None, on_run_tool=None):
    """Modal dialog shown after `bloodhound-python` completes.

    Three sections:
      1. Findings summary (users / kerberoastable / unconstrained, etc.)
      2. ZIP path with buttons: Open folder / Copy path / Open ZIP /
         VIEW ATTACK GRAPH (when graph_data is provided)
      3. BloodHound GUI note — short line clarifying HAWK's native graph
         is above, and the ZIP can still feed BloodHound CE for advanced
         Cypher queries if the user wants more.

    Args:
      parent:     Tk parent (any HAWK widget — usually self.app)
      target:     str — the target the collection ran against
      stats:      dict with keys
                    users, computers, groups,
                    kerberoastable, asrepable, unconstrained,
                    da_members  (each int; lists optional)
      zip_path:   str — absolute path to the produced *_bloodhound.zip
                  (may be None if the collector failed to drop one)
      graph_data: dict from utils.bloodhound_graph.build_graph_data(),
                  or None.  When present, a 'VIEW ATTACK GRAPH' button
                  is rendered alongside the ZIP action buttons.
      on_run_tool: optional callable `on_run_tool(tool_id, prefill_dict)`
                  passed through to the graph window.  When set, the
                  graph side panel renders real 'RUN IN <tool>' buttons
                  on attackable nodes; click → opens the tool dialog
                  pre-filled for that specific target.  Usually the
                  CardWidget.launch_tool_prefilled method.
    """
    import subprocess
    import shutil

    win = _make_win(parent, "BloodHound — collection complete", 720, 720)
    _title(win, "BLOODHOUND — collection complete")
    _sub(win, f"target: {target}", color=COLORS["text_dim"])
    _divider(win)

    # All report content goes into a scrollable body so a tall dialog
    # (summary + zip path + BH CE steps) is fully reachable via a
    # right-side scrollbar instead of being clipped at the bottom on
    # shorter screens.  The CLOSE button stays outside it, pinned to the
    # window bottom.  `win` is aliased to the body so the section code
    # below keeps packing into it unchanged; it's restored before CLOSE.
    _outer_win = win
    body = ctk.CTkScrollableFrame(
        win, fg_color="transparent",
        scrollbar_button_color=COLORS["border_dim"],
        scrollbar_button_hover_color=COLORS["text_dim"])
    body.pack(fill="both", expand=True, padx=0, pady=(0, 4))
    win = body

    # ── §1 Findings summary ──────────────────────────────────────────
    s = stats or {}
    summary_lines = [
        f"  Users                          : {s.get('users', 0)}",
        f"  Computers                      : {s.get('computers', 0)}",
        f"  Groups                         : {s.get('groups', 0)}",
        "",
        f"  Kerberoastable (hasspn)        : {s.get('kerberoastable', 0)}",
        f"  AS-REP roastable (no preauth)  : {s.get('asrepable', 0)}",
        f"  Unconstrained delegation PCs   : {s.get('unconstrained', 0)}",
        f"  Domain Admin members           : {s.get('da_members', 0)}",
    ]
    crit = (s.get('kerberoastable', 0) > 0
            or s.get('unconstrained', 0) > 0)
    border = COLORS["text_red"] if crit else COLORS["border_green"]
    _note_box(win, "\n".join(summary_lines),
              color=border, selectable=True)
    if crit:
        ctk.CTkLabel(
            win,
            text="  ⚠  high-impact findings — see Target Intel for the "
                 "full description.",
            font=_f("md", True), text_color=COLORS["text_red"],
        ).pack(pady=(0, 4))

    _divider(win)

    # ── §2 ZIP path + actions ─────────────────────────────────────────
    if zip_path and os.path.isfile(zip_path):
        ctk.CTkLabel(
            win, text="  ZIP output:",
            font=_f("md", True), text_color=COLORS["text_bright"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(2, 0))
        # wrap="none": the zip path is one long unbreakable token — word
        # wrap can't split it, so it would be clipped at the right edge.
        # A horizontal scrollbar keeps the whole path reachable.
        _selectable_text(win, zip_path,
                         color=COLORS["text_green"], height=56,
                         wrap="none")

        zip_dir = os.path.dirname(zip_path)

        def _open_folder():
            try:
                if shutil.which("xdg-open"):
                    subprocess.Popen(
                        ["xdg-open", zip_dir],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                elif shutil.which("open"):  # macOS
                    subprocess.Popen(["open", zip_dir])
                else:
                    # Windows fallback
                    os.startfile(zip_dir)  # type: ignore[attr-defined]
            except Exception as e:
                print(f"[HAWK] open folder failed: {e}")

        def _open_zip():
            try:
                if shutil.which("xdg-open"):
                    subprocess.Popen(
                        ["xdg-open", zip_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                elif shutil.which("open"):
                    subprocess.Popen(["open", zip_path])
                else:
                    os.startfile(zip_path)  # type: ignore[attr-defined]
            except Exception as e:
                print(f"[HAWK] open zip failed: {e}")

        def _copy_path():
            try:
                from utils.clipboard import clipboard_copy
                if not clipboard_copy(zip_path):
                    win.clipboard_clear()
                    win.clipboard_append(zip_path)
            except Exception:
                try:
                    win.clipboard_clear()
                    win.clipboard_append(zip_path)
                except Exception:
                    pass

        actions = ctk.CTkFrame(win, fg_color="transparent")
        actions.pack(pady=(2, 6))
        _btn(actions, "OPEN FOLDER", _open_folder, primary=True, w=150)
        _btn(actions, "OPEN ZIP",    _open_zip,    w=120)
        _btn(actions, "COPY PATH",   _copy_path,   w=130)

        # VIEW ATTACK GRAPH — only when the parser prepared a graph dict.
        # Keep it right next to the ZIP actions so the user sees at a
        # glance that the graph is the "headline" feature and the ZIP is
        # just the raw archive.
        if graph_data and graph_data.get("nodes"):
            def _open_graph():
                try:
                    show_bloodhound_graph_window(
                        parent, target, graph_data,
                        on_run_tool=on_run_tool)
                except Exception as e:
                    print(f"[HAWK] open graph window failed: {e}")
            _btn(actions, "VIEW ATTACK GRAPH", _open_graph,
                 primary=True, w=200)

        # ── BH CE setup guide (in-app, offline-friendly) ─────────────
        # Standalone button so users who land here WITHOUT a graph
        # (missing matplotlib, or first-time users exploring) still
        # see the setup docs one click away.
        _btn(actions, "⚙  BH CE SETUP GUIDE",
             lambda: show_bloodhound_ce_setup_dialog(parent),
             w=210)
    else:
        _note_box(
            win,
            "ZIP not found on disk — bloodhound-python did not drop a "
            ".zip in the expected output dir.  HAWK fell back to parsing "
            "stdout summary only; re-run with --zip for full graph data.",
            color=COLORS["border_amber"])

    _divider(win)

    # ── §3 Optional: feed the ZIP to BloodHound CE ───────────────────
    # HAWK draws the attack graph natively (VIEW ATTACK GRAPH above),
    # so this section is purely for power users who want Cypher queries
    # or multi-domain path computation.  Kept as a short step-by-step
    # so a first-time user doesn't have to hunt the BH CE docs.
    footer = (
        "The ATTACK GRAPH above is HAWK's native view of the collected "
        "AD topology — every user, computer and group is drawn, and "
        "attackable entities are color-highlighted.  The .zip below is "
        "also kept on disk so you can feed it to BloodHound CE "
        "(github.com/SpecterOps/BloodHound) for Cypher queries or "
        "multi-session path computation across domains.\n\n"
        "Steps to stand up BloodHound CE and ingest this ZIP:"
    )
    _note_box(win, footer, color=COLORS["border_dim"])

    _sub(win,
         "1 · open a terminal inside your hawkC folder "
         "(right-click → Open Terminal Here, or `cd` into it) and clone "
         "the BloodHound CE repo:",
         color=COLORS["text_dim"], wrap=660)
    _selectable_text(
        win,
        "git clone https://github.com/SpecterOps/BloodHound.git",
        color=COLORS["text_green"], height=48, wrap="none")

    _sub(win,
         "2 · bring BloodHound CE up with Docker "
         "(the compose file ships in the repo):",
         color=COLORS["text_dim"], wrap=660)
    _selectable_text(
        win,
        "cd BloodHound/examples/docker-compose && "
        "docker compose pull && docker compose up -d",
         color=COLORS["text_green"], height=48, wrap="none")

    _sub(win,
         "3 · open http://localhost:8080 in your browser and sign in. "
         "Default user is  admin  — the one-time password is printed in "
         "the container logs ( docker compose logs | grep -i password ).",
         color=COLORS["text_dim"], wrap=660)

    _sub(win,
         "4 · in the BloodHound CE UI click the gear (top-right) → "
         "Administration → File Ingest → UPLOAD FILE(S), then drop the "
         "ZIP whose path is shown above in §2 (OPEN FOLDER / COPY PATH "
         "buttons help).  Ingest takes a few seconds; when it finishes, "
         "switch to Explore and start running pre-built queries or "
         "Cypher.",
         color=COLORS["text_dim"], wrap=660)

    # ── Close (pinned to the window bottom, outside the scroll body) ──
    win = _outer_win
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True, w=120)


def show_bloodhound_graph_window(parent, target, graph_data,
                                 on_run_tool=None):
    """Open a dedicated window that draws the collected AD topology as
    an interactive graph.

    Features:
      · All nodes drawn — attackable ones colored, rest dark grey.
      · Edge types: MemberOf (groups), AdminTo (local admin),
        HasSession (computer→user), AllowedToDelegate.
      · matplotlib toolbar (pan + zoom rectangle) + mouse-wheel zoom.
      · Click on any node → side panel with properties & attack flags.
      · Legend top-right.
      · When `on_run_tool` is provided, attackable nodes get real
        `RUN IN <tool>` buttons that open the tool dialog pre-filled
        for that specific target (kerberoast, AS-REP).

    Gracefully degrades when matplotlib / networkx are not installed —
    pops a small dialog with the pip command instead of crashing.

    Args:
      parent:      Tk parent (HAWK app or any widget).
      target:      str — used only as the window title suffix.
      graph_data:  dict from utils.bloodhound_graph.build_graph_data().
      on_run_tool: optional callable `(tool_id, prefill_dict) → None`.
                   Usually CardWidget.launch_tool_prefilled.  When set,
                   each attackable-node click populates the side panel
                   with action buttons (kerberoastable → RUN KERBEROAST,
                   asrep → RUN AS-REP ROAST, ...) that open the right
                   tool dialog pre-filled with the node's username.
    """
    # ── Deferred imports so HAWK starts fine without matplotlib.
    try:
        import matplotlib
        matplotlib.use("TkAgg")
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import (
            FigureCanvasTkAgg, NavigationToolbar2Tk)
        import networkx as nx
    except ImportError as e:
        _show_graph_missing_deps(parent, str(e))
        return

    nodes = (graph_data or {}).get("nodes") or []
    edges = (graph_data or {}).get("edges") or []
    if not nodes:
        _show_graph_empty(parent)
        return

    # ── Window shell ────────────────────────────────────────────────────
    win = ctk.CTkToplevel(parent)
    win.withdraw()
    win.title(f"BloodHound — Attack Graph — {target}")
    win.configure(fg_color=COLORS["bg_primary"])
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    w = min(1300, int(sw * 0.92))
    h = min(850, int(sh * 0.92))
    win.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
    win.minsize(900, 600)

    ctk.CTkFrame(win, fg_color=COLORS["border_green"],
                 height=2, corner_radius=0).pack(fill="x")

    # ── Header + legend ────────────────────────────────────────────────
    header = ctk.CTkFrame(win, fg_color="transparent")
    header.pack(fill="x", padx=18, pady=(10, 4))
    ctk.CTkLabel(
        header, text=f"BLOODHOUND — Attack Graph — {target}",
        font=_f("xl", True),
        text_color=COLORS["text_bright"], anchor="w",
    ).pack(side="left")

    # Legend (right-aligned): dot-colored labels matching node palette.
    legend = ctk.CTkFrame(header, fg_color="transparent")
    legend.pack(side="right")
    _LEGEND = [
        ("#FF4A4A", "critical"),   # DA/EA, unconstrained
        ("#FFA030", "attackable"),  # kerberoast / asrep
        ("#E8D020", "priv-group"),  # account/backup operators etc
        ("#55708A", "normal"),     # rest (dark grey-blue)
    ]
    for color, label in _LEGEND:
        chip = ctk.CTkFrame(legend, fg_color="transparent")
        chip.pack(side="left", padx=6)
        ctk.CTkLabel(chip, text="●", font=_f("lg", True),
                     text_color=color).pack(side="left")
        ctk.CTkLabel(chip, text=label, font=_f("sm"),
                     text_color=COLORS["text_dim"]).pack(side="left",
                                                          padx=(2, 0))

    _divider(win)

    # ── Main area = graph (left, expandable) + detail panel (right) ────
    main = ctk.CTkFrame(win, fg_color="transparent")
    main.pack(fill="both", expand=True, padx=8, pady=(0, 6))

    graph_fr = ctk.CTkFrame(main, fg_color=COLORS["bg_primary"],
                            border_color=COLORS["border_dim"],
                            border_width=1, corner_radius=4)
    graph_fr.pack(side="left", fill="both", expand=True, padx=(4, 4))

    detail_fr = ctk.CTkFrame(main, fg_color=COLORS["bg_card"],
                             border_color=COLORS["border_dim"],
                             border_width=1, corner_radius=4,
                             width=340)
    detail_fr.pack(side="right", fill="y", padx=(0, 4))
    detail_fr.pack_propagate(False)

    ctk.CTkLabel(
        detail_fr, text="  NODE DETAILS",
        font=_f("md", True), text_color=COLORS["text_green"],
        anchor="w",
    ).pack(fill="x", padx=8, pady=(8, 4))
    _divider(detail_fr)

    # Top half: properties textbox (grows); bottom: action button stack
    # (height = content, packed against the bottom).  Splitting the
    # panel this way means we can swap the button set on every node
    # click without having to re-create the textbox or fight pack
    # geometry.
    detail_box = ctk.CTkTextbox(
        detail_fr, font=_f("md"),
        fg_color="transparent",
        text_color=COLORS["text_bright"],
        border_width=0, corner_radius=0, wrap="word")
    detail_box.pack(fill="both", expand=True, padx=8, pady=(4, 4))
    detail_box.insert("1.0",
                      "Click any node on the graph to see\n"
                      "its properties, attack flags, and\n"
                      "suggested follow-up tools here.\n\n"
                      "Attackable nodes (bright colors) also get\n"
                      "one-click RUN buttons for the relevant HAWK\n"
                      "tool, pre-filled with the node's data.")
    detail_box.configure(state="disabled")

    action_fr = ctk.CTkFrame(detail_fr, fg_color="transparent")
    action_fr.pack(fill="x", padx=8, pady=(0, 10), side="bottom")

    def _set_details(text: str):
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
        """Stack a full-width action button under the details textbox.
        Primary buttons use HAWK's green border/text; secondary are
        dim grey.  Width=320 fills the 340-px detail panel minus
        padding."""
        bc = COLORS["border_green"] if primary else COLORS["border_dim"]
        tc = COLORS["text_green"]    if primary else COLORS["text_dim"]
        ctk.CTkButton(
            action_fr, text=text, width=320, height=34,
            font=_f("md", primary),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_card_hover"],
            border_color=bc, border_width=1, text_color=tc,
            corner_radius=4, command=cmd,
        ).pack(fill="x", pady=3)

    # ── Build networkx graph + layout ──────────────────────────────────
    G = nx.DiGraph()
    for n in nodes:
        G.add_node(n["id"], data=n)
    for e in edges:
        if G.has_node(e["src"]) and G.has_node(e["dst"]):
            G.add_edge(e["src"], e["dst"], type=e.get("type", ""))

    # Spring layout up to ~200 nodes (nice organic clustering); beyond
    # that kamada-kawai is more stable for dense graphs.
    n_count = G.number_of_nodes()
    try:
        if n_count <= 200:
            pos = nx.spring_layout(G, k=1.6, iterations=80, seed=42)
        else:
            pos = nx.kamada_kawai_layout(G)
    except Exception:
        # kamada_kawai needs scipy — fall back to spring if missing.
        pos = nx.spring_layout(G, k=1.6, iterations=60, seed=42)

    # ── Figure ─────────────────────────────────────────────────────────
    fig = Figure(figsize=(10, 6.5), dpi=100,
                 facecolor=COLORS["bg_primary"])
    ax = fig.add_subplot(111, facecolor=COLORS["bg_primary"])

    # Edges — one draw call (keeps perf OK even with 2k edges).
    nx.draw_networkx_edges(
        G, pos, ax=ax,
        edge_color="#2A3642",
        width=0.7, arrows=False, alpha=0.55)

    # Nodes — grouped by category so the legend semantics line up.
    # Draw in order: normal → medium → warn → critical so bright nodes
    # sit visually on top of the grey backdrop.
    _CAT_COLOR = {
        "critical": "#FF4A4A",
        "warn":     "#FFA030",
        "medium":   "#E8D020",
        "normal":   "#55708A",
    }
    _CAT_ALPHA = {
        "critical": 1.00,
        "warn":     1.00,
        "medium":   0.95,
        "normal":   0.60,
    }
    _TYPE_SIZE = {
        "Computer": 320,
        "Group":    280,
        "User":     220,
    }
    _TYPE_MARKER = {
        "Computer": "s",   # square
        "Group":    "D",   # diamond
        "User":     "o",   # circle
    }

    for cat in ("normal", "medium", "warn", "critical"):
        # Further split by type so the marker shape matches the entity.
        for ntype in ("User", "Computer", "Group"):
            ids = [n["id"] for n in nodes
                   if n.get("category") == cat and n.get("type") == ntype]
            if not ids:
                continue
            nx.draw_networkx_nodes(
                G, pos, nodelist=ids, ax=ax,
                node_color=_CAT_COLOR[cat],
                node_size=_TYPE_SIZE[ntype],
                edgecolors=COLORS["bg_primary"],
                linewidths=0.9,
                node_shape=_TYPE_MARKER[ntype],
                alpha=_CAT_ALPHA[cat])

    # Labels: draw ONLY on attackable / priv nodes (critical/warn/medium).
    # Drawing 500 labels over grey nodes turns the canvas into soup — the
    # user can still click any grey node to see its name in the side
    # panel.
    labels = {n["id"]: n["label"]
              for n in nodes
              if n.get("category") in ("critical", "warn", "medium")}
    if labels:
        nx.draw_networkx_labels(
            G, pos, labels=labels, ax=ax,
            font_size=11, font_color="#E8F0F8",
            font_family="monospace")

    ax.set_axis_off()
    ax.margins(0.05)

    # ── Embed in tk ────────────────────────────────────────────────────
    canvas = FigureCanvasTkAgg(fig, master=graph_fr)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # Toolbar (pan + zoom rectangle + home + save PNG).  Keep it compact
    # but visible — native toolbar is the cleanest way to give the user
    # matplotlib-standard navigation without reinventing it.
    tbar_fr = ctk.CTkFrame(win, fg_color=COLORS["bg_secondary"],
                           height=32, corner_radius=0)
    tbar_fr.pack(fill="x")
    try:
        toolbar = NavigationToolbar2Tk(canvas, tbar_fr)
        toolbar.update()
    except Exception as e:
        print(f"[HAWK] matplotlib toolbar failed: {e}")

    # ── Mouse-wheel zoom (centered on cursor) ─────────────────────────
    def _on_scroll(event):
        if event.inaxes is None or event.xdata is None:
            return
        scale = 0.85 if getattr(event, "button", "") == "up" else 1.18
        xlim = ax.get_xlim()
        ylim = ax.get_ylim()
        xdata, ydata = event.xdata, event.ydata
        new_w = (xlim[1] - xlim[0]) * scale
        new_h = (ylim[1] - ylim[0]) * scale
        relx = (xlim[1] - xdata) / (xlim[1] - xlim[0]) if (xlim[1] - xlim[0]) else 0.5
        rely = (ylim[1] - ydata) / (ylim[1] - ylim[0]) if (ylim[1] - ylim[0]) else 0.5
        ax.set_xlim([xdata - new_w * (1 - relx), xdata + new_w * relx])
        ax.set_ylim([ydata - new_h * (1 - rely), ydata + new_h * rely])
        canvas.draw_idle()
    canvas.mpl_connect("scroll_event", _on_scroll)

    # ── Click a node → update detail panel ─────────────────────────────
    node_by_id = {n["id"]: n for n in nodes}
    all_ids = [nid for nid in node_by_id if nid in pos]

    def _on_click(event):
        if event.inaxes is None or event.xdata is None:
            return
        # toolbar modes (pan/zoom) use clicks — don't hijack them.
        try:
            tb_mode = canvas.toolbar.mode if canvas.toolbar else ""
        except Exception:
            tb_mode = ""
        if tb_mode:
            return
        # Find closest node in data coords.
        min_d2 = float("inf")
        closest = None
        for nid in all_ids:
            x, y = pos[nid]
            d2 = (x - event.xdata) ** 2 + (y - event.ydata) ** 2
            if d2 < min_d2:
                min_d2 = d2
                closest = nid
        # Accept the click only if the cursor was reasonably close to a
        # node (relative to current view extent — so zoom respects it).
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

        # ── Build action buttons based on node flags ─────────────────
        # Strategy: EVERY attackable flag gets a real one-click button
        # (kerberoastable / asrep) when an `on_run_tool` callback was
        # plumbed through.  Flags without a direct HAWK tool
        # (unconstrained / da_member) fall back to an info line
        # displayed via a disabled-looking button — same visual
        # rhythm, but it just shows the suggestion text.
        _clear_actions()
        flags = n.get("flags") or []
        n_label = n.get("label") or ""
        n_type = n.get("type") or ""

        if on_run_tool and n_type == "User":
            if "kerberoastable" in flags and n_label:
                # Kerberoast: -request-user <SAMNAME> via extras.  The
                # dialog's credential fields auto-populate from the
                # Credential Store, so the user only needs to confirm
                # & click RUN.
                def _do_kerb(u=n_label):
                    try:
                        on_run_tool("getuserspns", {
                            "extras": f"-request-user {u}",
                            "_origin": f"BloodHound graph — "
                                       f"kerberoast {u}",
                        })
                    except Exception as e:
                        print(f"[HAWK] graph kerberoast launch: {e}")
                _add_action_button(
                    f"→ RUN KERBEROAST on {n_label}",
                    _do_kerb, primary=True)

            if "asrep" in flags and n_label:
                # AS-REP: minimal single-user dialog (_route_asrep_
                # single_user) since this user doesn't need a wordlist
                # — we already know who to target.
                def _do_asrep(u=n_label):
                    try:
                        on_run_tool("getnpusers", {
                            "username": u,
                            "_origin": f"BloodHound graph — "
                                       f"AS-REP {u}",
                        })
                    except Exception as e:
                        print(f"[HAWK] graph asrep launch: {e}")
                _add_action_button(
                    f"→ RUN AS-REP ROAST on {n_label}",
                    _do_asrep, primary=True)

        # Info-only hints for flags without a 1:1 HAWK tool.  Rendered
        # as non-primary buttons so they read as "here's what you'd do
        # manually" rather than active actions.
        if "unconstrained" in flags:
            _add_action_button(
                "ⓘ  TGT hijack — printerbug / PetitPotam",
                lambda: None, primary=False)
        if "da_member" in flags:
            _add_action_button(
                "ⓘ  Domain Admin — own this = domain compromise",
                lambda: None, primary=False)
    canvas.mpl_connect("button_press_event", _on_click)

    # ── Footer buttons ────────────────────────────────────────────────
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True, w=120)

    # Apply context menus + reveal (same pattern as _make_win).
    def _reveal():
        try:
            if win.winfo_exists():
                win.deiconify(); win.lift(); win.focus_force()
        except Exception:
            pass
    win.after(180, _reveal)


def _show_graph_missing_deps(parent, err: str):
    """Fallback dialog when matplotlib or networkx aren't installed."""
    win = _make_win(parent, "Graph — missing dependencies", 620, 340)
    _title(win, "⚠  Attack graph needs matplotlib + networkx")
    _sub(win, "HAWK keeps these optional to stay light at startup.",
         COLORS["text_dim"])
    _note_box(
        win,
        "The ZIP above has been parsed — summary, Target Intel "
        "findings and Credential Store entries are all in place.  "
        "Only the GRAPH view is unavailable.\n\n"
        f"Import error:  {err}",
        color=COLORS["border_amber"])
    _selectable_text(
        win,
        "pip install matplotlib networkx --break-system-packages",
        color=COLORS["text_green"], height=34)
    _sub(win,
         "After install, close and re-open HAWK, re-run bloodhound "
         "or click VIEW ATTACK GRAPH from the summary dialog again.",
         COLORS["text_dim"])
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True, w=120)


def _show_graph_empty(parent):
    win = _make_win(parent, "Graph — no data", 540, 260)
    _title(win, "Attack graph — nothing to draw")
    _sub(win,
         "bloodhound-python did not produce any users/computers/groups "
         "to plot.  The collection may have failed partway — check the "
         "HAWK terminal for errors.",
         COLORS["text_dim"], wrap=460)
    row = _btn_row(win)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), primary=True, w=120)


def show_bloodhound_ce_setup_dialog(parent):
    """Offline-friendly setup guide for BloodHound Community Edition.

    Shows the 10 install/ops steps in a scrollable dialog with each
    section's shell commands inside a selectable text block.  Two
    action buttons:

      · COPY ALL COMMANDS — copies the full one-shot bash install
        script to the clipboard; user pastes into a terminal and
        walks away.
      · OPEN SPECTEROPS DOCS — launches the official docs page.

    Deliberately embedded (no network fetch) so HAWK stays useful
    on air-gapped Kali installs during on-site engagements.
    """
    win = _make_win(parent,
                      "BloodHound CE — Start / Setup Guide",
                      900, 820)
    _title(win, "⚙  BloodHound CE — Start / Setup Guide")
    _sub(win,
         "Offline guide.  Use 'Starting the services' if BH CE is "
         "already installed; jump to 'Installation guide' below if "
         "you don't have it yet.",
         COLORS["text_dim"])

    _note_box(
        win,
        "HAWK draws its own attack graph natively (VIEW ATTACK "
        "GRAPH button), so you DON'T need BH CE for the basics.  "
        "Install it when you want the richer Cypher query engine, "
        "Shortest Path pathfinding, multi-domain trust analysis, "
        "and custom query persistence.",
        COLORS["border_dim"])

    # ── Scrollable body — everything below this point lives in the
    #    same CTkScrollableFrame so the wheel scrolls the WHOLE
    #    dialog content (start-services + creds + install + tshoot)
    #    in one continuous flow instead of getting trapped in
    #    individual blocks.  Embedded code snippets opt out of
    #    capturing the wheel via _selectable_text's bubble flag
    #    (see the helper at the top of this file).
    _outer = win
    body = ctk.CTkScrollableFrame(
        _outer, fg_color="transparent",
        scrollbar_button_color=COLORS["border_dim"],
        scrollbar_button_hover_color=COLORS["border_green"])
    body.pack(fill="both", expand=True, padx=0, pady=(2, 2))

    # ── 1. STARTING THE SERVICES (already installed) ────────────────
    # The 99% case for an operator who has BH CE installed already:
    # they just need to bring the docker compose stack up + know
    # which URL to hit + how to read logs.
    ctk.CTkLabel(
        body, text="  ▶  STARTING THE SERVICES  (already installed)",
        font=_f("lg", True),
        text_color=COLORS["text_green"],
        anchor="w",
    ).pack(fill="x", padx=24, pady=(8, 2))
    _selectable_text(
        body,
        "# Bring the BH CE docker stack up (postgres + neo4j +\n"
        "# bloodhound API + nginx) in detached mode.\n"
        "cd ~/bloodhound-ce && docker compose up -d\n"
        "\n"
        "# Verify all 4 containers are 'running' (give it ~30s on\n"
        "# first boot — neo4j needs time to initialise its store).\n"
        "cd ~/bloodhound-ce && docker compose ps\n"
        "\n"
        "# Open the web UI.  Default port is 8080 (the docker\n"
        "# compose maps 127.0.0.1:8080 → container:8080).  If you\n"
        "# changed it in docker-compose.yml replace 8080 below.\n"
        "xdg-open http://localhost:8080  ||  firefox http://localhost:8080  &\n"
        "\n"
        "# Want it on port 8000 instead?  Edit ~/bloodhound-ce/\n"
        "# docker-compose.yml — find the bloodhound service\n"
        "# 'ports:' block and change '127.0.0.1:8080:8080' to\n"
        "# '127.0.0.1:8000:8080', then  docker compose up -d  again.\n"
        "\n"
        "# Tail the logs while the stack starts (Ctrl+C to detach,\n"
        "# the containers keep running in the background).\n"
        "cd ~/bloodhound-ce && docker compose logs -f bloodhound\n"
        "\n"
        "# Stop the stack (data is preserved on disk):\n"
        "cd ~/bloodhound-ce && docker compose down\n"
        "\n"
        "# Restart only the bloodhound API (faster than full stack\n"
        "# bounce, useful after editing config):\n"
        "cd ~/bloodhound-ce && docker compose restart bloodhound",
        color=COLORS["text_bright"], height=300)

    # ── 2. CREDENTIALS quick-reference ─────────────────────────────
    # The #1 question every new user asks is "what's my BH CE password?".
    # Put the recovery commands here so they're visible right after
    # the start-services block.
    ctk.CTkLabel(
        body, text="  🔑  CREDENTIALS — quick reference",
        font=_f("md", True),
        text_color=COLORS["text_yellow"],
        anchor="w",
    ).pack(fill="x", padx=24, pady=(14, 2))

    _selectable_text(
        body,
        "# Username is ALWAYS:  admin\n"
        "\n"
        "# Initial one-time password (first boot only):\n"
        "cd ~/bloodhound-ce && \\\n"
        "  docker compose logs bloodhound 2>&1 | grep -i "
        "'Initial Password'\n"
        "\n"
        "# Forgot the password after you changed it?  Reset to a\n"
        "# known value without losing BH data (see step 7 of the\n"
        "# Installation guide below):\n"
        "cd ~/bloodhound-ce && docker compose exec bloodhound "
        "python3 -c \"\n"
        "import bcrypt, psycopg2, os\n"
        "c = psycopg2.connect(os.environ['BHE_DATABASE_CONNECTION'])\n"
        "h = bcrypt.hashpw(b'HawkRecovered123!',\n"
        "                  bcrypt.gensalt()).decode()\n"
        "cur = c.cursor()\n"
        "cur.execute(\\\"UPDATE auth_secrets SET digest=%s WHERE \\\n"
        "  user_id=(SELECT id FROM users WHERE \\\n"
        "  principal_name='admin');\\\", (h,))\n"
        "c.commit(); print('OK — admin reset to HawkRecovered123!')\"",
        color=COLORS["text_bright"], height=220)

    # ── 3. INSTALLATION GUIDE (10 steps) ────────────────────────────
    ctk.CTkLabel(
        body, text="  ⚙  INSTALLATION GUIDE  "
                    "(only if BH CE isn't on this Kali yet)",
        font=_f("lg", True),
        text_color=COLORS["text_cyan"],
        anchor="w",
    ).pack(fill="x", padx=24, pady=(18, 4))
    ctk.CTkLabel(
        body,
        text="       Walk top to bottom.  Tested on Kali rolling "
             "2025.  Each step has a copyable shell snippet.",
        font=_f("sm"), text_color=COLORS["text_dim"],
        anchor="w", justify="left", wraplength=820,
    ).pack(fill="x", padx=24, pady=(0, 6))

    for title, cmd in _BHCE_SETUP_STEPS:
        ctk.CTkLabel(
            body, text=f"  ◇  {title}",
            font=_f("md", True),
            text_color=COLORS["text_green"],
            anchor="w",
        ).pack(fill="x", padx=24, pady=(10, 2))
        _selectable_text(body, cmd,
                          color=COLORS["text_bright"],
                          height=max(50, cmd.count("\n") * 20 + 40))

    # ── Troubleshooting appendix ─────────────────────────────────────
    ctk.CTkLabel(
        body, text="  ⚑  Troubleshooting",
        font=_f("md", True),
        text_color=COLORS["text_yellow"],
        anchor="w",
    ).pack(fill="x", padx=24, pady=(14, 2))
    _note_box(
        body,
        "unknown command: docker compose\n"
        "   → plugin not installed / not visible.  Redo step 2.\n"
        "\n"
        "permission denied on /var/run/docker.sock\n"
        "   → docker group not loaded in the current shell.\n"
        "     Run  newgrp docker  or reopen the terminal.\n"
        "\n"
        "Unit docker.service not found\n"
        "   → daemon not installed.  Redo step 1 "
        "(apt install docker.io).\n"
        "\n"
        "localhost:8080 connection refused\n"
        "   → container not up.  docker compose ps  — if empty, \n"
        "     redo  up -d ;  if 'restarting', run  docker compose logs.\n"
        "\n"
        "Images don't download\n"
        "   → network / DNS issue.  Test:  curl "
        "https://registry-1.docker.io/v2/",
        color=COLORS["border_dim"], selectable=True)

    # ── Footer buttons ──────────────────────────────────────────────
    win = _outer

    def _copy_script():
        try:
            from utils.clipboard import clipboard_copy
            if not clipboard_copy(_BHCE_SETUP_SCRIPT):
                win.clipboard_clear()
                win.clipboard_append(_BHCE_SETUP_SCRIPT)
        except Exception:
            try:
                win.clipboard_clear()
                win.clipboard_append(_BHCE_SETUP_SCRIPT)
            except Exception:
                pass

    def _open_docs():
        import webbrowser
        try:
            webbrowser.open(
                "https://bloodhound.specterops.io/get-started/"
                "quickstart/community-edition-quickstart", new=2)
        except Exception:
            pass

    row = _btn_row(win)
    _btn(row, "COPY ALL COMMANDS",
         _copy_script, primary=True, w=220)
    _btn(row, "IMPORT 30 CYPHER QUERIES",
         lambda: show_bh_cypher_importer_dialog(parent),
         w=240)
    _btn(row, "OPEN SPECTEROPS DOCS",
         _open_docs, w=210)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)


def show_bh_cypher_importer_dialog(parent):
    """Push the 30 curated attack-surface queries into a running
    BH CE instance via its /api/v2/saved-queries REST endpoint.

    Flow:
      1. Collect BH CE URL + admin user + password from the form.
      2. Run the importer on a background thread so the UI stays
         responsive (login + 30 POST calls take 5-15s on a local
         install, longer over WAN).
      3. Stream per-query status into a textbox.  On finish, show a
         summary counter (imported / skipped / failed).

    Works on a fresh Kali with no extra pip install — uses stdlib
    urllib.  Credentials live only in this dialog's local scope;
    nothing is persisted to the HAWK session.
    """
    import threading
    from utils.bloodhound_queries import (
        bulk_import, CURATED_QUERIES)

    win = _make_win(parent,
                    "BloodHound CE — import Cypher queries",
                    720, 640)
    _title(win, "📥  Import Cypher queries into BloodHound CE")
    _sub(win,
         f"Push {len(CURATED_QUERIES)} pre-built attack-surface "
         "queries into your BH CE instance.",
         COLORS["text_dim"])

    _note_box(
        win,
        "HAWK logs in with your BH CE admin credentials, fetches a "
        "session token, then POSTs each query via "
        "/api/v2/saved-queries.  Duplicates (same name) are skipped "
        "automatically — safe to re-run.\n\n"
        "Credentials stay in memory for this dialog only; nothing "
        "is saved to disk or to the HAWK session.",
        color=COLORS["border_dim"])

    # Form fields.
    base_var = ctk.StringVar(value="http://localhost:8080")
    user_var = ctk.StringVar(value="admin")
    pwd_var  = ctk.StringVar(value="")

    def _row(label, var, placeholder="", show=""):
        fr = ctk.CTkFrame(win, fg_color="transparent")
        fr.pack(fill="x", padx=24, pady=(4, 0))
        ctk.CTkLabel(
            fr, text=label, width=90, anchor="w",
            font=_f("sm", True),
            text_color=COLORS["text_bright"],
        ).pack(side="left")
        e = ctk.CTkEntry(
            fr, textvariable=var, font=_f("md"), height=30,
            show=show,
            placeholder_text=placeholder,
            fg_color=COLORS["bg_card"],
            text_color=COLORS["text_bright"],
            border_color=COLORS["border_green"],
            border_width=1, corner_radius=3)
        e.pack(side="left", fill="x", expand=True)
        add_context_menu(e)
        return e

    _row("BH URL:",  base_var, "http://localhost:8080")
    _row("Username:", user_var, "admin")
    _row("Password:", pwd_var, "(required)", show="*")

    # Progress log.
    ctk.CTkLabel(
        win, text="  LOG",
        font=_f("sm", True), text_color=COLORS["text_green"],
        anchor="w").pack(fill="x", padx=24, pady=(10, 2))
    log_box = ctk.CTkTextbox(
        win, font=_f("sm"),
        fg_color=COLORS["bg_card"],
        text_color=COLORS["text_bright"],
        border_color=COLORS["border_dim"],
        border_width=1, corner_radius=3, wrap="word", height=220)
    log_box.pack(fill="both", expand=True, padx=14, pady=(0, 6))
    log_box.insert("1.0",
                    "(idle — click START IMPORT to begin)\n")
    log_box.configure(state="disabled")

    counter_var = ctk.StringVar(value="")
    ctk.CTkLabel(
        win, textvariable=counter_var,
        font=_f("sm", True),
        text_color=COLORS["text_yellow"]).pack(pady=(2, 4))

    def _append(line, color=None):
        try:
            log_box.configure(state="normal")
            log_box.insert("end", line + "\n")
            log_box.see("end")
            log_box.configure(state="disabled")
        except Exception:
            pass

    # The button we flip during the run so the user can't double-submit.
    running = {"flag": False}

    def _on_progress(event, name, detail):
        # Called from the background thread — use after() to marshal
        # to the UI thread.
        def _ui():
            if event == "login_ok":
                _append("[+] login OK — pushing queries…")
            elif event == "skip":
                _append(f"    ~ {name}   (already present)")
            elif event == "ok":
                _append(f"    ✓ {name}")
            elif event == "err":
                _append(f"    ✗ {name}   ({detail})")
            elif event == "done":
                _append(f"\n[DONE] {detail}")
                counter_var.set(detail)
        try:
            win.after(0, _ui)
        except Exception:
            pass

    def _start():
        if running["flag"]:
            return
        base = base_var.get().strip()
        user = user_var.get().strip() or "admin"
        pwd  = pwd_var.get()
        if not base or not pwd:
            counter_var.set("URL and password are required.")
            return

        # Reset log.
        try:
            log_box.configure(state="normal")
            log_box.delete("1.0", "end")
            log_box.insert("1.0",
                            f"[*] target: {base}\n"
                            f"[*] user:   {user}\n\n")
            log_box.configure(state="disabled")
        except Exception:
            pass
        counter_var.set("Running…")
        running["flag"] = True
        start_btn.configure(state="disabled", text="IMPORTING…")

        def _bg():
            try:
                bulk_import(
                    base, user, pwd,
                    on_progress=_on_progress,
                    skip_existing=True,
                    verify_ssl=not base.lower().startswith("http://"))
            except Exception as e:
                try:
                    win.after(0, lambda:
                               counter_var.set(f"crashed: {e}"))
                except Exception:
                    pass
            finally:
                try:
                    win.after(0, lambda: (
                        start_btn.configure(
                            state="normal", text="START IMPORT"),
                        running.__setitem__("flag", False)))
                except Exception:
                    pass

        threading.Thread(target=_bg, daemon=True).start()

    row = _btn_row(win)
    start_btn = ctk.CTkButton(
        row, text="START IMPORT", command=_start,
        width=180, height=34,
        font=_f("md", True),
        fg_color=COLORS["bg_card"],
        hover_color=COLORS["bg_card_hover"],
        border_color=COLORS["border_green"],
        border_width=1,
        text_color=COLORS["text_green"],
        corner_radius=4)
    start_btn.pack(side="left", padx=6)
    _btn(row, "CLOSE", lambda: _safe_destroy(win), w=120)


__all__ = ['show_bloodhound_summary_dialog', 'show_bloodhound_graph_window', '_show_graph_missing_deps', '_show_graph_empty', 'show_bloodhound_ce_setup_dialog', 'show_bh_cypher_importer_dialog']
