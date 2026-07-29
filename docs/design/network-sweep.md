# HAWK — Network Sweep + Host Graph — Design Spec

Status: DRAFT (agreed in the Specs & Decision chat, 2026-07-24). Implementation
happens in a separate operational chat. No code here — this is the contract.

Scope: (A) network sweep + host graph; (B) ARGUS teaser button refinement +
removal of the C2 button (§12). Bundled because both live in `target_bar.py` and
ship in a single target-bar pass.

## 1. Goal & gap

Today HAWK is host-centric: one session targets one IP. There is no way to
discover *which* hosts exist on a network before picking a target. This feature
adds **network-level discovery**: sweep a CIDR range, list the live hosts, and
visualise them as an interactive node graph. Selecting a node promotes that host
to the active target (its own session), so the operator moves across a network
one host at a time without losing state.

Constraints inherited from HAWK philosophy: 100% local, deterministic, no
cloud/AI, no telemetry. All artifacts under `<HAWK>/outputs/`, never `$HOME`.

## 2. UI — target bar row

New row placed in the empty band between the TARGET IP row and the TARGET DOMAIN
row (the region the operator circled). Single horizontal line:

```
NETWORK SWEEP:  [ base IP ]  / [ prefix ]   [▶ RUN SWEEP]   ( [◈ OPEN GRAPH] )
```

- **base IP** — entry, e.g. `192.168.176.0`. Placeholder shows an example.
- **prefix** — narrow entry for the CIDR mask (e.g. `24`, `16`, `8`).
- Live helper text next to the fields, computed from base+prefix via
  `utils/target_validator.py`: normalised network + host count, e.g.
  `192.168.176.0/24 → 254 hosts`. Invalid input disables RUN SWEEP.
- **RUN SWEEP** — starts the sweep (async, mirrored to the terminal).
- **OPEN GRAPH** — hidden until a sweep has produced results; then it appears
  next to RUN SWEEP and opens the graph viewer (Toplevel).

Widget lives in `gui/widgets/target_bar.py`, styled like the existing controls.

## 3. Session & inventory model — LAZY

Decision: swept hosts become **sessions**, but materialised lazily to avoid
generating hundreds of JSON files from one sweep.

- A sweep writes **one inventory artifact**: `outputs/sweeps/<range>-<ts>.json`.
  It holds every discovered host + summary (alive, responded-via, port hints,
  os_hint) and a per-host `session_ref` (initially null).
- The full inventory is held in memory for instant switching.
- A host's **Session is created on first selection** (click on its graph node),
  via the existing `SessionManager.new_session(ip, platform)`. The inventory
  records the resulting `session_ref` (session_id / file), so subsequent
  selections of that IP **load the existing session** instead of creating a new
  one — seamless switching, full persisted state per host.
- Sessions keep the current on-disk format (`{ip}-{date}-{time}.json`). The
  inventory is the IP→session index that the current model lacks.
- Re-running a sweep on the same range updates/merges the inventory; existing
  `session_ref`s are preserved (never orphan a host the operator already worked).

## 4. Discovery engine

Deterministic, layered, offline. Two phases; phase 2 is optional and off by
default.

### Phase 1 — host discovery (always)
Answer only "alive / not alive". No port scan. Fast.

- **Local /24 (same L2 segment)** → ARP is authoritative (`nmap -sn` uses ARP
  automatically on-link; `arp-scan` as an alternative). ARP cannot be firewalled
  at layer 2, so ICMP-off Windows hosts are still found.
- **Routed ranges** → multi-probe discovery so ICMP-filtered hosts still answer:
  `nmap -sn -PE -PP -PS445,3389,443,80,22 -PA80 -T4`. Windows boxes reply on
  445/3389 even with ICMP echo blocked.
- **Large ranges** → `masscan` for speed (reuse the existing masscan progress bar
  in `terminal_widget.py`). Threshold at which HAWK prefers masscan over nmap is
  a tuning constant.

CRITICAL: **do NOT use `-Pn` in phase 1.** `-Pn` disables host discovery and
marks every address in the range as up — on a /24 that yields 254 phantom hosts.
The Windows/ICMP concern is solved by the multi-probe set above, not by `-Pn`.

### Phase 2 — light enrichment (optional, off by default)
A checkbox enables a light port peek on hosts already found alive. Purpose: an
*idea* of exposure to colour the graph nodes — not a full scan.

- `nmap -Pn --top-ports 100 <alive-hosts>` (or `-F`). **No `-sV`, no `-sC`/NSE,
  no vuln scripts.** Here `-Pn` is correct: the host is confirmed up, so we skip
  redundant discovery and it still works against ICMP-off Windows.
- The real per-target scanning (`-sV`, NSE, vuln) stays where it already lives:
  the normal HAWK kill-chain phases, after the host is promoted to active target.

### OS hint (free, deterministic)
No `-O` (heavy, noisy, needs root). Infer a cheap hint from which probes/ports
answered: 445/3389 → "likely Windows"; 22/80 only → "likely Linux/web";
otherwise "unknown". Feeds node colour/icon only — never asserted as fact.

## 5. Proxy / Tor interaction

Sweep uses raw sockets (ICMP / ARP / TCP SYN/ACK) that do **not** traverse
Tor/proxychains. When `PROXY: TOR` is active:
- Run the sweep in the clear and surface an explicit banner in the terminal
  ("network sweep bypasses the active proxy — raw probes go out on the local
  interface"). Do not silently leak through/around the proxy without telling the
  operator.
- (Decided: warn + run in clear, not block. Revisit if the operator wants a hard
  block instead.)

## 6. Scale guardrail — WARNING only

No hard cap. `/16` = 65k hosts, `/8` = 16M. Above `/16`, show a confirmation
dialog with the host count and an ETA hint, and force the masscan path. The
operator decides. Authorized-use reminder shown for any range sweep (a network
sweep is noisier and more intrusive than a single ping).

## 7. Data contracts

### Inventory (`outputs/sweeps/<range>-<ts>.json`)
```
{
  "range": "192.168.176.0/24",
  "started": "<iso>", "finished": "<iso>",
  "method": "nmap-sn|masscan|arp-scan",
  "hosts": [
    { "ip": "192.168.176.10",
      "alive": true,
      "responded_via": ["arp","syn:445"],
      "port_hints": [445, 3389],          // phase 2 only, else []
      "os_hint": "windows|linux|unknown",
      "session_ref": null }               // filled on first promotion
  ]
}
```

### Graph data — REUSE the BloodHound contract
The graph reuses the existing `{nodes, edges, stats}` dict shape produced by
`utils/bloodhound_graph.py` and consumed by the matplotlib+networkx renderer in
`gui/dialogs_bloodhound.py`. A new pure-data builder
(`utils/sweep_graph.py`, mirroring `bloodhound_graph.py` — no tkinter imports)
converts an inventory into:
- **nodes**: one `subnet` root, one `host` per alive host; optional `service`
  nodes per port hint (phase 2). Node `category` drives colour:
  - `critical`/`warn` — host exposing 445/3389/22 (notable attack surface)
  - `medium` — host with any open port hint
  - `normal` — alive, no port info
- **edges**: subnet→host (`contains`), host→service (`runs`).
- **stats**: total/alive counts, per-os-hint counts, notable-port counts.

## 8. Graph viewer

Reuse the BloodHound renderer path (networkx spring layout + matplotlib embedded
via `backend_tkagg`) so there is one graph style in HAWK, not two. Opens in a
Toplevel, consistent with the curation/ARGUS/BloodHound dialogs.

- Click a **host node** → promote to active target: fill TARGET IP, create or
  load that host's session (§3), and (optionally) jump the main view to Target
  Intel for that host.
- The node of a host already worked on is visually distinct (has a session /
  findings), so the operator sees progress across the network at a glance.
- Matplotlib/networkx are already optional deps used by the BloodHound dialog;
  degrade gracefully with a clear message if unavailable (same pattern).

## 9. Integration points (files)

- `gui/widgets/target_bar.py` — the new sweep row + OPEN GRAPH button + promote
  handler.
- `modules/` — a discovery tool definition (extend `recon.py` or a new
  `modules/discovery.py`) driven by the existing `ToolRunner`, with live line
  callback to the terminal and the masscan/nmap progress bar.
- `utils/sweep_graph.py` — new pure-data inventory→graph builder (mirrors
  `bloodhound_graph.py`).
- Graph renderer — reuse/extend the BloodHound renderer in `gui/`.
- `utils/session.py` / `SessionManager` — no format change; add the IP→session
  lookup used by promotion (via the inventory `session_ref`).
- Inventory persistence under `outputs/sweeps/` (gitignored, like all runtime).

## 10. Out of scope / future

- No auto-exploitation or heavy scanning during the sweep — discovery only.
- No continuous/scheduled monitoring — a sweep is a one-shot on demand.
- Passive discovery, IPv6 ranges, and multi-hop/pivot sweeps are future work.

## 11. Resolved decisions

1. Session model: **lazy** (session created on first node click, then recalled).
2. Scan profile: **light** — phase-1 multi-probe discovery (no `-Pn`), optional
   phase-2 top-100 peek (`-Pn`), no `-sV`/NSE/vuln in the sweep.
3. Scale: **warning only** above /16, no hard cap.
4. `-Pn`: belongs to phase 2 (enrichment on known-up hosts), NOT phase 1
   (discovery) where it would fabricate live hosts.
5. Tor active: **warn + run in the clear**, do not block.
6. Graph: **reuse** the BloodHound networkx+matplotlib renderer and its
   `{nodes, edges, stats}` contract.

## 12. Bundled — ARGUS teaser button (+ remove C2)

Bundled into this spec because it lives in the same file (`target_bar.py`) and
the same target-bar pass. ARGUS itself stays a **separate paid plugin** (a
`hawk_argus` wheel); HAWK core ships only this button + the plugin loader. See
`utils/plugin_loader.py` and the existing `_make_argus_button` /
`_build_coming_soon_buttons` in `target_bar.py`.

### Product model
ARGUS is a paid add-on **for users who already own HAWK**. A HAWK user who has
not purchased/licensed ARGUS still sees the button — as a subtle teaser, never a
nag.

### Unlicensed state (the common case) — subtle teaser
When ARGUS is absent or unlicensed, the button renders low-key, nothing loud:
- Button **dimmed / opacified** (reduced contrast vs the active controls).
- A single **small yellow indicator light** that pulses **briefly every ~5
  seconds** — low amplitude, easy to miss unless looked for. Retune the existing
  teaser pulse (currently ~3 s) to 5 s + yellow.
- **Hover** → tooltip explaining in ~4 lines what ARGUS is and what it will do.
- Click while unlicensed: shows the same explanatory info (teaser dialog); no
  functional action.

Placeholder hover copy (finalise later):
```
ARGUS — passive defensive fingerprinting.
Identifies the target's EDR / AV / SIEM / WAF from data HAWK already has —
no extra probes, no added noise. Know what's watching before you move.
Paid add-on for HAWK · coming soon.
```

### Licensed / active state
With a valid, licensed ARGUS plugin present, the button is **functional**
(full-contrast) and opens ARGUS in a Toplevel — the existing
`_make_argus_active_button` / `_open_argus_window` path. Unchanged.

### State mapping (plugin_loader)
Collapse the current four visual buckets into two, keyed off the loader state:
- `not_installed` / `import_error` / `incompatible` / `no_license` / `expired`
  → the single **dimmed + yellow-pulse + hover** teaser above. Optionally the
  hover's last line varies ("coming soon" vs "license expired — renew").
- `active` → functional button.

### Remove the C2 button
Only the ARGUS button stays in the teaser area. `_build_coming_soon_buttons`
already instantiates ARGUS only, but stale scaffolding still assumes two CTAs —
remove it: the "two CTAs / both buttons" comments, the width-normaliser's
two-button assumption, and any dead COMMAND AND CONTROL wiring or
`_make_coming_soon_button` C2 call. Net result: one ARGUS teaser button, no C2.

### Resolved decisions (this part)
7. Only the ARGUS button; the C2 (COMMAND AND CONTROL) teaser is removed.
8. Unlicensed ARGUS look: dimmed button + a small yellow light pulsing every
   ~5 s + hover with a ~4-line explanation. Very subtle. Active state opens
   ARGUS as it does today.
