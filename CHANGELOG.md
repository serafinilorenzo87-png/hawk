# HAWK Changelog

All notable changes to HAWK are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-08-13

First stable release. HAWK is a complete, portable pentest orchestration
suite: a customtkinter GUI on Kali that drives the full engagement
kill-chain from a single console, with no cloud dependency and no AI
component. 100% open source under Apache 2.0. This entry consolidates
the project's history into one baseline; earlier development entries
remain in the git history.

### Engagement workflow
- Full ten-phase kill-chain UI (recon → reporting), each phase wiring the
  relevant tooling behind a consistent console.
- Tooling integration: nmap, gobuster, hydra, msfconsole, certipy,
  bloodhound, oracle, et al.
- Network sweep with local-vs-routed host banding: on ranges that spill
  into routed networks, off-subnet hosts are labelled and collapsed so
  the alive count reflects reachable, on-link targets.
- Stealth mode toggle and proxychains integration.
- Session manager with autosave and atomic snapshots; the LOAD dialog
  offers sort-by last-modified and sort-by in-name timestamp.

### Plugin architecture
- `utils/plugin_loader.py` — generic loader for HAWK plugins. Discovers
  installed plugin packages, verifies the contract version
  (`HAWK_API_VERSION`), instantiates the plugin via its `create_plugin()`
  factory, validates its license, and exposes a clean `mount`/`unmount`
  lifecycle. Six observable states: `not_installed`, `import_error`,
  `incompatible`, `no_license`, `expired`, `active`. Never raises into
  HAWK — all failure modes are reported via state + a human-readable
  `error` field.
- `HAWK_API_VERSION = "1.0.0"` constant in `utils/config.py` — the
  plugin contract, independent from the app version. The contract is
  published in the ARGUS repository at `argus/docs/plugin-contract.md`.
- State-aware ARGUS button on the target bar: it discovers the ARGUS
  plugin at boot and renders one of four visual buckets — grey lock
  (missing / import error), amber lock (license required), amber clock
  (license expired), cyan functional (active). Each non-active state
  surfaces a dialog explaining the next step. HAWK remains fully open
  source; plugins are independent artifacts with their own license terms.

### Presentation
- Customisable banner, config-driven colour scheme, and font scale.
