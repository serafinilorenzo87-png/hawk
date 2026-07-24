# HAWK Changelog

All notable changes to HAWK are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] — 2026-05-01

This release introduces the **plugin architecture** that the ARGUS
commercial plugin (and any future plugin) installs into. HAWK itself
remains 100% open source under Apache 2.0; plugins are independent
artifacts with their own license terms.

### Added
- `utils/plugin_loader.py` — generic loader for HAWK plugins. Discovers
  installed plugin packages, verifies the contract version
  (`HAWK_API_VERSION`), instantiates the plugin via its `create_plugin()`
  factory, validates its license, and exposes a clean `mount`/`unmount`
  lifecycle. Six observable states: `not_installed`, `import_error`,
  `incompatible`, `no_license`, `expired`, `active`. Never raises into
  HAWK — all failure modes are reported via state + a human-readable
  `error` field.
- `HAWK_API_VERSION = "1.0.0"` constant in `utils/config.py`. The plugin
  contract is published in the ARGUS repository at
  `argus/docs/plugin-contract.md`.
- ARGUS button on the target bar is now **state-aware**: it discovers
  the ARGUS plugin at boot and renders one of four visual buckets:
  - grey lock (plugin missing or import error)
  - amber lock (license required)
  - amber clock (license expired)
  - cyan functional (active — opens the ARGUS tab in a Toplevel window)
  Each non-active state surfaces a state-specific dialog explaining
  the next step.
- `tests/test_plugin_loader.py` — 13 unit tests covering every state
  transition, including contract violations (raised from
  `verify_license`, `mount_in`).
- `tests/test_argus_button.py` — 6 visual-state tests verifying the
  button accent colour and icon match the underlying plugin state.

### Changed
- `gui/widgets/target_bar.py`: the legacy ARGUS teaser button was
  replaced by the state-aware variant. The teaser-button helper
  (`_make_coming_soon_button`) gained three optional, non-breaking
  parameters (`accent_color`, `lock_icon`, `on_click`) so it can be
  reused by the ARGUS state-specific renders. The COMMAND AND CONTROL
  teaser button is unchanged.

### Notes for plugin developers
- The plugin contract is at `argus/docs/plugin-contract.md` (versioned
  v1.0.0).
- A minimal hello-world plugin example is in §7 of that document.
- Plugins are distributed as Python wheels and discovered by
  `pip install`-style availability of the `hawk_argus` (or other)
  package in HAWK's Python environment.

## [1.0.0] — 2026-04-15

Initial public release.

### Added
- Full ten-phase kill-chain UI (recon → reporting).
- Tooling integration: nmap, gobuster, hydra, msfconsole, certipy,
  bloodhound, oracle, et al.
- Stealth mode toggle, proxychains integration.
- Session manager with autosave and atomic snapshots.
- Customisable banner, config-driven colour scheme, font scale.
