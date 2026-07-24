# HAWK DB profiles

Cheatsheets shown in the floating **📋 CMDS** dialog (per-port button
in the Target Intel ports panel) come from the YAML files in this
directory.  HAWK reads:

1. `hawkC/profiles/db_profiles/*.yaml` — bundled defaults (this dir)
2. `~/.config/hawk/db_profiles/*.yaml` — user extensions

User entries with the same `name:` as a built-in profile **replace**
the built-in entirely.  Add a new file with a brand-new `name:` to
extend HAWK's coverage to a database it doesn't ship with — no code
changes required, just a restart.

## Schema

```yaml
name: redis                      # canonical key (required, lowercase)
title: "Redis"                   # display title (required)
aliases:                         # optional — extra service-name
  - redis-cli                    #   variants that map to this profile.
  - rdb                          #   nmap -sV output goes here.

intro: |                         # optional multi-line description
  Vanilla Redis < 6 has NO authentication.  CONFIG SET dir /
  dbfilename + SAVE is the classic abuse chain.

commands:                        # required, non-empty list
  - cmd: "INFO"
    desc: "Server info (version, mode, clients)"
  - cmd: "PING"
    desc: "Connectivity check (PONG = OK)"
  - cmd: "-- Section header below:"   # desc='' = inline note, no COPY
    desc: ""
  - cmd: "CONFIG GET *"
    desc: "All server config"
```

### Field rules

| Field | Required | Type | Notes |
|---|---|---|---|
| `name` | yes | string | Lowercased canonical key.  Must match the filename: `redis.yaml` → `name: redis`. |
| `title` | yes | string | Shown in the cheatsheet dialog header. |
| `aliases` | no | list of strings | Lowercase service-name aliases that nmap might emit (e.g. `cassandra-cql`).  The `name` itself is always an alias — don't duplicate it. |
| `intro` | no | multi-line string | Optional blurb shown above the command list. |
| `commands` | yes | list of mappings | Each entry has `cmd` (the shell/SQL/HTTP command, can contain placeholders like `<table>`) and `desc` (one-line description).  Empty `desc` = inline section header / note (no COPY button). |

### Validation

Bad YAML → skipped with a warning to stderr.  Missing required field
→ skipped with a warning.  The rest of the dir loads normally.

### Where the canonical keys are wired

The canonical `name:` is the same string used by:

- `_cheatsheet_key_for(svc)` in `gui/widgets/target_intel_widget.py`
  to decide whether to show the **📋 CMDS** button on a port row
- `db_fingerprint.py` to report `svc=<key>` when it identifies a DB
- The Connect cmd templates in `target_intel_widget.py` (future
  STEP 3.1 / 3.2 — connect-action coverage)

So adding `name: cockroachdb` to a YAML file makes the button appear
for any port nmap labels as `cockroachdb` (or whose alias matches).

### Regenerating bundled defaults

If you edit the in-memory dict `TargetIntelWidget._CONNECT_CHEATSHEETS`
(e.g. STEP 3 expansion), regenerate this dir with:

```bash
python3 hawkC/tmp/_migrate_cheatsheets_to_yaml.py
```

The script overwrites every file in this directory based on the
current value of `_CONNECT_CHEATSHEETS`.
