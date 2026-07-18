# Presence UI — AI is controlling this computer

When Computer Use / desktop automation is active, operators need a **foreground signal** that is independent of the agent chat window.

## Goals

1. Make active control **impossible to miss**
2. Show **what** the host is doing (capability + detail)
3. Let a human **Stop / Pause** without racing the agent
4. Keep the control chrome **out of the AI click surface** (do not let the model click Stop)

## Architecture

```text
desktop-mcp (stdio)
    │
    ▼
desktop-host  ──publish──►  {artifact_dir}/presence/current.json
    │         ──open -g──►  ComputerUsePresence.app  (auto on startup)
    │                       {artifact_dir}/presence/events.jsonl
    │
    └─ Presence UI polls current.json → HUD / edge glow / AI cursor
```

### Install + auto-launch

```bash
npm run install:presence-ui   # builds lab Swift app → Application Support/…/PresenceUI/
```

Host default: **auto-launch on** (`LAZY_DESKTOP_AUTO_LAUNCH_PRESENCE_UI` unset).  
Disable: `LAZY_DESKTOP_AUTO_LAUNCH_PRESENCE_UI=0`.

`desktop.runtime` exposes:

- `presence_state_path`
- `presence_events_path`
- `presence_stop_path`
- `presence_pause_path`

so clients can discover the files without hardcoding.

## Operator STOP / PAUSE (host enforced)

Same control-file contract as `computer-use-lab`:

| File | Host behavior |
|------|----------------|
| `STOP` | **Deny** gated actions (`session.open`, app/window/input). Closes live sessions. Read-only tools (`desktop.runtime`, lists, capture/OCR/vision) and `session.close` still work. |
| `PAUSE` | **Wait** (poll 100ms, max 300s) on gated actions until the file is removed (Resume) or `STOP` appears. |

Error codes:

- `SESSION_STOPPED` — clear `STOP` before continuing  
- `SESSION_PAUSED` — wait timed out (or message while waiting via presence snapshot)

`session.open` clears **PAUSE** only (fresh session); it does **not** clear **STOP** (operator must clear intentionally).

## Snapshot schema

```json
{
  "phase": "controlling",
  "updated_at": "2026-07-18T08:00:00Z",
  "source": "lazy-desktop-host",
  "capability": "input.click",
  "detail": "Clicked at (840, 315).",
  "session_id": "…",
  "decision": "allowed",
  "dry_run": false,
  "target_app": "Google Chrome"
}
```

### Phases

| phase | meaning | menu bar color |
|-------|---------|----------------|
| `idle` | no active automation | gray |
| `arming` | session opening / countdown | yellow |
| `controlling` | host executing actions | orange |
| `paused` | denied / waiting on human | blue |
| `stopped` | operator halt | red |

## Menu bar indicator (product)

Minimal macOS menu bar extra:

- Title: `● CU` or SF Symbol `laptopcomputer`
- Color by phase
- Menu items:
  - Phase + capability + detail
  - Open presence folder
  - **Stop session** (writes a STOP flag or calls host cancel — product choice)
  - Dry-run / live badge

Implementation options:

1. **Runnable lab app:** `computer-use-lab/macos/PresenceMenuBarApp`  
   (`./Scripts/run.sh` — MenuBarExtra + floating HUD + crosshair + PAUSE/STOP)
2. Python lab: `python -m computer_use presence-watch` (terminal stand-in)
3. Future: host embeds a tiny status item process; honor `PAUSE` in host session loop

## Overlay HUD

See the full SwiftUI contract in the lab:

`computer-use-lab/macos/PresenceOverlay-SPEC.md`

## Safety rules

- Presence UI process should run as a **separate binary** from the action injector when possible
- Stop control must not be reachable via `input.click` coordinates on the same synthetic path without elevation
- Do not put secrets in `detail` (no typed passwords); prefer redacted previews (audit already hashes sensitive payloads)
- `dry_run: true` must be visually distinct from live control

## Local lab parity

The Python lab and PresenceMenuBarApp **default to the same host directory**:

```text
~/Library/Application Support/dev.lazy.desktop-mcp/artifacts/presence/
```

(`ProjectDirs::from("dev", "lazy", "desktop-mcp")` + `artifacts/presence`)

```bash
python -m computer_use demo --hud
python -m computer_use presence-watch
# Menu bar app reads the same path by default
```

## Rollout

1. **Done in host**: publish `current.json` / `events.jsonl` on every handled request  
2. **Done in host**: honor `STOP` / `PAUSE` control files on gated actions  
3. **Client**: show path from `desktop.runtime`  
4. **Menu bar / HUD**: `computer-use-lab` PresenceMenuBarApp  
5. **Human priority**: presence UI writes `PAUSE` on HID; host waits
