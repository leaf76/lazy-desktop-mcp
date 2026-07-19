# Desktop control for users

## What you get

When an AI agent controls your Mac through **lazy-desktop-mcp**:

1. **MCP host** performs clicks, typing, and screenshots (with your permissions).
2. **Computer Use Presence** (small menu-bar app) shows that AI is active:
   - A calm floating indicator: “AI is using your computer”
   - Pause / Resume / Stop
   - Soft screen-edge glow
   - AI cursor on actions (not a second mouse always following you)

You do **not** need to know about multiple source repos. One install path is enough.

The first time Presence opens, a short welcome explains what can happen and how to stop.

## First-time setup (once)

```bash
cd lazy-desktop-mcp
npm install
npm run build:native
npm run install:presence-ui   # installs ComputerUsePresence.app
```

Grant macOS **Screen Recording** and **Accessibility** when prompted (for control and/or the Presence UI).

## Everyday use

| When | What happens |
|------|----------------|
| MCP / host starts | Presence stays **closed** (no idle “AI controlling” signal) |
| Agent opens a session or controls the desktop | Host launches Presence UI (if installed + auto-launch on) |
| Agent closes the last session (`session.close`) | Host **quits** Presence UI (default) so HUD/glow go away |
| Host / MCP process exits | Host also quits Presence UI (default) |
| Next agent session | Host opens Presence UI again |

**Closing Presence UI by itself does not stop the agent** (default). Use **Stop** on the HUD (or the STOP file) to halt control.

Optional: Settings → enable **Write STOP when HUD is closed** if you want closing the panel to stop the agent.

Agents can also call the MCP tool `presence.ui.quit` to force-close Presence anytime.

To keep Presence open after sessions (not recommended for daily use):

```bash
export LAZY_DESKTOP_AUTO_QUIT_PRESENCE_UI=0
```

## Turn auto-open off

```bash
export LAZY_DESKTOP_AUTO_LAUNCH_PRESENCE_UI=0
```

Then open Presence manually when you want visuals:

```bash
open -g "$HOME/Library/Application Support/dev.lazy.desktop-mcp/PresenceUI/ComputerUsePresence.app"
```

## Where state lives

```text
~/Library/Application Support/dev.lazy.desktop-mcp/artifacts/presence/
  current.json   # live status
  STOP           # halt control
  PAUSE          # pause until removed
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| No HUD / no glow | `npm run install:presence-ui`, restart MCP |
| Host log: app not found | Same install; or set `LAZY_DESKTOP_PRESENCE_UI_PATH` |
| Agent still running after closing UI | Expected unless STOP-on-close is enabled; press **Stop** |
| Want UI always on | Set idle auto-quit to `0` in Presence Settings |

More detail: [presence-ui.md](./presence-ui.md).
