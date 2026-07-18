# Desktop App Development

## Audience

This guide is for local development workflows that use `lazy-desktop-mcp` to drive desktop apps such as Tauri and PyQt from Codex or OpenCode.

## Canonical Development Config

The repository keeps a single development wiring source in `config/client-config.json`.

It defines:

- the local `desktop-mcp` binary path
- the local `desktop-host` binary path
- the repo-managed development policy path
- optional vision command wiring
- feature intent for OCR, vision, window control, and input control

`npm run sync:clients` materializes `config/policy.dev.json` from that canonical file and upserts client config entries for:

- Codex: `~/.codex/config.toml`
- OpenCode: `~/.config/opencode/opencode.json`

Useful variants:

```bash
npm run sync:clients
npm run sync:clients:dry
LAZY_DESKTOP_CLIENTS=codex npm run sync:clients
LAZY_DESKTOP_CLIENTS=opencode npm run sync:clients
CODEX_CONFIG_PATH=/tmp/codex.toml OPENCODE_CONFIG_PATH=/tmp/opencode.json npm run sync:clients
```

## Standard Workflow

1. Build native binaries:

   ```bash
   npm run build:native
   ```

2. Sync the development config:

   ```bash
   npm run sync:clients
   ```

3. Grant desktop permissions when the platform backend requires them.
4. Start the target application.
5. Check `desktop.capabilities`, `desktop.permissions`, and `desktop.runtime`.
6. Open a scoped session with the smallest app/window/screen allowlists that fit the scenario.
7. Run the verification flow:
   - activate the target app with `app.activate` when you do not want to depend on an exact window title
   - focus the target window with `window.focus` using `window_id`, exact `title`, `title_contains`, or `app`
   - move to the relevant window
   - send text, hotkeys, or low-level clicks
   - prefer `input.click_target` for OCR text matching or window-relative clicks before falling back to raw coordinates
   - capture the screen
   - optionally run OCR or, when configured, vision

## Tauri Guidance

Use the MCP when you need to validate the real desktop shell or a workflow that crosses the WebView boundary.

Good fits:

- first-run onboarding
- update dialogs
- file picker flows
- tray or dock interactions
- desktop permission prompts

Keep framework-native tests for deterministic browser-side logic, routing, rendering, and component state.

## PyQt Guidance

Use the MCP when you need to validate the actual native window tree, keyboard shortcuts, or screenshot-based regressions.

Good fits:

- main-window launch smoke tests
- menu and dialog focus flows
- shortcut handling
- screenshot and OCR verification of rendered desktop state

Keep PyQt-native tests for widget logic, models, and isolated signal/slot behavior.

## Troubleshooting

- `desktop.capabilities` returns a capability as unsupported:
  check the current platform backend, required external dependencies, and the repo-managed development policy.
- `desktop.capabilities` says a capability is disabled by host policy:
  run `desktop.runtime` and confirm `security_policy_path` points at the intended file. For local repo development it should usually be `config/policy.dev.json`, not `config/policy.example.json`.
- `desktop.permissions` shows denied or not checked:
  grant the specific macOS permission before retrying. `window_*` flows depend on both Accessibility and Automation; screenshot-driven flows depend on Screen Recording.
- `window_list` or `window_focus` still fails with a macOS `-1743` / Apple Events authorization error:
  grant Automation permission so the host can control `System Events`, then restart the client and retry.
- a session opens but target actions are blocked:
  request only the app, window, or screen scope you need so approval and allowlist checks can succeed.
- a click target is not found:
  first confirm the window selector resolves cleanly, then verify OCR is available on the machine and the requested text is actually visible on screen.
- Codex or OpenCode is still pointing at an old binary:
  rerun `npm run sync:clients` after rebuilding.
