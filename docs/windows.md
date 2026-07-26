# Windows Support

`lazy-desktop-mcp` runs on Windows 10/11 (x64) with a Win32 + `enigo` backend. This page is the platform matrix and setup guide for Windows operators.

## Build requirements

Native binaries are built at `postinstall` / `npm run build:native`:

| Dependency | Notes |
|------------|--------|
| Node.js 20+ | Launcher + packaging |
| Rust + Cargo | MSVC host (`x86_64-pc-windows-msvc`) |
| Visual Studio Build Tools | Workload **Desktop development with C++** / `VCTools` |

```powershell
# From a Developer PowerShell or after VsDevCmd.bat
npm install
# or, in a checkout:
npm run build:native
```

Skip the install-time build:

```powershell
$env:LAZY_DESKTOP_SKIP_POSTINSTALL = "1"
npm install
npm run build:native
```

## Capability matrix (Windows)

| Capability | Supported | Backend |
|------------|-----------|---------|
| `app_list` | Yes | `sysinfo` process enumeration |
| `app_launch` | Yes | `cmd /C start` |
| `app_quit` | Yes | `WM_CLOSE` to matching process windows |
| `window_list` | Yes | Win32 `EnumWindows` |
| `window_focus` | Yes | `SetForegroundWindow` + thread attach |
| `window_move` / `window_resize` | Yes | `SetWindowPos` |
| `observe_capture` | Yes | PowerShell `CopyFromScreen` → PNG |
| `ocr_read` | Optional | Requires `tesseract` on `PATH` |
| `vision_*` | Optional | `LAZY_DESKTOP_VISION_COMMAND` |
| `input_click` / `input_type` / `input_hotkey` | Yes | `enigo` |
| Presence UI | No | macOS-only (`.app` HUD) |
| Runtime approval dialog | Yes | WinForms MessageBox via PowerShell STA |

Always trust `desktop.capabilities` / `desktop.permissions` / `desktop.runtime` on the live machine.

## Permissions and elevation

Windows does not use macOS-style Accessibility / Screen Recording prompts for this backend.

- `desktop.permissions` reports a single `ui_automation` probe (can we enumerate windows?).
- **Elevated (admin) target windows** may refuse focus or input from a non-elevated host. Run the MCP host elevated only if you intentionally need that scope.
- Screenshot capture uses the interactive desktop session; headless/service sessions may fail.

## Policy notes for Windows

1. Point `LAZY_DESKTOP_POLICY_PATH` at a JSON policy (see `config/policy.example.json`).
2. An **empty** host `allowed_apps` / `allowed_windows` list means unrestricted for that target kind (matches the session policy engine). Non-empty lists are strict allowlists.
3. When a non-empty allowlist is set and a request goes outside it, the Windows approval MessageBox can widen the overlay. **Allow** persists into `%LOCALAPPDATA%\lazy\desktop-mcp\data\policy-overlay.json`.
4. Prefer process names as returned by `app.list` (often `Notepad.exe`). Launch aliases like `notepad` also work with `app.launch`.

Example minimal Windows policy:

```json
{
  "allowed_standalone_capabilities": [
    "app_list",
    "window_list",
    "observe_capture",
    "ocr_read"
  ],
  "allowed_session_capabilities": [
    "app_launch",
    "app_quit",
    "window_focus",
    "window_move",
    "window_resize",
    "input_click",
    "input_type",
    "input_hotkey"
  ],
  "allowed_apps": ["notepad", "Notepad.exe"],
  "allowed_windows": [],
  "allowed_screens": ["primary"],
  "allow_raw_input": true,
  "max_actions_per_minute": 60
}
```

## Data directories

| Path | Purpose |
|------|---------|
| `%LOCALAPPDATA%\lazy\desktop-mcp\data\` | Host data root |
| `...\audit.db` | Local audit SQLite |
| `...\artifacts\` | Screenshots / presence files |
| `...\policy-overlay.json` | Runtime-approved targets |

## Client wiring

After a local build:

```powershell
npm run sync:clients
```

Or register manually (Codex):

```toml
[mcp_servers.lazy-desktop]
command = "npx"
args = ["-y", "lazy-desktop-mcp"]

[mcp_servers.lazy-desktop.env]
LAZY_DESKTOP_POLICY_PATH = "C:\\path\\to\\policy.json"
```

## Known limitations

- Presence UI (menu bar glow / AI cursor) is macOS-only; presence JSON files still work for STOP/PAUSE.
- Writing the presence `STOP` file **force-closes all live automation sessions** (same as macOS). Clear STOP before opening a new session.
- Foreground focus is best-effort under Windows focus-stealing mitigation.
- `app.quit` posts `WM_CLOSE` to matching windows, then stops remaining processes by name (needed for UWP apps whose HWND is owned by `ApplicationFrameHost.exe`, e.g. Calculator).
- OCR / vision remain optional external tooling.

## Verification

```powershell
npm run test:js
cargo test --all --all-features
npm run build:native
# Multi-layer computer-use smoke (requires an interactive desktop session):
npm run test:windows-e2e
```

Smoke-check tools via any MCP client: `desktop.capabilities`, `app.list`, `window.list`, `observe.capture`, then a scoped `session.open` + `app.launch`.
