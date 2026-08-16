# Client / Provider Compatibility

`lazy-desktop-mcp` is an MCP **stdio** server. It is meant to work with any client that speaks the Model Context Protocol (Grok, Codex, Claude Code, OpenCode, Cursor, custom hosts, etc.).

## Tool naming (important)

As of **v0.1.9**, all tools are advertised with **underscore names** only:

| Tool (canonical) | Purpose |
|------------------|---------|
| `desktop_capabilities` | Platform capability matrix |
| `desktop_permissions` | OS permission probes |
| `desktop_runtime` | Policy / data paths |
| `presence_ui_quit` | Quit Presence UI (macOS) |
| `session_open` / `session_close` | Automation session |
| `app_list` / `app_launch` / `app_activate` / `app_quit` | Apps |
| `window_list` / `window_focus` / `window_move` / `window_resize` | Windows |
| `observe_capture` | Screenshot |
| `ocr_read` | OCR |
| `vision_describe` / `vision_locate` | Vision (optional) |
| `input_click` / `input_click_target` / `input_type` / `input_hotkey` | Input |

### Why not dots?

MCP allows `.` in tool names, but several **host / model providers** validate tools with a stricter pattern closer to:

```text
^[A-Za-z0-9_-]+$
```

(for example OpenAI-compatible tool schemas, and Grok session registration).  
With dotted names (`app.list`), some clients still complete the MCP handshake but register **zero tools** (`tool_count: 0`), which looks like “connection failed”.

Underscore names work across:

- Grok Build / Grok CLI  
- Codex  
- Claude Code  
- OpenCode  
- Other stdio MCP clients that mirror OpenAI tool-name rules  

### Backward compatibility

`tools/call` still accepts **legacy dotted names** (`app.list`, `desktop.capabilities`, …) by normalizing `.` → `_` before dispatch.  
`tools/list` only returns the underscore names so strict clients never see invalid characters.

## Setup snippets

### Grok (`~/.grok/config.toml`)

```toml
[mcp_servers.lazy-desktop]
command = "npx"
args = ["-y", "lazy-desktop-mcp@0.1.9"]
enabled = true
startup_timeout_sec = 120

[mcp_servers.lazy-desktop.env]
LAZY_DESKTOP_POLICY_PATH = "C:\\path\\to\\policy.json"
```

On Windows, prefer absolute paths after a global install (avoids cold `npx` rebuild delays):

```toml
[mcp_servers.lazy-desktop]
command = 'C:\Program Files\nodejs\node.exe'
args = ['C:\Users\YOU\AppData\Roaming\npm\node_modules\lazy-desktop-mcp\bin\lazy-desktop-mcp.js']
enabled = true
startup_timeout_sec = 120

[mcp_servers.lazy-desktop.env]
DESKTOP_HOST_BIN = 'C:\Users\YOU\AppData\Roaming\npm\node_modules\lazy-desktop-mcp\target\release\desktop-host.exe'
LAZY_DESKTOP_POLICY_PATH = 'C:\Users\YOU\AppData\Local\lazy\desktop-mcp\policy.json'
```

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.lazy-desktop]
command = "npx"
args = ["-y", "lazy-desktop-mcp@0.1.9"]
startup_timeout_sec = 120

[mcp_servers.lazy-desktop.env]
LAZY_DESKTOP_POLICY_PATH = "/absolute/path/to/policy.json"
```

### Claude Code / generic MCP

Register a stdio server with the same `command` + `args` + policy env as above.  
After connect, list tools and confirm names use underscores (e.g. `window_list`, not `window.list`).

## Platform notes

| Platform | Status |
|----------|--------|
| macOS | Full backend + Presence UI |
| Windows | Win32 window/input/screenshot; see [windows.md](./windows.md) |
| Linux | Partial (observation-oriented) |

## Verify

```bash
# Any machine with the package built/installed:
npx -y lazy-desktop-mcp@0.1.9
# Then MCP initialize + tools/list should show 22 underscore tool names.
```

```powershell
# Grok
grok mcp doctor lazy-desktop
```

Expect: handshake OK and **non-zero** tools discovered (22 when all features are listed).

## Policy vs tool names

Host **policy JSON** still uses capability enums like `app_list` / `window_focus` (serde `snake_case`).  
That is separate from MCP tool names; both now use underscores for consistency.
