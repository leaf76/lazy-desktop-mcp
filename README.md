# lazy-desktop-mcp

[![npm version](https://img.shields.io/npm/v/lazy-desktop-mcp)](https://www.npmjs.com/package/lazy-desktop-mcp)
[![npm downloads](https://img.shields.io/npm/dm/lazy-desktop-mcp)](https://www.npmjs.com/package/lazy-desktop-mcp)
[![license](https://img.shields.io/github/license/leaf76/lazy-desktop-mcp)](https://github.com/leaf76/lazy-desktop-mcp/blob/main/LICENSE)

`lazy-desktop-mcp` is a local-first desktop automation MCP stack with a Rust host process and an npm-distributed launcher.

## What Ships

- `desktop-core`: shared types, policy evaluation, audit payload handling, and host wire protocol
- `desktop-host`: local privileged host with audit storage, session handling, screenshot capture, and platform adapters
- `desktop-mcp`: MCP stdio server that proxies tool calls to `desktop-host`
- `lazy-desktop-mcp`: Node launcher published to npm so Codex can start the MCP server with `npx` or a global install

## Security Defaults

The public package is intentionally locked down until the operator configures a host policy file.

- `desktop.capabilities`, `desktop.permissions`, `session.open`, and `session.close` are always available
- standalone capabilities such as `app.list` and `observe.capture` are disabled until allowed by host policy
- session capabilities such as `app.launch` are disabled until allowed by host policy
- raw coordinate input is disabled unless explicitly enabled by host policy
- on macOS, out-of-policy app, window, and session-scope requests can trigger a local user approval dialog that persists a target-only allowlist overlay
- `desktop-mcp` refuses to start if it cannot find the expected `desktop-host` binary

See [SECURITY.md](./SECURITY.md) and [docs/security-model.md](./docs/security-model.md) before enabling desktop control features.

## Installation

The npm package builds native binaries during `postinstall`, so the target machine needs:

- Node.js 20+
- Rust and Cargo

Install globally:

```bash
npm install -g lazy-desktop-mcp
```

Or run without a global install:

```bash
npx -y lazy-desktop-mcp
```

The published package was smoke-tested from the npm registry with `npx -y lazy-desktop-mcp` on macOS, including a real MCP `initialize` handshake.

If you want to skip the install-time build for CI or packaging experiments:

```bash
LAZY_DESKTOP_SKIP_POSTINSTALL=1 npm install
npm run build:native
```

## Host Policy

The host reads a JSON policy file from `LAZY_DESKTOP_POLICY_PATH` or its local application data directory. Start from the shipped example:

```bash
cp config/policy.example.json /path/to/policy.json
export LAZY_DESKTOP_POLICY_PATH=/path/to/policy.json
```

Example policy:

```json
{
  "allowed_standalone_capabilities": ["app_list", "observe_capture", "ocr_read"],
  "allowed_session_capabilities": ["app_launch"],
  "allowed_apps": ["TextEdit"],
  "allowed_windows": [],
  "allowed_screens": ["primary"],
  "allow_raw_input": false,
  "max_actions_per_minute": 30
}
```

## Runtime Approval Overlay

When the host policy enables a capability class but the requested app, window, or screen target is outside the configured allowlist, the macOS system backend can ask the logged-in user for approval.

- the dialog is local to the target machine and uses the native macOS dialog UI
- `Allow` persists only the requested target into a local `policy-overlay.json`
- `Deny`, closing the dialog, or timeout keeps the request blocked
- runtime approval never enables a new capability class and never enables raw coordinate input

The overlay file is stored under the host application data directory and merged with the base policy at startup. Delete that overlay file if you need to clear previously approved targets.

## Codex Setup

Register the published package with Codex:

```bash
codex mcp add lazy-desktop \
  -- npx --prefix ~/.codex/mcp-cache/lazy-desktop-mcp -y lazy-desktop-mcp
```

The isolated `--prefix` keeps npm's execution context stable even when Codex is launched from a repository that has the same package name as the published MCP package.

If you need an explicit config entry:

```toml
[mcp_servers.lazy-desktop]
command = "npx"
args = ["--prefix", "/absolute/path/to/.codex/mcp-cache/lazy-desktop-mcp", "-y", "lazy-desktop-mcp"]

[mcp_servers.lazy-desktop.env]
LAZY_DESKTOP_POLICY_PATH = "/absolute/path/to/policy.json"
```

If you prefer a fully deterministic local install, `npm install -g lazy-desktop-mcp` and pointing Codex at the global `lazy-desktop-mcp` binary also works.

## Current System Backend Scope

Implemented:

- `desktop.capabilities`
- `desktop.permissions`
- `session.open`
- `session.close`
- `app.list`
- `app.launch`
- primary-display `observe.capture`
- `ocr.read` when `tesseract` is installed

Present but still `ERR_UNSUPPORTED` on the default system backend:

- `app.quit`
- `window.*`
- `vision.*`
- `input.*`

## Local Development

Build native binaries:

```bash
npm run build:native
```

Run the full verification stack:

```bash
npm run security
npm run verify
npm run pack:dry
```

The verification flow runs:

- JavaScript wrapper tests
- `cargo fmt --check`
- `cargo clippy -D warnings`
- `cargo test`
- `cargo audit`
- `npm pack --dry-run`

## Publishing

Before `npm publish`, make sure:

- the version in [package.json](./package.json) matches the Rust workspace version in [Cargo.toml](./Cargo.toml)
- the policy example still matches the shipped host behavior
- the README and security docs reflect the actual supported capabilities

See [docs/publishing.md](./docs/publishing.md) for the release checklist.
