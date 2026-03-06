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

## Codex Setup

Register the published package with Codex:

```bash
codex mcp add lazy-desktop -- npx -y lazy-desktop-mcp
```

If you need to override the host binary path:

```toml
[mcp_servers.lazy-desktop]
command = "npx"
args = ["-y", "lazy-desktop-mcp"]

[mcp_servers.lazy-desktop.env]
DESKTOP_HOST_BIN = "/absolute/path/to/desktop-host"
LAZY_DESKTOP_POLICY_PATH = "/absolute/path/to/policy.json"
```

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
