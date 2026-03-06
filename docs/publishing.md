# Publishing Guide

## Package Shape

The npm package is a Node launcher plus the Rust workspace source.

- `postinstall` builds `desktop-mcp` and `desktop-host` into `target/release`.
- `lazy-desktop-mcp` is the executable that Codex or `npx` should launch.
- The launcher injects `DESKTOP_HOST_BIN` so the Rust MCP process does not fall back to `PATH`.

## Pre-Publish Checks

Run these commands from the repository root:

```bash
npm run security
npm run verify
npm run pack:dry
```

Before tagging a release, also confirm:

- `package.json` and the Rust workspace use the same version
- README and security docs describe the current runtime approval behavior
- the shipped policy example still reflects the minimum secure default

## Codex Registration

After publishing, users can wire the package into Codex with:

```bash
codex mcp add lazy-desktop \
  -- npx --prefix ~/.codex/mcp-cache/lazy-desktop-mcp -y lazy-desktop-mcp
```

Using an isolated `--prefix` avoids npm resolution conflicts when Codex is started from a repository whose package name matches the published MCP package.

## Operator Notes

- The installer requires Rust and Cargo because the native binaries are built during `postinstall`.
- Users can skip the install-time build with `LAZY_DESKTOP_SKIP_POSTINSTALL=1`, but the package will not work until `npm run build:native` succeeds.
- Public release notes should call out the secure default policy posture and the requirement to configure `policy.json`.
- If the release changes approval or allowlist behavior, note how the local `policy-overlay.json` state is created, persisted, and cleared.
