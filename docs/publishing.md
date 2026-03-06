# Publishing Guide

## Package Shape

The npm package is a Node launcher plus the Rust workspace source.

- `postinstall` builds `desktop-mcp` and `desktop-host` into `target/release`.
- `lazy-desktop-mcp` is the executable that Codex or `npx` should launch.
- The launcher injects `DESKTOP_HOST_BIN` so the Rust MCP process does not fall back to `PATH`.

## Pre-Publish Checks

Run these commands from the repository root:

```bash
npm run release:prep
npm run release:notes
npm run release:check
```

What each command does:

- `npm run release:prep`: checks version alignment, latest tag, dirty worktree state, and prints draft release notes plus next steps
- `npm run release:notes`: prints the release note draft only
- `npm run release:check`: runs the full publish gate (`security`, `verify`, `pack:dry`) after `release:prep` passes

Before tagging a release, also confirm:

- `package.json` and the Rust workspace use the same version
- `config/client-config.json` still describes the intended local development wiring
- `config/policy.dev.json` matches the policy template rendered from `config/client-config.json`
- README and security docs describe the current runtime approval behavior
- the shipped policy example still reflects the minimum secure default

`release:prep` intentionally fails when:

- `package.json` and the Rust workspace version do not match
- the current version already matches the latest git tag
- the git working tree is dirty

That failure is the expected guard before publishing. Bump the version, commit the release changes, and rerun the command.

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
- The repo-managed sync flow is `npm run sync:clients`; use `npm run sync:clients:dry` to preview the generated policy and client config before writing.
- Public release notes should call out the secure default policy posture and the requirement to configure `policy.json`.
- If the release changes approval or allowlist behavior, note how the local `policy-overlay.json` state is created, persisted, and cleared.
