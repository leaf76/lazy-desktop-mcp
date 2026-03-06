# Security Policy

## Supported Versions

Only the latest published npm package and the matching Rust workspace revision are supported for security fixes.

## Reporting

Do not open public issues for a desktop-control vulnerability. Report security issues privately to the maintainers through your existing private channel, and include:

- affected version
- operating system
- reproduction steps
- observed impact

## Secure Defaults

The published package is locked down by default.

- `desktop.capabilities`, `desktop.permissions`, `session.open`, and `session.close` are always available.
- All other standalone capabilities are disabled until the host policy file enables them.
- All session capabilities are disabled until the host policy file enables them.
- Raw coordinate input is disabled unless the host policy file opts in.

## Host Policy

The host reads a JSON policy file from `LAZY_DESKTOP_POLICY_PATH` or its local application data directory.

- Start from [`config/policy.example.json`](/Users/cy76/WorkSpace/sideProject/lazy_desktop_mcp/config/policy.example.json).
- Restrict `allowed_apps`, `allowed_windows`, and `allowed_screens` to the minimum set you need.
- Keep `allow_raw_input` as `false` unless you have a controlled environment.

## Audit and Privacy

- Audit events are stored in a local SQLite database.
- Typed text, hotkeys, app names, window titles, and raw click coordinates are hashed in audit payloads instead of stored in plaintext.
- Screenshot artifacts stay local to the machine running `desktop-host`.

## Release Checklist

- Run `npm run security`.
- Run `npm run verify`.
- Run `npm run pack:dry`.
- Confirm the packaged README and policy example still match the shipped behavior.
