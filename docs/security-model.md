# Security Model

## Trust Boundaries

- `desktop-mcp` is the MCP-facing process that speaks JSON-RPC over stdio.
- `desktop-host` is the local privileged process that touches OS APIs, audit storage, and screenshot artifacts.
- The host policy file is the server-owned security boundary. Session requests can only narrow the capabilities and targets allowed by that file.

## Default Release Posture

The npm package ships in a deny-by-default posture.

- `desktop.capabilities`, `desktop.permissions`, `desktop.runtime`, `session.open`, and `session.close` stay available so the operator can inspect the local runtime before granting control.
- No session capability is enabled until the operator adds it to the host policy file.
- No standalone observation capability is enabled until the operator adds it to the host policy file.
- Raw coordinate input is blocked unless explicitly enabled.
- Runtime approval can persist additional app, window, or screen targets into a local overlay policy, but only if the base host policy already enabled the underlying capability class.
- `desktop-mcp` fails closed if it cannot find the colocated `desktop-host` binary.

## Data Handling

- Audit events are append-only SQLite records.
- Sensitive action metadata is hashed before persistence.
- Runtime approval audit rows keep non-sensitive preview fields while hashing the approved target value.
- Screenshot artifacts are written to the local application data directory, mode `0600` when the OS allows it, and referenced by hash. They are not returned as MCP image bytes.
- Artifacts expire after `capture_retain_seconds` and are deleted when the last session closes or the host process exits.
- Duplicate captures with the same SHA-256 return `unchanged: true` without creating a new file.
- OCR and vision are local-host operations; there is no remote transport in the current release. Full OCR text requires `ocr_allow_full`.
- `desktop.runtime` default MCP output is compact (policy basename and capability counts). Pass `detail=full` for local diagnostics including paths and policy snapshots. Compact output does not include secrets, tokens, or captured payload contents.

## Observation ladder (token compression)

Prefer low-token steps; do not loop full-screen capture plus `vision.describe`.

1. Selectors: `app.activate`, `window.focus`, `input.click_target`
2. Compact lists: `window.list` / `app.list` with `query` (host caps `lists_max_items`)
3. Scoped capture: `observe.capture` (primary by default; `window_id` only if `capture_scope` is not `primary`); scaled/JPEG locally; MCP returns id/sha256/bytes only
4. Skip unchanged frames (`unchanged: true`)
5. `ocr.read` summary (truncated); `mode=full` only when policy allows
6. Vision last, and only if a local absolute-path adapter is configured

## Current Limits

- The macOS system backend currently supports `app.list`, `app.launch`, `window.list`, `window.focus`, `window.move`, `window.resize`, `observe.capture`, `input.click`, `input.type`, and `input.hotkey` when the required permissions are granted.
- OCR is available when `tesseract` is installed and screen capture permission is granted.
- Vision remains command-driven; without a configured local adapter, `vision.*` stays unavailable even if policy allows it.
- Graceful app quit is still stubbed on the system backend.
- Screenshot capture currently supports the primary display only.

## Recommended Operator Setup

- Run the package only on a trusted local workstation.
- Treat `config/client-config.json` as the canonical development wiring source and regenerate `config/policy.dev.json` via the sync script when local development defaults change.
- Keep the host policy file under source control if you need repeatable configuration.
- Treat the local overlay policy as machine-specific state; back it up or clear it intentionally.
- Enable only the apps and screens required for your automation.
- Review local OS permissions after installation: Accessibility, Automation, and Screen Recording on macOS, equivalent desktop automation permissions on other platforms.
- After rebuilding or changing client wiring, use `desktop.runtime` to confirm the active `security_policy_path` matches the policy you intended to load.
