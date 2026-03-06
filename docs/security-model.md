# Security Model

## Trust Boundaries

- `desktop-mcp` is the MCP-facing process that speaks JSON-RPC over stdio.
- `desktop-host` is the local privileged process that touches OS APIs, audit storage, and screenshot artifacts.
- The host policy file is the server-owned security boundary. Session requests can only narrow the capabilities and targets allowed by that file.

## Default Release Posture

The npm package ships in a deny-by-default posture.

- No session capability is enabled until the operator adds it to the host policy file.
- No standalone observation capability is enabled until the operator adds it to the host policy file.
- Raw coordinate input is blocked unless explicitly enabled.
- `desktop-mcp` fails closed if it cannot find the colocated `desktop-host` binary.

## Data Handling

- Audit events are append-only SQLite records.
- Sensitive action metadata is hashed before persistence.
- Screenshot artifacts are written to the local application data directory and referenced by hash.
- OCR and vision are local-host operations; there is no remote transport in the current release.

## Current Limits

- The system backend currently supports `app.list`, `app.launch`, and primary-display screenshot capture.
- Window management, input synthesis, vision providers, and graceful app quit are still stubbed on the system backend.
- Screenshot capture currently supports the primary display only.

## Recommended Operator Setup

- Run the package only on a trusted local workstation.
- Keep the host policy file under source control if you need repeatable configuration.
- Enable only the apps and screens required for your automation.
- Review local OS permissions after installation: Accessibility and Screen Recording on macOS, equivalent desktop automation permissions on other platforms.
