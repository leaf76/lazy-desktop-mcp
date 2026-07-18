#!/usr/bin/env bash
# Build ComputerUsePresence.app and install next to lazy-desktop-host data dir
# so the MCP host can auto-launch it on startup.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${LAZY_DESKTOP_DATA_DIR:-$HOME/Library/Application Support/dev.lazy.desktop-mcp}"
INSTALL_DIR="$DATA_DIR/PresenceUI"
APP_NAME="ComputerUsePresence.app"

# Source tree for the Swift UI (override if needed)
LAB_APP="${LAZY_DESKTOP_PRESENCE_UI_SOURCE:-$HOME/WorkSpace/sideProject/others_projects/computer-use-lab/macos/PresenceMenuBarApp}"
if [[ ! -d "$LAB_APP" ]]; then
  LAB_APP="/Users/cy76/WorkSpace/sideProject/others_projects/computer-use-lab/macos/PresenceMenuBarApp"
fi

if [[ ! -f "$LAB_APP/Package.swift" ]]; then
  echo "error: PresenceMenuBarApp source not found at: $LAB_APP" >&2
  echo "Set LAZY_DESKTOP_PRESENCE_UI_SOURCE to the PresenceMenuBarApp directory." >&2
  exit 1
fi

echo "==> building Presence UI from $LAB_APP"
(
  cd "$LAB_APP"
  chmod +x Scripts/build-app.sh 2>/dev/null || true
  ./Scripts/build-app.sh release
)

SRC_APP="$LAB_APP/.build/App/$APP_NAME"
if [[ ! -d "$SRC_APP" ]]; then
  echo "error: build did not produce $SRC_APP" >&2
  exit 1
fi

echo "==> installing to $INSTALL_DIR/$APP_NAME"
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/$APP_NAME"
cp -R "$SRC_APP" "$INSTALL_DIR/$APP_NAME"

# Write a small pointer file for debugging
cat > "$INSTALL_DIR/README.txt" <<EOF
Computer Use Presence UI for lazy-desktop-mcp
Installed: $(date)
Source: $LAB_APP
Presence dir: $DATA_DIR/artifacts/presence

Host auto-launches this app on startup unless:
  LAZY_DESKTOP_AUTO_LAUNCH_PRESENCE_UI=0

Override app path:
  LAZY_DESKTOP_PRESENCE_UI_PATH=$INSTALL_DIR/$APP_NAME
EOF

echo "OK: $INSTALL_DIR/$APP_NAME"
echo "Try: open -g \"$INSTALL_DIR/$APP_NAME\""
