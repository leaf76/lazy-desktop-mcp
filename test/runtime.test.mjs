import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { hasNativeBinaries, nativeExecutableName, resolveNativePaths } from "../lib/runtime.mjs";

test("resolveNativePaths returns release binary paths", () => {
  const packageRoot = mkdtempSync(path.join(os.tmpdir(), "lazy-desktop-mcp-"));
  const paths = resolveNativePaths({ packageRoot, platform: "linux" });

  assert.equal(paths.releaseDir, path.join(packageRoot, "target", "release"));
  assert.equal(paths.mcpBinary, path.join(packageRoot, "target", "release", "desktop-mcp"));
  assert.equal(paths.hostBinary, path.join(packageRoot, "target", "release", "desktop-host"));
});

test("hasNativeBinaries detects both binaries", () => {
  const packageRoot = mkdtempSync(path.join(os.tmpdir(), "lazy-desktop-mcp-"));
  const paths = resolveNativePaths({ packageRoot, platform: process.platform });
  mkdirSync(paths.releaseDir, { recursive: true });

  writeFileSync(paths.mcpBinary, "");
  assert.equal(hasNativeBinaries({ packageRoot, platform: process.platform }), false);

  writeFileSync(paths.hostBinary, "");
  assert.equal(hasNativeBinaries({ packageRoot, platform: process.platform }), true);
});

test("nativeExecutableName adds exe suffix on windows", () => {
  assert.equal(nativeExecutableName("desktop-mcp", "win32"), "desktop-mcp.exe");
  assert.equal(nativeExecutableName("desktop-mcp", "linux"), "desktop-mcp");
});
