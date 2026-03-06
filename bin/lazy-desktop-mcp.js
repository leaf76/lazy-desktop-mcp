#!/usr/bin/env node

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import process from "node:process";
import { resolveNativePaths } from "../lib/runtime.mjs";

const paths = resolveNativePaths();
const hostBinary = process.env.DESKTOP_HOST_BIN ?? paths.hostBinary;
const mcpBinary = paths.mcpBinary;

if (!existsSync(mcpBinary)) {
  console.error(
    [
      "lazy-desktop-mcp could not find the native desktop-mcp binary.",
      `Expected: ${mcpBinary}`,
      "Run `npm run build:native` in the package root or reinstall with scripts enabled.",
    ].join("\n"),
  );
  process.exit(1);
}

if (!existsSync(hostBinary)) {
  console.error(
    [
      "lazy-desktop-mcp could not find the native desktop-host binary.",
      `Expected: ${hostBinary}`,
      "Set DESKTOP_HOST_BIN to the absolute host binary path, or run `npm run build:native`.",
    ].join("\n"),
  );
  process.exit(1);
}

const child = spawn(mcpBinary, process.argv.slice(2), {
  stdio: "inherit",
  env: {
    ...process.env,
    DESKTOP_HOST_BIN: hostBinary,
  },
});

child.on("error", (error) => {
  console.error(`lazy-desktop-mcp failed to start: ${error.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 1);
});
