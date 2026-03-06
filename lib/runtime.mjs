import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

export function nativeExecutableName(baseName, platform = process.platform) {
  return platform === "win32" ? `${baseName}.exe` : baseName;
}

export function resolveNativePaths({
  packageRoot = PACKAGE_ROOT,
  platform = process.platform,
} = {}) {
  const releaseDir = path.join(packageRoot, "target", "release");

  return {
    packageRoot,
    releaseDir,
    mcpBinary: path.join(releaseDir, nativeExecutableName("desktop-mcp", platform)),
    hostBinary: path.join(releaseDir, nativeExecutableName("desktop-host", platform)),
  };
}

export function hasNativeBinaries(options) {
  const paths = resolveNativePaths(options);
  return existsSync(paths.mcpBinary) && existsSync(paths.hostBinary);
}
