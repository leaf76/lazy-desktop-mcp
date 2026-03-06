import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

if (process.env.LAZY_DESKTOP_SKIP_POSTINSTALL === "1") {
  console.log("Skipping native build because LAZY_DESKTOP_SKIP_POSTINSTALL=1.");
  process.exit(0);
}

const packageRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const result = spawnSync(process.execPath, ["./scripts/build-native.mjs"], {
  cwd: packageRoot,
  stdio: "inherit",
  env: process.env,
});

process.exit(result.status ?? 1);
