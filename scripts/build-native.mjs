import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const cargo = process.env.CARGO_BIN ?? "cargo";
const targetDir = path.join(packageRoot, "target");

const result = spawnSync(
  cargo,
  ["build", "--release", "--bins", "--target-dir", targetDir],
  {
    cwd: packageRoot,
    stdio: "inherit",
    env: process.env,
  },
);

if (result.error) {
  if (result.error.code === "ENOENT") {
    console.error(
      "Cargo is required to build lazy-desktop-mcp. Install Rust from https://rustup.rs first.",
    );
  } else {
    console.error(`Failed to execute cargo: ${result.error.message}`);
  }
  process.exit(1);
}

process.exit(result.status ?? 1);
