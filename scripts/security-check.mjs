import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const allowedExtensions = new Set([
  ".json",
  ".js",
  ".md",
  ".mjs",
  ".rs",
  ".toml",
  ".txt",
]);

const hardcodedSecretPattern =
  /\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*["'][^"'\n]+["']/i;
const unsafeRustPattern = /\bunsafe\s+/;
const ignoredDirectories = new Set([".git", "target", "node_modules"]);

const failures = [];

walk(packageRoot);

const audit = spawnSync("cargo", ["audit"], {
  cwd: packageRoot,
  stdio: "inherit",
  env: process.env,
});

if (audit.error) {
  console.error(
    "cargo-audit is required for `npm run security`. Install it with `cargo install cargo-audit`.",
  );
  process.exit(1);
}

if (audit.status !== 0) {
  process.exit(audit.status ?? 1);
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(failure);
  }
  process.exit(1);
}

console.log("Security checks passed.");

function walk(currentPath) {
  for (const entry of readdirSync(currentPath)) {
    const fullPath = path.join(currentPath, entry);
    const relativePath = path.relative(packageRoot, fullPath);
    const stats = statSync(fullPath);

    if (stats.isDirectory()) {
      if (!ignoredDirectories.has(entry)) {
        walk(fullPath);
      }
      continue;
    }

    if (!allowedExtensions.has(path.extname(entry))) {
      continue;
    }

    const content = readFileSync(fullPath, "utf8");
    if (
      hardcodedSecretPattern.test(content) &&
      !relativePath.startsWith("docs/") &&
      relativePath !== "SECURITY.md"
    ) {
      failures.push(`Hardcoded secret-like pattern found in ${relativePath}`);
    }

    if (relativePath.endsWith(".rs") && unsafeRustPattern.test(content)) {
      failures.push(`Unsafe Rust is not allowed in ${relativePath}`);
    }
  }
}
