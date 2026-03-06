import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseCargoWorkspaceVersion,
  parseGitCommitLog,
  renderReleaseNotes,
} from "../lib/release-flow.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cargoToml = readFileSync(path.join(packageRoot, "Cargo.toml"), "utf8");
const latestTag = execFileSync("git", ["tag", "--sort=-creatordate"], {
  cwd: packageRoot,
  encoding: "utf8",
})
  .trim()
  .split(/\r?\n/)
  .filter(Boolean)[0];
const logRange = latestTag ? `${latestTag}..HEAD` : "HEAD";
const commits = parseGitCommitLog(
  execFileSync("git", ["log", "--oneline", logRange], {
    cwd: packageRoot,
    encoding: "utf8",
  }).trim(),
);

console.log(
  renderReleaseNotes({
    version: parseCargoWorkspaceVersion(cargoToml),
    previousTag: latestTag,
    commits,
    releaseDate: today(),
  }),
);

function today() {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}
