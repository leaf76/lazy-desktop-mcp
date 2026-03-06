import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  assessRelease,
  nextReleaseSteps,
  parseCargoWorkspaceVersion,
  parseGitCommitLog,
  renderReleaseNotes,
} from "../lib/release-flow.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const options = parseArgs(process.argv.slice(2));

const packageJson = JSON.parse(
  readFileSync(path.join(packageRoot, "package.json"), "utf8"),
);
const cargoToml = readFileSync(path.join(packageRoot, "Cargo.toml"), "utf8");
const latestTag = firstLine(runGit(["tag", "--sort=-creatordate"]));
const gitStatusLines = lines(runGit(["status", "--short"]));
const logRange = latestTag ? `${latestTag}..HEAD` : "HEAD";
const commits = parseGitCommitLog(runGit(["log", "--oneline", logRange]));

const assessment = assessRelease({
  packageVersion: packageJson.version,
  cargoVersion: parseCargoWorkspaceVersion(cargoToml),
  latestTag,
  gitStatusLines,
  commits,
  allowDirty: options.allowDirty,
});

const releaseNotes = renderReleaseNotes({
  version: assessment.packageVersion,
  previousTag: assessment.latestTag,
  commits: assessment.commits,
  releaseDate: today(),
});

if (options.notesPath) {
  mkdirSync(path.dirname(options.notesPath), { recursive: true });
  writeFileSync(options.notesPath, releaseNotes);
}

printSummary(assessment);

if (!options.summaryOnly) {
  console.log("\n## Release Notes\n");
  console.log(releaseNotes.trimEnd());
}

if (assessment.warnings.length > 0) {
  console.log("\n## Warnings");
  for (const warning of assessment.warnings) {
    console.log(`- ${warning}`);
  }
}

if (assessment.errors.length > 0) {
  console.error("\n## Blocking Issues");
  for (const error of assessment.errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

if (options.runChecks) {
  runPackageScript("security");
  runPackageScript("verify");
  runPackageScript("pack:dry");
}

console.log("\n## Next Steps");
for (const step of nextReleaseSteps({
  version: assessment.packageVersion,
  latestTag: assessment.latestTag,
  runChecks: options.runChecks,
})) {
  console.log(step);
}

function parseArgs(args) {
  const options = {
    allowDirty: false,
    runChecks: false,
    summaryOnly: false,
    notesPath: "",
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--allow-dirty":
        options.allowDirty = true;
        break;
      case "--run-checks":
        options.runChecks = true;
        break;
      case "--summary-only":
        options.summaryOnly = true;
        break;
      case "--notes-path":
        options.notesPath = path.resolve(packageRoot, readValue(args, index, arg));
        index += 1;
        break;
      default:
        throw new Error(`Unsupported argument: ${arg}`);
    }
  }

  return options;
}

function readValue(args, index, flagName) {
  const value = args[index + 1];
  if (!value) {
    throw new Error(`Missing value for ${flagName}.`);
  }
  return value;
}

function runGit(args) {
  return execFileSync("git", args, {
    cwd: packageRoot,
    encoding: "utf8",
  }).trim();
}

function runPackageScript(name) {
  const result = spawnSync("npm", ["run", name], {
    cwd: packageRoot,
    stdio: "inherit",
    env: process.env,
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function printSummary(assessment) {
  console.log("## Release Summary");
  console.log(`- package.json version: ${assessment.packageVersion}`);
  console.log(`- Cargo workspace version: ${assessment.cargoVersion}`);
  console.log(`- latest tag: ${assessment.latestTag ?? "_none_"}`);
  console.log(`- commits since tag: ${assessment.commits.length}`);
  console.log(`- working tree dirty: ${assessment.dirty ? "yes" : "no"}`);
}

function firstLine(contents) {
  return lines(contents)[0] ?? "";
}

function lines(contents) {
  return String(contents)
    .replace(/\r/g, "")
    .split("\n")
    .map((line) => line.trimEnd())
    .filter(Boolean);
}

function today() {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}
