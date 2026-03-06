import test from "node:test";
import assert from "node:assert/strict";

import {
  assessRelease,
  parseCargoWorkspaceVersion,
  parseGitCommitLog,
  renderReleaseNotes,
} from "../lib/release-flow.mjs";

test("parseCargoWorkspaceVersion reads the workspace package version", () => {
  const cargoToml = `
[workspace]
members = ["crates/desktop-host"]

[workspace.package]
version = "0.2.0"
edition = "2024"
`.trim();

  assert.equal(parseCargoWorkspaceVersion(cargoToml), "0.2.0");
});

test("parseGitCommitLog extracts hash and subject lines", () => {
  const commits = parseGitCommitLog(`
abc1234 Add release helper
def5678 Update docs
`.trim());

  assert.deepEqual(commits, [
    { hash: "abc1234", subject: "Add release helper" },
    { hash: "def5678", subject: "Update docs" },
  ]);
});

test("assessRelease passes when versions match and release version is new", () => {
  const assessment = assessRelease({
    packageVersion: "0.2.0",
    cargoVersion: "0.2.0",
    latestTag: "v0.1.9",
    gitStatusLines: [],
    commits: [{ hash: "abc1234", subject: "Add release helper" }],
  });

  assert.deepEqual(assessment.errors, []);
  assert.deepEqual(assessment.warnings, []);
});

test("assessRelease flags mismatched versions, unchanged tag, and dirty worktree", () => {
  const assessment = assessRelease({
    packageVersion: "0.1.3",
    cargoVersion: "0.1.4",
    latestTag: "v0.1.3",
    gitStatusLines: [" M README.md"],
    commits: [{ hash: "abc1234", subject: "Add release helper" }],
  });

  assert.deepEqual(assessment.errors, [
    "package.json version and Cargo.toml workspace version must match.",
    "Current version already matches the latest git tag. Bump the version before publishing again.",
    "Working tree is not clean. Commit or stash changes before publishing.",
  ]);
});

test("renderReleaseNotes creates a publish-ready markdown summary", () => {
  const notes = renderReleaseNotes({
    version: "0.2.0",
    previousTag: "v0.1.9",
    commits: [
      { hash: "abc1234", subject: "Add release helper" },
      { hash: "def5678", subject: "Update publishing guide" },
    ],
    releaseDate: "2026-03-07",
  });

  assert.match(notes, /^# lazy-desktop-mcp 0\.2\.0/m);
  assert.match(notes, /Previous tag: `v0\.1\.9`/);
  assert.match(notes, /- abc1234 Add release helper/);
  assert.match(notes, /- def5678 Update publishing guide/);
});
