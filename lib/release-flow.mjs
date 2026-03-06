export function parseCargoWorkspaceVersion(contents) {
  const match = contents.match(/^\s*version\s*=\s*"([^"]+)"\s*$/m);
  if (!match) {
    throw new Error("Could not find workspace package version in Cargo.toml.");
  }
  return match[1];
}

export function parseGitCommitLog(contents) {
  return normalizeLines(contents)
    .filter(Boolean)
    .map((line) => {
      const separator = line.indexOf(" ");
      if (separator === -1) {
        return { hash: line.trim(), subject: "" };
      }

      return {
        hash: line.slice(0, separator).trim(),
        subject: line.slice(separator + 1).trim(),
      };
    });
}

export function assessRelease({
  packageVersion,
  cargoVersion,
  latestTag,
  gitStatusLines,
  commits,
  allowDirty = false,
} = {}) {
  const errors = [];
  const warnings = [];
  const normalizedLatestTag = latestTag?.trim() || null;
  const normalizedStatusLines = normalizeLines(gitStatusLines).filter(Boolean);
  const normalizedCommits = commits ?? [];

  if (packageVersion !== cargoVersion) {
    errors.push("package.json version and Cargo.toml workspace version must match.");
  }

  if (normalizedLatestTag && normalizedLatestTag === `v${packageVersion}`) {
    errors.push(
      "Current version already matches the latest git tag. Bump the version before publishing again.",
    );
  }

  if (!allowDirty && normalizedStatusLines.length > 0) {
    errors.push("Working tree is not clean. Commit or stash changes before publishing.");
  }

  if (normalizedCommits.length === 0) {
    warnings.push("No commits were found between the latest tag and HEAD.");
  }

  if (!normalizedLatestTag) {
    warnings.push("No git tag was found. This will be treated as the first npm release.");
  }

  return {
    packageVersion,
    cargoVersion,
    latestTag: normalizedLatestTag,
    dirty: normalizedStatusLines.length > 0,
    gitStatusLines: normalizedStatusLines,
    commits: normalizedCommits,
    errors,
    warnings,
  };
}

export function renderReleaseNotes({
  version,
  previousTag,
  commits,
  releaseDate,
}) {
  const commitLines = (commits ?? []).length
    ? commits.map(({ hash, subject }) => `- ${hash} ${subject}`.trimEnd()).join("\n")
    : "- No commits recorded.";

  return [
    `# lazy-desktop-mcp ${version}`,
    "",
    `Release date: ${releaseDate}`,
    `Previous tag: ${previousTag ? `\`${previousTag}\`` : "_none_"}`,
    "",
    "## Changes",
    commitLines,
    "",
  ].join("\n");
}

export function nextReleaseSteps({ version, latestTag, runChecks }) {
  return [
    `1. Review the generated release notes for v${version}.`,
    `2. ${runChecks ? "Checks already ran." : "Run `npm run release:check` to execute the full publish gate."}`,
    `3. Commit the release version bump and tag it as \`v${version}\`.`,
    `4. Publish with \`npm publish\`.`,
    latestTag
      ? `5. Compare npm package behavior against ${latestTag} release notes after publish.`
      : "5. Verify the first published package with `npx -y lazy-desktop-mcp`.",
  ];
}

function normalizeLines(value) {
  if (Array.isArray(value)) {
    return value.map((line) => String(line).replace(/\r/g, ""));
  }
  return String(value ?? "")
    .replace(/\r/g, "")
    .split("\n");
}
