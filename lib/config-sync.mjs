import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const DEFAULT_CANONICAL_CONFIG = "config/client-config.json";
const MANAGED_BLOCK_START = "# BEGIN lazy-desktop-mcp managed block";
const MANAGED_BLOCK_END = "# END lazy-desktop-mcp managed block";

export function readCanonicalClientConfig({
  packageRoot,
  configPath = DEFAULT_CANONICAL_CONFIG,
}) {
  const absolutePath = path.resolve(packageRoot, configPath);
  return JSON.parse(readFileSync(absolutePath, "utf8"));
}

export function resolveClientConfigPaths({ packageRoot, canonicalConfig }) {
  return {
    serverName: canonicalConfig.serverName,
    mcpBinary: path.resolve(packageRoot, canonicalConfig.binaries.mcp),
    hostBinary: path.resolve(packageRoot, canonicalConfig.binaries.host),
    policyPath: path.resolve(packageRoot, canonicalConfig.policy.dev),
    policyTemplate: canonicalConfig.policy.template ?? {},
    visionCommand:
      typeof canonicalConfig.vision?.command === "string" &&
      canonicalConfig.vision.command.length > 0
        ? path.resolve(packageRoot, canonicalConfig.vision.command)
        : null,
    visionArgs: Array.isArray(canonicalConfig.vision?.args)
      ? canonicalConfig.vision.args.filter(
          (value) => typeof value === "string" && value.length > 0,
        )
      : [],
    features: canonicalConfig.features ?? {},
  };
}

export function mergeCodexConfig(existingContents, resolvedConfig) {
  const block = renderCodexBlock(resolvedConfig);
  const normalized = normalizeLineEndings(existingContents).trimEnd();

  if (normalized.includes(MANAGED_BLOCK_START)) {
    return `${normalized.replace(
      new RegExp(
        `${escapeRegExp(MANAGED_BLOCK_START)}[\\s\\S]*?${escapeRegExp(MANAGED_BLOCK_END)}`,
        "m",
      ),
      block,
    )}\n`;
  }

  const withoutExisting = stripCodexServer(
    normalized,
    resolvedConfig.serverName,
  ).trimEnd();
  const next = withoutExisting ? `${withoutExisting}\n\n${block}` : block;
  return `${next}\n`;
}

export function mergeOpenCodeConfig(existingConfig, resolvedConfig) {
  return {
    ...(existingConfig ?? {}),
    mcp: {
      ...((existingConfig ?? {}).mcp ?? {}),
      [resolvedConfig.serverName]: {
        type: "local",
        command: [resolvedConfig.mcpBinary],
        environment: buildEnvironment(resolvedConfig),
        enabled: true,
      },
    },
  };
}

export function renderPolicyFile(resolvedConfig) {
  return `${JSON.stringify(resolvedConfig.policyTemplate, null, 2)}\n`;
}

export function syncClientConfigs({
  packageRoot,
  configPath = DEFAULT_CANONICAL_CONFIG,
  clientTargets = defaultClientTargets(),
  clients = selectedClients(),
  write = true,
}) {
  const canonicalConfig = readCanonicalClientConfig({ packageRoot, configPath });
  const resolvedConfig = resolveClientConfigPaths({ packageRoot, canonicalConfig });
  const policyContents = renderPolicyFile(resolvedConfig);

  const codexExisting = existsSync(clientTargets.codex)
    ? readFileSync(clientTargets.codex, "utf8")
    : "";
  const codexConfig = mergeCodexConfig(codexExisting, resolvedConfig);

  const openCodeExisting = existsSync(clientTargets.opencode)
    ? JSON.parse(readFileSync(clientTargets.opencode, "utf8"))
    : { $schema: "https://opencode.ai/config.json", mcp: {} };
  const openCodeConfig = `${JSON.stringify(
    mergeOpenCodeConfig(openCodeExisting, resolvedConfig),
    null,
    2,
  )}\n`;

  if (write) {
    ensureParentDir(resolvedConfig.policyPath);
    writeFileSync(resolvedConfig.policyPath, policyContents);

    if (clients.includes("codex")) {
      ensureParentDir(clientTargets.codex);
      writeFileSync(clientTargets.codex, codexConfig);
    }

    if (clients.includes("opencode")) {
      ensureParentDir(clientTargets.opencode);
      writeFileSync(clientTargets.opencode, openCodeConfig);
    }
  }

  return {
    resolvedConfig,
    policyPath: resolvedConfig.policyPath,
    policyContents,
    codexPath: clientTargets.codex,
    codexConfig,
    opencodePath: clientTargets.opencode,
    opencodeConfig: openCodeConfig,
  };
}

export function applyCodexConfig(configPath, resolvedConfig) {
  const existing = existsSync(configPath) ? readFileSync(configPath, "utf8") : "";
  const next = mergeCodexConfig(existing, resolvedConfig);

  ensureParentDir(configPath);
  writeFileSync(configPath, next);
}

export function applyOpenCodeConfig(configPath, resolvedConfig) {
  const existing = existsSync(configPath)
    ? JSON.parse(readFileSync(configPath, "utf8"))
    : { $schema: "https://opencode.ai/config.json", mcp: {} };
  const next = mergeOpenCodeConfig(existing, resolvedConfig);

  ensureParentDir(configPath);
  writeFileSync(configPath, `${JSON.stringify(next, null, 2)}\n`);
}

export function defaultClientTargets(env = process.env) {
  const homeDir = env.HOME ?? os.homedir();
  return {
    codex:
      env.CODEX_CONFIG_PATH ?? path.join(homeDir, ".codex", "config.toml"),
    opencode:
      env.OPENCODE_CONFIG_PATH ??
      path.join(homeDir, ".config", "opencode", "opencode.json"),
  };
}

export function selectedClients(rawValue = process.env.LAZY_DESKTOP_CLIENTS) {
  if (!rawValue) {
    return ["codex", "opencode"];
  }

  return rawValue
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

function buildEnvironment(resolvedConfig) {
  const env = {
    DESKTOP_HOST_BIN: resolvedConfig.hostBinary,
    LAZY_DESKTOP_POLICY_PATH: resolvedConfig.policyPath,
  };

  const visionCommand = resolvedConfig.visionCommand ?? null;
  const visionArgs = Array.isArray(resolvedConfig.visionArgs)
    ? resolvedConfig.visionArgs
    : [];

  if (visionCommand) {
    env.LAZY_DESKTOP_VISION_COMMAND = visionCommand;
  }

  if (visionArgs.length > 0) {
    env.LAZY_DESKTOP_VISION_ARGS = JSON.stringify(visionArgs);
  }

  return env;
}

function renderCodexBlock(resolvedConfig) {
  const environment = buildEnvironment(resolvedConfig);
  const envLines = Object.entries(environment)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key} = "${escapeTomlString(value)}"`)
    .join("\n");

  return [
    MANAGED_BLOCK_START,
    `[mcp_servers.${resolvedConfig.serverName}]`,
    `command = "${escapeTomlString(resolvedConfig.mcpBinary)}"`,
    "",
    `[mcp_servers.${resolvedConfig.serverName}.env]`,
    envLines,
    MANAGED_BLOCK_END,
  ].join("\n");
}

function stripCodexServer(contents, serverName) {
  const lines = normalizeLineEndings(contents).split("\n");
  const result = [];
  let index = 0;

  while (index < lines.length) {
    if (lines[index].trim() === `[mcp_servers.${serverName}]`) {
      index = skipCodexSections(lines, index, serverName);
      continue;
    }
    result.push(lines[index]);
    index += 1;
  }

  return collapseBlankLines(result).join("\n");
}

function skipCodexSections(lines, startIndex, serverName) {
  const headers = new Set([
    `[mcp_servers.${serverName}]`,
    `[mcp_servers.${serverName}.env]`,
  ]);
  let index = startIndex;

  while (index < lines.length && headers.has(lines[index].trim())) {
    index += 1;
    while (index < lines.length && !isTomlHeader(lines[index])) {
      index += 1;
    }
  }

  while (index < lines.length && lines[index].trim() === "") {
    index += 1;
  }

  return index;
}

function collapseBlankLines(lines) {
  const result = [];
  for (const line of lines) {
    if (
      line.trim() === "" &&
      result.length > 0 &&
      result[result.length - 1].trim() === ""
    ) {
      continue;
    }
    result.push(line);
  }
  return result;
}

function isTomlHeader(line) {
  return /^\[[^\]]+\]$/.test(line.trim());
}

function ensureParentDir(filePath) {
  mkdirSync(path.dirname(filePath), { recursive: true });
}

function normalizeLineEndings(value) {
  return value.replaceAll("\r\n", "\n");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeTomlString(value) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
