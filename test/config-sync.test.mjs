import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  applyCodexConfig,
  applyOpenCodeConfig,
  mergeCodexConfig,
  mergeOpenCodeConfig,
  readCanonicalClientConfig,
  resolveClientConfigPaths,
  syncClientConfigs,
} from "../lib/config-sync.mjs";

function createWorkspace() {
  return mkdtempSync(path.join(os.tmpdir(), "lazy-desktop-config-"));
}

function writeCanonicalConfig(root, overrides = {}) {
  const configDir = path.join(root, "config");
  mkdirSync(configDir, { recursive: true });
  const configPath = path.join(configDir, "client-config.json");
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        serverName: "lazy-desktop",
        binaries: {
          mcp: "target/release/desktop-mcp",
          host: "target/release/desktop-host",
        },
        policy: {
          dev: "config/policy.dev.json",
          template: {
            allowed_standalone_capabilities: [
              "app_list",
              "window_list",
              "observe_capture",
              "ocr_read",
            ],
            allowed_session_capabilities: [
              "app_launch",
              "window_focus",
              "input_click",
              "input_type",
              "input_hotkey",
            ],
            allowed_apps: ["TextEdit"],
            allowed_windows: ["Notes"],
            allowed_screens: ["primary"],
            allow_raw_input: false,
            max_actions_per_minute: 60,
          },
        },
        vision: {
          command: null,
          args: [],
        },
        features: {
          ocr: "auto",
          vision: "disabled",
          windowControl: "enabled",
          inputControl: "enabled",
        },
        ...overrides,
      },
      null,
      2,
    ),
  );
  return configPath;
}

test("resolveClientConfigPaths resolves binaries and policy relative to package root", () => {
  const packageRoot = createWorkspace();
  const resolved = resolveClientConfigPaths({
    packageRoot,
    canonicalConfig: {
      serverName: "lazy-desktop",
      binaries: {
        mcp: "target/release/desktop-mcp",
        host: "target/release/desktop-host",
      },
      policy: {
        dev: "config/policy.dev.json",
        template: {
          allowed_standalone_capabilities: ["app_list"],
        },
      },
      vision: {
        command: "scripts/mock-vision.sh",
        args: ["--json"],
      },
    },
  });

  assert.equal(resolved.serverName, "lazy-desktop");
  assert.equal(resolved.mcpBinary, path.join(packageRoot, "target", "release", "desktop-mcp"));
  assert.equal(resolved.hostBinary, path.join(packageRoot, "target", "release", "desktop-host"));
  assert.equal(resolved.policyPath, path.join(packageRoot, "config", "policy.dev.json"));
  assert.equal(
    resolved.visionCommand,
    path.join(packageRoot, "scripts", "mock-vision.sh"),
  );
  assert.deepEqual(resolved.visionArgs, ["--json"]);
  assert.deepEqual(resolved.policyTemplate, {
    allowed_standalone_capabilities: ["app_list"],
  });
});

test("applyCodexConfig inserts or replaces the lazy-desktop sections", () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), "lazy-desktop-codex-"));
  const configPath = path.join(tempRoot, "config.toml");
  writeFileSync(configPath, 'model = "gpt-5.4"\n\n[mcp_servers.filesystem]\ncommand = "npx"\n');

  applyCodexConfig(configPath, {
    serverName: "lazy-desktop",
    mcpBinary: "/tmp/desktop-mcp",
    hostBinary: "/tmp/desktop-host",
    policyPath: "/tmp/policy.dev.json",
  });

  const updated = readFileSync(configPath, "utf8");
  assert.match(updated, /\[mcp_servers\.lazy-desktop\]/);
  assert.match(updated, /command = "\/tmp\/desktop-mcp"/);
  assert.match(updated, /DESKTOP_HOST_BIN = "\/tmp\/desktop-host"/);
  assert.match(updated, /LAZY_DESKTOP_POLICY_PATH = "\/tmp\/policy\.dev\.json"/);

  applyCodexConfig(configPath, {
    serverName: "lazy-desktop",
    mcpBinary: "/opt/desktop-mcp",
    hostBinary: "/opt/desktop-host",
    policyPath: "/opt/policy.dev.json",
  });

  const replaced = readFileSync(configPath, "utf8");
  assert.equal((replaced.match(/\[mcp_servers\.lazy-desktop\]/g) ?? []).length, 1);
  assert.match(replaced, /command = "\/opt\/desktop-mcp"/);
  assert.match(replaced, /DESKTOP_HOST_BIN = "\/opt\/desktop-host"/);
});

test("applyOpenCodeConfig writes a local mcp entry without disturbing existing servers", () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), "lazy-desktop-opencode-"));
  const configPath = path.join(tempRoot, "opencode.json");
  mkdirSync(tempRoot, { recursive: true });
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        $schema: "https://opencode.ai/config.json",
        mcp: {
          filesystem: {
            type: "local",
            command: ["npx", "-y", "@modelcontextprotocol/server-filesystem"],
            enabled: true,
          },
        },
      },
      null,
      2,
    ),
  );

  applyOpenCodeConfig(configPath, {
    serverName: "lazy-desktop",
    mcpBinary: "/tmp/desktop-mcp",
    hostBinary: "/tmp/desktop-host",
    policyPath: "/tmp/policy.dev.json",
  });

  const updated = JSON.parse(readFileSync(configPath, "utf8"));
  assert.equal(updated.mcp.filesystem.enabled, true);
  assert.deepEqual(updated.mcp["lazy-desktop"].command, ["/tmp/desktop-mcp"]);
  assert.equal(updated.mcp["lazy-desktop"].environment.DESKTOP_HOST_BIN, "/tmp/desktop-host");
  assert.equal(
    updated.mcp["lazy-desktop"].environment.LAZY_DESKTOP_POLICY_PATH,
    "/tmp/policy.dev.json",
  );
});

test("readCanonicalClientConfig loads the canonical repo config", () => {
  const workspace = createWorkspace();
  const configPath = writeCanonicalConfig(workspace, {
    vision: {
      command: "scripts/mock-vision.sh",
      args: ["--json"],
    },
  });

  const loaded = readCanonicalClientConfig({
    packageRoot: workspace,
    configPath: path.relative(workspace, configPath),
  });

  assert.equal(loaded.serverName, "lazy-desktop");
  assert.equal(loaded.policy.template.max_actions_per_minute, 60);
  assert.equal(loaded.vision.command, "scripts/mock-vision.sh");
});

test("mergeCodexConfig replaces existing lazy-desktop sections with a managed block", () => {
  const merged = mergeCodexConfig(
    `
model = "gpt-5.4"

[mcp_servers.brave-search]
command = "npx"

[mcp_servers.lazy-desktop]
command = "old-command"

[mcp_servers.lazy-desktop.env]
DESKTOP_HOST_BIN = "old-host"
LAZY_DESKTOP_POLICY_PATH = "old-policy"
`,
    {
      serverName: "lazy-desktop",
      mcpBinary: "/tmp/repo/target/release/desktop-mcp",
      hostBinary: "/tmp/repo/target/release/desktop-host",
      policyPath: "/tmp/repo/config/policy.dev.json",
      policyTemplate: {},
      visionCommand: "/tmp/repo/scripts/vision.sh",
      visionArgs: ["--json"],
    },
  );

  assert.match(merged, /# BEGIN lazy-desktop-mcp managed block/);
  assert.match(merged, /command = "\/tmp\/repo\/target\/release\/desktop-mcp"/);
  assert.match(merged, /DESKTOP_HOST_BIN = "\/tmp\/repo\/target\/release\/desktop-host"/);
  assert.match(merged, /LAZY_DESKTOP_POLICY_PATH = "\/tmp\/repo\/config\/policy\.dev\.json"/);
  assert.match(merged, /LAZY_DESKTOP_VISION_COMMAND = "\/tmp\/repo\/scripts\/vision\.sh"/);
  assert.match(merged, /LAZY_DESKTOP_VISION_ARGS = "\[\\\"--json\\\"\]"/);
  assert.equal((merged.match(/\[mcp_servers\.lazy-desktop\]/g) ?? []).length, 1);
});

test("mergeOpenCodeConfig upserts a lazy-desktop entry with optional vision env", () => {
  const merged = mergeOpenCodeConfig(
    {
      $schema: "https://opencode.ai/config.json",
      mcp: {
        filesystem: {
          type: "local",
          command: ["npx", "-y", "@modelcontextprotocol/server-filesystem"],
          enabled: true,
        },
      },
    },
    {
      serverName: "lazy-desktop",
      mcpBinary: "/tmp/repo/target/release/desktop-mcp",
      hostBinary: "/tmp/repo/target/release/desktop-host",
      policyPath: "/tmp/repo/config/policy.dev.json",
      policyTemplate: {},
      visionCommand: "/tmp/repo/scripts/vision.sh",
      visionArgs: ["--json"],
    },
  );

  assert.equal(
    merged.mcp["lazy-desktop"].command[0],
    "/tmp/repo/target/release/desktop-mcp",
  );
  assert.deepEqual(merged.mcp["lazy-desktop"].environment, {
    DESKTOP_HOST_BIN: "/tmp/repo/target/release/desktop-host",
    LAZY_DESKTOP_POLICY_PATH: "/tmp/repo/config/policy.dev.json",
    LAZY_DESKTOP_VISION_COMMAND: "/tmp/repo/scripts/vision.sh",
    LAZY_DESKTOP_VISION_ARGS: "[\"--json\"]",
  });
  assert.equal(merged.mcp.filesystem.enabled, true);
});

test("syncClientConfigs writes the policy template and both client config files", () => {
  const workspace = createWorkspace();
  const configPath = writeCanonicalConfig(workspace);
  const codexPath = path.join(workspace, ".codex", "config.toml");
  const opencodePath = path.join(workspace, ".config", "opencode", "opencode.json");
  mkdirSync(path.dirname(codexPath), { recursive: true });
  mkdirSync(path.dirname(opencodePath), { recursive: true });
  writeFileSync(codexPath, 'model = "gpt-5.4"\n');
  writeFileSync(
    opencodePath,
    JSON.stringify({ $schema: "https://opencode.ai/config.json", mcp: {} }, null, 2),
  );

  const result = syncClientConfigs({
    packageRoot: workspace,
    configPath: path.relative(workspace, configPath),
    clientTargets: {
      codex: codexPath,
      opencode: opencodePath,
    },
  });

  assert.equal(result.policyPath, path.join(workspace, "config", "policy.dev.json"));
  assert.equal(existsSync(result.policyPath), true);
  const policy = JSON.parse(readFileSync(result.policyPath, "utf8"));
  assert.equal(policy.max_actions_per_minute, 60);

  const codexConfig = readFileSync(codexPath, "utf8");
  assert.match(codexConfig, /\[mcp_servers\.lazy-desktop\]/);

  const openCodeConfig = JSON.parse(readFileSync(opencodePath, "utf8"));
  assert.equal(openCodeConfig.mcp["lazy-desktop"].enabled, true);
  assert.equal(
    openCodeConfig.mcp["lazy-desktop"].environment.LAZY_DESKTOP_POLICY_PATH,
    result.policyPath,
  );
});
