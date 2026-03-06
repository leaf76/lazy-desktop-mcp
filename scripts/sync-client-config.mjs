import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  defaultClientTargets,
  selectedClients,
  syncClientConfigs,
} from "../lib/config-sync.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const options = parseArgs(process.argv.slice(2));
const targets = defaultClientTargets({
  ...process.env,
  ...(options.codexPath ? { CODEX_CONFIG_PATH: options.codexPath } : {}),
  ...(options.opencodePath ? { OPENCODE_CONFIG_PATH: options.opencodePath } : {}),
});

const result = syncClientConfigs({
  packageRoot,
  configPath: options.configPath ?? "config/client-config.json",
  clientTargets: targets,
  clients: selectedClients(options.clients ?? process.env.LAZY_DESKTOP_CLIENTS),
  write: !options.dryRun,
});

if (options.dryRun) {
  console.log(`# policy: ${result.policyPath}`);
  console.log(result.policyContents);
  console.log(`# codex: ${result.codexPath}`);
  console.log(result.codexConfig);
  console.log(`# opencode: ${result.opencodePath}`);
  console.log(result.opencodeConfig);
} else {
  console.log(`Synced lazy-desktop client config.`);
  console.log(`Policy: ${result.policyPath}`);
  console.log(`Codex: ${result.codexPath}`);
  console.log(`OpenCode: ${result.opencodePath}`);
}

function parseArgs(args) {
  const options = {
    dryRun: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--config":
        options.configPath = readValue(args, index, arg);
        index += 1;
        break;
      case "--clients":
        options.clients = readValue(args, index, arg);
        index += 1;
        break;
      case "--codex-path":
        options.codexPath = readValue(args, index, arg);
        index += 1;
        break;
      case "--opencode-path":
        options.opencodePath = readValue(args, index, arg);
        index += 1;
        break;
      case "--dry-run":
        options.dryRun = true;
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
