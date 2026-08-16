/**
 * Multi-layer Windows computer-use smoke test for lazy-desktop-mcp.
 *
 * Layers:
 *  L0  MCP handshake / capabilities / permissions / runtime
 *  L1  Observation (app.list, window.list, observe.capture)
 *  L2  App lifecycle (launch, activate, quit)
 *  L3  Window control (focus, move, resize)
 *  L4  Input (type, hotkey, click coordinates)
 *  L5  Policy / presence STOP
 *
 * Usage:
 *   node scripts/windows-computer-use-e2e.mjs [path/to/desktop-mcp.exe]
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mcpBin =
  process.argv[2] ||
  path.join(root, "target", "release", "desktop-mcp.exe");
const hostBin =
  process.env.DESKTOP_HOST_BIN ||
  path.join(root, "target", "release", "desktop-host.exe");

if (!existsSync(mcpBin) || !existsSync(hostBin)) {
  console.error("Missing native binaries. Run: npm run build:native");
  process.exit(1);
}

const results = [];
function record(layer, name, ok, detail = "") {
  results.push({ layer, name, ok, detail });
  const mark = ok ? "PASS" : "FAIL";
  console.log(`[${mark}] ${layer} ${name}${detail ? " — " + detail : ""}`);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function createClient() {
  const child = spawn(mcpBin, [], {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      DESKTOP_HOST_BIN: hostBin,
      LAZY_DESKTOP_POLICY_PATH:
        process.env.LAZY_DESKTOP_POLICY_PATH ||
        path.join(root, "config", "policy.dev.json"),
    },
  });

  let buf = "";
  let nextId = 1;
  const pending = new Map();
  let stderr = "";

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id != null && pending.has(msg.id)) {
        pending.get(msg.id).resolve(msg);
        pending.delete(msg.id);
      }
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (c) => {
    stderr += c;
  });

  function request(method, params = {}, timeoutMs = 45000) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`timeout ${method}`)),
        timeoutMs,
      );
      pending.set(id, {
        resolve: (msg) => {
          clearTimeout(timer);
          resolve(msg);
        },
      });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  async function tool(name, args = {}) {
    const msg = await request("tools/call", { name, arguments: args });
    return msg;
  }

  function text(msg) {
    return (msg.result?.content || []).map((c) => c.text || "").join("\n");
  }
  function sc(msg) {
    return msg.result?.structuredContent;
  }
  function isErr(msg) {
    return Boolean(msg.result?.isError || msg.error);
  }

  return {
    child,
    request,
    tool,
    text,
    sc,
    isErr,
    getStderr: () => stderr,
    async close() {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
      await sleep(200);
    },
  };
}

async function main() {
  const client = createClient();
  try {
    // ---------- L0 ----------
    const init = await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "windows-computer-use-e2e", version: "0.1.8" },
    });
    record(
      "L0",
      "initialize",
      init.result?.serverInfo?.name === "desktop-mcp",
      init.result?.serverInfo?.version || "",
    );
    client.child.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) +
        "\n",
    );

    const caps = await client.tool("desktop.capabilities");
    const supported = (client.sc(caps)?.capabilities || [])
      .filter((c) => c.supported)
      .map((c) => c.capability);
    const need = [
      "app_list",
      "app_launch",
      "app_quit",
      "window_list",
      "window_focus",
      "window_move",
      "window_resize",
      "observe_capture",
      "input_click",
      "input_type",
      "input_hotkey",
    ];
    const missing = need.filter((c) => !supported.includes(c));
    record(
      "L0",
      "capabilities matrix",
      missing.length === 0,
      missing.length ? `missing: ${missing.join(",")}` : `${supported.length} supported`,
    );

    const perms = await client.tool("desktop.permissions");
    record(
      "L0",
      "permissions",
      !client.isErr(perms) && client.sc(perms)?.platform === "windows",
      client.text(perms),
    );

    const runtime = await client.tool("desktop.runtime");
    record(
      "L0",
      "runtime",
      !client.isErr(runtime) &&
        client.sc(runtime)?.runtime?.platform === "windows",
      client.sc(runtime)?.runtime?.security_policy_path || client.text(runtime),
    );

    // ---------- L1 observation ----------
    const apps = await client.tool("app.list");
    const appCount = client.sc(apps)?.apps?.length || 0;
    record("L1", "app.list", !client.isErr(apps) && appCount > 0, `${appCount} apps`);

    const wins0 = await client.tool("window.list");
    const winCount0 = client.sc(wins0)?.windows?.length || 0;
    record(
      "L1",
      "window.list",
      !client.isErr(wins0) && winCount0 > 0,
      `${winCount0} windows`,
    );

    const cap1 = await client.tool("observe.capture", { screen: "primary" });
    const art1 = client.sc(cap1)?.artifact;
    record(
      "L1",
      "observe.capture",
      !client.isErr(cap1) && art1?.bytes > 0 && existsSync(art1.path),
      art1 ? `${art1.bytes} bytes` : client.text(cap1),
    );

    // ---------- session ----------
    const open = await client.tool("session.open", {
      capabilities: [
        "app_launch",
        "app_quit",
        "window_focus",
        "window_move",
        "window_resize",
        "input_type",
        "input_click",
        "input_hotkey",
      ],
      allow_raw_input: true,
      max_actions_per_minute: 120,
    });
    const sessionId = client.sc(open)?.session?.id;
    record("L2", "session.open", Boolean(sessionId) && !client.isErr(open), sessionId || client.text(open));
    if (!sessionId) throw new Error("no session");

    // ---------- L2 app lifecycle ----------
    let r = await client.tool("app.launch", {
      session_id: sessionId,
      app: "notepad",
    });
    record("L2", "app.launch notepad", !client.isErr(r), client.text(r));
    await sleep(2200);

    r = await client.tool("window.list", {});
    let windows = client.sc(r)?.windows || [];
    let notepad = windows.find((w) =>
      (w.app_name || "").toLowerCase().includes("notepad"),
    );
    record(
      "L2",
      "notepad window visible",
      Boolean(notepad),
      notepad ? notepad.title : "not found",
    );

    r = await client.tool("app.activate", {
      session_id: sessionId,
      app: "Notepad.exe",
    });
    record(
      "L2",
      "app.activate existing",
      !client.isErr(r) && /Activated|Launch|Focused/i.test(client.text(r)),
      client.text(r),
    );

    // ---------- L3 window control ----------
    if (notepad) {
      r = await client.tool("window.focus", {
        session_id: sessionId,
        window_id: notepad.id,
      });
      record("L3", "window.focus", !client.isErr(r), client.text(r));
      await sleep(300);

      r = await client.tool("window.move", {
        session_id: sessionId,
        title: notepad.title,
        x: 180,
        y: 160,
      });
      record("L3", "window.move", !client.isErr(r), client.text(r));

      r = await client.tool("window.resize", {
        session_id: sessionId,
        title: notepad.title,
        width: 800,
        height: 560,
      });
      record("L3", "window.resize", !client.isErr(r), client.text(r));

      // verify geometry via list
      r = await client.tool("window.list", {});
      windows = client.sc(r)?.windows || [];
      const after = windows.find((w) => w.id === notepad.id);
      const geomOk =
        after &&
        after.position &&
        Math.abs(after.position.x - 180) < 40 &&
        after.size &&
        Math.abs(after.size.width - 800) < 40;
      record(
        "L3",
        "geometry verify",
        Boolean(geomOk),
        after
          ? `pos=${JSON.stringify(after.position)} size=${JSON.stringify(after.size)}`
          : "missing",
      );
    } else {
      record("L3", "window.focus", false, "skipped — no notepad");
      record("L3", "window.move", false, "skipped");
      record("L3", "window.resize", false, "skipped");
      record("L3", "geometry verify", false, "skipped");
    }

    // ---------- L4 input ----------
    r = await client.tool("input.type", {
      session_id: sessionId,
      text: "Layer4-Type-OK\n",
    });
    record("L4", "input.type", !client.isErr(r), client.text(r));

    r = await client.tool("input.hotkey", {
      session_id: sessionId,
      keys: ["control", "a"],
    });
    record("L4", "input.hotkey ctrl+a", !client.isErr(r), client.text(r));
    await sleep(150);

    r = await client.tool("input.type", {
      session_id: sessionId,
      text: "selected-replaced\n",
    });
    record("L4", "input.type after select-all", !client.isErr(r), client.text(r));

    // Click near top-left of primary (safe desktop area) then re-focus notepad
    r = await client.tool("input.click", {
      session_id: sessionId,
      coordinates: { x: 50, y: 50 },
    });
    record("L4", "input.click coordinates", !client.isErr(r), client.text(r));

    if (notepad) {
      r = await client.tool("window.focus", {
        session_id: sessionId,
        window_id: notepad.id,
      });
      record("L4", "re-focus after click", !client.isErr(r), client.text(r));
    }

    // Second capture after interaction
    r = await client.tool("observe.capture", { screen: "primary" });
    const art2 = client.sc(r)?.artifact;
    record(
      "L4",
      "capture after input",
      !client.isErr(r) && art2?.bytes > 0,
      art2 ? `${art2.bytes} bytes` : client.text(r),
    );

    // ---------- cleanup lifecycle (before STOP, which force-closes sessions) ----------
    r = await client.tool("app.quit", {
      session_id: sessionId,
      app: "Notepad.exe",
    });
    record("L2", "app.quit notepad", !client.isErr(r), client.text(r));
    await sleep(900);

    r = await client.tool("window.list", {});
    windows = client.sc(r)?.windows || [];
    const stillOpen = windows.some((w) =>
      (w.app_name || "").toLowerCase().includes("notepad"),
    );
    record("L2", "notepad closed", !stillOpen, stillOpen ? "still open" : "gone");

    r = await client.tool("session.close", { session_id: sessionId });
    record("L0", "session.close", !client.isErr(r), client.text(r));

    // Multi-app: Calculator (UWP / ApplicationFrameHost frame)
    const open2 = await client.tool("session.open", {
      capabilities: ["app_launch", "app_quit", "window_focus", "input_type"],
      max_actions_per_minute: 60,
    });
    const sid2 = client.sc(open2)?.session?.id;
    record("L2", "session.open (calc)", Boolean(sid2) && !client.isErr(open2), sid2 || client.text(open2));
    if (sid2) {
      r = await client.tool("app.launch", {
        session_id: sid2,
        app: "calc",
      });
      record("L2", "app.launch calc", !client.isErr(r), client.text(r));
      await sleep(2500);
      r = await client.tool("window.list", {});
      windows = client.sc(r)?.windows || [];
      const calc = windows.find((w) => {
        const app = (w.app_name || "").toLowerCase();
        const title = (w.title || "").trim();
        if (app.includes("calculatorapp") || app.includes("win32calc")) return true;
        if (app.includes("applicationframehost") && /小算盤|計算機|^Calculator$/i.test(title)) {
          return true;
        }
        // Never match terminals whose title merely mentions "calculator".
        if (app.includes("terminal") || app.includes("windowsterminal")) return false;
        return title === "小算盤" || title === "計算機" || /^Calculator$/i.test(title);
      });
      record(
        "L2",
        "calc window visible",
        Boolean(calc),
        calc ? `${calc.app_name}:${calc.title}` : "not found",
      );
      if (calc) {
        r = await client.tool("window.focus", {
          session_id: sid2,
          window_id: calc.id,
        });
        record("L3", "calc focus", !client.isErr(r), client.text(r));
      }
      // Quit by process name (CalculatorApp) — host kills process even if HWND is framed.
      r = await client.tool("app.quit", {
        session_id: sid2,
        app: "CalculatorApp.exe",
      });
      record("L2", "app.quit CalculatorApp", !client.isErr(r), client.text(r));
      await sleep(800);

      // ---------- L5 policy / presence (STOP force-closes all sessions) ----------
      const presenceStop =
        client.sc(runtime)?.runtime?.presence_stop_path ||
        path.join(
          process.env.LOCALAPPDATA || "",
          "lazy",
          "desktop-mcp",
          "data",
          "artifacts",
          "presence",
          "STOP",
        );
      const fs = await import("node:fs");
      try {
        fs.mkdirSync(path.dirname(presenceStop), { recursive: true });
        fs.writeFileSync(presenceStop, "e2e-stop\n");
        r = await client.tool("input.type", {
          session_id: sid2,
          text: "should-be-blocked",
        });
        record(
          "L5",
          "presence STOP blocks + closes sessions",
          client.isErr(r) && /STOP|stopped|SessionStopped/i.test(client.text(r)),
          client.text(r),
        );
        // After STOP, original session is gone by design.
        r = await client.tool("session.close", { session_id: sid2 });
        record(
          "L5",
          "session gone after STOP",
          client.isErr(r),
          client.text(r),
        );
        fs.unlinkSync(presenceStop);
      } catch (e) {
        record("L5", "presence STOP blocks + closes sessions", false, String(e));
        try {
          fs.unlinkSync(presenceStop);
        } catch {
          /* ignore */
        }
      }
    }

    // capability denied without session
    r = await client.tool("input.type", {
      session_id: "00000000-0000-0000-0000-000000000000",
      text: "nope",
    });
    record(
      "L5",
      "invalid session denied",
      client.isErr(r),
      client.text(r),
    );
  } catch (e) {
    record("ERR", "fatal", false, String(e));
    console.error(client.getStderr().slice(-1500));
  } finally {
    await client.close();
  }

  const failed = results.filter((r) => !r.ok);
  console.log("\n======== SUMMARY ========");
  console.log(
    `total=${results.length} pass=${results.length - failed.length} fail=${failed.length}`,
  );
  if (failed.length) {
    console.log("Failures:");
    for (const f of failed) {
      console.log(`  - ${f.layer} ${f.name}: ${f.detail}`);
    }
  }
  process.exit(failed.length ? 1 : 0);
}

main();
