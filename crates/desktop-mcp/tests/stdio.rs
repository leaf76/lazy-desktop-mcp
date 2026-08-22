use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

struct IsolatedMcpHarness {
    _data_dir: TempDir,
    child: Child,
}

impl IsolatedMcpHarness {
    fn spawn(write_requests: impl FnOnce(&mut std::process::ChildStdin)) -> Self {
        let data_dir = TempDir::new().expect("temp data dir");
        let mut child = Command::new(env!("CARGO_BIN_EXE_desktop-mcp"))
            .env("DESKTOP_HOST_BIN", resolve_host_binary())
            .env("LAZY_DESKTOP_DATA_DIR", data_dir.path())
            .env("LAZY_DESKTOP_AUTO_LAUNCH_PRESENCE_UI", "0")
            .env("LAZY_DESKTOP_AUTO_QUIT_PRESENCE_UI", "0")
            .env_remove("LAZY_DESKTOP_POLICY_PATH")
            .env_remove("LAZY_DESKTOP_VISION_COMMAND")
            .env_remove("LAZY_DESKTOP_VISION_ARGS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn desktop-mcp");

        {
            let stdin = child.stdin.as_mut().expect("stdin");
            write_requests(stdin);
        }

        Self {
            _data_dir: data_dir,
            child,
        }
    }

    fn finish(self) -> String {
        let output = self.child.wait_with_output().expect("wait for desktop-mcp");
        assert!(
            output.status.success(),
            "desktop-mcp should exit cleanly after stdin closes: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

fn resolve_host_binary() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_desktop-host")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let current_exe = std::env::current_exe().expect("current exe");
            current_exe
                .parent()
                .expect("deps dir")
                .parent()
                .expect("debug dir")
                .join(if cfg!(windows) {
                    "desktop-host.exe"
                } else {
                    "desktop-host"
                })
        })
}

fn response_lines(stdout: &str) -> Vec<&str> {
    stdout.lines().collect()
}

fn assert_tool_success(response: &Value) {
    assert_eq!(
        response["result"]["isError"],
        Value::Bool(false),
        "expected tool success, got: {}",
        serde_json::to_string_pretty(response).unwrap_or_else(|_| response.to_string())
    );
}

fn assert_tool_error(response: &Value, code: &str) {
    assert_eq!(response["result"]["isError"], Value::Bool(true));
    assert_eq!(
        response["result"]["structuredContent"]["error"]["code"],
        Value::String(code.to_string())
    );
}

#[test]
fn invalid_tool_arguments_return_structured_error_without_crashing_server() {
    let stdout = IsolatedMcpHarness::spawn(|stdin| {
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .expect("write initialize");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"app_launch","arguments":{{"app":"TextEdit"}}}}}}"#
        )
        .expect("write invalid tool call");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"desktop_capabilities","arguments":{{}}}}}}"#
        )
        .expect("write valid tool call");
    })
    .finish();

    let lines = response_lines(&stdout);
    assert_eq!(lines.len(), 3, "expected initialize + 2 tool responses");

    let invalid_response: Value = serde_json::from_str(lines[1]).expect("invalid call response");
    assert_tool_error(&invalid_response, "VALIDATION");

    let valid_response: Value = serde_json::from_str(lines[2]).expect("valid call response");
    assert_tool_success(&valid_response);
}

#[test]
fn runtime_tool_returns_runtime_details() {
    let stdout = IsolatedMcpHarness::spawn(|stdin| {
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .expect("write initialize");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"desktop_runtime","arguments":{{}}}}}}"#
        )
        .expect("write runtime tool call");
    })
    .finish();

    let lines = response_lines(&stdout);
    assert_eq!(lines.len(), 2, "expected initialize + runtime response");

    let runtime_response: Value = serde_json::from_str(lines[1]).expect("runtime call response");
    assert_tool_success(&runtime_response);
    assert_eq!(
        runtime_response["result"]["structuredContent"]["kind"],
        Value::String("runtime".to_string())
    );
    assert!(
        runtime_response["result"]["structuredContent"]["runtime"]["security_policy_path"]
            .is_string()
    );
    assert!(
        runtime_response["result"]["structuredContent"]["runtime"]
            .get("base_policy")
            .is_none()
    );
    assert!(
        runtime_response["result"]["structuredContent"]["runtime"]
            .get("artifact_dir")
            .is_none()
    );
}

#[test]
fn tools_list_includes_activate_and_click_target_tools() {
    let stdout = IsolatedMcpHarness::spawn(|stdin| {
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .expect("write initialize");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
        )
        .expect("write tools/list");
    })
    .finish();

    let lines = response_lines(&stdout);
    assert_eq!(lines.len(), 2, "expected initialize + tools/list response");

    let tools_response: Value = serde_json::from_str(lines[1]).expect("tools/list response");
    let tools = tools_response["result"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<_> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();

    assert!(names.contains(&"app_activate"));
    assert!(names.contains(&"input_click_target"));
    // Strict-client safe: no dots in published tool names.
    assert!(names.iter().all(|name| !name.contains('.')));
    assert!(names.contains(&"presence_ui_quit"));
}

#[test]
fn runtime_detail_full_includes_policy_snapshot() {
    let stdout = IsolatedMcpHarness::spawn(|stdin| {
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .expect("write initialize");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"desktop.runtime","arguments":{{"detail":"full"}}}}}}"#
        )
        .expect("write runtime tool call");
    })
    .finish();

    let lines = response_lines(&stdout);
    assert_eq!(lines.len(), 2, "expected initialize + runtime response");

    let runtime_response: Value = serde_json::from_str(lines[1]).expect("runtime call response");
    assert_tool_success(&runtime_response);
    assert!(runtime_response["result"]["structuredContent"]["runtime"]["base_policy"].is_object());
    assert!(runtime_response["result"]["structuredContent"]["runtime"]["artifact_dir"].is_string());
}
