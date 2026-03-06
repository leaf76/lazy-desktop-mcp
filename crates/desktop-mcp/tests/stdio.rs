use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn invalid_tool_arguments_return_structured_error_without_crashing_server() {
    let host_binary = std::env::var("CARGO_BIN_EXE_desktop-host")
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
        });
    let mut child = Command::new(env!("CARGO_BIN_EXE_desktop-mcp"))
        .env("DESKTOP_HOST_BIN", host_binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn desktop-mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .expect("write initialize");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"app.launch","arguments":{{"app":"TextEdit"}}}}}}"#
        )
        .expect("write invalid tool call");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"desktop.capabilities","arguments":{{}}}}}}"#
        )
        .expect("write valid tool call");
    }

    let output = child.wait_with_output().expect("wait for desktop-mcp");
    assert!(
        output.status.success(),
        "desktop-mcp should keep running and exit cleanly after stdin closes: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "expected initialize + 2 tool responses");

    let invalid_response: Value = serde_json::from_str(lines[1]).expect("invalid call response");
    assert_eq!(invalid_response["result"]["isError"], Value::Bool(true));
    assert_eq!(
        invalid_response["result"]["structuredContent"]["error"]["code"],
        Value::String("VALIDATION".to_string())
    );

    let valid_response: Value = serde_json::from_str(lines[2]).expect("valid call response");
    assert_eq!(valid_response["result"]["isError"], Value::Bool(false));
}
