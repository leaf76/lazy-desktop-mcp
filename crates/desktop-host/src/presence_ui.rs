//! Launch and quit the Computer Use Presence visual UI around control sessions.
//!
//! The MCP host does not draw overlays itself; it publishes presence JSON and
//! optionally opens `ComputerUsePresence.app`, which reads the same presence dir.
//! After the last automation session closes (or the host process exits), the host
//! quits the Presence UI so operators do not keep seeing "AI is using your computer".

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const AUTO_LAUNCH_ENV: &str = "LAZY_DESKTOP_AUTO_LAUNCH_PRESENCE_UI";
const AUTO_QUIT_ENV: &str = "LAZY_DESKTOP_AUTO_QUIT_PRESENCE_UI";
const UI_PATH_ENV: &str = "LAZY_DESKTOP_PRESENCE_UI_PATH";
const PROCESS_NAME: &str = "PresenceMenuBarApp";
const APP_BUNDLE_NAME: &str = "ComputerUsePresence.app";
const APP_BUNDLE_ID: &str = "com.leaf76.computer-use-presence";
const APP_NAME: &str = "ComputerUsePresence";

#[derive(Debug, Clone)]
pub struct PresenceUiLaunchResult {
    pub launched: bool,
    pub already_running: bool,
    pub app_path: Option<PathBuf>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PresenceUiQuitResult {
    pub quit: bool,
    pub was_running: bool,
    pub message: String,
}

/// Whether auto-launch is enabled (default: true on macOS unless env is "0"/"false").
/// Launch happens on session open / gated control — not on idle host startup.
pub fn auto_launch_enabled() -> bool {
    env_flag_enabled(std::env::var(AUTO_LAUNCH_ENV).ok().as_deref(), true)
}

/// Whether to quit Presence UI when the last session closes or the host exits.
/// Default: true (unless env is "0"/"false"/"no"/"off").
pub fn auto_quit_enabled() -> bool {
    env_flag_enabled(std::env::var(AUTO_QUIT_ENV).ok().as_deref(), true)
}

/// Pure helpers for unit tests.
#[cfg(test)]
pub fn auto_launch_enabled_from(value: Option<&str>) -> bool {
    env_flag_enabled(value, true)
}

#[cfg(test)]
pub fn auto_quit_enabled_from(value: Option<&str>) -> bool {
    env_flag_enabled(value, true)
}

fn env_flag_enabled(value: Option<&str>, default: bool) -> bool {
    match value {
        Some(raw) => {
            let v = raw.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "no" || v == "off")
        }
        None => default,
    }
}

pub fn is_presence_ui_running() -> bool {
    Command::new("pgrep")
        .args(["-x", PROCESS_NAME])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Resolve the Presence UI .app bundle path.
pub fn resolve_presence_ui_app(data_dir: &Path) -> Option<PathBuf> {
    if let Ok(raw) = std::env::var(UI_PATH_ENV) {
        let path = PathBuf::from(raw);
        if path.exists() {
            return Some(path);
        }
    }

    let candidates = [
        data_dir.join("PresenceUI").join(APP_BUNDLE_NAME),
        // Next to host binary: …/bin/../PresenceUI/…
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.join("PresenceUI").join(APP_BUNDLE_NAME)))
            .unwrap_or_default(),
        // Lab build output (local development)
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("WorkSpace/sideProject/others_projects/computer-use-lab/macos/PresenceMenuBarApp/.build/App")
            .join(APP_BUNDLE_NAME),
        PathBuf::from("/Users/cy76/WorkSpace/sideProject/others_projects/computer-use-lab/macos/PresenceMenuBarApp/.build/App")
            .join(APP_BUNDLE_NAME),
    ];

    candidates
        .into_iter()
        .find(|path| !path.as_os_str().is_empty() && path.exists())
}

/// Launch Presence UI if enabled and not already running.
pub fn maybe_launch_presence_ui(data_dir: &Path, presence_dir: &Path) -> PresenceUiLaunchResult {
    if !cfg!(target_os = "macos") {
        return PresenceUiLaunchResult {
            launched: false,
            already_running: false,
            app_path: None,
            message: "Presence UI auto-launch is only supported on macOS.".to_string(),
        };
    }

    if !auto_launch_enabled() {
        return PresenceUiLaunchResult {
            launched: false,
            already_running: false,
            app_path: None,
            message: format!("Presence UI auto-launch disabled ({AUTO_LAUNCH_ENV}=0)."),
        };
    }

    if is_presence_ui_running() {
        return PresenceUiLaunchResult {
            launched: false,
            already_running: true,
            app_path: resolve_presence_ui_app(data_dir),
            message: "Presence UI already running.".to_string(),
        };
    }

    let Some(app_path) = resolve_presence_ui_app(data_dir) else {
        return PresenceUiLaunchResult {
            launched: false,
            already_running: false,
            app_path: None,
            message: format!(
                "Presence UI app not found. Install with `npm run install:presence-ui` or set {UI_PATH_ENV}. Expected: {}/PresenceUI/{APP_BUNDLE_NAME}",
                data_dir.display()
            ),
        };
    };

    // Ensure presence dir exists before the UI starts polling.
    let _ = std::fs::create_dir_all(presence_dir);

    // `open` reuses an existing instance when possible; -g keeps focus on the user.
    let status = Command::new("open").arg("-g").arg(&app_path).status();

    match status {
        Ok(code) if code.success() => PresenceUiLaunchResult {
            launched: true,
            already_running: false,
            app_path: Some(app_path.clone()),
            message: format!(
                "Launched Presence UI: {} (presence dir: {})",
                app_path.display(),
                presence_dir.display()
            ),
        },
        Ok(code) => PresenceUiLaunchResult {
            launched: false,
            already_running: false,
            app_path: Some(app_path),
            message: format!("Failed to launch Presence UI (exit {code})."),
        },
        Err(error) => PresenceUiLaunchResult {
            launched: false,
            already_running: false,
            app_path: Some(app_path),
            message: format!("Failed to launch Presence UI: {error}"),
        },
    }
}

/// Quit Presence UI when auto-quit is enabled (default) and the process is running.
pub fn maybe_quit_presence_ui() -> PresenceUiQuitResult {
    if !cfg!(target_os = "macos") {
        return PresenceUiQuitResult {
            quit: false,
            was_running: false,
            message: "Presence UI auto-quit is only supported on macOS.".to_string(),
        };
    }

    if !auto_quit_enabled() {
        return PresenceUiQuitResult {
            quit: false,
            was_running: is_presence_ui_running(),
            message: format!("Presence UI auto-quit disabled ({AUTO_QUIT_ENV}=0)."),
        };
    }

    quit_presence_ui()
}

/// Quit Presence UI if running (ignores auto-quit env; used for host Drop / forced cleanup).
pub fn quit_presence_ui() -> PresenceUiQuitResult {
    if !cfg!(target_os = "macos") {
        return PresenceUiQuitResult {
            quit: false,
            was_running: false,
            message: "Presence UI quit is only supported on macOS.".to_string(),
        };
    }

    if !is_presence_ui_running() {
        return PresenceUiQuitResult {
            quit: false,
            was_running: false,
            message: "Presence UI was not running.".to_string(),
        };
    }

    // Prefer a graceful Apple Event quit; fall back to process kill.
    let _ = Command::new("osascript")
        .args([
            "-e",
            &format!("tell application id \"{APP_BUNDLE_ID}\" to quit"),
        ])
        .status();

    // Brief wait for graceful exit.
    for _ in 0..10 {
        if !is_presence_ui_running() {
            return PresenceUiQuitResult {
                quit: true,
                was_running: true,
                message: format!("Quit Presence UI ({APP_NAME})."),
            };
        }
        thread::sleep(Duration::from_millis(50));
    }

    let _ = Command::new("osascript")
        .args(["-e", &format!("tell application \"{APP_NAME}\" to quit")])
        .status();
    thread::sleep(Duration::from_millis(100));

    if is_presence_ui_running() {
        let _ = Command::new("pkill").args(["-x", PROCESS_NAME]).status();
        thread::sleep(Duration::from_millis(100));
    }

    if is_presence_ui_running() {
        PresenceUiQuitResult {
            quit: false,
            was_running: true,
            message: format!("Presence UI ({PROCESS_NAME}) still running after quit attempts."),
        }
    } else {
        PresenceUiQuitResult {
            quit: true,
            was_running: true,
            message: format!("Quit Presence UI ({APP_NAME})."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn resolve_prefers_data_dir_bundle() {
        let dir = tempdir().expect("tempdir");
        let app = dir.path().join("PresenceUI").join(APP_BUNDLE_NAME);
        fs::create_dir_all(&app).expect("mkdir app");
        let found = resolve_presence_ui_app(dir.path()).expect("found");
        assert_eq!(found, app);
    }

    #[test]
    fn auto_launch_env_off() {
        assert!(!auto_launch_enabled_from(Some("0")));
        assert!(!auto_launch_enabled_from(Some("false")));
        assert!(!auto_launch_enabled_from(Some("NO")));
        assert!(auto_launch_enabled_from(Some("1")));
        assert!(auto_launch_enabled_from(None));
    }

    #[test]
    fn auto_quit_env_defaults_on() {
        assert!(auto_quit_enabled_from(None));
        assert!(auto_quit_enabled_from(Some("1")));
        assert!(!auto_quit_enabled_from(Some("0")));
        assert!(!auto_quit_enabled_from(Some("false")));
        assert!(!auto_quit_enabled_from(Some("OFF")));
    }
}
