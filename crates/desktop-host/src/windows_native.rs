//! Win32 desktop helpers for the Windows host backend.
//!
//! Covers window enumeration / focus / geometry, process-aware app quit, and
//! basic UI automation probing. Compiled only on Windows.

use desktop_core::{Coordinate, Size, ToolError, WindowDescriptor};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, RECT, WPARAM};
use windows::Win32::System::ProcessStatus::K32GetModuleBaseNameW;
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, BringWindowToTop, EnumWindows, GetForegroundWindow, GetWindowRect,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindow,
    IsWindowVisible, PostMessageW, SW_RESTORE, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
    SWP_SHOWWINDOW, SetForegroundWindow, SetWindowPos, ShowWindow, WM_CLOSE,
};
use windows::core::BOOL;

/// `ASFW_ANY` — allow any process to set the foreground window (best-effort).
const ASFW_ANY: u32 = u32::MAX;

/// List top-level visible windows that have a non-empty title.
pub fn list_windows(trace_id: &str) -> Result<Vec<WindowDescriptor>, ToolError> {
    let mut windows = Vec::new();
    let mut state = EnumState {
        windows: &mut windows,
        error: None,
    };

    // SAFETY: callback only touches `state` for the duration of EnumWindows.
    let result = unsafe {
        EnumWindows(
            Some(enum_windows_proc),
            LPARAM(std::ptr::from_mut(&mut state) as isize),
        )
    };

    if let Some(error) = state.error {
        return Err(ToolError::internal(error, trace_id));
    }

    if result.is_err() {
        return Err(ToolError::internal(
            "EnumWindows failed while enumerating desktop windows.",
            trace_id,
        ));
    }

    windows.sort_by(|left, right| left.title.cmp(&right.title));
    Ok(windows)
}

pub fn focus_window(window: &WindowDescriptor, trace_id: &str) -> Result<String, ToolError> {
    let hwnd = resolve_window_hwnd(window, trace_id)?;
    focus_hwnd(hwnd, trace_id)?;
    let app = window
        .app_name
        .as_deref()
        .unwrap_or("unknown application");
    Ok(format!(
        "Focused window {} for application {}.",
        window.title, app
    ))
}

pub fn move_window(
    title: &str,
    coordinate: Coordinate,
    trace_id: &str,
) -> Result<String, ToolError> {
    let hwnd = find_window_by_title(title, trace_id)?;
    let mut rect = RECT::default();
    unsafe {
        GetWindowRect(hwnd, &mut rect).map_err(|error| {
            ToolError::internal(format!("GetWindowRect failed: {error}"), trace_id)
        })?;
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        SetWindowPos(
            hwnd,
            None,
            coordinate.x,
            coordinate.y,
            width,
            height,
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW,
        )
        .map_err(|error| {
            ToolError::internal(format!("SetWindowPos (move) failed: {error}"), trace_id)
        })?;
    }

    let app = window_process_name(hwnd).unwrap_or_else(|| "unknown".to_string());
    Ok(format!(
        "Moved window {title} for application {app} to ({}, {}).",
        coordinate.x, coordinate.y
    ))
}

pub fn resize_window(
    title: &str,
    width: u32,
    height: u32,
    trace_id: &str,
) -> Result<String, ToolError> {
    let hwnd = find_window_by_title(title, trace_id)?;
    let mut rect = RECT::default();
    unsafe {
        GetWindowRect(hwnd, &mut rect).map_err(|error| {
            ToolError::internal(format!("GetWindowRect failed: {error}"), trace_id)
        })?;
        SetWindowPos(
            hwnd,
            None,
            rect.left,
            rect.top,
            width as i32,
            height as i32,
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW,
        )
        .map_err(|error| {
            ToolError::internal(format!("SetWindowPos (resize) failed: {error}"), trace_id)
        })?;
    }

    let app = window_process_name(hwnd).unwrap_or_else(|| "unknown".to_string());
    Ok(format!(
        "Resized window {title} for application {app} to {width}x{height}."
    ))
}

/// Focus the first visible window belonging to `app` (process base name).
/// Returns `Ok(None)` when no matching window is open so callers can launch.
pub fn try_focus_app(app: &str, trace_id: &str) -> Result<Option<String>, ToolError> {
    let target = normalize_process_name(app);
    let windows = list_windows(trace_id)?;
    let Some(window) = windows.into_iter().find(|window| {
        window
            .app_name
            .as_deref()
            .map(|name| normalize_process_name(name) == target)
            .unwrap_or(false)
    }) else {
        return Ok(None);
    };

    focus_window(&window, trace_id)?;
    Ok(Some(format!(
        "Activated application {app} via existing window {}.",
        window.title
    )))
}

/// Close an application by process base name (with or without `.exe`).
///
/// Strategy:
/// 1. `WM_CLOSE` every top-level window whose owning module name matches.
/// 2. `WM_CLOSE` windows whose thread process id belongs to a matching process
///    (covers cases where the visible HWND is a host frame).
/// 3. Fall back to terminating still-running processes with that name (needed
///    for some UWP apps such as Calculator whose HWND is owned by
///    `ApplicationFrameHost.exe`).
pub fn quit_app(app: &str, trace_id: &str) -> Result<String, ToolError> {
    let target = normalize_process_name(app);
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let mut target_pids = std::collections::BTreeSet::new();
    for (pid, process) in system.processes() {
        if normalize_process_name(&process.name().to_string_lossy()) == target {
            target_pids.insert(pid.as_u32());
        }
    }

    let windows = list_windows(trace_id)?;
    let mut closed = 0usize;

    for window in windows {
        let Ok(hwnd) = parse_hwnd(&window.id) else {
            continue;
        };

        let matches_module = window
            .app_name
            .as_deref()
            .map(|name| normalize_process_name(name) == target)
            .unwrap_or(false);

        let matches_pid = unsafe {
            let mut process_id = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut process_id));
            target_pids.contains(&process_id)
        };

        if !matches_module && !matches_pid {
            continue;
        }

        unsafe {
            if !IsWindow(Some(hwnd)).as_bool() {
                continue;
            }
            let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
        closed += 1;
    }

    // Brief pause so graceful close can take effect before process kill.
    if closed > 0 {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut killed = 0usize;
    for (pid, process) in system.processes() {
        if normalize_process_name(&process.name().to_string_lossy()) != target {
            continue;
        }
        if process.kill() {
            killed += 1;
        } else {
            tracing::debug!(
                target: "windows_native",
                "Failed to kill process {} ({})",
                process.name().to_string_lossy(),
                pid
            );
        }
    }

    if closed == 0 && killed == 0 {
        return Err(ToolError::not_found(
            format!("No open windows or running processes found for application {app}."),
            trace_id,
        ));
    }

    Ok(format!(
        "Quit request for {app}: closed {closed} window(s), stopped {killed} process(es)."
    ))
}

/// Probe that basic Win32 window APIs are callable in this session.
pub fn probe_ui_automation() -> desktop_core::PermissionState {
    match list_windows("permission-probe") {
        Ok(_) => desktop_core::PermissionState::Granted,
        Err(_) => desktop_core::PermissionState::Denied,
    }
}

struct EnumState<'a> {
    windows: &'a mut Vec<WindowDescriptor>,
    error: Option<String>,
}

// SAFETY: Called by EnumWindows with LPARAM pointing at EnumState for the
// duration of the enumeration. Must not panic.
unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = unsafe { &mut *(lparam.0 as *mut EnumState<'_>) };

    if let Err(error) = collect_window(hwnd, state.windows) {
        state.error = Some(error);
        return BOOL(0);
    }

    BOOL(1)
}

fn collect_window(hwnd: HWND, out: &mut Vec<WindowDescriptor>) -> Result<(), String> {
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() {
            return Ok(());
        }

        let length = GetWindowTextLengthW(hwnd);
        if length <= 0 {
            return Ok(());
        }

        let mut buffer = vec![0u16; (length + 1) as usize];
        let written = GetWindowTextW(hwnd, &mut buffer);
        if written <= 0 {
            return Ok(());
        }
        buffer.truncate(written as usize);
        let title = OsString::from_wide(&buffer)
            .to_string_lossy()
            .trim()
            .to_string();
        if title.is_empty() {
            return Ok(());
        }

        let mut rect = RECT::default();
        let (position, size) = if GetWindowRect(hwnd, &mut rect).is_ok() {
            (
                Some(Coordinate {
                    x: rect.left,
                    y: rect.top,
                }),
                Some(Size {
                    width: (rect.right - rect.left).max(0) as u32,
                    height: (rect.bottom - rect.top).max(0) as u32,
                }),
            )
        } else {
            (None, None)
        };

        out.push(WindowDescriptor {
            id: format_hwnd(hwnd),
            title,
            app_name: window_process_name(hwnd),
            position,
            size,
        });
    }

    Ok(())
}

fn resolve_window_hwnd(window: &WindowDescriptor, trace_id: &str) -> Result<HWND, ToolError> {
    if let Ok(hwnd) = parse_hwnd(&window.id) {
        unsafe {
            if IsWindow(Some(hwnd)).as_bool() {
                return Ok(hwnd);
            }
        }
    }

    find_window_by_title(&window.title, trace_id)
}

fn find_window_by_title(title: &str, trace_id: &str) -> Result<HWND, ToolError> {
    let windows = list_windows(trace_id)?;
    let matches: Vec<_> = windows
        .into_iter()
        .filter(|window| window.title == title)
        .collect();

    match matches.as_slice() {
        [] => Err(ToolError::not_found(
            format!("No window found with title: {title}"),
            trace_id,
        )),
        [only] => parse_hwnd(&only.id).map_err(|error| ToolError::internal(error, trace_id)),
        many => Err(ToolError::validation(
            format!(
                "Multiple windows share title {title}. Use window_id to disambiguate. Count: {}",
                many.len()
            ),
            trace_id,
        )),
    }
}

fn focus_hwnd(hwnd: HWND, trace_id: &str) -> Result<(), ToolError> {
    unsafe {
        if !IsWindow(Some(hwnd)).as_bool() {
            return Err(ToolError::not_found(
                "The target window no longer exists.",
                trace_id,
            ));
        }

        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }

        // Best-effort: allow this process to set the foreground window.
        let _ = AllowSetForegroundWindow(ASFW_ANY);

        let foreground = GetForegroundWindow();
        if foreground != hwnd && !foreground.0.is_null() {
            let mut foreground_pid = 0u32;
            let foreground_tid = GetWindowThreadProcessId(foreground, Some(&mut foreground_pid));
            let current_tid = GetCurrentThreadId();
            if foreground_tid != 0 && foreground_tid != current_tid {
                let _ = AttachThreadInput(current_tid, foreground_tid, true);
                let _ = BringWindowToTop(hwnd);
                let focused = SetForegroundWindow(hwnd);
                let _ = AttachThreadInput(current_tid, foreground_tid, false);
                if !focused.as_bool() {
                    let _ = SetForegroundWindow(hwnd);
                }
            } else {
                let _ = BringWindowToTop(hwnd);
                let _ = SetForegroundWindow(hwnd);
            }
        } else {
            let _ = BringWindowToTop(hwnd);
            let _ = SetForegroundWindow(hwnd);
        }

        let _ = SetWindowPos(
            hwnd,
            None,
            0,
            0,
            0,
            0,
            SWP_NOZORDER | SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW,
        );
    }

    Ok(())
}

fn window_process_name(hwnd: HWND) -> Option<String> {
    unsafe {
        let mut process_id = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));
        if process_id == 0 {
            return None;
        }

        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            process_id,
        )
        .ok()?;

        let mut buffer = [0u16; 260];
        let length = K32GetModuleBaseNameW(handle, None, &mut buffer);
        let _ = CloseHandle(handle);
        if length == 0 {
            return None;
        }

        Some(
            OsString::from_wide(&buffer[..length as usize])
                .to_string_lossy()
                .into_owned(),
        )
    }
}

fn format_hwnd(hwnd: HWND) -> String {
    format!("hwnd:{}", hwnd.0 as usize)
}

fn parse_hwnd(id: &str) -> Result<HWND, String> {
    let value = if let Some(rest) = id.strip_prefix("hwnd:") {
        if let Some(hex) = rest
            .strip_prefix("0x")
            .or_else(|| rest.strip_prefix("0X"))
        {
            usize::from_str_radix(hex, 16)
                .map_err(|error| format!("Invalid window id {id}: {error}"))?
        } else {
            rest.parse::<usize>()
                .map_err(|error| format!("Invalid window id {id}: {error}"))?
        }
    } else if let Some(hex) = id.strip_prefix("0x").or_else(|| id.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16)
            .map_err(|error| format!("Invalid window id {id}: {error}"))?
    } else {
        id.parse::<usize>()
            .map_err(|error| format!("Invalid window id {id}: {error}"))?
    };

    Ok(HWND(value as *mut core::ffi::c_void))
}

fn normalize_process_name(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"');
    let file_name = Path::new(trimmed)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(trimmed);
    let lower = file_name.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .unwrap_or(&lower)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_and_parse_hwnd_round_trip() {
        let hwnd = HWND(0x1234_abcd_usize as *mut core::ffi::c_void);
        let id = format_hwnd(hwnd);
        let parsed = parse_hwnd(&id).expect("parse");
        assert_eq!(parsed.0 as usize, hwnd.0 as usize);
    }

    #[test]
    fn normalize_process_name_strips_exe_and_path() {
        assert_eq!(normalize_process_name("Notepad.exe"), "notepad");
        assert_eq!(
            normalize_process_name("C:\\Windows\\System32\\notepad.EXE"),
            "notepad"
        );
        assert_eq!(normalize_process_name("notepad"), "notepad");
    }
}
