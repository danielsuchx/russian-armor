//! Private Unix-socket transport for the native macOS app. No webview, public
//! HTTP management endpoint, arbitrary evaluation or shell-command dispatcher.
use serde::{Serialize, de::DeserializeOwned, Deserialize};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use tauri::{Listener, Manager};

static EVENTS: OnceLock<Arc<Mutex<VecDeque<Value>>>> = OnceLock::new();
static CONFIGURATION_LOCK: Mutex<()> = Mutex::new(());

fn read_only(command: &str) -> bool {
    (command.starts_with("get_") && command != "get_coverage_snapshot")
        || ["native_ping", "native_poll_events", "take_pending_alert", "list_routes",
            "list_claude_profiles_cmd", "check_cli_protection_status", "scan_claude_data_cmd"].contains(&command)
}

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_CLIENTS: usize = 32;

/// Debug-only packaging/IPC check: no audits, recovery or configuration writes.
pub fn smoke_mode() -> bool {
    cfg!(debug_assertions) && std::env::args().any(|argument| argument == "--native-smoke-test")
}

#[derive(Deserialize)]
struct Request {
    token: String,
    command: String,
    #[serde(default = "empty_args")]
    args: Value,
}
fn empty_args() -> Value { json!({}) }

pub fn argument<T: DeserializeOwned>(args: &Value, name: &str) -> Result<T, Value> {
    serde_json::from_value(args.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|_| json!({"message":format!("Invalid argument: {name}")}))
}
pub fn value<T: Serialize>(value: T) -> Result<Value, Value> {
    serde_json::to_value(value).map_err(|_| json!({"message":"Could not encode result"}))
}
pub fn result<T: Serialize, E: Serialize>(result: Result<T, E>) -> Result<Value, Value> {
    result.map_err(|e| serde_json::to_value(e).unwrap_or(json!({"message":"Command failed"})))
        .and_then(value)
}

pub fn start(app: tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let index = args.iter().position(|s| s == "--native-bridge").ok_or("Native transport is required")?;
    let path = Path::new(args.get(index + 1).ok_or("Missing socket path")?);
    if path.as_os_str().len() >= 104 { return Err("Socket path is too long".into()); }
    let parent = path.parent().ok_or("Missing socket directory")?;
    let meta = std::fs::symlink_metadata(parent)?;
    let uid = unsafe { libc::getuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err("Socket directory must be private and owned by the user".into());
    }
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if !existing.file_type().is_socket() || existing.uid() != uid {
            return Err("Refusing to replace a foreign socket path".into());
        }
        if UnixStream::connect(path).is_ok() { return Err("Engine socket is already in use".into()); }
        std::fs::remove_file(path)?;
    }
    let token_path = parent.join("session");
    let metadata = std::fs::symlink_metadata(&token_path)?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err("Session file must be private".into());
    }
    let token = std::fs::read_to_string(token_path)?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid session token".into());
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let clients = Arc::new(AtomicUsize::new(0));
    let events = EVENTS.get_or_init(|| Arc::new(Mutex::new(VecDeque::new()))).clone();
    app.listen_any("interceptor://risk-detected", {
        let events = events.clone(); move |event| record_event(&events, "interceptor://risk-detected", event)
    });
    app.listen_any("interceptor://enriched", {
        let events = events.clone(); move |event| record_event(&events, "interceptor://enriched", event)
    });
    app.listen_any("interceptor://resolved", move |event| record_event(&events, "interceptor://resolved", event));
    std::thread::Builder::new().name("armor-native-ipc".into()).spawn(move || {
        for stream in listener.incoming().flatten() {
            if clients.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                clients.fetch_sub(1, Ordering::SeqCst); continue;
            }
            let clients = clients.clone(); let app = app.clone(); let token = token.clone();
            std::thread::spawn(move || {
                let _ = serve(stream, app, &token);
                clients.fetch_sub(1, Ordering::SeqCst);
            });
        }
    })?;
    Ok(())
}

fn record_event(events: &Mutex<VecDeque<Value>>, name: &str, event: tauri::Event) {
    if let Ok(payload) = serde_json::from_str::<Value>(event.payload()) {
        if let Ok(mut events) = events.lock() {
            if events.len() >= 128 { events.pop_front(); }
            events.push_back(json!({"name":name,"payload":payload}));
        }
    }
}

fn authenticated(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |difference, (x,y)| difference | (x ^ y)) == 0
}

fn serve(mut stream: UnixStream, app: tauri::AppHandle, token: &str) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut uid = 0; let mut gid = 0;
    use std::os::fd::AsRawFd;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 || uid != unsafe { libc::getuid() } {
        return Ok(());
    }
    let mut bytes = Vec::new();
    let mut reader = BufReader::new(stream.try_clone()?);
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() { return Ok(()); }
        let count = available.iter().position(|b| *b == b'\n').map_or(available.len(), |n| n+1);
        if bytes.len() + count > MAX_REQUEST { return Ok(()); }
        bytes.extend_from_slice(&available[..count]); reader.consume(count);
        if bytes.last() == Some(&b'\n') { break; }
    }
    let request: Request = match serde_json::from_slice(&bytes) { Ok(r) => r, Err(_) => return Ok(()) };
    if !authenticated(&request.token, token) { return Ok(()); }
    // Heartbeats remain responsive during a long audit. Configuration changes
    // and shutdown are serialized, so a queued enable cannot outlive cleanup.
    let _configuration = if read_only(&request.command) { None } else {
        Some(CONFIGURATION_LOCK.lock().map_err(|_| std::io::Error::other("Configuration lock failed"))?)
    };
    let shutdown = request.command == "native_shutdown";
    let response = if request.command == "native_ping" {
        Ok(json!({"protocol":1,"engine":"Russian Armor","version":env!("CARGO_PKG_VERSION")}))
    } else if smoke_mode() && !["native_shutdown", "get_state", "get_startup_state", "native_poll_events"].contains(&request.command.as_str()) {
        Err(json!({"message":"Mutation and network commands are disabled in smoke tests"}))
    } else if request.command == "native_poll_events" {
        let events = EVENTS.get_or_init(|| Arc::new(Mutex::new(VecDeque::new())));
        Ok(json!(events.lock().map(|mut events| events.drain(..).collect::<Vec<_>>()).unwrap_or_default()))
    } else if shutdown {
        if smoke_mode() {
            serde_json::to_writer(&mut stream, &json!({"ok":true,"value":true}))?;
            stream.write_all(b"\n")?; stream.flush()?;
            app.exit(0);
            return Ok(());
        }
        crate::startup::note_shutdown(&app);
        match crate::sysproxy::cleanup_on_shutdown_once(Some(&app), "native-quit") {
            Some(report) if report.has_failures() => {
                crate::sysproxy::reset_shutdown_cleanup_guard();
                Err(json!({"message":"Не все настройки восстановлены. Закройте браузеры и повторите выход из Russian Armor."}))
            },
            _ => Ok(json!(true)),
        }
    } else {
        let startup = app.state::<Arc<crate::startup::StartupState>>();
        if startup.is_shutting_down() && !read_only(&request.command) {
            Err(json!({"message":"Сетевой модуль завершает восстановление. Закройте браузеры и повторите выход из Russian Armor."}))
        } else if !startup.is_ready() && !["get_state", "get_startup_state"].contains(&request.command.as_str()) {
            Err(json!({"message":"Startup recovery is still running; retry after it completes"}))
        } else {
            tauri::async_runtime::block_on(crate::native_dispatch::dispatch(app.clone(), &request.command, request.args))
        }
    };
    let success = response.is_ok();
    let envelope = match response { Ok(value) => json!({"ok":true,"value":value}), Err(error) => json!({"ok":false,"error":error}) };
    serde_json::to_writer(&mut stream, &envelope)?;
    stream.write_all(b"\n")?; stream.flush()?;
    if shutdown && success { app.exit(0); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn tokens_and_arguments_fail_closed() {
        assert!(authenticated("abcdef", "abcdef"));
        assert!(!authenticated("abcdeg", "abcdef"));
        assert!(!authenticated("abc", "abcdef"));
        assert!(argument::<String>(&json!({}), "key").is_err());
        assert_eq!(argument::<Option<String>>(&json!({}), "key").unwrap(), None);
        assert_eq!(argument::<bool>(&json!({"enabled":true}), "enabled").unwrap(), true);
        assert!(read_only("native_ping"));
        assert!(read_only("get_state"));
        assert!(!read_only("toggle_sysproxy"));
        assert!(!read_only("get_coverage_snapshot"));
        assert!(!read_only("native_shutdown"));
    }
}
