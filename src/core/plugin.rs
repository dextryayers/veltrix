use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::credential::Credential;
use super::error::AttackError;
use super::result::AuthResult;
use super::target::Target;
use crate::proxy::ProxyConfig;

static PLUGIN_REGISTRY: OnceLock<std::sync::Mutex<HashMap<String, PluginEntry>>> = OnceLock::new();

fn registry() -> &'static std::sync::Mutex<HashMap<String, PluginEntry>> {
    PLUGIN_REGISTRY.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

#[derive(Clone)]
pub struct PluginEntry {
    pub name: String,
    pub path: String,
    pub default_port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct PluginRequest {
    host: String,
    port: u16,
    protocol: String,
    username: String,
    password: String,
    timeout_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PluginResponse {
    success: bool,
    error: Option<String>,
    duration_ms: u64,
}

pub fn register_plugin(name: &str, path: &str, default_port: u16) {
    let mut reg = registry().lock().unwrap();
    reg.insert(
        name.to_lowercase(),
        PluginEntry {
            name: name.to_string(),
            path: path.to_string(),
            default_port,
        },
    );
    log::info!("Registered plugin: {} -> {}", name, path);
}

pub fn get_plugin(name: &str) -> Option<PluginEntry> {
    let reg = registry().lock().unwrap();
    reg.get(&name.to_lowercase()).cloned()
}

#[allow(dead_code)]
pub fn list_plugins() -> Vec<String> {
    let reg = registry().lock().unwrap();
    let mut names: Vec<String> = reg.keys().cloned().collect();
    names.sort();
    names
}

#[allow(dead_code)]
pub fn clear_plugins() {
    let mut reg = registry().lock().unwrap();
    reg.clear();
}

#[allow(dead_code)]
pub fn has_plugin(name: &str) -> bool {
    let reg = registry().lock().unwrap();
    reg.contains_key(&name.to_lowercase())
}

pub async fn execute_plugin(
    entry: &PluginEntry,
    target: &Target,
    credential: &Credential,
    timeout: Duration,
    _proxy: &Option<ProxyConfig>,
) -> AuthResult {
    let start = std::time::Instant::now();

    let request = PluginRequest {
        host: target.host.clone(),
        port: target.port,
        protocol: target.protocol.clone(),
        username: credential.username.clone(),
        password: credential.password.clone(),
        timeout_secs: timeout.as_secs(),
    };

    let request_json = match serde_json::to_string(&request) {
        Ok(j) => j,
        Err(e) => {
            return AuthResult::new(
                target.host.clone(),
                target.port,
                &target.protocol,
                credential.username.clone(),
                credential.password.clone(),
                false,
                start.elapsed(),
                Some(format!("Plugin serialization error: {}", e)),
            );
        }
    };

    let mut cmd = tokio::process::Command::new(&entry.path);
    cmd.arg("--authenticate")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return AuthResult::new(
                target.host.clone(),
                target.port,
                &target.protocol,
                credential.username.clone(),
                credential.password.clone(),
                false,
                start.elapsed(),
                Some(format!("Plugin spawn error: {}", e)),
            );
        }
    };

    if let Some(stdin) = child.stdin.as_mut() {
        let mut msg = request_json.clone();
        msg.push('\n');
        if let Err(e) = stdin.write_all(msg.as_bytes()).await {
            let _ = child.kill().await;
            return AuthResult::new(
                target.host.clone(),
                target.port,
                &target.protocol,
                credential.username.clone(),
                credential.password.clone(),
                false,
                start.elapsed(),
                Some(format!("Plugin stdin error: {}", e)),
            );
        }
    }
    drop(child.stdin.take());

    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut response_line = String::new();
    match tokio::time::timeout(timeout, stdout.read_line(&mut response_line)).await {
        Ok(Ok(n)) if n > 0 => {
            let response: PluginResponse = match serde_json::from_str(response_line.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return AuthResult::new(
                        target.host.clone(),
                        target.port,
                        &target.protocol,
                        credential.username.clone(),
                        credential.password.clone(),
                        false,
                        start.elapsed(),
                        Some(format!("Plugin JSON parse error: {} — raw: {}", e, response_line.trim())),
                    );
                }
            };

            let _ = child.kill().await;
            let _ = child.wait().await;

            AuthResult::new(
                target.host.clone(),
                target.port,
                &target.protocol,
                credential.username.clone(),
                credential.password.clone(),
                response.success,
                Duration::from_millis(response.duration_ms),
                response.error,
            )
        }
        Ok(Ok(_)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            AuthResult::new(
                target.host.clone(),
                target.port,
                &target.protocol,
                credential.username.clone(),
                credential.password.clone(),
                false,
                start.elapsed(),
                Some("Plugin returned empty response".into()),
            )
        }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            AuthResult::new(
                target.host.clone(),
                target.port,
                &target.protocol,
                credential.username.clone(),
                credential.password.clone(),
                false,
                start.elapsed(),
                Some(format!("Plugin read error: {}", e)),
            )
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            AuthResult::new(
                target.host.clone(),
                target.port,
                &target.protocol,
                credential.username.clone(),
                credential.password.clone(),
                false,
                start.elapsed(),
                Some("Plugin timed out".into()),
            )
        }
    }
}

pub fn validate_plugin_binary(path: &str) -> Result<PluginEntry, AttackError> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| AttackError::config(format!("Plugin not found at '{}': {}", path, e)))?;

    if !metadata.is_file() {
        return Err(AttackError::config(format!("Plugin path is not a file: {}", path)));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = metadata.permissions();
        if perms.mode() & 0o111 == 0 {
            return Err(AttackError::config(format!(
                "Plugin '{}' is not executable. Run 'chmod +x {}'",
                path, path
            )));
        }
    }

    let name = std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin")
        .to_string();

    Ok(PluginEntry {
        name,
        path: path.to_string(),
        default_port: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::Mutex;

    /// Ensure plugin tests are serialized to avoid global state conflicts
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn serialize() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn test_register_and_get_plugin() {
        let _lock = serialize();
        clear_plugins();
        register_plugin("tg1", "/usr/bin/tg1", 9999);
        let entry = get_plugin("tg1").unwrap();
        assert_eq!(entry.name, "tg1");
        assert_eq!(entry.path, "/usr/bin/tg1");
        assert_eq!(entry.default_port, 9999);
    }

    #[test]
    fn test_register_and_get_plugin_case_insensitive() {
        let _lock = serialize();
        clear_plugins();
        register_plugin("TestProto", "/usr/bin/test", 1234);
        assert!(has_plugin("testproto"));
        assert!(has_plugin("TestProto"));
        assert!(has_plugin("TESTPROTO"));
    }

    #[test]
    fn test_get_plugin_nonexistent() {
        let _lock = serialize();
        clear_plugins();
        assert!(get_plugin("nonexistent_test").is_none());
    }

    #[test]
    fn test_has_plugin() {
        let _lock = serialize();
        clear_plugins();
        register_plugin("has_test", "/bin/test", 1111);
        assert!(has_plugin("has_test"));
        assert!(!has_plugin("nonexistent_other"));
    }

    #[test]
    fn test_list_plugins() {
        let _lock = serialize();
        clear_plugins();
        register_plugin("z_plugin", "/bin/z", 1);
        register_plugin("a_plugin", "/bin/a", 2);
        let list = list_plugins();
        assert_eq!(list, vec!["a_plugin", "z_plugin"]);
    }

    #[test]
    fn test_clear_plugins() {
        let _lock = serialize();
        clear_plugins();
        register_plugin("xclear", "/usr/x", 1);
        assert!(has_plugin("xclear"));
        clear_plugins();
        assert!(!has_plugin("xclear"));
    }

    #[test]
    fn test_validate_plugin_binary_not_found() {
        let _lock = serialize();
        let result = validate_plugin_binary("/nonexistent/plugin");
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_entry_clone() {
        // No lock needed - no global state
        let e1 = PluginEntry {
            name: "p".into(),
            path: "/bin/p".into(),
            default_port: 8080,
        };
        let e2 = e1.clone();
        assert_eq!(e1.name, e2.name);
        assert_eq!(e1.path, e2.path);
        assert_eq!(e1.default_port, e2.default_port);
    }
}
