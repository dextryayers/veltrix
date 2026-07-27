pub mod negotiation;

use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::tcp::{connect_optimized, tune_tcp, alloc_read_buf};
use super::Protocol;

pub struct TelnetProtocol;

const SUCCESS_INDICATORS: &[&str] = &[
    "last login", "$ ", "# ", "> ", "~$ ",
    "welcome", "shell", "terminal",
];
const FAILURE_INDICATORS: &[&str] = &[
    "incorrect", "invalid", "failed", "denied", "wrong",
    "error", "try again", "unauthorized", "rejected",
    "bad", "failed login",
];

#[async_trait]
impl Protocol for TelnetProtocol {
    fn name(&self) -> &'static str { "telnet" }
    fn default_port(&self) -> u16 { 23 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();

        match timeout(timeout_dur, async {
            let mut stream = match proxy {
                Some(p) => {
                    let s = p.tcp_connect(&target.addr_string(), timeout_dur).await
                        .map_err(|e| format!("Proxy connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => connect_optimized(&target.addr_string(), timeout_dur).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            // Read initial data and handle telnet negotiation
            let mut buf = alloc_read_buf();
            let banner_read = timeout(Duration::from_secs(2), async {
                let mut total = 0usize;
                loop {
                    match stream.read(&mut buf[total..]).await {
                        Ok(0) => break,
                        Ok(n) => {
                            // Handle telnet negotiation
                            let neg = negotiation::handle_telnet_negotiation(&buf[total..total + n]);
                            if !neg.is_empty() {
                                stream.write_all(&neg).await.ok();
                            }

                            total += n;
                            // Check for prompt characters in received data
                            let data = String::from_utf8_lossy(&buf[..total]);
                            let data_lower = data.to_lowercase();
                            if data_lower.contains(':') || data_lower.contains("login:")
                                || data_lower.contains("username:")
                                || data_lower.contains("password:")
                                || data_lower.contains("user:")
                            {
                                break;
                            }
                            if total >= buf.len() { break; }
                        }
                        Err(_) => break,
                    }
                }
                Ok::<usize, String>(total)
            }).await.unwrap_or(Ok(0)).unwrap_or(0);

            let initial = String::from_utf8_lossy(&buf[..banner_read]);
            let initial_lower = initial.to_lowercase();

            // Check if we got a password prompt directly (no login needed)
            if initial_lower.contains("password:") {
                stream.write_all(format!("{}\r\n", credential.password).as_bytes()).await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
            } else {
                // Send username
                stream.write_all(format!("{}\r\n", credential.username).as_bytes()).await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;

                tokio::time::sleep(Duration::from_millis(200)).await;

                // Wait for password prompt
                let mut pw_buf = alloc_read_buf();
                let pw_read = timeout(Duration::from_secs(2), async {
                    let mut total = 0usize;
                    loop {
                        match stream.read(&mut pw_buf[total..]).await {
                            Ok(0) => break,
                            Ok(n) => {
                                total += n;
                                if total >= pw_buf.len() { break; }
                                let data = String::from_utf8_lossy(&pw_buf[..total]);
                                if data.contains(':') || data.contains("assword") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    Ok::<usize, String>(total)
                }).await.unwrap_or(Ok(0)).unwrap_or(0);

                stream.write_all(format!("{}\r\n", credential.password).as_bytes()).await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
            }

            // Read auth response - collect all data with timeout
            let mut resp = String::new();
            let mut resp_buf = alloc_read_buf();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                match timeout(remaining, stream.read(&mut resp_buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        resp.push_str(&String::from_utf8_lossy(&resp_buf[..n]));
                        let resp_lower = resp.to_lowercase();

                        // Check for success indicators
                        let has_success = SUCCESS_INDICATORS.iter().any(|s| resp_lower.contains(s));
                        let has_failure = FAILURE_INDICATORS.iter().any(|s| resp_lower.contains(s));

                        if has_success && !has_failure {
                            return Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                                credential.username.clone(), credential.password.clone(),
                                true, start.elapsed(), None));
                        }
                        if has_failure {
                            return Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                                credential.username.clone(), credential.password.clone(),
                                false, start.elapsed(), Some(resp.trim().to_string())));
                        }
                    }
                    _ => break,
                }
            }

            let resp_lower = resp.to_lowercase();
            let success = resp_lower.contains("last login") || resp_lower.contains("$ ")
                || resp_lower.contains("# ") || resp_lower.contains("> ")
                || (!FAILURE_INDICATORS.iter().any(|s| resp_lower.contains(s)) && !resp_lower.contains("assword:"));

            Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(),
                if success { None } else { Some(resp.trim().to_string()) }))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
