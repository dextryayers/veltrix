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
    "welcome", "shell",
];
const FAILURE_INDICATORS: &[&str] = &[
    "incorrect", "invalid", "failed", "denied", "wrong",
    "error", "try again", "unauthorized", "rejected",
    "bad", "failed login", "login failed",
];

async fn read_with_negotiation(
    stream: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
    timeout_dur: Duration,
    stop_chars: &[char],
) -> Result<usize, String> {
    let start = tokio::time::Instant::now();
    let mut total = 0usize;
    loop {
        let remaining = timeout_dur.saturating_sub(start.elapsed());
        if remaining.is_zero() { break; }
        let mut byte = [0u8; 1];
        match timeout(remaining, stream.read(&mut byte)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                if byte[0] == 255 {
                    let mut iac = [0u8; 2];
                    if stream.read_exact(&mut iac).await.is_ok() {
                        match iac[0] {
                            253 | 251 => {
                                let resp = [255, if iac[0] == 253 { 252 } else { 254 }, iac[1]];
                                stream.write_all(&resp).await.ok();
                            }
                            _ => {}
                        }
                    }
                } else {
                    if total < buf.len() {
                        buf[total] = byte[0];
                    }
                    total += 1;
                    let c = byte[0] as char;
                    if stop_chars.contains(&c) {
                        break;
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    Ok(total)
}

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

            let mut buf = alloc_read_buf();

            // Wait for login prompt (max 3s, stop at ':' or "login" or "user")
            let banner_len = read_with_negotiation(
                &mut stream, &mut buf, Duration::from_secs(3), &[':'],
            ).await.map_err(|e| e)?;

            let initial = String::from_utf8_lossy(&buf[..banner_len]);
            let initial_lower = initial.to_lowercase();

            if initial_lower.contains("password:") {
                // Direct password-only prompt
                stream.write_all(format!("{}\r\n", credential.password).as_bytes()).await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
            } else {
                // Send username
                stream.write_all(format!("{}\r\n", credential.username).as_bytes()).await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;

                // Wait for password prompt (max 1.5s, stop at ':' or "assword")
                let mut pw_buf = alloc_read_buf();
                let pw_len = read_with_negotiation(
                    &mut stream, &mut pw_buf, Duration::from_millis(1500), &[':'],
                ).await.map_err(|e| e)?;

                let pw_prompt = String::from_utf8_lossy(&pw_buf[..pw_len]);
                if !pw_prompt.to_lowercase().contains("assword") && !pw_prompt.contains(':') {
                    // No password prompt detected, might be on wrong path
                    return Ok(AuthResult::new(target.host.clone(), target.port, "telnet",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some("No password prompt".into())));
                }

                stream.write_all(format!("{}\r\n", credential.password).as_bytes()).await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
            }

            // Read response (max 2s)
            let mut resp = String::new();
            let mut resp_buf = alloc_read_buf();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                match timeout(remaining, stream.read(&mut resp_buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Filter IAC bytes from response
                        let clean: Vec<u8> = resp_buf[..n].iter().copied().filter(|&b| b != 255).collect();
                        resp.push_str(&String::from_utf8_lossy(&clean));
                        let resp_lower = resp.to_lowercase();

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
