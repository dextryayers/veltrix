use async_trait::async_trait;
use std::time::{Duration, Instant};
use ssh2::{Session, KeyboardInteractivePrompt, Prompt};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;
use super::tcp::{connect_optimized, tune_tcp};

pub struct SshProtocol;

struct PwdPrompt {
    password: String,
}

impl KeyboardInteractivePrompt for PwdPrompt {
    fn prompt<'a>(
        &mut self,
        _username: &str,
        _instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String> {
        prompts.iter()
            .map(|p| {
                if p.echo { String::new() } else { self.password.clone() }
            })
            .collect()
    }
}

#[async_trait]
impl Protocol for SshProtocol {
    fn name(&self) -> &'static str { "ssh" }
    fn default_port(&self) -> u16 { 22 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();

        let stream = match timeout(timeout_dur, async {
            match proxy {
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Proxy connect: {}", e))?;
                    tune_tcp(&s);
                    Ok(s)
                },
                None => connect_optimized(&addr, timeout_dur).await,
            }
        }).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return AuthResult::new(
                target.host.clone(), target.port, "ssh",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => return AuthResult::new(
                target.host.clone(), target.port, "ssh",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout connecting".into()),
            ),
        };

        let std_stream = match stream.into_std() {
            Ok(s) => s,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, "ssh",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Stream conversion: {}", e)),
            ),
        };

        let target_c = target.clone();
        let username = credential.username.clone();
        let password = credential.password.clone();
        let timeout_c = timeout_dur;

        let spawn_result = tokio::time::timeout(timeout_c, tokio::task::spawn_blocking(move || {
            std_stream.set_read_timeout(Some(timeout_c)).ok();
            std_stream.set_write_timeout(Some(timeout_c)).ok();
            let mut session = match Session::new() {
                Ok(s) => s,
                Err(e) => return AuthResult::new(
                    target_c.host, target_c.port, "ssh",
                    username, password,
                    false, start.elapsed(), Some(format!("Session init: {}", e)),
                ),
            };
            session.set_tcp_stream(std_stream);
            session.set_timeout(timeout_c.as_millis() as u32);
            if let Err(e) = session.handshake() {
                return AuthResult::new(
                    target_c.host, target_c.port, "ssh",
                    username, password,
                    false, start.elapsed(), Some(format!("SSH handshake: {}", e)),
                );
            }
            let pwd = password.clone();
            match session.userauth_password(&username, &password) {
                Ok(()) => AuthResult::new(
                    target_c.host, target_c.port, "ssh",
                    username, password,
                    true, start.elapsed(), None,
                ),
                Err(e) => {
                    if e.code() == ssh2::ErrorCode::Session(-18) {
                        return AuthResult::new(
                            target_c.host, target_c.port, "ssh",
                            username, password,
                            false, start.elapsed(), Some(e.to_string()),
                        );
                    }
                    let mut pwd_prompt = PwdPrompt { password: pwd };
                    match session.userauth_keyboard_interactive(
                        &username,
                        &mut pwd_prompt,
                    ) {
                        Ok(()) => AuthResult::new(
                            target_c.host, target_c.port, "ssh",
                            username, password,
                            true, start.elapsed(), None,
                        ),
                        Err(e2) => AuthResult::new(
                            target_c.host, target_c.port, "ssh",
                            username, password,
                            false, start.elapsed(), Some(e2.to_string()),
                        ),
                    }
                }
            }
        })).await;

        match spawn_result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "ssh",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e.to_string()),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "ssh",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
