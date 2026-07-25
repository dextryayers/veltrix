use async_trait::async_trait;
use std::time::{Duration, Instant};
use ssh2::Session;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct SshProtocol;

#[async_trait]
impl Protocol for SshProtocol {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn default_port(&self) -> u16 {
        22
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();

        let connect_result = match timeout(timeout_dur, async {
            let stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => {
                    let s = TcpStream::connect(&addr).await
                        .map_err(|e| format!("Connect: {}", e))?;
                    s.set_nodelay(true).ok();
                    s
                },
            };

            let std_stream = stream.into_std()
                .map_err(|e| format!("Stream conversion: {}", e))?;

            let target_c = target.clone();
            let username = credential.username.clone();
            let password = credential.password.clone();
            let timeout_c = timeout_dur;

            let result: Result<AuthResult, String> = tokio::task::spawn_blocking(move || {
                std_stream.set_read_timeout(Some(timeout_c)).ok();
                std_stream.set_write_timeout(Some(timeout_c)).ok();
                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => return Ok(AuthResult::new(
                        target_c.host.clone(), target_c.port, "ssh",
                        username, password,
                        false, start.elapsed(), Some(format!("Session init: {}", e)),
                    )),
                };
                session.set_tcp_stream(std_stream);
                if let Err(e) = session.handshake() {
                    return Ok(AuthResult::new(
                        target_c.host.clone(), target_c.port, "ssh",
                        username, password,
                        false, start.elapsed(), Some(format!("SSH handshake: {}", e)),
                    ));
                }
                match session.userauth_password(&username, &password) {
                    Ok(()) => Ok(AuthResult::new(
                        target_c.host.clone(), target_c.port, "ssh",
                        username, password,
                        true, start.elapsed(), None,
                    )),
                    Err(e) => Ok(AuthResult::new(
                        target_c.host.clone(), target_c.port, "ssh",
                        username, password,
                        false, start.elapsed(), Some(e.to_string()),
                    )),
                }
            }).await.map_err(|e| format!("Task error: {}", e))?;

            result
        }).await {
            Ok(r) => r,
            Err(_) => return AuthResult::new(
                target.host.clone(), target.port, "ssh",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        };

        match connect_result {
            Ok(r) => r,
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "ssh",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
        }
    }
}
