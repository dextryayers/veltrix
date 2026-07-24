use async_trait::async_trait;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use ssh2::Session;

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
        timeout: Duration,
        _proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let target_c = target.clone();
        let cred = credential.clone();
        let timeout_c = timeout;

        let result = tokio::task::spawn_blocking(move || {
            let _addr = target_c.addr_string();
            match TcpStream::connect_timeout(
                &format!("{}:{}", target_c.host, target_c.port).parse().unwrap_or_else(|_| {
                    std::net::SocketAddr::new("0.0.0.0".parse().unwrap(), target_c.port)
                }),
                timeout_c,
            ) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(timeout_c)).ok();
                    stream.set_write_timeout(Some(timeout_c)).ok();
                    let mut session = Session::new().unwrap();
                    session.set_tcp_stream(stream);
                    session.handshake().ok();
                    match session.userauth_password(&cred.username, &cred.password) {
                        Ok(()) => AuthResult::new(
                            target_c.host.clone(),
                            target_c.port,
                            "ssh",
                            cred.username.clone(),
                            cred.password.clone(),
                            true,
                            start.elapsed(),
                            None,
                        ),
                        Err(e) => AuthResult::new(
                            target_c.host.clone(),
                            target_c.port,
                            "ssh",
                            cred.username.clone(),
                            cred.password.clone(),
                            false,
                            start.elapsed(),
                            Some(e.to_string()),
                        ),
                    }
                }
                Err(e) => AuthResult::new(
                    target_c.host.clone(),
                    target_c.port,
                    "ssh",
                    cred.username.clone(),
                    cred.password.clone(),
                    false,
                    start.elapsed(),
                    Some(format!("Connection failed: {}", e)),
                ),
            }
        }).await;

        match result {
            Ok(r) => r,
            Err(e) => AuthResult::new(
                target.host.clone(),
                target.port,
                "ssh",
                credential.username.clone(),
                credential.password.clone(),
                false,
                start.elapsed(),
                Some(format!("Task error: {}", e)),
            ),
        }
    }
}
