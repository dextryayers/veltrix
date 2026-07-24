use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct RedisProtocol;

#[async_trait]
impl Protocol for RedisProtocol {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn default_port(&self) -> u16 {
        6379
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();

        match timeout(timeout_dur, async {
            let addr = target.addr_string();
            let mut stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            let cmd = format!("AUTH {} {}\r\n", credential.username, credential.password);
            stream.write_all(cmd.as_bytes()).await
                .map_err(|e| format!("AUTH cmd: {}", e))?;
            stream.flush().await.ok();

            let mut buf_reader = BufReader::new(&mut stream);
            let mut buf = String::new();
            buf_reader.read_line(&mut buf).await
                .map_err(|e| format!("Read resp: {}", e))?;

            let trimmed = buf.trim();
            if trimmed.starts_with("+OK") {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "redis",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ))
            } else if trimmed.starts_with("-ERR") || trimmed.starts_with("-NOAUTH") {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "redis",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(trimmed.to_string()),
                ))
            } else {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "redis",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Unexpected: {}", trimmed)),
                ))
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "redis",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "redis",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
