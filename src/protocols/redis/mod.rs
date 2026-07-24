use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct RedisProtocol;

async fn redis_auth(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    target: &Target,
    credential: &Credential,
    start: Instant,
) -> Result<AuthResult, String> {
    let cmd = format!("AUTH {} {}\r\n", credential.username, credential.password);
    writer.write_all(cmd.as_bytes()).await
        .map_err(|e| format!("AUTH cmd: {}", e))?;
    writer.flush().await.ok();

    let mut buf = String::new();
    reader.read_line(&mut buf).await
        .map_err(|e| format!("Read resp: {}", e))?;

    let trimmed = buf.trim();
    if trimmed.starts_with("+OK") {
        Ok(AuthResult::new(target.host.clone(), target.port, "redis",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(), None))
    } else if trimmed.starts_with("-ERR") || trimmed.starts_with("-NOAUTH") {
        Ok(AuthResult::new(target.host.clone(), target.port, "redis",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(trimmed.to_string())))
    } else {
        Ok(AuthResult::new(target.host.clone(), target.port, "redis",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("Unexpected: {}", trimmed))))
    }
}

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
        let use_tls = target.port == 6380;

        match timeout(timeout_dur, async {
            let addr = target.addr_string();
            let stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            if use_tls {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                let mut tls_stream = connector.connect(&target.host, stream).await
                    .map_err(|e| format!("TLS connect: {}", e))?;

                let cmd = format!("AUTH {} {}\r\n", credential.username, credential.password);
                tls_stream.write_all(cmd.as_bytes()).await
                    .map_err(|e| format!("AUTH cmd: {}", e))?;
                tls_stream.flush().await.ok();

                let mut buf = vec![0u8; 4096];
                let n = tls_stream.read(&mut buf).await
                    .map_err(|e| format!("Read resp: {}", e))?;
                let trimmed = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                if trimmed.starts_with("+OK") {
                    return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None));
                }
                return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(trimmed)));
            }

            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            redis_auth(&mut buf_reader, &mut writer, target, credential, start).await
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "redis",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "redis",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
