use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::tcp::{connect_optimized, tune_tcp};
use super::Protocol;

pub struct RedisProtocol;

async fn try_cmd(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    cmd: &str,
) -> Result<String, String> {
    writer.write_all(cmd.as_bytes()).await
        .map_err(|e| format!("Write cmd: {}", e))?;
    writer.flush().await
        .map_err(|e| format!("Flush cmd: {}", e))?;
    let mut buf = String::new();
    reader.read_line(&mut buf).await
        .map_err(|e| format!("Read resp: {}", e))?;
    Ok(buf.trim().to_string())
}

async fn redis_auth(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    target: &Target,
    credential: &Credential,
    start: Instant,
) -> Result<AuthResult, String> {
    let resp = try_cmd(reader, writer, "PING\r\n").await?;
    if resp == "+PONG" {
        return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(), None));
    }

    let cmd = format!("AUTH {} {}\r\n", credential.username, credential.password);
    let resp = try_cmd(reader, writer, &cmd).await?;
    if resp.starts_with("+OK") {
        return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(), None));
    }

    if resp.contains("wrong number of arguments") {
        let cmd = format!("AUTH {}\r\n", credential.password);
        let resp = try_cmd(reader, writer, &cmd).await?;
        if resp.starts_with("+OK") {
            return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                credential.username.clone(), credential.password.clone(),
                true, start.elapsed(), None));
        }
        return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(resp)));
    }

    Ok(AuthResult::new(target.host.clone(), target.port, "redis",
        credential.username.clone(), credential.password.clone(),
        false, start.elapsed(), Some(resp)))
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
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Proxy connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => connect_optimized(&addr, timeout_dur).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            if use_tls {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                let tls_stream = connector.connect(&target.host, stream).await
                    .map_err(|e| format!("TLS connect: {}", e))?;

                let (r, w) = tokio::io::split(tls_stream);
                let mut reader = BufReader::new(r);
                let mut writer = w;

                let resp = {
                    let cmd = "PING\r\n";
                    writer.write_all(cmd.as_bytes()).await
                        .map_err(|e| format!("Write cmd: {}", e))?;
                    writer.flush().await
                        .map_err(|e| format!("Flush PING: {}", e))?;
                    let mut buf = String::new();
                    reader.read_line(&mut buf).await
                        .map_err(|e| format!("Read resp: {}", e))?;
                    buf.trim().to_string()
                };

                if resp == "+PONG" {
                    return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None));
                }

                let resp = {
                    let cmd = format!("AUTH {} {}\r\n", credential.username, credential.password);
                    writer.write_all(cmd.as_bytes()).await
                        .map_err(|e| format!("Write cmd: {}", e))?;
                    writer.flush().await
                        .map_err(|e| format!("Flush AUTH: {}", e))?;
                    let mut buf = String::new();
                    reader.read_line(&mut buf).await
                        .map_err(|e| format!("Read resp: {}", e))?;
                    buf.trim().to_string()
                };

                if resp.starts_with("+OK") {
                    return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None));
                }

                if resp.contains("wrong number of arguments") {
                    let resp = {
                        let cmd = format!("AUTH {}\r\n", credential.password);
                        writer.write_all(cmd.as_bytes()).await
                            .map_err(|e| format!("Write cmd: {}", e))?;
                    writer.flush().await
                        .map_err(|e| format!("Flush AUTH: {}", e))?;
                        let mut buf = String::new();
                        reader.read_line(&mut buf).await
                            .map_err(|e| format!("Read resp: {}", e))?;
                        buf.trim().to_string()
                    };

                    if resp.starts_with("+OK") {
                        return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                            credential.username.clone(), credential.password.clone(),
                            true, start.elapsed(), None));
                    }
                    return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some(resp)));
                }

                return Ok(AuthResult::new(target.host.clone(), target.port, "redis",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(resp)));
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
