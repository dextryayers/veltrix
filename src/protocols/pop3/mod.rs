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

pub struct Pop3Protocol;

async fn pop3_auth_tls(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    start: Instant,
    stream: TcpStream,
) -> Result<AuthResult, String> {
    let connector = TlsConnector::from(
        NativeTlsConnector::builder().build()
            .map_err(|e| format!("TLS build: {}", e))?
    );
    let mut tls_stream = connector.connect(host, stream).await
        .map_err(|e| format!("TLS connect: {}", e))?;

    tls_stream.write_all(format!("USER {}\r\n", username).as_bytes()).await
        .map_err(|e| format!("USER cmd: {}", e))?;
    tls_stream.flush().await.ok();

    let mut buf = vec![0u8; 4096];
    let n = tls_stream.read(&mut buf).await
        .map_err(|e| format!("USER resp: {}", e))?;
    let user_resp = String::from_utf8_lossy(&buf[..n]);
    if !user_resp.starts_with("+OK") {
        return Ok(AuthResult::new(
            host.to_string(), port, "pop3",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
        ));
    }

    tls_stream.write_all(format!("PASS {}\r\n", password).as_bytes()).await
        .map_err(|e| format!("PASS cmd: {}", e))?;
    tls_stream.flush().await.ok();

    let mut buf = vec![0u8; 4096];
    let n = tls_stream.read(&mut buf).await
        .map_err(|e| format!("PASS resp: {}", e))?;
    let pass_resp = String::from_utf8_lossy(&buf[..n]);
    let success = pass_resp.starts_with("+OK");

    Ok(AuthResult::new(
        host.to_string(), port, "pop3",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp.trim().to_string()) },
    ))
}

async fn pop3_auth_plain(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    start: Instant,
    stream: TcpStream,
) -> Result<AuthResult, String> {
    let mut buf = vec![0u8; 4096];

    stream.readable().await.ok();
    let n = stream.try_read(&mut buf).unwrap_or(0);
    let banner = String::from_utf8_lossy(&buf[..n]);
    if !banner.starts_with("+OK") {
        return Ok(AuthResult::new(
            host.to_string(), port, "pop3",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim())),
        ));
    }

    // Try STLS (STARTTLS) for POP3
    stream.writable().await.ok();
    stream.try_write(b"STLS\r\n").ok();
    buf.clear();
    stream.readable().await.ok();
    let n = stream.try_read(&mut buf).unwrap_or(0);
    let stls_resp = String::from_utf8_lossy(&buf[..n]);
    if stls_resp.starts_with("+OK") {
        let connector = TlsConnector::from(
            NativeTlsConnector::builder().build()
                .map_err(|e| format!("TLS build: {}", e))?
        );
        match connector.connect(host, stream).await {
            Ok(mut tls_stream) => {
                tls_stream.write_all(format!("USER {}\r\n", username).as_bytes()).await
                    .map_err(|e| format!("USER cmd: {}", e))?;
                tls_stream.flush().await.ok();
                let mut tb = vec![0u8; 4096];
                let n = tls_stream.read(&mut tb).await
                    .map_err(|e| format!("USER resp: {}", e))?;
                let user_resp = String::from_utf8_lossy(&tb[..n]);
                if !user_resp.starts_with("+OK") {
                    return Ok(AuthResult::new(
                        host.to_string(), port, "pop3",
                        username.to_string(), password.to_string(),
                        false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
                    ));
                }

                tls_stream.write_all(format!("PASS {}\r\n", password).as_bytes()).await
                    .map_err(|e| format!("PASS cmd: {}", e))?;
                tls_stream.flush().await.ok();
                let n = tls_stream.read(&mut tb).await
                    .map_err(|e| format!("PASS resp: {}", e))?;
                let pass_resp = String::from_utf8_lossy(&tb[..n]);
                let success = pass_resp.starts_with("+OK");

                return Ok(AuthResult::new(
                    host.to_string(), port, "pop3",
                    username.to_string(), password.to_string(),
                    success, start.elapsed(),
                    if success { None } else { Some(pass_resp.trim().to_string()) },
                ));
            }
            Err(_) => return Ok(AuthResult::new(
                host.to_string(), port, "pop3",
                username.to_string(), password.to_string(),
                false, start.elapsed(), Some("STLS upgrade failed".into()),
            )),
        }
    }

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut buf = Vec::new();

    writer.write_all(format!("USER {}\r\n", username).as_bytes()).await
        .map_err(|e| format!("USER cmd: {}", e))?;
    writer.flush().await.ok();
    buf.clear();
    buf_reader.read_until(b'\n', &mut buf).await
        .map_err(|e| format!("USER resp: {}", e))?;
    let user_resp = String::from_utf8_lossy(&buf);
    if !user_resp.starts_with("+OK") {
        let _ = writer.write_all(b"QUIT\r\n").await;
        return Ok(AuthResult::new(
            host.to_string(), port, "pop3",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
        ));
    }

    writer.write_all(format!("PASS {}\r\n", password).as_bytes()).await
        .map_err(|e| format!("PASS cmd: {}", e))?;
    writer.flush().await.ok();
    buf.clear();
    buf_reader.read_until(b'\n', &mut buf).await
        .map_err(|e| format!("PASS resp: {}", e))?;
    let pass_resp = String::from_utf8_lossy(&buf);
    let success = pass_resp.starts_with("+OK");

    let _ = writer.write_all(b"QUIT\r\n").await;

    Ok(AuthResult::new(
        host.to_string(), port, "pop3",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp.trim().to_string()) },
    ))
}

#[async_trait]
impl Protocol for Pop3Protocol {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn default_port(&self) -> u16 {
        110
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
        let use_tls = target.port == 995;

        match timeout(timeout_dur, async {
            let stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Connect: {}", e))?,
                None => {
                    let s = TcpStream::connect(&addr).await
                        .map_err(|e| format!("Connect: {}", e))?;
                    s.set_nodelay(true).ok();
                    s
                },
            };

            if use_tls {
                pop3_auth_tls(
                    &target.host, target.port,
                    &credential.username, &credential.password,
                    start, stream,
                ).await
            } else {
                pop3_auth_plain(
                    &target.host, target.port,
                    &credential.username, &credential.password,
                    start, stream,
                ).await
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "pop3",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "pop3",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
