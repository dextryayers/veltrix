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
use super::tcp::{connect_optimized, tune_tcp, alloc_read_buf};

pub struct ImapProtocol;

async fn imap_auth_tls(
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

    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let n = tls_stream.read(&mut tmp).await
        .map_err(|e| format!("Read greeting: {}", e))?;
    buf.extend_from_slice(&tmp[..n]);

    let cmd = format!("a001 LOGIN {} {}\r\n", username, password);
    tls_stream.write_all(cmd.as_bytes()).await
        .map_err(|e| format!("LOGIN cmd: {}", e))?;
    tls_stream.flush().await.ok();

    buf.clear();
    let mut resp = String::new();
    loop {
        let n = tls_stream.read(&mut tmp).await
            .map_err(|e| format!("Read resp: {}", e))?;
        if n == 0 {
            break;
        }
        resp.push_str(&String::from_utf8_lossy(&tmp[..n]));
        if resp.contains("a001 ") {
            break;
        }
    }

    let resp_lower = resp.to_lowercase();
    let success = resp_lower.contains("a001 ok");
    let is_fail = resp_lower.contains("a001 no") || resp_lower.contains("a001 bad");

    Ok(AuthResult::new(
        host.to_string(), port, "imap",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else if is_fail { Some("Auth denied".into()) } else { Some(resp.trim().to_string()) },
    ))
}

async fn imap_auth_plain(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    start: Instant,
    stream: TcpStream,
) -> Result<AuthResult, String> {
    let mut buf = alloc_read_buf();

    stream.readable().await.ok();
    let _n = stream.try_read(&mut buf).ok();

    stream.writable().await.ok();
    stream.try_write(b"a001 CAPABILITY\r\n").ok();
    stream.readable().await.ok();
    let _n = stream.try_read(&mut buf).ok();

    let caps = String::from_utf8_lossy(&buf);

    if caps.to_uppercase().contains("STARTTLS") {
        stream.writable().await.ok();
        stream.try_write(b"a002 STARTTLS\r\n").ok();
        buf.clear();
        stream.readable().await.ok();
        let n = stream.try_read(&mut buf).unwrap_or(0);
        let stls_resp = String::from_utf8_lossy(&buf[..n]);
        if stls_resp.starts_with("a002 OK") {
            let connector = TlsConnector::from(
                NativeTlsConnector::builder().build()
                    .map_err(|e| format!("TLS build: {}", e))?
            );
            match connector.connect(host, stream).await {
                Ok(mut tls_stream) => {
                    let mut tb = alloc_read_buf();
                    tls_stream.read(&mut tb).await.ok();
                    let cmd = format!("a003 LOGIN {} {}\r\n", username, password);
                    tls_stream.write_all(cmd.as_bytes()).await.map_err(|e| format!("LOGIN cmd: {}", e))?;
                    tls_stream.flush().await.ok();
                    let mut tresp = String::new();
                    loop {
                        let n = tls_stream.read(&mut tb).await.map_err(|e| format!("Read resp: {}", e))?;
                        if n == 0 { break; }
                        tresp.push_str(&String::from_utf8_lossy(&tb[..n]));
                        if tresp.contains("a003 ") { break; }
                    }
                    let success = tresp.to_lowercase().contains("a003 ok");
                    return Ok(AuthResult::new(host.to_string(), port, "imap",
                        username.to_string(), password.to_string(),
                        success, start.elapsed(),
                        if success { None } else { Some("Auth denied".into()) }));
                }
                Err(e) => {
                    return Ok(AuthResult::new(host.to_string(), port, "imap",
                        username.to_string(), password.to_string(),
                        false, start.elapsed(), Some(format!("STARTTLS failed: {}", e))));
                }
            }
        }
    }

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let cmd = format!("a003 LOGIN {} {}\r\n", username, password);
    writer.write_all(cmd.as_bytes()).await
        .map_err(|e| format!("LOGIN cmd: {}", e))?;
    writer.flush().await.ok();

    let mut resp = String::new();
    loop {
        let mut line = Vec::new();
        let n = buf_reader.read_until(b'\n', &mut line).await
            .map_err(|e| format!("Read resp: {}", e))?;
        if n == 0 { break; }
        resp.push_str(&String::from_utf8_lossy(&line));
        if resp.contains("a003 ") { break; }
    }

    let _ = writer.write_all(b"a004 LOGOUT\r\n").await;

    let resp_lower = resp.to_lowercase();
    let success = resp_lower.contains("a003 ok");

    Ok(AuthResult::new(
        host.to_string(), port, "imap",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some("Auth denied".into()) },
    ))
}

#[async_trait]
impl Protocol for ImapProtocol {
    fn name(&self) -> &'static str {
        "imap"
    }

    fn default_port(&self) -> u16 {
        143
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
        let use_tls = target.port == 993;

        match timeout(timeout_dur, async {
            let stream = match proxy {
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => {
                    connect_optimized(&addr, timeout_dur).await
                        .map_err(|e| format!("Connect: {}", e))?
                },
            };

            if use_tls {
                imap_auth_tls(&target.host, target.port, &credential.username, &credential.password, start, stream).await
            } else {
                imap_auth_plain(&target.host, target.port, &credential.username, &credential.password, start, stream).await
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "imap",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "imap",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
