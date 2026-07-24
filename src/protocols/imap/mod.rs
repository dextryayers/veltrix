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
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut buf = Vec::new();

    buf_reader.read_until(b'\n', &mut buf).await
        .map_err(|e| format!("Read greeting: {}", e))?;

    let cmd = format!("a001 LOGIN {} {}\r\n", username, password);
    writer.write_all(cmd.as_bytes()).await
        .map_err(|e| format!("LOGIN cmd: {}", e))?;
    writer.flush().await.ok();

    buf.clear();
    let mut resp = String::new();
    loop {
        buf.clear();
        let n = buf_reader.read_until(b'\n', &mut buf).await
            .map_err(|e| format!("Read resp: {}", e))?;
        if n == 0 {
            break;
        }
        resp.push_str(&String::from_utf8_lossy(&buf));
        if resp.contains("a001 ") {
            break;
        }
    }

    let _ = writer.write_all(b"a002 LOGOUT\r\n").await;

    let resp_lower = resp.to_lowercase();
    let success = resp_lower.contains("a001 ok");

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
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
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
