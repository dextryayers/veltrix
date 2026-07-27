use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;
use super::tcp::{connect_optimized, tune_tcp, alloc_read_buf};

async fn ftp_auth_inner(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    host: &str, port: u16, credential: &Credential, start: Instant,
) -> AuthResult {
    let mut buf = alloc_read_buf();
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let banner = String::from_utf8_lossy(&buf[..n]);
    if !banner.starts_with("220") {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim())));
    }

    let user_cmd = format!("USER {}\r\n", credential.username);
    stream.write_all(user_cmd.as_bytes()).await.unwrap_or_default();
    stream.flush().await.ok();
    buf.clear();
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let user_resp = String::from_utf8_lossy(&buf[..n]);
    if !user_resp.starts_with("2") && !user_resp.starts_with("3") {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())));
    }

    buf.clear();
    let pass_cmd = format!("PASS {}\r\n", credential.password);
    stream.write_all(pass_cmd.as_bytes()).await.unwrap_or_default();
    stream.flush().await.ok();
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let pass_resp = String::from_utf8_lossy(&buf[..n]);
    let success = pass_resp.starts_with("230");

    AuthResult::new(host.to_string(), port, "ftp",
        credential.username.clone(), credential.password.clone(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp.trim().to_string()) })
}

pub struct FtpProtocol;

#[async_trait]
impl Protocol for FtpProtocol {
    fn name(&self) -> &'static str { "ftp" }
    fn default_port(&self) -> u16 { 21 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();
        let host = target.host.clone();
        let port = target.port;

        match timeout(timeout_dur, async {
            let stream = match proxy {
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Proxy connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => connect_optimized(&addr, timeout_dur).await?,
            };

            if target.port == 990 {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                let mut tls_stream = connector.connect(&host, stream).await
                    .map_err(|e| format!("TLS connect: {}", e))?;
                return Ok(ftp_auth_inner(&mut tls_stream, &host, port, credential, start).await);
            }

            let mut stream = stream;
            let mut buf = alloc_read_buf();
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let banner = String::from_utf8_lossy(&buf[..n]);
            if !banner.starts_with("220") {
                return Ok(AuthResult::new(host, port, "ftp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim()))));
            }

            stream.write_all(b"AUTH TLS\r\n").await.unwrap_or_default();
            buf.clear();
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let auth_resp = String::from_utf8_lossy(&buf[..n]);
            if auth_resp.starts_with("234") {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                match connector.connect(&host, stream).await {
                    Ok(mut tls_stream) => {
                        return Ok(ftp_auth_inner(&mut tls_stream, &host, port, credential, start).await);
                    }
                    Err(e) => {
                        return Ok(AuthResult::new(host, port, "ftp",
                            credential.username.clone(), credential.password.clone(),
                            false, start.elapsed(), Some(format!("TLS upgrade failed: {}", e))));
                    }
                }
            }

            let result = ftp_auth_inner(&mut stream, &host, port, credential, start).await;
            Ok(result)
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "ftp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "ftp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
