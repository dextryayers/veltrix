use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct FtpProtocol;

#[async_trait]
impl Protocol for FtpProtocol {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn default_port(&self) -> u16 {
        21
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
        let use_tls = target.port == 990;
        let host = target.host.clone();
        let port = target.port;

        match timeout(timeout_dur, async {
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
                let mut tls_stream = connector.connect(&host, stream).await
                    .map_err(|e| format!("TLS connect: {}", e))?;

                let result = ftp_auth_tls_inner(&mut tls_stream, &host, port, credential, start).await;
                return Ok(result);
            }

            let mut buf = vec![0u8; 4096];

            stream.readable().await.map_err(|e| format!("Banner ready: {}", e))?;
            let n = stream.try_read(&mut buf).map_err(|e| format!("Banner read: {}", e))?;
            let banner = String::from_utf8_lossy(&buf[..n]);
            if !banner.starts_with("220") {
                return Ok(AuthResult::new(
                    host, port, "ftp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim())),
                ));
            }

            stream.writable().await.ok();
            let _= stream.try_write(b"AUTH TLS\r\n");
            buf.clear();
            stream.readable().await.ok();
            let n = stream.try_read(&mut buf).unwrap_or(0);
            let auth_resp = String::from_utf8_lossy(&buf[..n]);
            if auth_resp.starts_with("234") {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                match connector.connect(&host, stream).await {
                    Ok(mut tls_stream) => {
                        let result = ftp_auth_tls_inner(&mut tls_stream, &host, port, credential, start).await;
                        return Ok(result);
                    }
                    Err(e) => {
                        return Ok(AuthResult::new(
                            host, port, "ftp",
                            credential.username.clone(), credential.password.clone(),
                            false, start.elapsed(), Some(format!("TLS upgrade failed: {}", e)),
                        ));
                    }
                }
            }

            buf.clear();
            stream.writable().await.ok();
            stream.try_write(format!("USER {}\r\n", credential.username).as_bytes()).ok();
            stream.readable().await.ok();
            let n = stream.try_read(&mut buf).unwrap_or(0);
            let user_resp = String::from_utf8_lossy(&buf[..n]);
            if !user_resp.starts_with("2") && !user_resp.starts_with("3") {
                stream.writable().await.ok();
                stream.try_write(b"QUIT\r\n").ok();
                return Ok(AuthResult::new(
                    host, port, "ftp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
                ));
            }

            buf.clear();
            stream.writable().await.ok();
            stream.try_write(format!("PASS {}\r\n", credential.password).as_bytes()).ok();
            stream.readable().await.ok();
            let n = stream.try_read(&mut buf).unwrap_or(0);
            let pass_resp = String::from_utf8_lossy(&buf[..n]);
            let success = pass_resp.starts_with("230");

            stream.writable().await.ok();
            stream.try_write(b"QUIT\r\n").ok();

            Ok(AuthResult::new(
                host, port, "ftp",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(),
                if success { None } else { Some(pass_resp.trim().to_string()) },
            ))
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

async fn ftp_auth_tls_inner(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
    host: &str,
    port: u16,
    credential: &Credential,
    start: Instant,
) -> AuthResult {
    let mut buf = vec![0u8; 4096];
    let n = match tls_stream.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("TLS banner read failed".into())),
    };
    let banner = String::from_utf8_lossy(&buf[..n]);
    if !banner.starts_with("220") {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("Bad TLS banner: {}", banner.trim())));
    }

    if tls_stream.write_all(format!("USER {}\r\n", credential.username).as_bytes()).await.is_err() {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("USER cmd failed".into()));
    }
    tls_stream.flush().await.ok();
    buf.clear();
    if tls_stream.read(&mut buf).await.is_err() {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("USER resp failed".into()));
    }
    let user_resp = String::from_utf8_lossy(&buf);
    if !user_resp.starts_with("2") && !user_resp.starts_with("3") {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())));
    }

    buf.clear();
    if tls_stream.write_all(format!("PASS {}\r\n", credential.password).as_bytes()).await.is_err() {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("PASS cmd failed".into()));
    }
    tls_stream.flush().await.ok();
    if tls_stream.read(&mut buf).await.is_err() {
        return AuthResult::new(host.to_string(), port, "ftp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("PASS resp failed".into()));
    }
    let pass_resp = String::from_utf8_lossy(&buf);
    let success = pass_resp.starts_with("230");

    AuthResult::new(host.to_string(), port, "ftp",
        credential.username.clone(), credential.password.clone(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp.trim().to_string()) })
}
