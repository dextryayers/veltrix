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

async fn read_response(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    buf: &mut Vec<u8>,
) -> Result<String, String> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        stream.read(&mut byte).await.map_err(|e| format!("Read: {}", e))?;
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(buf).trim().to_string())
}

async fn write_command(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    cmd: &str,
) -> Result<(), String> {
    stream.write_all(cmd.as_bytes()).await.map_err(|e| format!("Write: {}", e))?;
    stream.flush().await.map_err(|e| format!("Flush: {}", e))
}

async fn ftp_auth_inner(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    host: &str, port: u16, username: &str, password: &str, start: Instant,
) -> Result<AuthResult, String> {
    let mut buf = alloc_read_buf();

    let banner = read_response(stream, &mut buf).await?;
    if !banner.starts_with("220") {
        return Ok(AuthResult::new(host.to_string(), port, "ftp",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("Bad banner: {}", banner))));
    }

    write_command(stream, &format!("USER {}\r\n", username)).await?;
    let user_resp = read_response(stream, &mut buf).await?;
    if !user_resp.starts_with("2") && !user_resp.starts_with("3") {
        return Ok(AuthResult::new(host.to_string(), port, "ftp",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp))));
    }

    write_command(stream, &format!("PASS {}\r\n", password)).await?;
    let pass_resp = read_response(stream, &mut buf).await?;
    let success = pass_resp.starts_with("230");

    Ok(AuthResult::new(host.to_string(), port, "ftp",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp) }))
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
        let username = credential.username.clone();
        let password = credential.password.clone();

        let result = timeout(timeout_dur, async {
            let mut stream = match proxy {
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Proxy connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => connect_optimized(&addr, timeout_dur).await?,
            };

            if port == 990 {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                let mut tls_stream = connector.connect(&host, stream).await
                    .map_err(|e| format!("TLS connect: {}", e))?;
                return ftp_auth_inner(&mut tls_stream, &host, port, &username, &password, start).await;
            }

            let mut buf = alloc_read_buf();
            let banner = read_response(&mut stream, &mut buf).await?;
            if !banner.starts_with("220") {
                return Ok(AuthResult::new(host, port, "ftp",
                    username, password,
                    false, start.elapsed(), Some(format!("Bad banner: {}", banner))));
            }

            write_command(&mut stream, "AUTH TLS\r\n").await?;
            let auth_resp = read_response(&mut stream, &mut buf).await?;
            if auth_resp.starts_with("234") {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                match connector.connect(&host, stream).await {
                    Ok(mut tls_stream) => {
                        return ftp_auth_inner(&mut tls_stream, &host, port, &username, &password, start).await;
                    }
                    Err(e) => {
                        return Ok(AuthResult::new(host, port, "ftp",
                            username, password,
                            false, start.elapsed(), Some(format!("TLS upgrade failed: {}", e))));
                    }
                }
            }

            ftp_auth_inner(&mut stream, &host, port, &username, &password, start).await
        }).await;

        match result {
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
