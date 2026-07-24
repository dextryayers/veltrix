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

                let mut buf = vec![0u8; 4096];
                let n = tls_stream.read(&mut buf).await
                    .map_err(|e| format!("FTP banner: {}", e))?;
                let banner = String::from_utf8_lossy(&buf[..n]);
                if !banner.starts_with("220") {
                    return Ok(AuthResult::new(
                        host, port, "ftp",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim())),
                    ));
                }

                tls_stream.write_all(format!("USER {}\r\n", credential.username).as_bytes()).await
                    .map_err(|e| format!("USER cmd: {}", e))?;
                tls_stream.flush().await.ok();
                let mut buf = vec![0u8; 1024];
                let n = tls_stream.read(&mut buf).await
                    .map_err(|e| format!("USER resp: {}", e))?;
                let user_resp = String::from_utf8_lossy(&buf[..n]);
                if !user_resp.starts_with("2") && !user_resp.starts_with("3") {
                    return Ok(AuthResult::new(
                        host, port, "ftp",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
                    ));
                }

                tls_stream.write_all(format!("PASS {}\r\n", credential.password).as_bytes()).await
                    .map_err(|e| format!("PASS cmd: {}", e))?;
                tls_stream.flush().await.ok();
                let mut buf = vec![0u8; 1024];
                let n = tls_stream.read(&mut buf).await
                    .map_err(|e| format!("PASS resp: {}", e))?;
                let pass_resp = String::from_utf8_lossy(&buf[..n]);
                let success = pass_resp.starts_with("230");

                Ok(AuthResult::new(
                    host, port, "ftp",
                    credential.username.clone(), credential.password.clone(),
                    success, start.elapsed(),
                    if success { None } else { Some(pass_resp.trim().to_string()) },
                ))
            } else {
                let (reader, mut writer) = stream.into_split();
                let mut buf_reader = BufReader::new(reader);
                let mut buf = Vec::new();

                buf_reader.read_until(b'\n', &mut buf).await
                    .map_err(|e| format!("Banner: {}", e))?;
                let banner = String::from_utf8_lossy(&buf);
                if !banner.starts_with("220") {
                    return Ok(AuthResult::new(
                        host, port, "ftp",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim())),
                    ));
                }

                writer.write_all(format!("USER {}\r\n", credential.username).as_bytes()).await
                    .map_err(|e| format!("USER cmd: {}", e))?;
                writer.flush().await.ok();
                buf.clear();
                buf_reader.read_until(b'\n', &mut buf).await
                    .map_err(|e| format!("USER resp: {}", e))?;
                let user_resp = String::from_utf8_lossy(&buf);
                if !user_resp.starts_with("2") && !user_resp.starts_with("3") {
                    let _ = writer.write_all(b"QUIT\r\n").await;
                    return Ok(AuthResult::new(
                        host, port, "ftp",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
                    ));
                }

                writer.write_all(format!("PASS {}\r\n", credential.password).as_bytes()).await
                    .map_err(|e| format!("PASS cmd: {}", e))?;
                writer.flush().await.ok();
                buf.clear();
                buf_reader.read_until(b'\n', &mut buf).await
                    .map_err(|e| format!("PASS resp: {}", e))?;
                let pass_resp = String::from_utf8_lossy(&buf);
                let success = pass_resp.starts_with("230");

                let _ = writer.write_all(b"QUIT\r\n").await;

                Ok(AuthResult::new(
                    host, port, "ftp",
                    credential.username.clone(), credential.password.clone(),
                    success, start.elapsed(),
                    if success { None } else { Some(pass_resp.trim().to_string()) },
                ))
            }
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
