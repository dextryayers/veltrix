use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct SmtpProtocol;

fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

async fn ehlo(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<Vec<String>, String> {
    let mut buf = Vec::new();
    let ehlo = "EHLO veltrix\r\n";
    writer.write_all(ehlo.as_bytes()).await.map_err(|e| format!("EHLO: {}", e))?;
    writer.flush().await.ok();
    let mut ok = false;
    let mut capabilities = Vec::new();
    loop {
        buf.clear();
        reader.read_until(b'\n', &mut buf).await.map_err(|e| format!("EHLO resp: {}", e))?;
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        if line.starts_with("250") {
            ok = true;
            if let Some(cap) = line.strip_prefix("250-").or_else(|| line.strip_prefix("250 ")) {
                capabilities.push(cap.to_uppercase());
            }
        }
        if !line.starts_with("250-") {
            break;
        }
    }
    if !ok {
        return Err("EHLO rejected".into());
    }
    Ok(capabilities)
}

#[async_trait]
impl Protocol for SmtpProtocol {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn default_port(&self) -> u16 {
        25
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

        let connect_result = match timeout(timeout_dur, async {
            let stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut buf = Vec::new();

            buf_reader.read_until(b'\n', &mut buf).await
                .map_err(|e| format!("Banner: {}", e))?;
            let banner = String::from_utf8_lossy(&buf);
            if !banner.starts_with("220") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "smtp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim())),
                ));
            }

            let caps = ehlo(&mut buf_reader, &mut writer).await.map_err(|e| e)?;

            // Try STARTTLS if advertised
            let supports_starttls = caps.iter().any(|c| c == "STARTTLS");
            let tls_used = if supports_starttls && target.port != 465 {
                let mut tls_buf = vec![0u8; 4096];
                writer.write_all(b"STARTTLS\r\n").await.ok();
                writer.flush().await.ok();
                buf.clear();
                buf_reader.read_until(b'\n', &mut buf).await.ok();
                let starttls_resp = String::from_utf8_lossy(&buf);
                if starttls_resp.starts_with("220") {
                    drop(buf_reader);
                    drop(writer);
                    let new_stream = match proxy {
                        Some(p) => p.tcp_connect(&addr, timeout_dur).await
                            .map_err(|e| format!("Proxy connect: {}", e))?,
                        None => TcpStream::connect(&addr).await
                            .map_err(|e| format!("Connect: {}", e))?,
                    };
                    let connector = TlsConnector::from(
                        NativeTlsConnector::builder().build()
                            .map_err(|e| format!("TLS build: {}", e))?
                    );
                    let mut tls_stream = connector.connect(&target.host, new_stream).await
                        .map_err(|e| format!("TLS connect: {}", e))?;

                    use tokio::io::AsyncReadExt;
                    tls_stream.read(&mut tls_buf).await.map_err(|e| format!("TLS banner: {}", e))?;
                    let tls_banner = String::from_utf8_lossy(&tls_buf);
                    if !tls_banner.starts_with("220") {
                        return Ok(AuthResult::new(
                            target.host.clone(), target.port, "smtp",
                            credential.username.clone(), credential.password.clone(),
                            false, start.elapsed(), Some(format!("TLS bad banner: {}", tls_banner.trim())),
                        ));
                    }

                    let tls_ehlo = "EHLO veltrix\r\n";
                    tls_stream.write_all(tls_ehlo.as_bytes()).await.ok();
                    tls_stream.flush().await.ok();
                    tls_buf.clear();
                    tls_stream.read(&mut tls_buf).await.ok();

                    return smtp_tls_auth(tls_stream, &target, credential, start).await;
                }
                false
            } else { false };

            let auth_user = base64_encode(&credential.username);
            let auth_pass = base64_encode(&credential.password);

            buf.clear();
            let auth_cmd = "AUTH LOGIN\r\n";
            writer.write_all(auth_cmd.as_bytes()).await
                .map_err(|e| format!("AUTH: {}", e))?;
            writer.flush().await.ok();
            buf_reader.read_until(b'\n', &mut buf).await
                .map_err(|e| format!("AUTH resp: {}", e))?;
            let auth_resp = String::from_utf8_lossy(&buf);

            if !auth_resp.starts_with("334") {
                let _ = writer.write_all(b"QUIT\r\n").await;
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "smtp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("AUTH not supported: {}", auth_resp.trim())),
                ));
            }

            buf.clear();
            writer.write_all(format!("{}\r\n", auth_user).as_bytes()).await
                .map_err(|e| format!("AUTH user: {}", e))?;
            writer.flush().await.ok();
            buf_reader.read_until(b'\n', &mut buf).await
                .map_err(|e| format!("AUTH user resp: {}", e))?;
            let user_resp = String::from_utf8_lossy(&buf);
            if !user_resp.starts_with("334") {
                let _ = writer.write_all(b"QUIT\r\n").await;
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "smtp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
                ));
            }

            buf.clear();
            writer.write_all(format!("{}\r\n", auth_pass).as_bytes()).await
                .map_err(|e| format!("AUTH pass: {}", e))?;
            writer.flush().await.ok();
            buf_reader.read_until(b'\n', &mut buf).await
                .map_err(|e| format!("AUTH pass resp: {}", e))?;
            let pass_resp = String::from_utf8_lossy(&buf);
            let success = pass_resp.starts_with("235");

            let _ = writer.write_all(b"QUIT\r\n").await;

            Ok(AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(),
                if success { None } else { Some(pass_resp.trim().to_string()) },
            ))
        }).await {
            Ok(r) => r,
            Err(_) => Ok(AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            )),
        };

        match connect_result {
            Ok(r) => r,
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
        }
    }
}

async fn smtp_tls_auth(
    mut tls_stream: tokio_native_tls::TlsStream<tokio::net::TcpStream>,
    target: &Target,
    credential: &Credential,
    start: Instant,
) -> Result<AuthResult, String> {
    use tokio::io::AsyncReadExt;
    let mut tls_buf = vec![0u8; 4096];

    let auth_user = base64_encode(&credential.username);
    let auth_pass = base64_encode(&credential.password);

    tls_stream.write_all(b"AUTH LOGIN\r\n").await.map_err(|e| format!("AUTH: {}", e))?;
    tls_stream.flush().await.ok();
    tls_buf.clear();
    tls_stream.read(&mut tls_buf).await.map_err(|e| format!("AUTH resp: {}", e))?;
    let auth_resp = String::from_utf8_lossy(&tls_buf);
    if !auth_resp.starts_with("334") {
        return Ok(AuthResult::new(
            target.host.clone(), target.port, "smtp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("AUTH not supported: {}", auth_resp.trim())),
        ));
    }

    tls_buf.clear();
    tls_stream.write_all(format!("{}\r\n", auth_user).as_bytes()).await.map_err(|e| format!("AUTH user: {}", e))?;
    tls_stream.flush().await.ok();
    tls_stream.read(&mut tls_buf).await.map_err(|e| format!("AUTH user resp: {}", e))?;
    let user_resp = String::from_utf8_lossy(&tls_buf);
    if !user_resp.starts_with("334") {
        return Ok(AuthResult::new(
            target.host.clone(), target.port, "smtp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
        ));
    }

    tls_buf.clear();
    tls_stream.write_all(format!("{}\r\n", auth_pass).as_bytes()).await.map_err(|e| format!("AUTH pass: {}", e))?;
    tls_stream.flush().await.ok();
    tls_stream.read(&mut tls_buf).await.map_err(|e| format!("AUTH pass resp: {}", e))?;
    let pass_resp = String::from_utf8_lossy(&tls_buf);
    let success = pass_resp.starts_with("235");

    Ok(AuthResult::new(
        target.host.clone(), target.port, "smtp",
        credential.username.clone(), credential.password.clone(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp.trim().to_string()) },
    ))
}
