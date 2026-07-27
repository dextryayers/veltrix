use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::conn::{self, read_crlf_line, write_line, upgrade_to_tls, read_line_tls, write_line_tls};
use super::tcp::alloc_read_buf;
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
    stream: &mut tokio::net::TcpStream,
    buf: &mut Vec<u8>,
) -> Result<Vec<String>, String> {
    write_line(stream, "EHLO veltrix\r\n").await?;
    let mut ok = false;
    let mut capabilities = Vec::new();
    loop {
        let line = read_crlf_line(stream, buf).await?;
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

async fn smtp_auth_login(
    stream: &mut tokio::net::TcpStream,
    user_b64: &str,
    pass_b64: &str,
    buf: &mut Vec<u8>,
) -> Result<bool, String> {
    write_line(stream, "AUTH LOGIN\r\n").await?;
    let auth_resp = read_crlf_line(stream, buf).await?;
    if !auth_resp.starts_with("334") {
        return Err(format!("AUTH not supported: {}", auth_resp));
    }

    write_line(stream, &format!("{}\r\n", user_b64)).await?;
    let user_resp = read_crlf_line(stream, buf).await?;
    if !user_resp.starts_with("334") {
        return Err(format!("User rejected: {}", user_resp));
    }

    write_line(stream, &format!("{}\r\n", pass_b64)).await?;
    let pass_resp = read_crlf_line(stream, buf).await?;
    Ok(pass_resp.starts_with("235"))
}

async fn smtp_auth_login_tls(
    tls_stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>,
    user_b64: &str,
    pass_b64: &str,
    buf: &mut Vec<u8>,
) -> Result<bool, String> {
    write_line_tls(tls_stream, "AUTH LOGIN\r\n").await?;
    let auth_resp = read_line_tls(tls_stream, buf).await?;
    if !auth_resp.starts_with("334") {
        return Err(format!("AUTH not supported: {}", auth_resp));
    }

    write_line_tls(tls_stream, &format!("{}\r\n", user_b64)).await?;
    let user_resp = read_line_tls(tls_stream, buf).await?;
    if !user_resp.starts_with("334") {
        return Err(format!("User rejected: {}", user_resp));
    }

    write_line_tls(tls_stream, &format!("{}\r\n", pass_b64)).await?;
    let pass_resp = read_line_tls(tls_stream, buf).await?;
    Ok(pass_resp.starts_with("235"))
}

#[async_trait]
impl Protocol for SmtpProtocol {
    fn name(&self) -> &'static str { "smtp" }
    fn default_port(&self) -> u16 { 25 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();
        let user_b64 = base64_encode(&credential.username);
        let pass_b64 = base64_encode(&credential.password);

        let result = timeout(timeout_dur, async {
            let mut stream = conn::tcp_connect(&addr, timeout_dur, proxy).await?;
            let mut buf = Vec::new();

            let banner = read_crlf_line(&mut stream, &mut buf).await?;
            if !banner.starts_with("220") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "smtp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Bad banner: {}", banner)),
                ));
            }

            let caps = ehlo(&mut stream, &mut buf).await?;

            let supports_starttls = caps.iter().any(|c| c == "STARTTLS");
            if supports_starttls && target.port != 465 {
                write_line(&mut stream, "STARTTLS\r\n").await?;
                let starttls_resp = read_crlf_line(&mut stream, &mut buf).await?;
                if starttls_resp.starts_with("220") {
                    let mut tls_stream = upgrade_to_tls(stream, &target.host).await?;

                    write_line_tls(&mut tls_stream, "EHLO veltrix\r\n").await?;
                    let mut tls_buf = alloc_read_buf();
                    tls_buf.clear();
                    tls_stream.read(&mut tls_buf).await.map_err(|e| format!("EHLO resp: {}", e))?;

                    let success = smtp_auth_login_tls(&mut tls_stream, &user_b64, &pass_b64, &mut buf).await.unwrap_or(false);
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "smtp",
                        credential.username.clone(), credential.password.clone(),
                        success, start.elapsed(),
                        if success { None } else { Some("Auth failed".into()) },
                    ));
                }
            }

            let success = smtp_auth_login(&mut stream, &user_b64, &pass_b64, &mut buf).await.unwrap_or(false);
            write_line(&mut stream, "QUIT\r\n").await.ok();
            Ok(AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(),
                if success { None } else { Some("Auth failed".into()) },
            ))
        }).await;

        match result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
