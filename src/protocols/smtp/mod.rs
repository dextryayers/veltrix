use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::{
    connect_tcp, upgrade_tls, TcpProtocolStream, TlsProtocolStream,
};
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
        let triple = ((chunk[0] as u32) << 16)
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | chunk.get(2).copied().unwrap_or(0) as u32;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((triple >> 6) & 0x3F) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { CHARS[(triple & 0x3F) as usize] as char } else { '=' });
    }
    result
}

async fn ehlo_tcp(
    stream: &mut TcpProtocolStream,
    buf: &mut Vec<u8>,
    timeout_dur: Duration,
) -> Result<Vec<String>, String> {
    stream.write_line("EHLO veltrix\r\n").await?;
    let mut ok = false;
    let mut capabilities = Vec::new();
    loop {
        let line = stream.read_line(buf, timeout_dur).await?;
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

async fn ehlo_tls(
    stream: &mut TlsProtocolStream,
    buf: &mut Vec<u8>,
    timeout_dur: Duration,
) -> Result<Vec<String>, String> {
    stream.write_line("EHLO veltrix\r\n").await?;
    let mut ok = false;
    let mut capabilities = Vec::new();
    loop {
        let line = stream.read_line(buf, timeout_dur).await?;
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

async fn smtp_auth_login_tcp(
    stream: &mut TcpProtocolStream,
    user_b64: &str,
    pass_b64: &str,
    buf: &mut Vec<u8>,
    timeout_dur: Duration,
) -> Result<bool, String> {
    stream.write_line("AUTH LOGIN\r\n").await?;
    let auth_resp = stream.read_line(buf, timeout_dur).await?;
    if !auth_resp.starts_with("334") {
        return Err(format!("AUTH not supported: {}", auth_resp));
    }
    stream.write_line(&format!("{}\r\n", user_b64)).await?;
    let user_resp = stream.read_line(buf, timeout_dur).await?;
    if !user_resp.starts_with("334") {
        return Err(format!("User rejected: {}", user_resp));
    }
    stream.write_line(&format!("{}\r\n", pass_b64)).await?;
    let pass_resp = stream.read_line(buf, timeout_dur).await?;
    Ok(pass_resp.starts_with("235"))
}

async fn smtp_auth_login_tls(
    stream: &mut TlsProtocolStream,
    user_b64: &str,
    pass_b64: &str,
    buf: &mut Vec<u8>,
    timeout_dur: Duration,
) -> Result<bool, String> {
    stream.write_line("AUTH LOGIN\r\n").await?;
    let auth_resp = stream.read_line(buf, timeout_dur).await?;
    if !auth_resp.starts_with("334") {
        return Err(format!("AUTH not supported: {}", auth_resp));
    }
    stream.write_line(&format!("{}\r\n", user_b64)).await?;
    let user_resp = stream.read_line(buf, timeout_dur).await?;
    if !user_resp.starts_with("334") {
        return Err(format!("User rejected: {}", user_resp));
    }
    stream.write_line(&format!("{}\r\n", pass_b64)).await?;
    let pass_resp = stream.read_line(buf, timeout_dur).await?;
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
        let user_b64 = base64_encode(&credential.username);
        let pass_b64 = base64_encode(&credential.password);

        let result = timeout(timeout_dur, async {
            let mut stream = connect_tcp(&target.addr_string(), timeout_dur, proxy).await?;
            let mut buf = Vec::new();

            let banner = stream.read_line(&mut buf, timeout_dur).await?;
            if !banner.starts_with("220") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "smtp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Bad banner: {}", banner)),
                ));
            }

            let caps = ehlo_tcp(&mut stream, &mut buf, timeout_dur).await?;

            let supports_starttls = caps.iter().any(|c| c == "STARTTLS");
            if supports_starttls && target.port != 465 {
                stream.write_line("STARTTLS\r\n").await?;
                let starttls_resp = stream.read_line(&mut buf, timeout_dur).await?;
                if starttls_resp.starts_with("220") {
                    let mut tls_stream = upgrade_tls(stream, &target.host).await?;

                    ehlo_tls(&mut tls_stream, &mut buf, timeout_dur).await?;

                    let success = smtp_auth_login_tls(&mut tls_stream, &user_b64, &pass_b64, &mut buf, timeout_dur).await?;
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "smtp",
                        credential.username.clone(), credential.password.clone(),
                        success, start.elapsed(),
                        if success { None } else { Some("Auth failed".into()) },
                    ));
                }
            }

            let success = smtp_auth_login_tcp(&mut stream, &user_b64, &pass_b64, &mut buf, timeout_dur).await?;
            stream.write_line("QUIT\r\n").await.ok();
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
