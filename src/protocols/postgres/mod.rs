use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::{ProtocolStream, connect_tcp, upgrade_tls};
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct PostgresProtocol;

fn md5_hash(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

fn pg_md5(password: &str, user: &str, salt: &[u8]) -> String {
    let inner = format!("{}{}", md5_hash(&format!("{}{}", password, user)), user);
    format!("md5{:x}", md5::compute(&[inner.as_bytes(), salt].concat()))
}

async fn pg_write_startup<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut ProtocolStream<S>,
    username: &str,
) -> Result<(), String> {
    let params = format!("\0user\0{}\0database\0{}\0\0", username, username);
    let payload_len = 4 + 4 + params.len() as u32;
    let mut startup = Vec::new();
    startup.extend_from_slice(&payload_len.to_be_bytes());
    startup.extend_from_slice(&(196608u32).to_be_bytes());
    startup.extend_from_slice(params.as_bytes());
    stream.write_all(&startup).await
}

async fn pg_read_auth_response<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut ProtocolStream<S>,
    host: &str, port: u16, username: &str, password: &str,
    start: Instant, timeout_dur: Duration,
) -> Result<AuthResult, String> {
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf, timeout_dur).await?;
    let resp_type = buf[0] as char;
    if resp_type == 'R' {
        let mut auth_type_buf = [0u8; 4];
        stream.read_exact(&mut auth_type_buf, timeout_dur).await?;
        let auth_ok = u32::from_be_bytes(auth_type_buf);
        if auth_ok == 0 {
            Ok(AuthResult::new(host.to_string(), port, "postgres",
                username.to_string(), password.to_string(), true, start.elapsed(), None))
        } else {
            Err(format!("Auth failed code: {}", auth_ok))
        }
    } else if resp_type == 'E' {
        let mut rest = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            match stream.read_some(&mut byte, timeout_dur).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    rest.push(byte[0]);
                    if rest.len() > 8192 { break; }
                }
            }
        }
        let err_msg = String::from_utf8_lossy(&rest);
        Ok(AuthResult::new(host.to_string(), port, "postgres",
            username.to_string(), password.to_string(), false, start.elapsed(),
            Some(err_msg.trim().to_string())))
    } else {
        Err(format!("Unexpected response: {}", resp_type))
    }
}

async fn pg_handle_auth<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut ProtocolStream<S>,
    host: &str, port: u16, credential: &Credential,
    start: Instant, timeout_dur: Duration,
) -> Result<AuthResult, String> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header, timeout_dur).await?;

    let msg_type = header[0] as char;

    if msg_type == 'R' {
        let payload_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if payload_len < 8 || payload_len > 1024 {
            return Err(format!("Invalid auth payload len: {}", payload_len));
        }
        let mut rest = stream.read_exact_vec(payload_len - 4, timeout_dur).await?;
        let mut payload = Vec::new();
        payload.extend_from_slice(&header[1..5]);
        payload.append(&mut rest);

        let auth_type = u32::from_be_bytes(
            payload[4..8].try_into().map_err(|_| "Bad auth type offset")?
        );
        match auth_type {
            0 => Ok(AuthResult::new(host.to_string(), port, "postgres",
                credential.username.clone(), credential.password.clone(), true, start.elapsed(), None)),
            3 => {
                let mut pw_buf = Vec::new();
                pw_buf.extend_from_slice(&(0u32.to_be_bytes()));
                pw_buf.extend_from_slice(credential.password.as_bytes());
                pw_buf.push(0);
                let len = pw_buf.len() as u32 + 4;
                let mut pkt = vec![b'p'];
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.extend_from_slice(&pw_buf);
                stream.write_all(&pkt).await?;
                pg_read_auth_response(stream, host, port, &credential.username, &credential.password, start, timeout_dur).await
            }
            5 => {
                let salt = &payload[8..12];
                let hash = pg_md5(&credential.password, &credential.username, salt);
                let mut pw_bytes = hash.as_bytes().to_vec();
                pw_bytes.push(0);
                let len = pw_bytes.len() as u32 + 4;
                let mut pkt = vec![b'p'];
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.extend_from_slice(&pw_bytes);
                stream.write_all(&pkt).await?;
                pg_read_auth_response(stream, host, port, &credential.username, &credential.password, start, timeout_dur).await
            }
            _ => Err(format!("Unsupported auth type: {}", auth_type)),
        }
    } else if msg_type == 'E' {
        let err_msg = format!("{:?}", String::from_utf8_lossy(&header));
        Ok(AuthResult::new(host.to_string(), port, "postgres",
            credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(err_msg)))
    } else {
        Err(format!("Unexpected msg type: {}", msg_type))
    }
}

#[async_trait]
impl Protocol for PostgresProtocol {
    fn name(&self) -> &'static str { "postgres" }
    fn default_port(&self) -> u16 { 5432 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        match timeout(timeout_dur, async {
            let tcp = connect_tcp(&target.addr_string(), timeout_dur, proxy).await?;

            let ssl_request: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];
            let mut tcp = tcp;
            tcp.write_all(&ssl_request).await?;

            let mut ssl_resp = [0u8; 1];
            if tcp.read_exact(&mut ssl_resp, timeout_dur).await.is_ok() && ssl_resp[0] == b'S' {
                let mut tls_stream = upgrade_tls(tcp, &target.host).await?;
                pg_write_startup(&mut tls_stream, &credential.username).await?;
                return pg_handle_auth(&mut tls_stream, &target.host, target.port, credential, start, timeout_dur).await;
            }

            pg_write_startup(&mut tcp, &credential.username).await?;
            pg_handle_auth(&mut tcp, &target.host, target.port, credential, start, timeout_dur).await
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "postgres",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "postgres",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
