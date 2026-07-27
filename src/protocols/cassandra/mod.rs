use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct CassandraProtocol;

fn build_startup_frame() -> Vec<u8> {
    let body = build_string_map(&[("CQL_VERSION", "3.0.0")]);
    build_frame(0x01, &body)
}

fn build_auth_response_frame(username: &str, password: &str) -> Vec<u8> {
    let mut body = Vec::new();
    let creds = format!("\0{}\0{}", username, password);
    body.extend_from_slice(&(creds.len() as u16).to_be_bytes());
    body.extend_from_slice(creds.as_bytes());
    build_frame(0x0f, &body)
}

fn build_string_map(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (k, v) in entries {
        buf.extend_from_slice(&(k.len() as u16).to_be_bytes());
        buf.extend_from_slice(k.as_bytes());
        buf.extend_from_slice(&(v.len() as u16).to_be_bytes());
        buf.extend_from_slice(v.as_bytes());
    }
    buf
}

fn build_frame(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(0x04);
    frame.push(0x00);
    frame.extend_from_slice(&0x0000u16.to_be_bytes());
    frame.push(opcode);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

#[async_trait]
impl Protocol for CassandraProtocol {
    fn name(&self) -> &'static str {
        "cassandra"
    }

    fn default_port(&self) -> u16 {
        9042
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        match timeout(timeout_dur, async {
            let mut stream = connect_tcp(&target.addr_string(), timeout_dur, proxy).await?;
            let startup = build_startup_frame();
            stream.write_all(&startup).await.map_err(|e| format!("Write startup: {}", e))?;
            let resp = stream.read_exact_vec(9, timeout_dur).await?;
            if resp.len() < 9 {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "cassandra",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("Short response".into()),
                ));
            }
            let opcode = resp[4];
            let body_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
            if body_len > 0 {
                let _body = stream.read_exact_vec(body_len, timeout_dur).await?;
            }
            if opcode == 0x00 {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "cassandra",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }
            if opcode == 0x03 {
                let auth_frame = build_auth_response_frame(&credential.username, &credential.password);
                stream.write_all(&auth_frame).await.map_err(|e| format!("Write auth: {}", e))?;
                let auth_resp = stream.read_exact_vec(9, timeout_dur).await?;
                if auth_resp.len() < 9 {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "cassandra",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some("No auth response".into()),
                    ));
                }
                let auth_opcode = auth_resp[4];
                if auth_opcode == 0x00 {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "cassandra",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    ));
                }
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "cassandra",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(),
                Some(format!("Opcode: {}", opcode)),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "cassandra",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "cassandra",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
