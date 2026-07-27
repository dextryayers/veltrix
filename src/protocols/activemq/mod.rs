use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct ActivemqProtocol;

fn build_wire_format_info() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"ActiveMQ");
    let size = 4 + 4 + 2 + 4 + 1;
    let mut header = Vec::new();
    header.extend_from_slice(&(size as u32).to_be_bytes());
    header.push(0x00);
    let version: u32 = 1;
    header.extend_from_slice(&version.to_be_bytes());
    header
}

fn build_connection_info_frame(username: &str, password: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x0f);
    let conn_id = 1u32;
    payload.extend_from_slice(&conn_id.to_le_bytes());
    let client_id = "veltrix";
    payload.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id.as_bytes());
    let user_bytes = username.as_bytes();
    payload.extend_from_slice(&(user_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(user_bytes);
    let pass_bytes = password.as_bytes();
    payload.extend_from_slice(&(pass_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(pass_bytes);
    let mut frame = Vec::new();
    frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

#[async_trait]
impl Protocol for ActivemqProtocol {
    fn name(&self) -> &'static str {
        "activemq"
    }

    fn default_port(&self) -> u16 {
        61616
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
            let wire_info = build_wire_format_info();
            stream.write_all(&wire_info).await.map_err(|e| format!("Write wire info: {}", e))?;
            let mut resp = vec![0u8; 4];
            stream.read_exact(&mut resp, timeout_dur).await?;
            let resp_len = u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
            if resp_len > 0 && resp_len < 65536 {
                let _body = stream.read_exact_vec(resp_len, timeout_dur).await?;
            }
            let ci_frame = build_connection_info_frame(&credential.username, &credential.password);
            stream.write_all(&ci_frame).await.map_err(|e| format!("Write ConnectionInfo: {}", e))?;
            let mut ci_resp = vec![0u8; 4];
            stream.read_exact(&mut ci_resp, timeout_dur).await?;
            let ci_len = u32::from_be_bytes([ci_resp[0], ci_resp[1], ci_resp[2], ci_resp[3]]) as usize;
            if ci_len > 0 && ci_len < 65536 {
                let ci_body = stream.read_exact_vec(ci_len, timeout_dur).await?;
                if ci_body.len() > 1 && ci_body[1] == 0x00 {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "activemq",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    ));
                }
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "activemq",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Auth failed".into()),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "activemq",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "activemq",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
