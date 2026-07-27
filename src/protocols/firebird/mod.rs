use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct FirebirdProtocol;

const OP_RESPONSE: u8 = 0x02;

fn build_connect_packet(username: &str, password: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.push(0x01);
    pkt.push(0x00);
    let user_bytes = username.as_bytes();
    let pass_bytes = password.as_bytes();
    pkt.extend_from_slice(&(user_bytes.len() as u16).to_le_bytes());
    pkt.extend_from_slice(user_bytes);
    pkt.extend_from_slice(&(pass_bytes.len() as u16).to_le_bytes());
    pkt.extend_from_slice(pass_bytes);
    pkt
}

#[async_trait]
impl Protocol for FirebirdProtocol {
    fn name(&self) -> &'static str {
        "firebird"
    }

    fn default_port(&self) -> u16 {
        3050
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
            let mut greeting = vec![0u8; 256];
            let n = stream.read_some(&mut greeting, timeout_dur).await?;
            if n == 0 {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "firebird",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("No greeting".into()),
                ));
            }
            let pkt = build_connect_packet(&credential.username, &credential.password);
            stream.write_all(&pkt).await.map_err(|e| format!("Write connect: {}", e))?;
            let mut resp = vec![0u8; 1024];
            let rn = stream.read_some(&mut resp, timeout_dur).await?;
            if rn == 0 {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "firebird",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("No response".into()),
                ));
            }
            if resp[0] == OP_RESPONSE && rn > 1 && resp[1] == 0x00 {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "firebird",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "firebird",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(),
                Some(format!("Response code: {}", resp[0])),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "firebird",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "firebird",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
