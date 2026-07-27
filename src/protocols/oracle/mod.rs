use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::conn::tcp_connect;
use super::Protocol;

pub struct OracleProtocol;

fn build_tns_connect_packet() -> Vec<u8> {
    let mut pkt = Vec::new();
    let connect_data = b"(CONNECT_DATA=(SID=ORCL)(CID=(PROGRAM=)(HOST=)(USER=)))";
    let total_len = connect_data.len() as u16 + 58;
    pkt.extend_from_slice(&total_len.to_be_bytes());
    for _ in 0..28 {
        pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    }
    pkt.push(0x01);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(connect_data);
    pkt
}

#[async_trait]
impl Protocol for OracleProtocol {
    fn name(&self) -> &'static str {
        "oracle"
    }

    fn default_port(&self) -> u16 {
        1521
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
            let mut stream = tcp_connect(&target.addr_string(), timeout_dur, proxy).await?;
            let pkt = build_tns_connect_packet();
            stream.write_all(&pkt).await.map_err(|e| format!("Write TNS: {}", e))?;
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.map_err(|e| format!("Read TNS: {}", e))?;
            if n == 0 {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "oracle",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("No response".into()),
                ));
            }
            let resp = String::from_utf8_lossy(&buf[..n]).to_lowercase();
            if resp.contains("accept") || resp.contains("refused") || resp.contains("ora-") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "oracle",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some("Server responded but auth not verified".into()),
                ));
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "oracle",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Unexpected response".into()),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "oracle",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "oracle",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
