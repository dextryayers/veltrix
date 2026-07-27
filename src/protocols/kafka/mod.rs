use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct KafkaProtocol;

fn build_kafka_request(api_key: i16, api_version: i16, body: &[u8]) -> Vec<u8> {
    let client_id = "veltrix";
    let header_len = 2 + 2 + 4 + 2 + client_id.len();
    let total_len = header_len + body.len();
    let mut buf = Vec::new();
    buf.extend_from_slice(&(total_len as u32).to_be_bytes());
    buf.extend_from_slice(&api_key.to_be_bytes());
    buf.extend_from_slice(&api_version.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(client_id.as_bytes());
    buf.extend_from_slice(body);
    buf
}

fn build_plain_sasl_bytes(username: &str, password: &str) -> Vec<u8> {
    let s = format!("\0{}\0{}", username, password);
    s.into_bytes()
}

#[async_trait]
impl Protocol for KafkaProtocol {
    fn name(&self) -> &'static str {
        "kafka"
    }

    fn default_port(&self) -> u16 {
        9092
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
            let av_req = build_kafka_request(18, 0, &[]);
            stream.write_all(&av_req).await.map_err(|e| format!("Write ApiVersions: {}", e))?;
            let _av_size = stream.read_frame_4be(timeout_dur).await?;
            let _av_body = stream.read_exact_vec(8, timeout_dur).await?;
            let sasl_body = build_kafka_request(17, 0, b"\x00\x05PLAIN");
            stream.write_all(&sasl_body).await.map_err(|e| format!("Write SASL Handshake: {}", e))?;
            let _sh_size = stream.read_frame_4be(timeout_dur).await?;
            let _sh_body = stream.read_exact_vec(8, timeout_dur).await?;
            let auth_bytes = build_plain_sasl_bytes(&credential.username, &credential.password);
            let mut auth_body = Vec::new();
            auth_body.extend_from_slice(&(auth_bytes.len() as u32).to_be_bytes());
            auth_body.extend_from_slice(&auth_bytes);
            let auth_req = build_kafka_request(36, 0, &auth_body);
            stream.write_all(&auth_req).await.map_err(|e| format!("Write SASL Auth: {}", e))?;
            let _auth_size = stream.read_frame_4be(timeout_dur).await?;
            let auth_resp = stream.read_exact_vec(12, timeout_dur).await?;
            if auth_resp.len() >= 12 {
                let err_code = i16::from_be_bytes([auth_resp[0], auth_resp[1]]);
                if err_code == 0 {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "kafka",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    ));
                }
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "kafka",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("SASL auth failed".into()),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "kafka",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "kafka",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
