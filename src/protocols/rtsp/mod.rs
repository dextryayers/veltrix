use async_trait::async_trait;
use base64::Engine;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct RtspProtocol;

fn build_describe_request(host: &str, port: u16, username: &str, password: &str) -> String {
    let auth = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", username, password));
    format!(
        "DESCRIBE rtsp://{}:{}/ RTSP/1.0\r\n\
         CSeq: 1\r\n\
         Authorization: Basic {}\r\n\
         \r\n",
        host, port, auth
    )
}

#[async_trait]
impl Protocol for RtspProtocol {
    fn name(&self) -> &'static str {
        "rtsp"
    }

    fn default_port(&self) -> u16 {
        554
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
            let describe = build_describe_request(
                &target.host, target.port,
                &credential.username, &credential.password,
            );
            stream.write_str(&describe).await.map_err(|e| format!("Write DESCRIBE: {}", e))?;
            let mut buf = Vec::new();
            let status = stream.read_line(&mut buf, timeout_dur).await?;
            if status.contains("200 OK") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "rtsp",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }
            if status.contains("401 Unauthorized") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "rtsp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("Unauthorized".into()),
                ));
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "rtsp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(),
                Some(format!("Status: {}", status)),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "rtsp",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "rtsp",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
