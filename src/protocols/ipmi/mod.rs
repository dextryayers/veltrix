use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct IpmiProtocol;

#[async_trait]
impl Protocol for IpmiProtocol {
    fn name(&self) -> &'static str { "ipmi" }

    fn default_port(&self) -> u16 { 623 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let host = target.host.clone();
        let port = target.port;
        let user = credential.username.clone();
        let pass = credential.password.clone();

        match timeout(timeout_dur, async {
            let mut stream = connect_tcp(&target.addr_string(), timeout_dur, proxy).await?;

            // Send RMCP+ header ping: RMCP version 0x06, reserved 0x00, header length 0xff, auth type 0x07
            let rmcp_ping = [0x06u8, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            stream.write_all(&rmcp_ping).await?;

            let mut buf = vec![0u8; 64];
            match stream.read_some(&mut buf, timeout_dur).await {
                Ok(n) if n > 0 => {
                    let data = &buf[..n];
                    // Check for RMCP response (should contain 0x06 0x00 0xff)
                    let success = data.len() >= 4 && data[0] == 0x06 && data[2] == 0xff;
                    Ok(AuthResult::new(
                        host.clone(), port, "ipmi",
                        user.clone(), pass.clone(),
                        success, start.elapsed(),
                        if success { None } else { Some("No valid RMCP response".into()) },
                    ))
                }
                _ => Ok(AuthResult::new(
                    host.clone(), port, "ipmi",
                    user.clone(), pass.clone(),
                    true, start.elapsed(), None,
                )),
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(host.clone(), port, "ipmi", user.clone(), pass.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(host.clone(), port, "ipmi", user.clone(), pass.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
