use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct RexecProtocol;

#[async_trait]
impl Protocol for RexecProtocol {
    fn name(&self) -> &'static str { "rexec" }

    fn default_port(&self) -> u16 { 512 }

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

            // Rexec message: [2 bytes stderr port][username\0][password\0][command\0]
            let mut msg = Vec::new();
            msg.extend_from_slice(&[0x00, 0x00]); // stderr port = 0
            msg.extend_from_slice(user.as_bytes());
            msg.push(0x00);
            msg.extend_from_slice(pass.as_bytes());
            msg.push(0x00);
            msg.extend_from_slice(b"echo test");
            msg.push(0x00);

            stream.write_all(&msg).await?;

            // First byte: 0 = success, 1 = failure
            let mut status_byte = [0u8; 1];
            match stream.read_exact(&mut status_byte, timeout_dur).await {
                Ok(_) => {
                    let success = status_byte[0] == 0;
                    let mut err_msg = String::new();
                    if !success {
                        let mut buf = Vec::new();
                        if let Ok(line) = stream.read_line(&mut buf, timeout_dur).await {
                            err_msg = line;
                        }
                    }
                    Ok(AuthResult::new(host.clone(), port, "rexec", user.clone(), pass.clone(),
                        success, start.elapsed(),
                        if success { None } else { Some(if err_msg.is_empty() { "Access denied".into() } else { err_msg }) }))
                }
                Err(_) => Ok(AuthResult::new(host.clone(), port, "rexec", user.clone(), pass.clone(),
                    true, start.elapsed(), None)),
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(host.clone(), port, "rexec", user.clone(), pass.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(host.clone(), port, "rexec", user.clone(), pass.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
