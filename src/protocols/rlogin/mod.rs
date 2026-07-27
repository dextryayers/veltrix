use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct RloginProtocol;

#[async_trait]
impl Protocol for RloginProtocol {
    fn name(&self) -> &'static str { "rlogin" }

    fn default_port(&self) -> u16 { 513 }

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

            // Rlogin sends: \0username\0password\0terminal/speed\0
            let mut msg = Vec::new();
            msg.push(0x00);
            msg.extend_from_slice(user.as_bytes());
            msg.push(0x00);
            msg.extend_from_slice(pass.as_bytes());
            msg.push(0x00);
            msg.extend_from_slice(b"vt120/9600");
            msg.push(0x00);

            stream.write_all(&msg).await?;

            let mut buf = vec![0u8; 256];
            match stream.read_some(&mut buf, timeout_dur).await {
                Ok(n) if n > 0 => {
                    let data = String::from_utf8_lossy(&buf[..n]);
                    let has_error = data.contains("login incorrect")
                        || data.contains("password incorrect")
                        || data.contains("denied");
                    let success = !has_error;
                    Ok(AuthResult::new(host.clone(), port, "rlogin", user.clone(), pass.clone(),
                        success, start.elapsed(),
                        if success { None } else { Some(data.to_string()) }))
                }
                _ => Ok(AuthResult::new(host.clone(), port, "rlogin", user.clone(), pass.clone(),
                    true, start.elapsed(), None)),
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(host.clone(), port, "rlogin", user.clone(), pass.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(host.clone(), port, "rlogin", user.clone(), pass.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
