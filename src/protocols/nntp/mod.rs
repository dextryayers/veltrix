use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct NntpProtocol;

#[async_trait]
impl Protocol for NntpProtocol {
    fn name(&self) -> &'static str { "nntp" }

    fn default_port(&self) -> u16 { 119 }

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
            let mut buf = Vec::new();

            let greeting = stream.read_line(&mut buf, timeout_dur).await?;
            if !greeting.starts_with("200") && !greeting.starts_with("201") {
                return Ok(AuthResult::new(host.clone(), port, "nntp", user.clone(), pass.clone(),
                    false, start.elapsed(), Some(format!("Bad greeting: {}", greeting))));
            }

            stream.write_line(&format!("AUTHINFO USER {}\r\n", user)).await?;
            let user_resp = stream.read_line(&mut buf, timeout_dur).await?;
            if !user_resp.starts_with("381") {
                return Ok(AuthResult::new(host.clone(), port, "nntp", user.clone(), pass.clone(),
                    false, start.elapsed(), Some(format!("User rejected: {}", user_resp))));
            }

            stream.write_line(&format!("AUTHINFO PASS {}\r\n", pass)).await?;
            let pass_resp = stream.read_line(&mut buf, timeout_dur).await?;
            let success = pass_resp.starts_with("281");

            Ok(AuthResult::new(host.clone(), port, "nntp", user.clone(), pass.clone(),
                success, start.elapsed(),
                if success { None } else { Some(pass_resp) }))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(host.clone(), port, "nntp", user.clone(), pass.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(host.clone(), port, "nntp", user.clone(), pass.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
