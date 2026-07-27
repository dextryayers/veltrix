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

pub struct MemcachedProtocol;

#[async_trait]
impl Protocol for MemcachedProtocol {
    fn name(&self) -> &'static str { "memcached" }

    fn default_port(&self) -> u16 { 11211 }

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

            // Try stats command first - no auth needed if we get STAT or END
            stream.write_line("stats\r\n").await?;
            let stats_resp = stream.read_line(&mut buf, timeout_dur).await?;
            if stats_resp.starts_with("STAT") || stats_resp.starts_with("END") {
                return Ok(AuthResult::new(host.clone(), port, "memcached", user.clone(), pass.clone(),
                    true, start.elapsed(), None));
            }

            // Try SASL auth
            stream.write_line("mechlist\r\n").await?;
            let _mech_resp = stream.read_line(&mut buf, timeout_dur).await?;

            let encoded = base64::engine::general_purpose::STANDARD.encode(format!("\x00{}\x00{}", user, pass));
            stream.write_line(&format!("auth plain {}\r\n", encoded)).await?;
            let auth_resp = stream.read_line(&mut buf, timeout_dur).await?;
            let success = auth_resp.contains("OK");

            Ok(AuthResult::new(host.clone(), port, "memcached", user.clone(), pass.clone(),
                success, start.elapsed(),
                if success { None } else { Some(auth_resp) }))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(host.clone(), port, "memcached", user.clone(), pass.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(host.clone(), port, "memcached", user.clone(), pass.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
