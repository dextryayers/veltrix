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

pub struct SquidProtocol;

#[async_trait]
impl Protocol for SquidProtocol {
    fn name(&self) -> &'static str { "squid" }

    fn default_port(&self) -> u16 { 3128 }

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

            let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
            let request = format!(
                "GET http://www.example.com/ HTTP/1.0\r\nProxy-Authorization: Basic {}\r\n\r\n",
                encoded
            );
            stream.write_all(request.as_bytes()).await?;

            let mut buf = Vec::new();
            let resp = stream.read_line(&mut buf, timeout_dur).await?;
            let success = resp.contains("200") || resp.contains("407");

            Ok(AuthResult::new(host.clone(), port, "squid", user.clone(), pass.clone(),
                success, start.elapsed(),
                if success { None } else { Some(resp) }))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(host.clone(), port, "squid", user.clone(), pass.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(host.clone(), port, "squid", user.clone(), pass.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
