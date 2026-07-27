use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct CvsProtocol;

#[async_trait]
impl Protocol for CvsProtocol {
    fn name(&self) -> &'static str { "cvs" }

    fn default_port(&self) -> u16 { 2401 }

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

            // Read banner
            let _banner = stream.read_line(&mut buf, timeout_dur).await?;

            let repo_path = "/root";
            let auth_msg = format!("BEGIN AUTH REQUEST\n{}\n{}\n{}\n\n", user, pass, repo_path);
            stream.write_all(auth_msg.as_bytes()).await?;

            let resp = stream.read_line(&mut buf, timeout_dur).await?;
            let success = resp.contains("I LOVE YOU") || resp.contains("200");

            Ok(AuthResult::new(host.clone(), port, "cvs", user.clone(), pass.clone(),
                success, start.elapsed(),
                if success { None } else { Some(resp) }))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(host.clone(), port, "cvs", user.clone(), pass.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(host.clone(), port, "cvs", user.clone(), pass.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
