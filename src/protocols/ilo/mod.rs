use async_trait::async_trait;
use std::time::{Duration, Instant};

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use crate::protocols::http_auth::http_basic_auth;
use super::Protocol;

pub struct IloProtocol;

#[async_trait]
impl Protocol for IloProtocol {
    fn name(&self) -> &'static str { "ilo" }

    fn default_port(&self) -> u16 { 443 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let url = format!("https://{}:{}/", target.host, target.port);
        http_basic_auth(target, credential, timeout_dur, proxy, &url, "ilo", start).await
    }
}
