use async_trait::async_trait;
use std::time::{Duration, Instant};
use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use crate::protocols::Protocol;
use crate::protocols::http_auth::http_basic_auth;

pub struct DockerProtocol;

#[async_trait]
impl Protocol for DockerProtocol {
    fn name(&self) -> &'static str { "docker" }
    fn default_port(&self) -> u16 { 5000 }
    async fn authenticate(&self, target: &Target, credential: &Credential, timeout_dur: Duration, proxy: &Option<ProxyConfig>) -> AuthResult {
        let start = Instant::now();
        let scheme = if target.port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, target.host, target.port, "/v2/_catalog");
        http_basic_auth(target, credential, timeout_dur, proxy, &url, "docker", start).await
    }
}
