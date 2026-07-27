use async_trait::async_trait;
use std::time::{Duration, Instant};
use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use crate::protocols::Protocol;
use crate::protocols::http_auth::http_basic_auth;

pub struct GitlabProtocol;

#[async_trait]
impl Protocol for GitlabProtocol {
    fn name(&self) -> &'static str { "gitlab" }
    fn default_port(&self) -> u16 { 80 }
    async fn authenticate(&self, target: &Target, credential: &Credential, timeout_dur: Duration, proxy: &Option<ProxyConfig>) -> AuthResult {
        let start = Instant::now();
        let scheme = if target.port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, target.host, target.port, "/api/v4/projects?per_page=1");
        http_basic_auth(target, credential, timeout_dur, proxy, &url, "gitlab", start).await
    }
}
