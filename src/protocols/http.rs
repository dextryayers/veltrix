use async_trait::async_trait;
use std::time::{Duration, Instant};

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct HttpProtocol;

#[async_trait]
impl Protocol for HttpProtocol {
    fn name(&self) -> &'static str { "http" }
    fn default_port(&self) -> u16 { 80 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let is_https = target.port == 443;
        let protocol = if is_https { "https" } else { "http" };
        let url = format!("{}://{}:{}/", protocol, target.host, target.port);

        let mut builder = reqwest::Client::builder()
            .timeout(timeout_dur)
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");

        if let Some(proxy_config) = proxy {
            if let Some(p) = proxy_config.to_reqwest_proxy() {
                builder = builder.proxy(p);
            }
        }

        match builder.build() {
            Ok(client) => {
                let response = client
                    .get(&url)
                    .basic_auth(&credential.username, Some(&credential.password))
                    .send()
                    .await;

                match response {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let success = status == 200 || status == 204 || status == 302
                            || status == 301 || status == 304;
                        let is_denied = status == 401 || status == 403;

                        AuthResult::new(
                            target.host.clone(), target.port, "http",
                            credential.username.clone(), credential.password.clone(),
                            success && !is_denied, start.elapsed(),
                            if success && !is_denied { None } else { Some(format!("HTTP {}", status)) },
                        )
                    }
                    Err(e) => AuthResult::new(
                        target.host.clone(), target.port, "http",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some(format!("Request error: {}", e)),
                    ),
                }
            }
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "http",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Client error: {}", e)),
            ),
        }
    }
}
