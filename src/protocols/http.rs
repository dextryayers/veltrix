use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

fn build_client(timeout_dur: Duration, proxy: &Option<ProxyConfig>) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout_dur)
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        .redirect(reqwest::redirect::Policy::limited(5));

    if let Some(proxy_config) = proxy {
        if let Some(p) = proxy_config.to_reqwest_proxy() {
            builder = builder.proxy(p);
        }
    }

    builder.build().map_err(|e| format!("Client error: {}", e))
}

fn is_success_status(status: u16) -> bool {
    matches!(status, 200 | 204 | 301 | 302 | 304)
}

fn is_denied_status(status: u16) -> bool {
    matches!(status, 401 | 403)
}

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

        match &target.protocol as &str {
            "http-form" => Self::authenticate_form(target, credential, timeout_dur, proxy, &url, start).await,
            _ => Self::authenticate_basic(target, credential, timeout_dur, proxy, &url, start).await,
        }
    }
}

impl HttpProtocol {
    async fn authenticate_basic(
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
        url: &str,
        start: Instant,
    ) -> AuthResult {
        let client = match build_client(timeout_dur, proxy) {
            Ok(c) => c,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, "http-basic",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
        };

        match client
            .get(url)
            .basic_auth(&credential.username, Some(&credential.password))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let success = is_success_status(status) && !is_denied_status(status);

                AuthResult::new(
                    target.host.clone(), target.port, "http-basic",
                    credential.username.clone(), credential.password.clone(),
                    success, start.elapsed(),
                    if success { None } else { Some(format!("HTTP {}", status)) },
                )
            }
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "http-basic",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Request error: {}", e)),
            ),
        }
    }

    async fn authenticate_form(
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
        url: &str,
        start: Instant,
    ) -> AuthResult {
        let client = match build_client(timeout_dur, proxy) {
            Ok(c) => c,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, "http-form",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
        };

        let mut form = HashMap::new();
        form.insert("username", &credential.username);
        form.insert("password", &credential.password);
        form.insert("login", &credential.username);

        match client
            .post(url)
            .form(&form)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default().to_lowercase();
                let has_error = text.contains("login failed")
                    || text.contains("invalid")
                    || text.contains("incorrect")
                    || text.contains("error");

                let success = is_success_status(status) && !has_error;

                AuthResult::new(
                    target.host.clone(), target.port, "http-form",
                    credential.username.clone(), credential.password.clone(),
                    success, start.elapsed(),
                    if success { None } else { Some(format!("HTTP {} | {}", status, if has_error { "form error" } else { "ok" })) },
                )
            }
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "http-form",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Request error: {}", e)),
            ),
        }
    }
}
