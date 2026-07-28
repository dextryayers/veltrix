use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

static HTTP_USERFIELD: OnceLock<String> = OnceLock::new();
static HTTP_PASSFIELD: OnceLock<String> = OnceLock::new();
static HTTP_SUCCESS: OnceLock<String> = OnceLock::new();

pub fn set_form_userfield(val: &str) { let _ = HTTP_USERFIELD.set(val.to_string()); }
pub fn set_form_passfield(val: &str) { let _ = HTTP_PASSFIELD.set(val.to_string()); }
pub fn set_form_success(val: &str) { let _ = HTTP_SUCCESS.set(val.to_string()); }

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
    matches!(status, 200 | 204)
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
            "http-form" | "http-form-login" => Self::authenticate_form(target, credential, timeout_dur, proxy, &url, start).await,
            "http-digest" => Self::authenticate_digest(target, credential, timeout_dur, proxy, &url, start).await,
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
                    if success { None } else { Some(format!("HTTP {} {}", status, if status >= 500 { "(server error)" } else { "" })) },
                )
            }
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "http-basic",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Request error: {}", e)),
            ),
        }
    }

    async fn authenticate_digest(
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
                target.host.clone(), target.port, "http-digest",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
        };

        let initial = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, "http-digest",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Request: {}", e)),
            ),
        };

        if is_success_status(initial.status().as_u16()) {
            return AuthResult::new(
                target.host.clone(), target.port, "http-digest",
                credential.username.clone(), credential.password.clone(),
                true, start.elapsed(), None,
            );
        }

        let www_auth = match initial.headers().get("www-authenticate") {
            Some(v) => v.to_str().unwrap_or("").to_string(),
            None => return AuthResult::new(
                target.host.clone(), target.port, "http-digest",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("No WWW-Authenticate header".into()),
            ),
        };

        if !www_auth.to_lowercase().starts_with("digest") {
            return AuthResult::new(
                target.host.clone(), target.port, "http-digest",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Server does not support Digest auth".into()),
            );
        }

        fn parse_digest_params(header: &str) -> HashMap<String, String> {
            let mut params = HashMap::new();
            if let Some(values) = header.strip_prefix("Digest ").or_else(|| header.strip_prefix("digest ")) {
                let mut key = String::new();
                let mut value = String::new();
                let mut in_key = true;
                let mut in_quote = false;
                for ch in values.chars() {
                    match ch {
                        '=' if in_key && !in_quote => { in_key = false; }
                        '"' => { in_quote = !in_quote; }
                        ',' | ';' if !in_quote => {
                            if !key.is_empty() {
                                params.insert(key.trim().to_lowercase(), value.trim().to_string());
                            }
                            key.clear();
                            value.clear();
                            in_key = true;
                        }
                        _ => {
                            if in_key { key.push(ch); } else { value.push(ch); }
                        }
                    }
                }
                if !key.is_empty() {
                    params.insert(key.trim().to_lowercase(), value.trim().to_string());
                }
            }
            params
        }

        fn md5_digest(input: &str) -> String {
            let mut hasher = md5::Context::new();
            hasher.consume(input.as_bytes());
            format!("{:x}", hasher.finalize())
        }

        fn compute_digest_response(
            username: &str,
            password: &str,
            realm: &str,
            nonce: &str,
            method: &str,
            uri: &str,
            qop: &str,
            nc: &str,
            cnonce: &str,
        ) -> String {
            let ha1 = md5_digest(&format!("{}:{}:{}", username, realm, password));
            let ha2 = md5_digest(&format!("{}:{}", method, uri));
            if qop == "auth" {
                md5_digest(&format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2))
            } else {
                md5_digest(&format!("{}:{}:{}", ha1, nonce, ha2))
            }
        }

        let params = parse_digest_params(&www_auth);
        let realm = params.get("realm").cloned().unwrap_or_default();
        let nonce = params.get("nonce").cloned().unwrap_or_default();
        let qop = params.get("qop").cloned().unwrap_or_default();
        let opaque = params.get("opaque").cloned().unwrap_or_default();
        let algorithm = params.get("algorithm").cloned().unwrap_or_else(|| "MD5".to_string());

        let nc = "00000001";
        let cnonce = format!("{:x}", rand::random::<u64>());
        let response = compute_digest_response(
            &credential.username, &credential.password,
            &realm, &nonce, "GET", url,
            &qop, nc, &cnonce,
        );

        let auth_header = if qop == "auth" {
            format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", qop={}, nc={}, cnonce=\"{}\", response=\"{}\", opaque=\"{}\", algorithm={}",
                credential.username, realm, nonce, url, qop, nc, cnonce, response, opaque, algorithm
            )
        } else {
            format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", opaque=\"{}\", algorithm={}",
                credential.username, realm, nonce, url, response, opaque, algorithm
            )
        };

        match client
            .get(url)
            .header("Authorization", &auth_header)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let success = is_success_status(status);
                AuthResult::new(
                    target.host.clone(), target.port, "http-digest",
                    credential.username.clone(), credential.password.clone(),
                    success, start.elapsed(),
                    if success { None } else { Some(format!("HTTP {}", status)) },
                )
            }
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "http-digest",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Digest request: {}", e)),
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

        let userfield = HTTP_USERFIELD.get().map(|s| s.as_str()).unwrap_or("username");
        let passfield = HTTP_PASSFIELD.get().map(|s| s.as_str()).unwrap_or("password");

        let mut form = HashMap::new();
        form.insert(userfield, &credential.username);
        form.insert(passfield, &credential.password);

        match client
            .post(url)
            .form(&form)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = match resp.text().await {
                    Ok(t) => t.to_lowercase(),
                    Err(e) => return AuthResult::new(
                        target.host.clone(), target.port, "http-form",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some(format!("Read body error: {}", e)),
                    ),
                };
                let success_str = HTTP_SUCCESS.get().map(|s| s.as_str()).unwrap_or("");

                let has_error = if success_str.is_empty() {
                    text.contains("login failed")
                        || text.contains("invalid")
                        || text.contains("incorrect")
                } else {
                    !text.contains(&success_str.to_lowercase())
                };

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
