use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;
use super::transport;

static HTTP_USERFIELD: OnceLock<String> = OnceLock::new();
static HTTP_PASSFIELD: OnceLock<String> = OnceLock::new();
static HTTP_SUCCESS: OnceLock<String> = OnceLock::new();

pub fn set_form_userfield(val: &str) { let _ = HTTP_USERFIELD.set(val.to_string()); }
pub fn set_form_passfield(val: &str) { let _ = HTTP_PASSFIELD.set(val.to_string()); }
pub fn set_form_success(val: &str) { let _ = HTTP_SUCCESS.set(val.to_string()); }

fn build_client(timeout_dur: Duration, proxy: &Option<ProxyConfig>) -> Result<reqwest::Client, String> {
    // F4.4: UA dirotasi per attempt dari pool realistis (atau override).
    let ua = transport::next_user_agent();
    let (client, warning) = transport::build_reqwest_client(
        timeout_dur,
        proxy,
        &ua,
    );
    if let Some(w) = warning {
        log::warn!("{}", w);
    }
    client
}

fn is_success_status(status: u16) -> bool {
    matches!(status, 200 | 204)
}

fn is_denied_status(status: u16) -> bool {
    matches!(status, 401 | 403)
}

/// F9.2: parser nilai WWW-Authenticate Digest, murni dan fuzzable.
/// Menangani quote, koma/semicolon di dalam quote, key case-insensitive.
pub(crate) fn parse_digest_params(header: &str) -> HashMap<String, String> {
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

/// F9.2: classifier body form-login, murni dan fuzzable.
/// `body_lower` HARUS sudah lowercase; `success_marker` lowercase juga.
/// Tanpa marker: gagal bila mengandung penanda error umum.
/// Dengan marker: sukses hanya bila marker hadir.
pub(crate) fn classify_form_body(status: u16, body_lower: &str, success_marker: &str) -> bool {
    let has_error = if success_marker.is_empty() {
        body_lower.contains("login failed")
            || body_lower.contains("invalid")
            || body_lower.contains("incorrect")
    } else {
        !body_lower.contains(success_marker)
    };
    is_success_status(status) && !has_error
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
                let success = classify_form_body(status, &text, &success_str.to_lowercase());

                AuthResult::new(
                    target.host.clone(), target.port, "http-form",
                    credential.username.clone(), credential.password.clone(),
                    success, start.elapsed(),
                    if success { None } else { Some(format!("HTTP {} | {}", status, if is_success_status(status) { "form error" } else { "bad status" })) },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_params_basic() {
        let p = parse_digest_params(
            r#"Digest realm="test", nonce="abc123", qop="auth", algorithm=MD5"#,
        );
        assert_eq!(p.get("realm").map(|s| s.as_str()), Some("test"));
        assert_eq!(p.get("nonce").map(|s| s.as_str()), Some("abc123"));
        assert_eq!(p.get("qop").map(|s| s.as_str()), Some("auth"));
        assert_eq!(p.get("algorithm").map(|s| s.as_str()), Some("MD5"));
    }

    #[test]
    fn digest_params_rejects_non_digest() {
        assert!(parse_digest_params("Basic realm=\"x\"").is_empty());
        assert!(parse_digest_params("").is_empty());
    }

    #[test]
    fn form_classifier_markers() {
        assert!(classify_form_body(200, "welcome to dashboard", ""));
        assert!(!classify_form_body(200, "login failed, try again", ""));
        assert!(!classify_form_body(200, "invalid credentials", ""));
        assert!(!classify_form_body(401, "welcome", ""));
        assert!(!classify_form_body(500, "welcome", ""));
        // Custom marker: hadir = sukses, absen = gagal.
        assert!(classify_form_body(200, "hello john, logout", "logout"));
        assert!(!classify_form_body(200, "hello john", "logout"));
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    // F9.2: HTTP response parsing tidak boleh panic untuk header/body apapun.
    const HDR: &[&str] = &[
        "Digest ", "digest ", "Basic ", "realm=", "nonce=", "qop=", "\"",
        ",", ";", "=", " ", "auth", "MD5", "abc123", "test,", "(stale)",
        "charset=utf-8", "\r\n",
    ];
    const BODY: &[&str] = &[
        "welcome", "dashboard", "login failed", "invalid", "incorrect",
        "logout", "401", "error", "<html>", "   ", "LOGIN FAILED",
        "session expired, please login again",
    ];

    #[test]
    fn fuzz_digest_params_never_panics() {
        let mut rng = Rng(0x0779);
        for _ in 0..3000 {
            let n = 1 + rng.below(8);
            let mut s = String::new();
            for _ in 0..n {
                s.push_str(HDR[rng.below(HDR.len())]);
            }
            let params = parse_digest_params(&s);
            // Invarian: key selalu lowercase, value tidak mengandung quote
            // pembatas yang belum di-strip secara brutal (sanity murah).
            for (k, _) in &params {
                assert_eq!(*k, k.to_lowercase());
            }
        }
    }

    #[test]
    fn fuzz_form_classifier_never_panics() {
        let mut rng = Rng(0xF02A);
        let statuses: &[u16] = &[0, 200, 204, 301, 302, 400, 401, 403, 404, 500, 502, 65535];
        for _ in 0..3000 {
            let n = rng.below(5);
            let mut body = String::new();
            for _ in 0..n {
                body.push_str(BODY[rng.below(BODY.len())]);
            }
            let status = statuses[rng.below(statuses.len())];
            let marker = if rng.below(2) == 0 { "" } else { BODY[rng.below(BODY.len())] };
            let _ = classify_form_body(status, &body.to_lowercase(), &marker.to_lowercase());
        }
    }
}
