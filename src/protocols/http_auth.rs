use std::sync::OnceLock;
use std::time::{Duration, Instant};
use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;

fn global_client() -> &'static reqwest::Client {
    use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE};
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .user_agent(super::transport::USER_AGENTS[0])
            .redirect(reqwest::redirect::Policy::limited(3))
            .cookie_store(true)
            .default_headers(headers)
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(256)
            .tcp_keepalive(Duration::from_secs(15))
            .build()
            .expect("Failed to build HTTP client")
    })
}

fn build_client_with_proxy(proxy: &ProxyConfig, timeout: Duration) -> Result<reqwest::Client, String> {
    let ua = super::transport::next_user_agent();
    let (client, warning) = super::transport::build_reqwest_client(
        timeout,
        &Some(proxy.clone()),
        &ua,
    );
    if let Some(w) = warning {
        log::warn!("{}", w);
    }
    client
}

pub async fn http_basic_auth(
    target: &Target,
    credential: &Credential,
    timeout_dur: Duration,
    proxy: &Option<ProxyConfig>,
    url: &str,
    proto_name: &str,
    start: Instant,
) -> AuthResult {
    let result = if let Some(ref p) = proxy {
        let client = match build_client_with_proxy(p, timeout_dur) {
            Ok(c) => c,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, proto_name,
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
        };
        tokio::time::timeout(timeout_dur, client
            .get(url)
            .basic_auth(&credential.username, Some(&credential.password))
            .send()).await
    } else {
        tokio::time::timeout(timeout_dur, global_client()
            .get(url)
            .basic_auth(&credential.username, Some(&credential.password))
            .send()).await
    };
    match result {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            let success = status >= 200 && status < 400;
            AuthResult::new(
                target.host.clone(), target.port, proto_name,
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(),
                if success { None } else { Some(format!("HTTP {} {}", status, if status >= 500 { "(server error)" } else { "" })) },
            )
        }
        Ok(Err(e)) => AuthResult::new(
            target.host.clone(), target.port, proto_name,
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("Request: {}", e)),
        ),
        Err(_) => AuthResult::new(
            target.host.clone(), target.port, proto_name,
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("Timeout".into()),
        ),
    }
}
