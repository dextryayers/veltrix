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

pub struct XmppProtocol;

fn build_stream_open(host: &str) -> String {
    format!(
        "<?xml version='1.0'?>\
         <stream:stream to='{}' xmlns='jabber:client' \
         xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
        host
    )
}

fn build_auth_plain(username: &str, password: &str) -> String {
    let payload = format!("\0{}\0{}", username, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    format!(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{}</auth>",
        encoded
    )
}

#[async_trait]
impl Protocol for XmppProtocol {
    fn name(&self) -> &'static str {
        "xmpp"
    }

    fn default_port(&self) -> u16 {
        5222
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        match timeout(timeout_dur, async {
            let mut stream = connect_tcp(&target.addr_string(), timeout_dur, proxy).await?;
            let stream_open = build_stream_open(&target.host);
            stream.write_str(&stream_open).await.map_err(|e| format!("Write stream open: {}", e))?;
            let mut buf = Vec::new();
            let mut response = String::new();
            loop {
                let line = stream.read_line(&mut buf, timeout_dur).await?;
                if line.is_empty() {
                    break;
                }
                response.push_str(&line);
                if line.contains("</stream:stream>") || line.contains("/>") {
                    break;
                }
            }
            if !response.contains("<stream:stream") && !response.contains("<stream") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "xmpp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some("No stream header received".into()),
                ));
            }
            let auth_xml = build_auth_plain(&credential.username, &credential.password);
            stream.write_str(&auth_xml).await.map_err(|e| format!("Write auth: {}", e))?;
            let mut auth_buf = Vec::new();
            let mut auth_response = String::new();
            loop {
                let line = stream.read_line(&mut auth_buf, timeout_dur).await?;
                if line.is_empty() {
                    break;
                }
                auth_response.push_str(&line);
                if line.contains("</auth>") || line.contains("/>") || line.contains("</failure>") {
                    break;
                }
            }
            if auth_response.contains("<success") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "xmpp",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "xmpp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(),
                Some(format!("Auth response: {}", auth_response)),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "xmpp",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "xmpp",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
