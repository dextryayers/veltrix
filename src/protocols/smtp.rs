use async_trait::async_trait;
use std::time::{Duration, Instant};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::SmtpTransport;
use lettre::Message;
use lettre::Transport;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct SmtpProtocol;

#[async_trait]
impl Protocol for SmtpProtocol {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn default_port(&self) -> u16 {
        25
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        _proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();

        let creds = Credentials::new(credential.username.clone(), credential.password.clone());

        let email = match Message::builder()
            .from(format!("{} <{}>", credential.username, credential.username)
                .parse()
                .unwrap_or_else(|_| "user@localhost".parse().unwrap()))
            .to("test@localhost".parse().unwrap())
            .subject("Test")
            .body("test".to_string())
        {
            Ok(m) => m,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Build error: {}", e)),
            ),
        };

        let use_tls = target.port == 465 || target.port == 587;
        let target_host = target.host.clone();
        let target_port = target.port;
        let target_clone = target.clone();
        let cred_clone = credential.clone();

        match tokio::time::timeout(timeout_dur, tokio::task::spawn_blocking(move || {
            let builder = if use_tls {
                SmtpTransport::starttls_relay(&target_host)
            } else {
                SmtpTransport::relay(&target_host)
            };

            match builder {
                Ok(relay) => {
                    let transport = relay
                        .port(target_port)
                        .credentials(creds)
                        .timeout(Some(timeout_dur))
                        .build();

                    match transport.send(&email) {
                        Ok(_) => AuthResult::new(
                            target_clone.host.clone(), target_clone.port, "smtp",
                            cred_clone.username.clone(), cred_clone.password.clone(),
                            true, start.elapsed(), None,
                        ),
                        Err(e) => {
                            let err_str = e.to_string();
                            let is_auth = err_str.contains("auth") || err_str.contains("credentials")
                                || err_str.contains("535") || err_str.contains("authentication");
                            AuthResult::new(
                                target_clone.host.clone(), target_clone.port, "smtp",
                                cred_clone.username.clone(), cred_clone.password.clone(),
                                false, start.elapsed(),
                                if is_auth { None } else { Some(err_str) },
                            )
                        }
                    }
                }
                Err(e) => AuthResult::new(
                    target_clone.host.clone(), target_clone.port, "smtp",
                    cred_clone.username.clone(), cred_clone.password.clone(),
                    false, start.elapsed(), Some(format!("Relay error: {}", e)),
                ),
            }
        })).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Task error: {}", e)),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "smtp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
