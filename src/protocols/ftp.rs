use async_trait::async_trait;
use std::time::{Duration, Instant};
use suppaftp::FtpStream;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct FtpProtocol;

#[async_trait]
impl Protocol for FtpProtocol {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn default_port(&self) -> u16 {
        21
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout: Duration,
        _proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();
        let target_clone = target.clone();
        let cred_clone = credential.clone();

        match tokio::time::timeout(timeout, async {
            tokio::task::spawn_blocking(move || {
                match FtpStream::connect(&addr) {
                    Ok(mut ftp) => {
                        match ftp.login(&cred_clone.username, &cred_clone.password) {
                            Ok(()) => {
                                let _ = ftp.quit();
                                AuthResult::new(
                                    target_clone.host.clone(),
                                    target_clone.port,
                                    "ftp",
                                    cred_clone.username.clone(),
                                    cred_clone.password.clone(),
                                    true,
                                    start.elapsed(),
                                    None,
                                )
                            }
                            Err(e) => AuthResult::new(
                                target_clone.host.clone(),
                                target_clone.port,
                                "ftp",
                                cred_clone.username.clone(),
                                cred_clone.password.clone(),
                                false,
                                start.elapsed(),
                                Some(e.to_string()),
                            ),
                        }
                    }
                    Err(e) => AuthResult::new(
                        target_clone.host.clone(),
                        target_clone.port,
                        "ftp",
                        cred_clone.username.clone(),
                        cred_clone.password.clone(),
                        false,
                        start.elapsed(),
                        Some(format!("Connection failed: {}", e)),
                    ),
                }
            }).await
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "ftp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Task error: {}", e)),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "ftp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
