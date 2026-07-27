use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct IrcProtocol;

fn build_nick_user(nick: &str) -> String {
    format!(
        "NICK {}\r\nUSER {} 0 * :{}\r\n",
        nick, nick, nick
    )
}

fn build_pass_nick_user(password: &str, nick: &str) -> String {
    format!(
        "PASS {}\r\nNICK {}\r\nUSER {} 0 * :{}\r\n",
        password, nick, nick, nick
    )
}

#[async_trait]
impl Protocol for IrcProtocol {
    fn name(&self) -> &'static str {
        "irc"
    }

    fn default_port(&self) -> u16 {
        6667
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
            let nick = &credential.username;
            if !credential.password.is_empty() {
                let reg = build_pass_nick_user(&credential.password, nick);
                stream.write_str(&reg).await.map_err(|e| format!("Write PASS+NICK: {}", e))?;
            } else {
                let reg = build_nick_user(nick);
                stream.write_str(&reg).await.map_err(|e| format!("Write NICK: {}", e))?;
            }
            let mut buf = Vec::new();
            let mut found_welcome = false;
            let mut found_motd_end = false;
            let mut lines_read = 0u32;
            loop {
                let line = stream.read_line(&mut buf, timeout_dur).await?;
                if line.is_empty() {
                    break;
                }
                lines_read += 1;
                if lines_read > 100 {
                    break;
                }
                if line.contains(" 001 ") || line.contains(" 001") {
                    found_welcome = true;
                }
                if line.contains(" 376 ") || line.contains(" 376") || line.contains(" 422 ") {
                    found_motd_end = true;
                }
                if line.contains("ERROR") || line.contains(" 464 ") || line.contains("Bad password") {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "irc",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(),
                        Some(format!("Error: {}", line)),
                    ));
                }
                if found_welcome && found_motd_end {
                    break;
                }
            }
            if found_welcome {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "irc",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }
            if found_motd_end {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "irc",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }
            Ok(AuthResult::new(
                target.host.clone(), target.port, "irc",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(),
                Some("No welcome message".into()),
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "irc",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "irc",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
