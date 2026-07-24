use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct Pop3Protocol;

#[async_trait]
impl Protocol for Pop3Protocol {
    fn name(&self) -> &'static str {
        "pop3"
    }

    fn default_port(&self) -> u16 {
        110
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();

        match timeout(timeout_dur, async {
            let mut stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await.map_err(|e| format!("Connect: {}", e))?,
                None => TcpStream::connect(&addr).await.map_err(|e| format!("Connect: {}", e))?,
            };
            let (reader, mut writer) = stream.split();
            let mut buf_reader = BufReader::new(reader);
            let mut buf = Vec::new();

            buf_reader.read_until(b'\n', &mut buf).await.map_err(|e| format!("Banner: {}", e))?;
            let banner = String::from_utf8_lossy(&buf);
            if !banner.starts_with("+OK") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "pop3",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Bad banner: {}", banner.trim())),
                ));
            }

            writer.write_all(format!("USER {}\r\n", credential.username).as_bytes()).await.map_err(|e| format!("USER cmd: {}", e))?;
            writer.flush().await.ok();
            buf.clear();
            buf_reader.read_until(b'\n', &mut buf).await.map_err(|e| format!("USER resp: {}", e))?;
            let user_resp = String::from_utf8_lossy(&buf);
            if !user_resp.starts_with("+OK") {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "pop3",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("User rejected: {}", user_resp.trim())),
                ));
            }

            writer.write_all(format!("PASS {}\r\n", credential.password).as_bytes()).await.map_err(|e| format!("PASS cmd: {}", e))?;
            writer.flush().await.ok();
            buf.clear();
            buf_reader.read_until(b'\n', &mut buf).await.map_err(|e| format!("PASS resp: {}", e))?;
            let pass_resp = String::from_utf8_lossy(&buf);

            let success = pass_resp.starts_with("+OK");

            writer.write_all(b"QUIT\r\n").await.ok();

            Ok(AuthResult::new(
                target.host.clone(), target.port, "pop3",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(),
                if success { None } else { Some(pass_resp.trim().to_string()) },
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "pop3",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "pop3",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
