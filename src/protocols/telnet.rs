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

pub struct TelnetProtocol;

const TELNET_IAC: u8 = 255;
const TELNET_DONT: u8 = 254;
const TELNET_DO: u8 = 253;
const TELNET_WONT: u8 = 252;
const TELNET_WILL: u8 = 251;

#[async_trait]
impl Protocol for TelnetProtocol {
    fn name(&self) -> &'static str {
        "telnet"
    }

    fn default_port(&self) -> u16 {
        23
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        _proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();

        match timeout(timeout_dur, async {
            let mut stream = TcpStream::connect(target.addr_string()).await.map_err(|e| e.to_string())?;
            let (reader, mut writer) = stream.split();
            let mut buf_reader = BufReader::new(reader);
            let mut buf = Vec::new();

            buf_reader.read_until(b'\n', &mut buf).await.ok();
            let neg = handle_telnet_negotiation(&buf);
            if !neg.is_empty() {
                writer.write_all(&neg).await.ok();
            }

            buf.clear();
            buf_reader.read_until(b':', &mut buf).await.map_err(|e| e.to_string())?;
            let prompt = String::from_utf8_lossy(&buf).to_lowercase();

            if prompt.contains("login") || prompt.contains("username") || prompt.contains("user") {
                writer.write_all(format!("{}\r\n", credential.username).as_bytes()).await.map_err(|e| e.to_string())?;
                writer.flush().await.map_err(|e| e.to_string())?;

                tokio::time::sleep(Duration::from_millis(300)).await;

                buf.clear();
                buf_reader.read_until(b':', &mut buf).await.map_err(|e| e.to_string())?;
            }

            writer.write_all(format!("{}\r\n", credential.password).as_bytes()).await.map_err(|e| e.to_string())?;
            writer.flush().await.map_err(|e| e.to_string())?;

            tokio::time::sleep(Duration::from_millis(500)).await;

            buf.clear();
            let _ = timeout(Duration::from_secs(3), buf_reader.read_until(b'\n', &mut buf)).await;
            let response = String::from_utf8_lossy(&buf).to_lowercase();

            let success = !(response.contains("incorrect") || response.contains("invalid")
                || response.contains("failed") || response.contains("denied")
                || response.contains("wrong") || response.contains("error")
                || response.contains("password") && response.contains(":"));

            if success {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "telnet",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ))
            } else {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "telnet",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(response),
                ))
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "telnet",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}

fn handle_telnet_negotiation(buf: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == TELNET_IAC && i + 2 < buf.len() {
            match buf[i + 1] {
                TELNET_DO => {
                    response.extend_from_slice(&[TELNET_IAC, TELNET_WONT, buf[i + 2]]);
                }
                TELNET_WILL => {
                    response.extend_from_slice(&[TELNET_IAC, TELNET_DONT, buf[i + 2]]);
                }
                TELNET_DONT | TELNET_WONT => {}
                _ => {}
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    response
}
