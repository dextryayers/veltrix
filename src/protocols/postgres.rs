use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct PostgresProtocol;

fn md5_hash(input: &str) -> String {
    let mut hasher = md5::Context::new();
    hasher.consume(input.as_bytes());
    let digest = hasher.finalize();
    format!("{:x}", digest)
}

fn pg_md5(password: &str, user: &str, salt: &[u8]) -> String {
    let inner = format!("{}{}", md5_hash(&format!("{}{}", password, user)), user);
    let mut hasher = md5::Context::new();
    hasher.consume(inner.as_bytes());
    hasher.consume(salt);
    let digest = hasher.finalize();
    format!("md5{:x}", digest)
}

#[async_trait]
impl Protocol for PostgresProtocol {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn default_port(&self) -> u16 {
        5432
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
            let addr = target.addr_string();
            let mut stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            let mut buf = vec![0u8; 8192];

            let params = format!("\0user\0{}\0database\0{}\0\0",
                credential.username, credential.username);
            let payload_len = 4 + 4 + params.len() as u32;
            let mut startup = Vec::new();
            startup.extend_from_slice(&payload_len.to_be_bytes());
            startup.extend_from_slice(&(196608u32).to_be_bytes());
            startup.extend_from_slice(params.as_bytes());
            stream.write_all(&startup).await
                .map_err(|e| format!("Startup: {}", e))?;
            stream.flush().await.ok();

            let n = stream.read(&mut buf).await
                .map_err(|e| format!("Read auth: {}", e))?;
            if n < 5 {
                return Err("Short auth response".into());
            }

            let msg_type = buf[0] as char;
            let _msg_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

            if msg_type == 'R' {
                let auth_type = u32::from_be_bytes([
                    buf[5], buf[6], buf[7], buf[8],
                ]);

                match auth_type {
                    0 => {
                        return Ok(AuthResult::new(
                            target.host.clone(), target.port, "postgres",
                            credential.username.clone(), credential.password.clone(),
                            true, start.elapsed(), None,
                        ));
                    }
                    3 => {
                        let mut pw_buf = Vec::new();
                        pw_buf.extend_from_slice(&(0u32.to_be_bytes()));
                        let pass_bytes = credential.password.as_bytes();
                        pw_buf.extend_from_slice(pass_bytes);
                        pw_buf.push(0);

                        let len = pw_buf.len() as u32 + 4;
                        let mut pkt = vec!['p' as u8];
                        pkt.extend_from_slice(&len.to_be_bytes());
                        pkt.extend_from_slice(&pw_buf);

                        stream.write_all(&pkt).await
                            .map_err(|e| format!("Password: {}", e))?;
                        stream.flush().await.ok();
                    }
                    5 => {
                        let salt = &buf[9..9 + 4];
                        let hash = pg_md5(&credential.password, &credential.username, salt);

                        let mut pw_bytes = hash.as_bytes().to_vec();
                        pw_bytes.push(0);
                        let len = pw_bytes.len() as u32 + 4;
                        let mut pkt = vec!['p' as u8];
                        pkt.extend_from_slice(&len.to_be_bytes());
                        pkt.extend_from_slice(&pw_bytes);

                        stream.write_all(&pkt).await
                            .map_err(|e| format!("MD5 password: {}", e))?;
                        stream.flush().await.ok();
                    }
                    _ => {
                        return Err(format!("Unsupported auth type: {}", auth_type));
                    }
                }

                let n = stream.read(&mut buf).await
                    .map_err(|e| format!("Read response: {}", e))?;
                if n < 5 {
                    return Err("Short response".into());
                }

                let resp_type = buf[0] as char;
                if resp_type == 'R' {
                    let auth_ok = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
                    if auth_ok == 0 {
                        Ok(AuthResult::new(
                            target.host.clone(), target.port, "postgres",
                            credential.username.clone(), credential.password.clone(),
                            true, start.elapsed(), None,
                        ))
                    } else {
                        Err(format!("Auth failed code: {}", auth_ok))
                    }
                } else if resp_type == 'E' {
                    let err_msg = String::from_utf8_lossy(&buf[..n.min(buf.len())]);
                    let is_auth = err_msg.contains("password")
                        || err_msg.contains("authentication")
                        || err_msg.contains("28P01");
                    Ok(AuthResult::new(
                        target.host.clone(), target.port, "postgres",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(),
                        if is_auth { None } else { Some(err_msg.trim().to_string()) },
                    ))
                } else {
                    Err(format!("Unexpected response: {}", resp_type))
                }
            } else if msg_type == 'E' {
                let err_msg = String::from_utf8_lossy(&buf[..n.min(buf.len())]);
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "postgres",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(format!("Error: {}", err_msg.trim())),
                ))
            } else {
                Err(format!("Unexpected msg type: {}", msg_type))
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "postgres",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "postgres",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
