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

pub struct VncProtocol;

const RFB_VERSION: &[u8; 12] = b"RFB 003.003\n";

fn vnc_des_encrypt(challenge: &[u8; 16], password: &[u8; 8]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for i in 0..8 {
        key[i] = password[i].reverse_bits();
    }
    let mut result = [0u8; 16];
    for block in 0..2 {
        let offset = block * 8;
        let mut data = [0u8; 8];
        data.copy_from_slice(&challenge[offset..offset + 8]);
        for _round in 0..16 {
            let k = key[_round % 8];
            for i in 0..8 {
                data[i] ^= k;
                data[i] = data[i].wrapping_add(0x3f);
                data[i] = data[i].rotate_left(3);
            }
        }
        result[offset..offset + 8].copy_from_slice(&data);
    }
    result
}

#[async_trait]
impl Protocol for VncProtocol {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn default_port(&self) -> u16 {
        5900
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
            let mut stream = match proxy {
                Some(p) => p.tcp_connect(&target.addr_string(), timeout_dur).await
                    .map_err(|e| format!("Connect: {}", e))?,
                None => {
                    let s = TcpStream::connect(target.addr_string()).await
                        .map_err(|e| format!("Connect: {}", e))?;
                    s.set_nodelay(true).ok();
                    s
                },
            };

            let mut buf = [0u8; 12];
            stream.read_exact(&mut buf).await
                .map_err(|e| format!("Read version: {}", e))?;
            let _server_version = String::from_utf8_lossy(&buf);

            stream.write_all(RFB_VERSION).await
                .map_err(|e| format!("Send version: {}", e))?;
            stream.flush().await.ok();

            let mut sec_count = [0u8; 1];
            stream.read_exact(&mut sec_count).await
                .map_err(|e| format!("Read sec count: {}", e))?;
            let count = sec_count[0] as usize;

            let mut sec_types = vec![0u8; count];
            if count > 0 {
                stream.read_exact(&mut sec_types).await
                    .map_err(|e| format!("Read sec types: {}", e))?;
            }

            if sec_types.contains(&0x01) {
                stream.write_all(&[0x01]).await
                    .map_err(|e| format!("Send sec None: {}", e))?;

                let mut sec_result = [0u8; 4];
                stream.read_exact(&mut sec_result).await
                    .map_err(|e| format!("Read sec result: {}", e))?;
                let result_val = u32::from_be_bytes(sec_result);

                if result_val == 0 {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "vnc",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    ));
                } else {
                    return Ok(AuthResult::new(
                        target.host.clone(), target.port, "vnc",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some("VNC auth failed (no security)".into()),
                    ));
                }
            }

            if sec_types.contains(&0x02) {
                stream.write_all(&[0x02]).await
                    .map_err(|e| format!("Send sec VNC: {}", e))?;

                let mut challenge = [0u8; 16];
                stream.read_exact(&mut challenge).await
                    .map_err(|e| format!("Read challenge: {}", e))?;

                let mut pass = [0u8; 8];
                let pw_bytes = credential.password.as_bytes();
                let len = pw_bytes.len().min(8);
                pass[..len].copy_from_slice(&pw_bytes[..len]);

                let response = vnc_des_encrypt(&challenge, &pass);
                stream.write_all(&response).await
                    .map_err(|e| format!("Send response: {}", e))?;
                stream.flush().await.ok();

                let mut sec_result = [0u8; 4];
                stream.read_exact(&mut sec_result).await
                    .map_err(|e| format!("Read sec result: {}", e))?;
                let result_val = u32::from_be_bytes(sec_result);

                if result_val == 0 {
                    Ok(AuthResult::new(
                        target.host.clone(), target.port, "vnc",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    ))
                } else {
                    Ok(AuthResult::new(
                        target.host.clone(), target.port, "vnc",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some("VNC auth failed".into()),
                    ))
                }
            } else {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "vnc",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("No supported auth type".into()),
                ))
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "vnc",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "vnc",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
