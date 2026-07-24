use async_trait::async_trait;
use sha1::{Sha1, digest::Digest as Sha1Digest};
use sha2::{Sha256, digest::Digest as Sha256Digest};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct MySqlProtocol;

async fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await
        .map_err(|e| format!("Read header: {}", e))?;
    let len = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await
            .map_err(|e| format!("Read payload: {}", e))?;
    }
    Ok(payload)
}

fn mysql_native_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut stage1 = Sha1::new();
    stage1.update(password.as_bytes());
    let stage1_hash = stage1.finalize();

    let mut stage2 = Sha1::new();
    stage2.update(&stage1_hash);
    let stage2_hash = stage2.finalize();

    let mut hash = Sha1::new();
    hash.update(salt);
    hash.update(&stage2_hash);
    let hash_result = hash.finalize();

    stage1_hash.iter().zip(hash_result.iter()).map(|(a, b)| a ^ b).collect()
}

fn caching_sha2_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut stage1 = Sha256::new();
    stage1.update(password.as_bytes());
    let stage1_hash = stage1.finalize();

    let mut stage2 = Sha256::new();
    stage2.update(&stage1_hash);
    let stage2_hash = stage2.finalize();

    let mut hash = Sha256::new();
    hash.update(salt);
    hash.update(&stage2_hash);
    let hash_result = hash.finalize();

    stage1_hash.iter().zip(hash_result.iter()).map(|(a, b)| a ^ b).collect()
}

const CLIENT_PROTOCOL_41: u32 = 0x00000200;
const CLIENT_SECURE_CONNECTION: u32 = 0x00008000;
const CLIENT_PLUGIN_AUTH: u32 = 0x00080000;
#[allow(dead_code)]
const CLIENT_CONNECT_WITH_DB: u32 = 0x00000008;

#[async_trait]
impl Protocol for MySqlProtocol {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn default_port(&self) -> u16 {
        3306
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

        let connect_result = match timeout(timeout_dur, async {
            let mut stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            let payload = read_packet(&mut stream).await?;

            if payload[0] == 0xff {
                let err_msg = String::from_utf8_lossy(&payload[3..]);
                return Err(format!("Server error: {}", err_msg.trim()));
            }

            let nul1 = payload[1..].iter().position(|&b| b == 0)
                .ok_or_else(|| "No server version null".to_string())?;
            let pos = 1 + nul1 + 1;

            let _connection_id = u32::from_le_bytes([
                payload[pos], payload[pos + 1], payload[pos + 2], payload[pos + 3],
            ]);
            let pos = pos + 4;

            let auth_plugin_data_part1 = &payload[pos..pos + 8];
            let pos = pos + 8 + 1;

            let capabilities1 = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
            let pos = pos + 2;

            let _character_set = payload[pos];
            let pos = pos + 1;

            let _status_flags = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
            let pos = pos + 2;

            let capabilities2 = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
            let pos = pos + 2;

            let capabilities = (capabilities2 as u32) << 16 | capabilities1 as u32;

            let auth_plugin_data_len = if pos < payload.len() { payload[pos] } else { 0 };
            let pos = pos + 1;

            let pos = pos + 10;

            let auth_plugin_data_part2 = if auth_plugin_data_len > 8 && pos < payload.len() {
                let part2_len = auth_plugin_data_len as usize - 8 - 1;
                let end = pos + part2_len.min(payload.len() - pos);
                &payload[pos..end]
            } else {
                &[]
            };

            let salt: Vec<u8> = auth_plugin_data_part1.iter()
                .chain(auth_plugin_data_part2.iter())
                .copied()
                .collect();

            let auth_plugin_name = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
                let after_part2 = pos + auth_plugin_data_part2.len();
                if after_part2 < payload.len() {
                    if let Some(nul_pos) = payload[after_part2..].iter().position(|&b| b == 0) {
                        Some(String::from_utf8_lossy(&payload[after_part2..after_part2 + nul_pos]).to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let auth_plugin = auth_plugin_name.as_deref().unwrap_or("mysql_native_password");

            let auth_response = match auth_plugin {
                "mysql_native_password" => mysql_native_password(&credential.password, &salt),
                "caching_sha2_password" => caching_sha2_password(&credential.password, &salt),
                _ => return Err(format!("Unsupported auth plugin: {}", auth_plugin)),
            };

            let client_flags = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
            let mut resp = Vec::new();
            resp.extend_from_slice(&client_flags.to_le_bytes());
            resp.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
            resp.push(8);
            resp.extend_from_slice(&[0u8; 23]);
            resp.extend_from_slice(credential.username.as_bytes());
            resp.push(0);
            resp.push(auth_response.len() as u8);
            resp.extend_from_slice(&auth_response);
            resp.extend_from_slice(auth_plugin.as_bytes());
            resp.push(0);

            stream.write_all(&resp).await
                .map_err(|e| format!("Write auth: {}", e))?;

            let mut seq_header = [0u8; 4];
            stream.read_exact(&mut seq_header).await
                .map_err(|e| format!("Read resp header: {}", e))?;
            let resp_len = (seq_header[0] as usize) | ((seq_header[1] as usize) << 8) | ((seq_header[2] as usize) << 16);
            let mut response = vec![0u8; resp_len];
            if resp_len > 0 {
                stream.read_exact(&mut response).await
                    .map_err(|e| format!("Read resp payload: {}", e))?;
            }

            if response.is_empty() {
                return Err("Empty response".into());
            }

            if response[0] == 0x00 {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "mysql",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ))
            } else if response[0] == 0xff {
                let err_code = u16::from_le_bytes([response[1], response[2]]);
                let err_msg = if response.len() > 9 {
                    String::from_utf8_lossy(&response[9..]).trim().to_string()
                } else {
                    format!("Error code {}", err_code)
                };
                let is_auth = err_code == 1045;
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "mysql",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    if is_auth { None } else { Some(err_msg) },
                ))
            } else if response[0] == 0x01 {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "mysql",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some("Auth switch needed, fast auth not implemented".into()),
                ))
            } else {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "mysql",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some(format!("Unexpected response type: {}", response[0])),
                ))
            }
        }).await {
            Ok(r) => r,
            Err(_) => Ok(AuthResult::new(
                target.host.clone(), target.port, "mysql",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            )),
        };

        match connect_result {
            Ok(r) => r,
            Err(e) => AuthResult::new(
                target.host.clone(), target.port, "mysql",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
        }
    }
}
