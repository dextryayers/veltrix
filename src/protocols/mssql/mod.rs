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
use super::tcp::{connect_optimized, tune_tcp};

pub struct MssqlProtocol;

fn tds_header(r#type: u8, length: u16) -> Vec<u8> {
    vec![
        r#type,
        0x01,
        (length >> 8) as u8,
        (length & 0xff) as u8,
        0x00, 0x00,
        0x00,
        0x00,
    ]
}

fn build_prelogin() -> Vec<u8> {
    let mut options = Vec::new();
    options.push(0x00); options.push(0x01); options.push(0x00); options.push(0x08);
    options.push(0x01); options.push(0x01); options.push(0x00); options.push(0x0e);
    options.push(0x02); options.push(0x01); options.push(0x00); options.push(0x10);
    options.push(0x03); options.push(0x01); options.push(0x00); options.push(0x12);
    options.push(0xff);

    let total_len = (8 + options.len()) as u16;
    let mut pkt = tds_header(0x12, total_len);
    pkt.extend_from_slice(&options);
    pkt
}

fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn build_login7(username: &str, password: &str, host: &str) -> Vec<u8> {
    let user_uni = to_utf16le(username);
    let _pass_uni = to_utf16le(password);
    let host_uni = to_utf16le(host);
    let app_uni = to_utf16le("veltrix");
    let db_uni = to_utf16le("");

    let mut body = vec![0u8; 90];
    let mut offset: u16 = 90;

    body[4..8].copy_from_slice(&(2u32).to_le_bytes());
    body[8..12].copy_from_slice(&(134217728u32).to_le_bytes());

    let ofs_user = offset;
    body[44..48].copy_from_slice(&(user_uni.len() as u32).to_le_bytes());
    body[48..50].copy_from_slice(&(user_uni.len() as u16).to_le_bytes());
    body[50..52].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += user_uni.len() as u16;

    let _ofs_pass = offset;
    let pass_enc: Vec<u8> = password.encode_utf16()
        .flat_map(|c| {
            let b = c.to_le_bytes();
            let xored = ((b[0] as u16) | ((b[1] as u16) << 8)) ^ 0xA5A5;
            xored.to_le_bytes().to_vec()
        })
        .collect();
    body[52..56].copy_from_slice(&(pass_enc.len() as u32).to_le_bytes());
    body[56..58].copy_from_slice(&(pass_enc.len() as u16).to_le_bytes());
    body[58..60].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += pass_enc.len() as u16;

    let _ofs_host = offset;
    body[60..64].copy_from_slice(&(host_uni.len() as u32).to_le_bytes());
    body[64..66].copy_from_slice(&(host_uni.len() as u16).to_le_bytes());
    body[66..68].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += host_uni.len() as u16;

    let _ofs_app = offset;
    body[68..72].copy_from_slice(&(app_uni.len() as u32).to_le_bytes());
    body[72..74].copy_from_slice(&(app_uni.len() as u16).to_le_bytes());
    body[74..76].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += app_uni.len() as u16;

    let _ofs_db = offset;
    body[76..80].copy_from_slice(&(db_uni.len() as u32).to_le_bytes());
    body[80..82].copy_from_slice(&(db_uni.len() as u16).to_le_bytes());
    body[82..84].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += db_uni.len() as u16;

    body[40..44].copy_from_slice(&(ofs_user as u32).to_le_bytes());
    body[44..48].copy_from_slice(&(user_uni.len() as u32).to_le_bytes());

    let total_len = 8 + offset as usize;
    let mut pkt = tds_header(0x10, total_len as u16);
    pkt.extend_from_slice(&body);
    pkt.extend_from_slice(&user_uni);
    pkt.extend_from_slice(&pass_enc);
    pkt.extend_from_slice(&host_uni);
    pkt.extend_from_slice(&app_uni);
    pkt.extend_from_slice(&db_uni);
    pkt
}

async fn tds_read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await
        .map_err(|e| format!("Read TDS header: {}", e))?;
    let len = ((header[2] as usize) << 8) | header[3] as usize;
    if len < 8 {
        return Err("Bad TDS packet len".into());
    }
    let mut data = vec![0u8; len - 8];
    if !data.is_empty() {
        stream.read_exact(&mut data).await
            .map_err(|e| format!("Read TDS data: {}", e))?;
    }
    Ok(data)
}

#[async_trait]
impl Protocol for MssqlProtocol {
    fn name(&self) -> &'static str {
        "mssql"
    }

    fn default_port(&self) -> u16 {
        1433
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
                Some(p) => {
                    let s = p.tcp_connect(&target.addr_string(), timeout_dur).await
                        .map_err(|e| format!("Connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => {
                    connect_optimized(&target.addr_string(), timeout_dur).await
                        .map_err(|e| format!("Connect: {}", e))?
                },
            };

            let prelogin = build_prelogin();
            stream.write_all(&prelogin).await
                .map_err(|e| format!("Send prelogin: {}", e))?;
            stream.flush().await.ok();

            tds_read_packet(&mut stream).await?;

            let login = build_login7(&credential.username, &credential.password, &target.host);
            stream.write_all(&login).await
                .map_err(|e| format!("Send login: {}", e))?;
            stream.flush().await.ok();

            let resp = tds_read_packet(&mut stream).await?;

            if resp.is_empty() {
                return Err("Empty response".into());
            }

            let msg_type = resp[0];
            if msg_type == 0xad || msg_type == 0x04 || msg_type == 0x79 {
                let has_error = resp.windows(3).any(|w| w == &[0xac, 0x00, 0x00])
                    || resp.windows(2).any(|w| w == &[0x05, 0x00]);

                if has_error {
                    Ok(AuthResult::new(
                        target.host.clone(), target.port, "mssql",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(), Some("Login denied".into()),
                    ))
                } else {
                    Ok(AuthResult::new(
                        target.host.clone(), target.port, "mssql",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    ))
                }
            } else {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "mssql",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some(format!("Unexpected response: 0x{:02x}", msg_type)),
                ))
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "mssql",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "mssql",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
