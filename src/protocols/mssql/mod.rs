use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct MssqlProtocol;

fn tds_header(r#type: u8, length: u16) -> Vec<u8> {
    vec![
        r#type, 0x01,
        (length >> 8) as u8, (length & 0xff) as u8,
        0x00, 0x00, 0x00, 0x00,
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
    let host_uni = to_utf16le(host);
    let app_uni = to_utf16le("veltrix");
    let db_uni = to_utf16le("");

    let mut body = vec![0u8; 90];
    let mut offset: u16 = 90;

    body[4..8].copy_from_slice(&(2u32).to_le_bytes());
    body[8..12].copy_from_slice(&(134217728u32).to_le_bytes());

    body[40..44].copy_from_slice(&(offset as u32).to_le_bytes());
    body[44..48].copy_from_slice(&(user_uni.len() as u32).to_le_bytes());
    body[48..50].copy_from_slice(&(user_uni.len() as u16).to_le_bytes());
    body[50..52].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += user_uni.len() as u16;

    let pass_enc: Vec<u8> = password.encode_utf16()
        .flat_map(|c| {
            let b = c.to_le_bytes();
            ((b[0] as u16 | ((b[1] as u16) << 8)) ^ 0xA5A5).to_le_bytes().to_vec()
        })
        .collect();
    body[52..56].copy_from_slice(&(pass_enc.len() as u32).to_le_bytes());
    body[56..58].copy_from_slice(&(pass_enc.len() as u16).to_le_bytes());
    body[58..60].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += pass_enc.len() as u16;

    body[60..64].copy_from_slice(&(host_uni.len() as u32).to_le_bytes());
    body[64..66].copy_from_slice(&(host_uni.len() as u16).to_le_bytes());
    body[66..68].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += host_uni.len() as u16;

    body[68..72].copy_from_slice(&(app_uni.len() as u32).to_le_bytes());
    body[72..74].copy_from_slice(&(app_uni.len() as u16).to_le_bytes());
    body[74..76].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += app_uni.len() as u16;

    body[76..80].copy_from_slice(&(db_uni.len() as u32).to_le_bytes());
    body[80..82].copy_from_slice(&(db_uni.len() as u16).to_le_bytes());
    body[82..84].copy_from_slice(&(offset as u16).to_le_bytes());
    offset += db_uni.len() as u16;

    let user_off_val = body[44];
    body[40..44].copy_from_slice(&(user_off_val as u32).to_le_bytes());

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

async fn tds_read_packet(
    stream: &mut TcpStream,
    timeout_dur: Duration,
) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 8];
    tokio::time::timeout(timeout_dur, stream.read_exact(&mut header)).await
        .map_err(|_| "Read TDS header timeout".to_string())?
        .map_err(|e| format!("Read TDS header: {}", e))?;
    let len = ((header[2] as usize) << 8) | header[3] as usize;
    if len < 8 {
        return Err("Bad TDS packet len".into());
    }
    let mut data = vec![0u8; len - 8];
    if !data.is_empty() {
        tokio::time::timeout(timeout_dur, stream.read_exact(&mut data)).await
            .map_err(|_| "Read TDS data timeout".to_string())?
            .map_err(|e| format!("Read TDS data: {}", e))?;
    }
    Ok(data)
}

fn parse_tds_response(data: &[u8]) -> (bool, Option<String>) {
    // TDS 7.x response tokens after login:
    // 0xab = LOGINACK (token byte, followed by length, then status byte)
    // 0x81 = DONE (token byte, success/error)
    // 0xfd = ERROR (token byte, followed by error info)
    // 0xac = DONEINPROC
    // 0xad = DONEPROC
    // 0x79 = RETURNSTATUS
    // 0xe3 = ENVCHANGE (normal post-login, not an error)

    if data.is_empty() {
        return (false, Some("Empty response".into()));
    }

    let mut has_loginack = false;
    let mut loginack_ok = false;
    let mut has_error_token = false;
    let mut error_msg = None;

    let mut i = 0;
    while i < data.len() {
        let token = data[i];
        if token == 0xab {
            // LOGINACK: token(1) + length(2) + interface(1) + status(1) + reserved(2) + name(0-terminated)
            if i + 5 < data.len() {
                has_loginack = true;
                let status = data[i + 4];
                loginack_ok = status == 0; // 0=success
                let name_start = i + 7;
                let name_end = data[name_start..].iter().position(|&b| b == 0)
                    .map(|p| name_start + p)
                    .unwrap_or(data.len());
                let _prog_name = String::from_utf8_lossy(&data[name_start..name_end.min(data.len())]);
                let token_len = ((data[i + 1] as usize) << 8) | data[i + 2] as usize;
                i += 3 + token_len;
                continue;
            }
            i += 1;
            continue;
        }
        if token == 0x81 || token == 0xac || token == 0xad {
            // DONE/DONEINPROC/DONEPROC: token(1) + status(2) + cur_cmd(2) + done_rows(8)
            let done_status = if i + 3 < data.len() {
                (data[i + 1] as u16) | ((data[i + 2] as u16) << 8)
            } else {
                0
            };
            // DONE_STATUS: 0x0001=DONE_ERROR, 0x0002=DONE_PROC
            if done_status & 0x0001 != 0 {
                has_error_token = true;
            }
            i += 13;
            continue;
        }
        if token == 0xfd {
            // ERROR: token(1) + length(2) + error_number(4) + state(1) + class(1) + msg(0-terminated string)
            has_error_token = true;
            if i + 4 < data.len() {
                let msg_len = ((data[i + 1] as usize) << 8) | data[i + 2] as usize;
                let error_number = u32::from_le_bytes(
                    data[i + 3..i + 7].try_into().unwrap_or([0u8; 4])
                );
                if i + 9 < data.len() {
                    let msg_start = i + 9;
                    // Find the 0 or 0x00 0x00 terminator of the message (could be UCS-2)
                    let mut msg_end = msg_start;
                    while msg_end < data.len() && data[msg_end] != 0 {
                        msg_end += 1;
                    }
                    let msg = String::from_utf8_lossy(&data[msg_start..msg_end.min(data.len())]);
                    error_msg = Some(format!("TDS error {}: {}", error_number, msg));
                }
                i += 3 + msg_len;
                continue;
            }
            i += 1;
            continue;
        }
        if token == 0x79 {
            // RETURNSTATUS: token(1) + value(4)
            // Not relevant for auth
            i += 5;
            continue;
        }
        if token == 0xe3 {
            // ENVCHANGE: token(1) + length(2) + type(1) + ...
            // Normal post-login, not an error
            if i + 2 < data.len() {
                let token_len = ((data[i + 1] as usize) << 8) | data[i + 2] as usize;
                i += 3 + token_len;
                continue;
            }
            i += 1;
            continue;
        }
        // Skip unknown tokens
        i += 1;
    }

    if has_error_token {
        return (false, error_msg.or(Some("TDS error token present".into())));
    }
    if has_loginack && loginack_ok {
        return (true, None);
    }
    (false, error_msg.or(Some("Login denied".into())))
}

#[async_trait]
impl Protocol for MssqlProtocol {
    fn name(&self) -> &'static str { "mssql" }
    fn default_port(&self) -> u16 { 1433 }

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

            let prelogin = build_prelogin();
            stream.write_all(&prelogin).await?;
            tds_read_packet(stream.get_mut(), timeout_dur).await?;

            let login = build_login7(&credential.username, &credential.password, &target.host);
            stream.write_all(&login).await?;
            let resp = tds_read_packet(stream.get_mut(), timeout_dur).await?;

            let (success, err_msg) = parse_tds_response(&resp);

            Ok(AuthResult::new(
                target.host.clone(), target.port, "mssql",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(), err_msg,
            ))
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
