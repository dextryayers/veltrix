use async_trait::async_trait;
use rand::Rng;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::tcp::{connect_optimized, tune_tcp};
use super::Protocol;

pub struct SmbProtocol;

fn to_utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn ntlm_hash(password: &str) -> Vec<u8> {
    use md4::{Md4, Digest};
    Md4::digest(&to_utf16_le(password)).to_vec()
}

fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    const BLOCK_SIZE: usize = 64;
    let mut k = key.to_vec();
    if k.len() > BLOCK_SIZE {
        let mut ctx = md5::Context::new();
        ctx.consume(&k);
        k = ctx.finalize().0.to_vec();
    }
    k.resize(BLOCK_SIZE, 0);
    let mut ipad = vec![0u8; BLOCK_SIZE];
    let mut opad = vec![0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let mut inner = md5::Context::new();
    inner.consume(&ipad);
    inner.consume(message);
    let inner_hash = inner.finalize();
    let mut outer = md5::Context::new();
    outer.consume(&opad);
    outer.consume(&*inner_hash);
    outer.finalize().0
}

fn ntlmv2_hash(password: &str, username: &str, domain: &str) -> Vec<u8> {
    let hash = ntlm_hash(password);
    let upper = username.to_uppercase();
    let mut ident = to_utf16_le(&upper);
    ident.extend_from_slice(&to_utf16_le(domain));
    hmac_md5(&hash, &ident).to_vec()
}

fn build_smb2_header(command: u16, message_id: u64, session_id: u64, _body_len: u16) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(64);
    hdr.extend_from_slice(&[0xFE, b'S', b'M', b'b']);
    hdr.extend_from_slice(&64u16.to_le_bytes());
    hdr.extend_from_slice(&0u16.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&command.to_le_bytes());
    hdr.extend_from_slice(&0u16.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&message_id.to_le_bytes());
    hdr.extend_from_slice(&0xFEFFu32.to_le_bytes());
    hdr.extend_from_slice(&0u32.to_le_bytes());
    hdr.extend_from_slice(&session_id.to_le_bytes());
    hdr.extend_from_slice(&[0u8; 8]);
    hdr
}

fn build_negotiate_request() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&36u16.to_le_bytes());
    body.extend_from_slice(&3u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    let guid = rand::random::<[u8; 16]>();
    body.extend_from_slice(&guid);
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0x0202u16.to_le_bytes());
    body.extend_from_slice(&0x0210u16.to_le_bytes());
    body.extend_from_slice(&0x0300u16.to_le_bytes());

    let mut msg = build_smb2_header(0x0000, 1, 0, body.len() as u16);
    msg.extend_from_slice(&body);
    msg
}

fn build_ntlmssp_negotiate(domain: &str, hostname: &str) -> Vec<u8> {
    let domain_utf16 = to_utf16_le(domain);
    let host_utf16 = to_utf16_le(hostname);
    let domain_offset = 64u32 + 16;
    let host_offset = domain_offset + domain_utf16.len() as u32;
    let flags: u32 = 0x02880201;

    let mut msg = Vec::new();
    msg.extend_from_slice(b"NTLMSSP\x00");
    msg.extend_from_slice(&1u32.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());
    msg.extend_from_slice(&(host_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(host_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&host_offset.to_le_bytes());
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&host_utf16);
    msg
}

fn parse_challenge(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    if data.len() < 48 || &data[..8] != b"NTLMSSP\x00" {
        return Err("Not NTLMSSP".to_string());
    }
    let msg_type = {
        let arr: [u8; 4] = data[8..12].try_into().map_err(|_| "Bad msg_type".to_string())?;
        u32::from_le_bytes(arr)
    };
    if msg_type != 2 {
        return Err(format!("Not challenge (type {} )", msg_type));
    }
    let server_challenge = data[24..32].to_vec();
    let target_name_len = {
        let arr: [u8; 2] = data[12..14].try_into().map_err(|_| "Bad tname_len".to_string())?;
        u16::from_le_bytes(arr) as usize
    };
    let target_name_off = {
        let arr: [u8; 4] = data[16..20].try_into().map_err(|_| "Bad tname_off".to_string())?;
        u32::from_le_bytes(arr) as usize
    };
    let mut target_name = Vec::new();
    if target_name_len > 0 && target_name_off + target_name_len <= data.len() {
        target_name = data[target_name_off..target_name_off + target_name_len].to_vec();
    }
    let context = if data.len() >= 56 {
        data[48..56].to_vec()
    } else {
        vec![0u8; 8]
    };
    Ok((server_challenge, target_name, context))
}

fn build_ntlmv2_auth(
    password: &str,
    username: &str,
    domain: &str,
    server_challenge: &[u8],
    target_info: &[u8],
) -> Vec<u8> {
    let mut client_nonce = [0u8; 8];
    let mut rng = rand::thread_rng();
    rng.fill(&mut client_nonce);

    let ntlmv2_hash_val = ntlmv2_hash(password, username, domain);

    let mut blob = Vec::new();
    blob.extend_from_slice(&[1u8, 1u8, 0u8, 0u8]);
    blob.extend_from_slice(&[0u8; 4]);
    blob.extend_from_slice(&0x00000000u64.to_le_bytes());
    blob.extend_from_slice(&client_nonce);
    blob.extend_from_slice(&[0u8; 4]);
    blob.extend_from_slice(target_info);
    blob.extend_from_slice(&[0u8; 4]);
    blob.extend_from_slice(&[0u8; 4]);
    blob.extend_from_slice(&[0u8; 4]);

    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(&[0u8; 8]);
    proof_input.extend_from_slice(server_challenge);
    proof_input.extend_from_slice(&blob);

    let nt_proof = hmac_md5(&ntlmv2_hash_val, &proof_input).to_vec();

    let mut ntlmv2_response = Vec::new();
    ntlmv2_response.extend_from_slice(&nt_proof);
    ntlmv2_response.extend_from_slice(&blob);

    let domain_utf16 = to_utf16_le(domain);
    let user_utf16 = to_utf16_le(username);
    let host_utf16 = to_utf16_le("WORKSTATION");

    let lmv2_response = client_nonce.to_vec();

    let mut msg = Vec::new();
    msg.extend_from_slice(b"NTLMSSP\x00");
    msg.extend_from_slice(&3u32.to_le_bytes());
    msg.extend_from_slice(&0x02880201u32.to_le_bytes());
    msg.extend_from_slice(&0x00000000u64.to_le_bytes());
    msg.extend_from_slice(&0x00000000u64.to_le_bytes());

    let lmv2_len = lmv2_response.len() as u16;
    let ntlmv2_len = ntlmv2_response.len() as u16;
    let domain_len = domain_utf16.len() as u16;
    let user_len = user_utf16.len() as u16;
    let host_len = host_utf16.len() as u16;

    let mut offset = 64u32 + 8 + 8;
    let lm_offset = offset;
    offset += lmv2_len as u32;
    let nt_offset = offset;
    offset += ntlmv2_len as u32;
    let dom_off = offset;
    offset += domain_len as u32;
    let user_off = offset;
    offset += user_len as u32;
    let host_off = offset;

    msg.extend_from_slice(&lv2_fields(lmv2_len, lm_offset));
    msg.extend_from_slice(&lv2_fields(ntlmv2_len, nt_offset));
    msg.extend_from_slice(&lv2_fields(domain_len, dom_off));
    msg.extend_from_slice(&lv2_fields(user_len, user_off));
    msg.extend_from_slice(&lv2_fields(host_len, host_off));
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&[0u8; 8]);

    msg.extend_from_slice(&lmv2_response);
    msg.extend_from_slice(&ntlmv2_response);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&user_utf16);
    msg.extend_from_slice(&host_utf16);

    msg
}

fn lv2_fields(len: u16, offset: u32) -> Vec<u8> {
    let mut fields = Vec::with_capacity(8);
    fields.extend_from_slice(&len.to_le_bytes());
    fields.extend_from_slice(&len.to_le_bytes());
    fields.extend_from_slice(&offset.to_le_bytes());
    fields
}

fn build_session_setup(security_blob: &[u8], message_id: u64, session_id: u64) -> Vec<u8> {
    let security_buf_offset: u16 = 64 + 24;
    let security_buf_len: u16 = security_blob.len() as u16;

    let mut body = Vec::new();
    body.extend_from_slice(&25u16.to_le_bytes());
    body.push(0x00);
    body.push(0x00);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&security_buf_offset.to_le_bytes());
    body.extend_from_slice(&security_buf_len.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());

    let total_body_len = body.len() as u16 + security_buf_len;
    let mut msg = build_smb2_header(0x0001, message_id, session_id, total_body_len);
    msg.extend_from_slice(&body);
    msg.extend_from_slice(security_blob);
    msg
}

fn split_username(input: &str) -> (String, String) {
    if let Some(idx) = input.find('\\') {
        (input[..idx].to_string(), input[idx + 1..].to_string())
    } else {
        ("".to_string(), input.to_string())
    }
}

fn read_u32_le(slice: &[u8], start: usize) -> Result<u32, String> {
    let arr: [u8; 4] = slice.get(start..start+4)
        .ok_or_else(|| format!("Bad u32 offset {}", start))?
        .try_into().map_err(|_| format!("Invalid u32 slice {}", start))?;
    Ok(u32::from_le_bytes(arr))
}

fn read_u16_le(slice: &[u8], start: usize) -> u16 {
    slice.get(start..start+2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0)
}

async fn read_smb2_response(stream: &mut TcpStream) -> Result<(u32, Vec<u8>), String> {
    let mut hdr = [0u8; 64];
    stream.read_exact(&mut hdr).await
        .map_err(|e| format!("Read SMB header: {}", e))?;

    if hdr[0] != 0xFE || hdr[1] != b'S' || hdr[2] != b'M' || hdr[3] != b'b' {
        return Err("Invalid SMB protocol ID".to_string());
    }

    let status = read_u32_le(&hdr, 8)?;
    let data_offset = 64usize;

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);

    let struct_size = read_u16_le(&hdr, 68);
    let sec_buf_off: u16;
    let sec_buf_len: u16;

    match struct_size {
        65 => {
            sec_buf_off = read_u16_le(&hdr, 72);
            sec_buf_len = read_u16_le(&hdr, 74);
        }
        9 => {
            sec_buf_off = read_u16_le(&hdr, 70);
            sec_buf_len = read_u16_le(&hdr, 72);
        }
        _ => {
            sec_buf_off = 0;
            sec_buf_len = 0;
        }
    }

    if sec_buf_len > 0 && sec_buf_off > 0 {
        let buf_end = data_offset.max(sec_buf_off as usize) + sec_buf_len as usize;
        if buf_end > data.len() {
            let remaining = buf_end - data.len();
            let mut extra = vec![0u8; remaining];
            let n = stream.read(&mut extra).await
                .map_err(|e| format!("Read SMB data: {}", e))?;
            extra.truncate(n);
            data.extend_from_slice(&extra);
        }
    }

    let security_blob = if sec_buf_len > 0 && sec_buf_off as usize + sec_buf_len as usize <= data.len() {
        data[sec_buf_off as usize..sec_buf_off as usize + sec_buf_len as usize].to_vec()
    } else {
        Vec::new()
    };

    Ok((status, security_blob))
}

#[async_trait]
impl Protocol for SmbProtocol {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn default_port(&self) -> u16 {
        445
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
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Proxy connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => connect_optimized(&addr, timeout_dur).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            let nego_req = build_negotiate_request();
            stream.write_all(&nego_req).await
                .map_err(|e| format!("Send negotiate: {}", e))?;
            stream.flush().await
                .map_err(|e| format!("Flush negotiate: {}", e))?;

            read_smb2_response(&mut stream).await?;

            let (domain, user) = split_username(&credential.username);
            let hostname = &target.host;

            let nego_token = build_ntlmssp_negotiate(&domain, hostname);
            let setup1 = build_session_setup(&nego_token, 2, 0);

            stream.write_all(&setup1).await
                .map_err(|e| format!("Send session setup 1: {}", e))?;
            stream.flush().await
                .map_err(|e| format!("Flush setup1: {}", e))?;

            let (status1, challenge_blob) = read_smb2_response(&mut stream).await?;

            if status1 != 0 && status1 != 0xc000006d {
                let err = format!("SMB session setup 1 failed: status 0x{:08x}", status1);
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "smb",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(err),
                ));
            }

            if challenge_blob.is_empty() {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "smb",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ));
            }

            let (server_challenge, _target_name, target_info) = parse_challenge(&challenge_blob)
                .map_err(|e| format!("Parse challenge: {}", e))?;

            let auth_token = build_ntlmv2_auth(
                &credential.password, &user, &domain,
                &server_challenge, &target_info,
            );

            let setup2 = build_session_setup(&auth_token, 3, 0);
            stream.write_all(&setup2).await
                .map_err(|e| format!("Send session setup 2: {}", e))?;
            stream.flush().await
                .map_err(|e| format!("Flush setup2: {}", e))?;

            let (status2, _final_blob) = read_smb2_response(&mut stream).await?;

            let success = status2 == 0;
            let err_msg = if !success {
                Some(format!("SMB auth failed: status 0x{:08x}", status2))
            } else {
                None
            };

            Ok(AuthResult::new(
                target.host.clone(), target.port, "smb",
                credential.username.clone(), credential.password.clone(),
                success, start.elapsed(), err_msg,
            ))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "smb",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "smb",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
