use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

type HmacSha256 = Hmac<Sha256>;

fn get_rand_bytes(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(rand::random::<u8>());
    }
    v
}

pub struct CredSSP_NTLM_AUTH {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub host: String,
}

pub async fn rdpmux_client_info(
    writer: &mut (impl AsyncWriteExt + Unpin),
    reader: &mut (impl AsyncReadExt + Unpin),
    username: &str,
) -> Result<(), String> {
    let mut packet = Vec::new();
    packet.write_u16::<LittleEndian>(1).unwrap();
    packet.write_u16::<LittleEndian>(0).unwrap();
    let core_data = [
        0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01,
    ];
    packet.extend_from_slice(&core_data);

    let cs_data = write_ts_cs_cluster_data();
    packet.extend_from_slice(&cs_data);

    let mut gcc_header = Vec::new();
    gcc_header.extend_from_slice(b"RDPBCR");
    gcc_header.write_u16::<LittleEndian>(packet.len() as u16).unwrap();
    let gcc_len = gcc_header.len() + packet.len() + 8;

    let mut connect_pdu = Vec::new();
    connect_pdu.extend_from_slice(&[0x03, 0x00, 0x00, 0x0c]);
    connect_pdu.write_u16::<LittleEndian>(0x0006).unwrap();
    connect_pdu.write_u16::<LittleEndian>(gcc_len as u16).unwrap();
    connect_pdu.extend_from_slice(&gcc_header);
    connect_pdu.extend_from_slice(&packet);

    let tpkt_len = connect_pdu.len() + 4;
    let mut tpkt = Vec::new();
    tpkt.extend_from_slice(&[0x03, 0x00, (tpkt_len >> 8) as u8, tpkt_len as u8]);
    tpkt.extend_from_slice(&connect_pdu);

    writer.write_all(&tpkt).await.map_err(|e| format!("Write CI: {}", e))?;
    writer.flush().await.ok();

    let mut resp = vec![0u8; 1024];
    let _ = reader.read(&mut resp).await.map_err(|e| format!("Read CI resp: {}", e))?;

    Ok(())
}

fn write_ts_cs_cluster_data() -> Vec<u8> {
    let mut data = Vec::new();
    data.write_u32::<LittleEndian>(0x00000004).unwrap();
    data.write_u32::<LittleEndian>(0x00000000).unwrap();
    data.write_u32::<LittleEndian>(0x00000000).unwrap();
    data
}

fn ntlm_hash(password: &str) -> Vec<u8> {
    let encoded: Vec<u16> = password.encode_utf16().collect();
    let encoded_bytes: Vec<u8> = encoded.iter()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let hash = md4::Md4::digest(&encoded_bytes);
    hash.to_vec()
}

fn ntlm_v2_hash(password: &str, username: &str, domain: &str) -> Vec<u8> {
    let ntlm_hash_val = ntlm_hash(password);
    let encoded: Vec<u16> = (username.to_uppercase() + domain).encode_utf16().collect();
    let encoded_bytes: Vec<u8> = encoded.iter()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut mac = HmacSha256::new_from_slice(&ntlm_hash_val).expect("HMAC init");
    mac.update(&encoded_bytes);
    mac.finalize().into_bytes().to_vec()
}

fn compute_nonce() -> Vec<u8> {
    get_rand_bytes(8)
}

fn compute_timestamp() -> Vec<u8> {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let ft = ns / 100 + 116444736000000000u64;
    ft.to_le_bytes().to_vec()
}

fn compute_ntlm_v2_response(
    ntlm_v2_hash: &[u8],
    server_challenge: &[u8],
    target_info: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let nonce = compute_nonce();
    let timestamp = compute_timestamp();

    let mut nt_proof_str = Vec::new();
    nt_proof_str.extend_from_slice(&[0x01u8; 1]);
    nt_proof_str.extend_from_slice(&[0x00u8; 1]);
    nt_proof_str.extend_from_slice(&timestamp);
    nt_proof_str.extend_from_slice(&nonce);
    nt_proof_str.extend_from_slice(&0i32.to_le_bytes());
    nt_proof_str.extend_from_slice(target_info);
    nt_proof_str.extend_from_slice(&[0x00u8; 4]);
    nt_proof_str.extend_from_slice(&[0x00u8; 4]);

    let mut mac = HmacSha256::new_from_slice(ntlm_v2_hash).expect("HMAC init");
    mac.update(server_challenge);
    mac.update(&nt_proof_str);
    let nt_proof_hash = mac.finalize().into_bytes().to_vec();

    let mut ntlm_v2_response = Vec::new();
    ntlm_v2_response.extend_from_slice(&nt_proof_hash);
    ntlm_v2_response.extend_from_slice(&nt_proof_str);

    (nt_proof_hash, ntlm_v2_response)
}

fn generate_neg_token_init(ntlm_v2_hash: &[u8], target_host: &str) -> Vec<u8> {
    let mut token = Vec::new();
    token.extend_from_slice(b"NTLMSSP\x00");
    token.extend_from_slice(&[0x01u8; 1]);
    token.extend_from_slice(&[0x00u8; 4]);

    let flags = 0x028a0205u32;
    token.extend_from_slice(&flags.to_le_bytes());

    let domain = "WORKGROUP".to_string();
    let dom_enc: Vec<u16> = domain.encode_utf16().collect();
    let dom_bytes: Vec<u8> = dom_enc.iter().flat_map(|c| c.to_le_bytes()).collect();
    token.extend_from_slice(&dom_bytes.len().to_le_bytes());
    token.extend_from_slice(&dom_bytes.len().to_le_bytes());
    token.extend_from_slice(&0i32.to_le_bytes());

    let host_enc: Vec<u16> = target_host.encode_utf16().collect();
    let host_bytes: Vec<u8> = host_enc.iter().flat_map(|c| c.to_le_bytes()).collect();
    token.extend_from_slice(&host_bytes.len().to_le_bytes());
    token.extend_from_slice(&host_bytes.len().to_le_bytes());
    token.extend_from_slice(&0i32.to_le_bytes());

    token.extend_from_slice(&[0x00u8; 8]);

    token
}

fn generate_neg_token_auth(
    ntlm_v2_hash: &[u8],
    server_challenge: &[u8],
    target_info: &[u8],
    username: &str,
    domain: &str,
) -> Vec<u8> {
    let (_, ntlm_v2_resp) = compute_ntlm_v2_response(ntlm_v2_hash, server_challenge, target_info);

    let mut token = Vec::new();
    token.extend_from_slice(b"NTLMSSP\x00");
    token.extend_from_slice(&[0x03u8; 1]);
    token.extend_from_slice(&[0x00u8; 4]);

    let lm_challenge = get_rand_bytes(24);
    token.extend_from_slice(&lm_challenge.len().to_le_bytes());
    token.extend_from_slice(&lm_challenge.len().to_le_bytes());
    token.extend_from_slice(&0i32.to_le_bytes());
    token.extend_from_slice(&lm_challenge);

    token.extend_from_slice(&ntlm_v2_resp.len().to_le_bytes());
    token.extend_from_slice(&ntlm_v2_resp.len().to_le_bytes());
    let nt_offset = token.len() as u32 + 8;
    token.extend_from_slice(&nt_offset.to_le_bytes());
    token.extend_from_slice(&ntlm_v2_resp);

    let dom_enc: Vec<u16> = domain.encode_utf16().collect();
    let dom_bytes: Vec<u8> = dom_enc.iter().flat_map(|c| c.to_le_bytes()).collect();
    token.extend_from_slice(&dom_bytes.len().to_le_bytes());
    token.extend_from_slice(&dom_bytes.len().to_le_bytes());
    let dom_offset = token.len() as u32 + 8;
    token.extend_from_slice(&dom_offset.to_le_bytes());
    token.extend_from_slice(&dom_bytes);

    let user_enc: Vec<u16> = username.encode_utf16().collect();
    let user_bytes: Vec<u8> = user_enc.iter().flat_map(|c| c.to_le_bytes()).collect();
    token.extend_from_slice(&user_bytes.len().to_le_bytes());
    token.extend_from_slice(&user_bytes.len().to_le_bytes());
    let user_offset = token.len() as u32 + 8;
    token.extend_from_slice(&user_offset.to_le_bytes());
    token.extend_from_slice(&user_bytes);

    token.extend_from_slice(&[0x00u8; 8]);

    let flags = 0x028a0205u32;
    token.extend_from_slice(&flags.to_le_bytes());

    token
}

fn decode_neg_token_challenge(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if data.len() < 12 || &data[0..8] != b"NTLMSSP\x00" {
        return Err("Not NTLMSSP challenge".into());
    }
    if data[8] != 0x02 {
        return Err("Not NTLM challenge type".into());
    }
    if data.len() < 48 {
        return Err("NTLM challenge too short".into());
    }
    let server_challenge = data[24..32].to_vec();
    let target_info_offset = {
        let mut c = Cursor::new(&data[40..48]);
        c.read_u32::<LittleEndian>().unwrap_or(0) as usize
    };
    let target_info_len = {
        let mut c = Cursor::new(&data[40..44]);
        c.read_u16::<LittleEndian>().unwrap_or(0) as usize
    };

    if target_info_offset > 0 && target_info_len > 0
        && target_info_offset + target_info_len <= data.len() {
        let target_info = data[target_info_offset..target_info_offset + target_info_len].to_vec();
        Ok((server_challenge, target_info))
    } else {
        Err("Invalid target info in NTLM challenge".into())
    }
}

fn wrap_ts_request(token: &[u8]) -> Vec<u8> {
    let mut nego_token = Vec::new();
    nego_token.extend_from_slice(&[0x01u8; 4]);
    nego_token.extend_from_slice(&(token.len() as u32).to_le_bytes());
    nego_token.extend_from_slice(token);
    nego_token
}

fn wrap_credssp(nego_tokens: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x00000000u32.to_le_bytes());
    msg.extend_from_slice(&(nego_tokens.len() as u32).to_le_bytes());
    for token in nego_tokens {
        msg.extend_from_slice(&[0x01u8; 4]);
        msg.extend_from_slice(&(token.len() as u32).to_le_bytes());
        msg.extend_from_slice(token);
    }
    msg
}

async fn send_tpkt(
    writer: &mut (impl AsyncWriteExt + Unpin),
    data: &[u8],
) -> Result<(), String> {
    let len = data.len() + 4;
    let mut tpkt = Vec::new();
    tpkt.extend_from_slice(&[0x03, 0x00, (len >> 8) as u8, len as u8]);
    tpkt.extend_from_slice(data);
    writer.write_all(&tpkt).await.map_err(|e| format!("Send: {}", e))?;
    writer.flush().await.ok();
    Ok(())
}

async fn recv_tpkt(reader: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await.map_err(|e| format!("Recv header: {}", e))?;
    if header[0] != 0x03 {
        return Err(format!("Bad TPKT version: {}", header[0]));
    }
    let len = ((header[2] as usize) << 8) | header[3] as usize;
    if len < 4 {
        return Err(format!("Bad TPKT len: {}", len));
    }
    let mut body = vec![0u8; len - 4];
    if !body.is_empty() {
        reader.read_exact(&mut body).await.map_err(|e| format!("Recv body: {}", e))?;
    }
    Ok(body)
}

pub async fn generate_rdp_credentials(
    writer: &mut (impl AsyncWriteExt + Unpin),
    reader: &mut (impl AsyncReadExt + Unpin),
    auth: &CredSSP_NTLM_AUTH,
) -> Result<(), String> {
    let ntlm_v2_hash_val = ntlm_v2_hash(&auth.password, &auth.username, &auth.domain);

    let neg_init = generate_neg_token_init(&ntlm_v2_hash_val, &auth.host);
    let ts_req_init = wrap_ts_request(&neg_init);
    let credssp_init = wrap_credssp(&[ts_req_init]);
    send_tpkt(writer, &credssp_init).await?;

    let resp = recv_tpkt(reader).await?;

    let mut offset = 0;
    if resp.len() < 8 {
        return Err("Response too short".into());
    }
    offset += 8;

    let token_count = {
        let mut c = Cursor::new(&resp[4..8]);
        c.read_u32::<LittleEndian>().unwrap()
    };
    if token_count == 0 {
        return Err("No tokens in response".into());
    }

    let mut nego_token = None;
    for _ in 0..token_count {
        if offset + 8 > resp.len() {
            break;
        }
        let token_len = {
            let mut c = Cursor::new(&resp[offset + 4..offset + 8]);
            c.read_u32::<LittleEndian>().unwrap() as usize
        };
        offset += 8;
        if offset + token_len > resp.len() {
            return Err("Token truncated".into());
        }
        if token_len >= 12 && &resp[offset..offset + 8] == b"NTLMSSP\x00" {
            nego_token = Some(resp[offset..offset + token_len].to_vec());
            break;
        }
        offset += token_len;
    }

    let challenge_token = nego_token.ok_or_else(|| "No NTLM challenge".to_string())?;
    let (server_challenge, target_info) = decode_neg_token_challenge(&challenge_token)?;

    let auth_token = generate_neg_token_auth(
        &ntlm_v2_hash_val,
        &server_challenge,
        &target_info,
        &auth.username,
        &auth.domain,
    );
    let ts_req_auth = wrap_ts_request(&auth_token);
    let credssp_auth = wrap_credssp(&[ts_req_auth]);
    send_tpkt(writer, &credssp_auth).await?;

    let final_resp = recv_tpkt(reader).await?;
    if final_resp.len() >= 8 {
        Ok(())
    } else {
        Err("Empty final response".into())
    }
}
