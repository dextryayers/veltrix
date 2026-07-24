use md4::{Md4, Digest as Md4Digest};
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;

pub fn to_utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

pub fn ntlm_hash(password: &str) -> Vec<u8> {
    let utf16 = to_utf16_le(password);
    Md4::digest(&utf16).to_vec()
}

pub fn ntlmv2_hash(password: &str, username: &str, domain: &str) -> Vec<u8> {
    let hash = ntlm_hash(password);
    let upper = username.to_uppercase();
    let mut ident = to_utf16_le(&upper);
    ident.extend_from_slice(&to_utf16_le(domain));

    let mut mac = Hmac::<Sha256>::new_from_slice(&hash).unwrap();
    mac.update(&ident);
    mac.finalize().into_bytes().to_vec()
}

pub fn build_ntlmssp_negotiate(domain: &str, hostname: &str) -> Vec<u8> {
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

pub fn parse_ntlmssp_challenge(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if data.len() < 48 || &data[..8] != b"NTLMSSP\x00" {
        return None;
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into().ok()?);
    if msg_type != 2 {
        return None;
    }
    let server_challenge = data[24..32].to_vec();
    let target_name_len = u16::from_le_bytes(data[12..14].try_into().ok()?) as usize;
    let target_name_off = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;
    let mut target_name = Vec::new();
    if target_name_len > 0 && target_name_off + target_name_len <= data.len() {
        target_name = data[target_name_off..target_name_off + target_name_len].to_vec();
    }
    let context = if data.len() >= 56 {
        data[48..56].to_vec()
    } else {
        vec![0u8; 8]
    };
    Some((server_challenge, target_name, context))
}

pub fn build_ntlmv2_auth(
    password: &str,
    username: &str,
    domain: &str,
    server_challenge: &[u8],
    target_info: &[u8],
) -> Vec<u8> {
    use rand::Rng;
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

    let mut mac = Hmac::<Sha256>::new_from_slice(&ntlmv2_hash_val).unwrap();
    mac.update(&proof_input);
    let nt_proof = mac.finalize().into_bytes();

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

fn encode_asn1_length(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }
    if len < 256 {
        return vec![0x81u8, len as u8];
    }
    let bytes = (len as u16).to_be_bytes();
    vec![0x82u8, bytes[0], bytes[1]]
}

fn asn1_sequence(contents: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x30u8];
    buf.extend_from_slice(&encode_asn1_length(contents.len()));
    buf.extend_from_slice(contents);
    buf
}

fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x04u8];
    buf.extend_from_slice(&encode_asn1_length(data.len()));
    buf.extend_from_slice(data);
    buf
}

fn asn1_context_tag(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut buf = vec![tag];
    buf.extend_from_slice(&encode_asn1_length(contents.len()));
    buf.extend_from_slice(contents);
    buf
}

pub fn build_credssp_tsrequest(nego_token: &[u8]) -> Vec<u8> {
    let nego_octet = asn1_octet_string(nego_token);
    let nego_seq = asn1_sequence(&nego_octet);
    let nego_tagged = asn1_context_tag(0xa0, &nego_seq);
    asn1_sequence(&nego_tagged)
}

pub fn build_credssp_tsrequest_auth(nego_token: &[u8], pub_key_auth: &[u8]) -> Vec<u8> {
    let nego_octet = asn1_octet_string(nego_token);
    let nego_seq = asn1_sequence(&nego_octet);
    let nego_tagged = asn1_context_tag(0xa0, &nego_seq);

    let auth_octet = asn1_octet_string(pub_key_auth);
    let auth_seq = asn1_sequence(&auth_octet);
    let auth_tagged = asn1_context_tag(0xa2, &auth_seq);

    let mut combined = nego_tagged;
    combined.extend_from_slice(&auth_tagged);
    asn1_sequence(&combined)
}

pub fn parse_asn1_octet_string(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    if data.is_empty() {
        return None;
    }
    let mut pos = 0;
    if data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (seq_len, adv) = read_asn1_length(data, pos)?;
    pos = adv;
    let seq_end = pos + seq_len;
    if seq_end > data.len() {
        return None;
    }
    if pos >= seq_end || data[pos] != 0xa0 {
        return None;
    }
    pos += 1;
    let (_tag_len, adv) = read_asn1_length(data, pos)?;
    pos = adv;
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let (_inner_len, adv) = read_asn1_length(data, pos)?;
    pos = adv;
    if pos >= data.len() || data[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let (str_len, adv) = read_asn1_length(data, pos)?;
    pos = adv;
    let end = pos + str_len;
    if end > data.len() {
        return None;
    }
    Some((data[pos..end].to_vec(), seq_end))
}

fn read_asn1_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= data.len() {
        return None;
    }
    if data[pos] < 128 {
        return Some((data[pos] as usize, pos + 1));
    }
    let num_bytes = (data[pos] & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || pos + num_bytes >= data.len() {
        return None;
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | data[pos + 1 + i] as usize;
    }
    Some((len, pos + 1 + num_bytes))
}

pub fn compute_pub_key_auth(ntlm_response: &[u8]) -> Vec<u8> {
    Sha256::digest(ntlm_response).to_vec()
}

pub fn split_domain_user(input: &str) -> (String, String) {
    if let Some(domain) = super::get_domain() {
        return (domain.to_string(), input.to_string());
    }
    if let Some(idx) = input.find('\\') {
        let domain = input[..idx].to_string();
        let user = input[idx + 1..].to_string();
        (domain, user)
    } else {
        ("".to_string(), input.to_string())
    }
}
