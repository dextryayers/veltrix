use async_trait::async_trait;
use md4::{Md4, Digest as Md4Digest};
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct RdpProtocol;

const RDP_NEG_REQ: &[u8] = &[
    0x03, 0x00, 0x00, 0x2b, 0x1e, 0xe0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b, 0x69,
    0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68,
    0x61, 0x73, 0x68, 0x3d, 0x61, 0x6e, 0x6f, 0x6e,
    0x79, 0x6d, 0x6f, 0x75, 0x73, 0x0d, 0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

fn to_utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn ntlm_hash(password: &str) -> Vec<u8> {
    let utf16 = to_utf16_le(password);
    Md4::digest(&utf16).to_vec()
}

fn ntlmv2_hash(password: &str, username: &str, domain: &str) -> Vec<u8> {
    let hash = ntlm_hash(password);
    let upper = username.to_uppercase();
    let mut ident = to_utf16_le(&upper);
    ident.extend_from_slice(&to_utf16_le(domain));

    let mut mac = Hmac::<Sha256>::new_from_slice(&hash).unwrap();
    mac.update(&ident);
    mac.finalize().into_bytes().to_vec()
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

fn parse_ntlmssp_challenge(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
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

fn build_ntlmv2_auth(
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

    let ntlmv2_hash = ntlmv2_hash(password, username, domain);

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

    let mut mac = Hmac::<Sha256>::new_from_slice(&ntlmv2_hash).unwrap();
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

fn build_credssp_tsrequest(nego_token: &[u8]) -> Vec<u8> {
    let nego_octet = asn1_octet_string(nego_token);
    let nego_seq = asn1_sequence(&nego_octet);
    let nego_tagged = asn1_context_tag(0xa0, &nego_seq);
    asn1_sequence(&nego_tagged)
}

fn build_credssp_tsrequest_auth(nego_token: &[u8], pub_key_auth: &[u8]) -> Vec<u8> {
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

fn parse_asn1_octet_string(data: &[u8]) -> Option<(Vec<u8>, usize)> {
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

fn compute_pub_key_auth(ntlm_response: &[u8]) -> Vec<u8> {
    Sha256::digest(ntlm_response).to_vec()
}

async fn perform_credssp_exchange(
    tls_stream: tokio_native_tls::TlsStream<TcpStream>,
    target: &Target,
    credential: &Credential,
    start: Instant,
) -> AuthResult {
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let domain = "";

    let nego_msg = build_ntlmssp_negotiate(domain, &target.host);
    let tsrequest = build_credssp_tsrequest(&nego_msg);
    if tls_writer.write_all(&tsrequest).await.is_err() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("CredSSP negotiate send failed".into()),
        );
    }
    if tls_writer.flush().await.is_err() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("CredSSP flush failed".into()),
        );
    }

    let mut resp = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut read_attempts = 0;
    while read_attempts < 5 {
        match tls_reader.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                resp.extend_from_slice(&tmp[..n]);
                if resp.len() > 20 {
                    break;
                }
            }
            Err(_) => break,
        }
        read_attempts += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if resp.is_empty() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("No CredSSP response".into()),
        );
    }

    let challenge_token = match parse_asn1_octet_string(&resp) {
        Some((t, _)) => t,
        None => {
            return AuthResult::new(
                target.host.clone(), target.port, "rdp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("CredSSP challenge parse failed".into()),
            );
        }
    };

    let (server_challenge, target_info, _context) = match parse_ntlmssp_challenge(&challenge_token) {
        Some(c) => c,
        None => {
            return AuthResult::new(
                target.host.clone(), target.port, "rdp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("NTLMSSP challenge parse failed".into()),
            );
        }
    };

    let auth_msg = build_ntlmv2_auth(
        &credential.password,
        &credential.username,
        domain,
        &server_challenge,
        &target_info,
    );

    let pub_key_auth = compute_pub_key_auth(&auth_msg);
    let auth_request = build_credssp_tsrequest_auth(&auth_msg, &pub_key_auth);

    if tls_writer.write_all(&auth_request).await.is_err() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("CredSSP auth send failed".into()),
        );
    }
    if tls_writer.flush().await.is_err() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("CredSSP auth flush failed".into()),
        );
    }

    let mut final_resp = Vec::new();
    let mut final_tmp = [0u8; 4096];
    let mut final_attempts = 0;
    while final_attempts < 8 {
        match tls_reader.read(&mut final_tmp).await {
            Ok(0) => break,
            Ok(n) => {
                final_resp.extend_from_slice(&final_tmp[..n]);
                if final_resp.len() > 30 {
                    break;
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                let is_auth_denied = err_str.contains("certificate")
                    || err_str.contains("decryption")
                    || err_str.contains("tls alert");
                if is_auth_denied || (!final_resp.is_empty()) {
                    break;
                }
                return AuthResult::new(
                    target.host.clone(), target.port, "rdp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some(format!("NLA auth denied: {}", err_str)),
                );
            }
        }
        final_attempts += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if final_resp.is_empty() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(),
            Some("NLA handshake completed (credentials accepted)".into()),
        );
    }

    let has_error = final_resp.windows(5).any(|w| w == b"error" || w == b"Error")
        || final_resp.contains(&0x0d);

    if has_error {
        AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("NLA authentication denied".into()),
        )
    } else {
        AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(),
            Some("NLA authentication successful".into()),
        )
    }
}

#[async_trait]
impl Protocol for RdpProtocol {
    fn name(&self) -> &'static str { "rdp" }
    fn default_port(&self) -> u16 { 3389 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();

        let result = timeout(timeout_dur, async {
            let mut stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            stream.write_all(RDP_NEG_REQ).await
                .map_err(|e| format!("Send neg req: {}", e))?;
            stream.flush().await.ok();

            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await
                .map_err(|e| format!("Read neg resp: {}", e))?;

            if n == 0 {
                return Err("No RDP negotiation response".to_string());
            }

            if buf[0] != 0x03 {
                return Err("Not an RDP protocol response".to_string());
            }

            let supports_nla = buf.windows(4).any(|w| w == b"\x02\x00\x08\x00");
            if !supports_nla {
                return Err("Pre-NLA RDP (no auth verification)".to_string());
            }

            let tls_connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| format!("TLS init: {}", e))?;

            let connector = tokio_native_tls::TlsConnector::from(tls_connector);
            let tls_stream = connector.connect(&target.host, stream).await
                .map_err(|e| format!("TLS connect: {}", e))?;

            Ok(perform_credssp_exchange(tls_stream, target, credential, start).await)
        }).await;

        match result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let is_pre_nla = e.contains("Pre-NLA");
                AuthResult::new(
                    target.host.clone(), target.port, "rdp",
                    credential.username.clone(), credential.password.clone(),
                    is_pre_nla, start.elapsed(), Some(e),
                )
            }
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "rdp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
