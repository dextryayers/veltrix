use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::core::credential::Credential;
use crate::core::engine::{ProtocolStream, ResponseBuffer};
use crate::core::result::AuthResult;
use crate::core::target::Target;
use super::crypto;

pub async fn perform_credssp_exchange(
    tls_stream: tokio_native_tls::TlsStream<TcpStream>,
    target: &Target,
    credential: &Credential,
    start: Instant,
    timeout_dur: Duration,
) -> AuthResult {
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (domain, username) = crypto::split_domain_user(&credential.username);

    let nego_msg = crypto::build_ntlmssp_negotiate(&domain, &target.host);
    let tsrequest = crypto::build_credssp_tsrequest(&nego_msg);
    if let Err(e) = tls_writer.write_all(&tsrequest).await {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("CredSSP send: {}", e)),
        );
    }
    if let Err(e) = tls_writer.flush().await {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("CredSSP flush: {}", e)),
        );
    }

    let mut tmp = [0u8; 4096];
    let mut resp_buf = Vec::new();
    {
        let mut ps = ProtocolStream::from_tls(&mut tls_reader);
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout_dur {
                break;
            }
            let remaining = timeout_dur - elapsed;
            match ps.read_some(&mut tmp, remaining).await {
                Ok(0) => break,
                Ok(n) => {
                    resp_buf.extend_from_slice(&tmp[..n]);
                    if resp_buf.len() > 20 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    if resp_buf.is_empty() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some("No CredSSP response".into()),
        );
    }

    let challenge_token = match crypto::parse_asn1_octet_string(&resp_buf) {
        Some((t, _)) => t,
        None => {
            return AuthResult::new(
                target.host.clone(), target.port, "rdp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("CredSSP challenge parse failed".into()),
            );
        }
    };

    let (server_challenge, target_info, _context) = match crypto::parse_ntlmssp_challenge(&challenge_token) {
        Some(c) => c,
        None => {
            return AuthResult::new(
                target.host.clone(), target.port, "rdp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("NTLMSSP challenge parse failed".into()),
            );
        }
    };

    let auth_msg = crypto::build_ntlmv2_auth(
        &credential.password,
        &username,
        &domain,
        &server_challenge,
        &target_info,
    );

    let pub_key_auth = crypto::compute_pub_key_auth(&auth_msg);
    let auth_request = crypto::build_credssp_tsrequest_auth(&auth_msg, &pub_key_auth);

    if let Err(e) = tls_writer.write_all(&auth_request).await {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("CredSSP auth send: {}", e)),
        );
    }
    if let Err(e) = tls_writer.flush().await {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("CredSSP auth flush: {}", e)),
        );
    }

    let mut final_resp = ResponseBuffer::new();
    let mut final_tmp = [0u8; 4096];
    {
        let mut ps = ProtocolStream::from_tls(&mut tls_reader);
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout_dur {
                break;
            }
            let remaining = timeout_dur - elapsed;
            match ps.read_some(&mut final_tmp, remaining).await {
                Ok(0) => break,
                Ok(n) => {
                    final_resp.extend(&final_tmp[..n]);
                    if final_resp.len() > 30 {
                        break;
                    }
                }
                Err(e) => {
                    let is_auth_denied = e.contains("certificate")
                        || e.contains("decryption")
                        || e.contains("tls alert");
                    if is_auth_denied || !final_resp.is_empty() {
                        break;
                    }
                    return AuthResult::new(
                        target.host.clone(), target.port, "rdp",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(),
                        Some(format!("NLA auth denied: {}", e)),
                    );
                }
            }
        }
    }

    if final_resp.is_empty() {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(),
            Some("NLA handshake completed (credentials accepted)".into()),
        );
    }

    let data = final_resp.as_slice();
    let has_error = data.windows(5).any(|w| w == b"error" || w == b"Error")
        || data.contains(&0x0d);

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
