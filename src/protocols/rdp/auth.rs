use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use super::crypto;

pub async fn perform_credssp_exchange(
    tls_stream: tokio_native_tls::TlsStream<TcpStream>,
    target: &Target,
    credential: &Credential,
    start: Instant,
) -> AuthResult {
    let (mut tls_reader, mut tls_writer) = tokio::io::split(tls_stream);
    let (domain, username) = crypto::split_domain_user(&credential.username);

    let nego_msg = crypto::build_ntlmssp_negotiate(&domain, &target.host);
    let tsrequest = crypto::build_credssp_tsrequest(&nego_msg);
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

    let challenge_token = match crypto::parse_asn1_octet_string(&resp) {
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
