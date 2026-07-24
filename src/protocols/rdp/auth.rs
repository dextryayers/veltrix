use std::time::Instant;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use std::time::Duration;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::crypto::{generate_rdp_credentials, rdp_encrypt, rdpmux_client_info, CredSSP_NTLM_AUTH};

pub static RDP_DOMAIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub async fn rdp_auth(
    target: &Target,
    credential: &Credential,
    proxy: &Option<ProxyConfig>,
    start: Instant,
) -> AuthResult {
    let addr = target.addr_string();
    let tcp_timeout = Duration::from_secs(30);

    let stream = match proxy {
        Some(p) => match p.tcp_connect(&addr, tcp_timeout).await {
            Ok(s) => s,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, "rdp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Proxy: {}", e)),
            ),
        },
        None => match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => return AuthResult::new(
                target.host.clone(), target.port, "rdp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(format!("Connect: {}", e)),
            ),
        },
    };

    let (mut reader, mut writer) = stream.into_split();

    let domain = RDP_DOMAIN.get().cloned().unwrap_or_else(|| "WORKGROUP".to_string());

    let mut username = credential.username.clone();
    if let Some(at_pos) = username.find('\\') {
        let (_, rest) = username.split_at(at_pos + 1);
        username = rest.to_string();
    }

    if let Err(e) = timeout(Duration::from_secs(15), async {
        let _ = rdpmux_client_info(&mut writer, &mut reader, &username).await;

        let ntlm = CredSSP_NTLM_AUTH {
            username: username.clone(),
            password: credential.password.clone(),
            domain: domain.clone(),
            host: target.host.clone(),
        };

        generate_rdp_credentials(&mut writer, &mut reader, &ntlm).await
    }).await {
        return AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(format!("RDP auth error: {}", e)),
        );
    }

    let creds = generate_rdp_credentials(&mut writer, &mut reader, &CredSSP_NTLM_AUTH {
        username: username.clone(),
        password: credential.password.clone(),
        domain: domain.clone(),
        host: target.host.clone(),
    }).await;

    match creds {
        Ok(_) => AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(), None,
        ),
        Err(e) => AuthResult::new(
            target.host.clone(), target.port, "rdp",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(), Some(e),
        ),
    }
}
