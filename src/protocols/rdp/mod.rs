pub mod crypto;
pub mod auth;

use async_trait::async_trait;
use std::sync::OnceLock;
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

static RDP_DOMAIN: OnceLock<String> = OnceLock::new();

pub fn set_domain(domain: &str) {
    let _ = RDP_DOMAIN.set(domain.to_string());
}

pub fn get_domain() -> Option<&'static str> {
    RDP_DOMAIN.get().map(|s| s.as_str())
}

const RDP_NEG_REQ: &[u8] = &[
    0x03, 0x00, 0x00, 0x2b, 0x1e, 0xe0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b, 0x69,
    0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68,
    0x61, 0x73, 0x68, 0x3d, 0x61, 0x6e, 0x6f, 0x6e,
    0x79, 0x6d, 0x6f, 0x75, 0x73, 0x0d, 0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

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

            Ok(auth::perform_credssp_exchange(tls_stream, target, credential, start).await)
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
