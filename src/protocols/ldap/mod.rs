pub mod ber;

use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;
use super::tcp::{connect_optimized, tune_tcp, alloc_read_buf};

pub struct LdapProtocol;

fn build_bind_request(dn: &str, password: &str) -> Vec<u8> {
    let auth = ber::ber_context_tag(0, password.as_bytes());
    let bind_content = {
        let mut b = ber::ber_integer(3);
        b.extend_from_slice(&ber::ber_octet_string(dn.as_bytes()));
        b.extend_from_slice(&auth);
        b
    };
    let bind_request = ber::ber_application(0, &bind_content);
    let message = {
        let mut m = ber::ber_integer(1);
        m.extend_from_slice(&bind_request);
        m
    };
    ber::ber_sequence(&message)
}

async fn read_ldap_response(stream: &mut TcpStream) -> Result<i32, String> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await
        .map_err(|e| format!("Read header: {}", e))?;

    if header[0] != 0x30 {
        return Err(format!("Not a SEQUENCE: 0x{:02x}", header[0]));
    }

    let len = if header[1] < 0x81 {
        header[1] as usize
    } else {
        let len_bytes = (header[1] & 0x0f) as usize;
        let mut len_buf = vec![0u8; len_bytes];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| format!("Read len: {}", e))?;
        let mut l = 0usize;
        for b in len_buf {
            l = (l << 8) | b as usize;
        }
        l
    };

    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await
        .map_err(|e| format!("Read data: {}", e))?;

    if data.is_empty() || data[0] != 0x02 {
        return Err("No messageID".into());
    }

    let tag = if data.len() > 1 { data[1] } else { return Err("No data".into()); };
    let id_len = if tag < 0x81 { tag as usize } else { 0 };
    let pos = 2 + id_len;

    if pos >= data.len() || data[pos] != 0x61 {
        return Err("Not a BindResponse".into());
    }

    let resp_start = pos + 2;
    if resp_start >= data.len() {
        return Err("Empty BindResponse".into());
    }

    let resp_tag = data[resp_start];
    if resp_tag != 0x0a {
        return Err("Not an ENUMERATED".into());
    }

    let v = data[resp_start + 1] as i32;
    if v == 1 {
        Ok(data[resp_start + 2] as i32)
    } else {
        let mut val = 0i32;
        for i in 0..v as usize {
            val = (val << 8) | data[resp_start + 2 + i] as i32;
        }
        Ok(val)
    }
}

#[async_trait]
impl Protocol for LdapProtocol {
    fn name(&self) -> &'static str {
        "ldap"
    }

    fn default_port(&self) -> u16 {
        389
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let use_tls = target.port == 636;

        match timeout(timeout_dur, async {
            let addr = target.addr_string();
            let stream = match proxy {
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Proxy connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => {
                    connect_optimized(&addr, timeout_dur).await
                        .map_err(|e| format!("Connect: {}", e))?
                },
            };

            if use_tls {
                let connector = TlsConnector::from(
                    NativeTlsConnector::builder().build()
                        .map_err(|e| format!("TLS build: {}", e))?
                );
                let mut tls_stream = connector.connect(&target.host, stream).await
                    .map_err(|e| format!("TLS connect: {}", e))?;

                let bind_req = build_bind_request(&credential.username, &credential.password);

                tls_stream.write_all(&bind_req).await
                    .map_err(|e| format!("Send bind: {}", e))?;
                tls_stream.flush().await.ok();

                let mut buf = alloc_read_buf();
                let n = tls_stream.read(&mut buf).await
                    .map_err(|e| format!("Read resp: {}", e))?;
                let result_code = parse_ldap_result_code(&buf[..n]);

                return Ok(ldap_result(target, credential, start, result_code));
            }

            let mut stream = stream;
            let bind_req = build_bind_request(&credential.username, &credential.password);

            stream.write_all(&bind_req).await
                .map_err(|e| format!("Send bind: {}", e))?;
            stream.flush().await.ok();

            let result_code = read_ldap_response(&mut stream).await?;

            Ok(ldap_result(target, credential, start, result_code))
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "ldap",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "ldap",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}

fn ldap_result(target: &Target, credential: &Credential, start: Instant, result_code: i32) -> AuthResult {
    if result_code == 0 {
        AuthResult::new(target.host.clone(), target.port, "ldap",
            credential.username.clone(), credential.password.clone(),
            true, start.elapsed(), None)
    } else {
        let err_msg = match result_code {
            1 => "OperationsError",
            2 => "ProtocolError",
            3 => "TimeLimitExceeded",
            4 => "SizeLimitExceeded",
            7 => "AuthMethodNotSupported",
            8 => "StrongerAuthRequired",
            14 => "SaslBindInProgress",
            49 => "InvalidCredentials",
            _ => "Unknown",
        };
        AuthResult::new(target.host.clone(), target.port, "ldap",
            credential.username.clone(), credential.password.clone(),
            false, start.elapsed(),
            if result_code == 49 { None } else { Some(err_msg.to_string()) })
    }
}

fn parse_ldap_result_code(data: &[u8]) -> i32 {
    if data.len() < 2 || data[0] != 0x30 {
        return -1;
    }
    let len = if data[1] < 0x81 { data[1] as usize } else { 0 };
    let pos = 2 + len + 2;
    if pos >= data.len() || data[pos] != 0x0a {
        return -1;
    }
    let v = data[pos + 1] as i32;
    if v == 1 {
        data.get(pos + 2).map(|&b| b as i32).unwrap_or(-1)
    } else {
        let mut val = 0i32;
        for i in 0..v as usize {
            if pos + 2 + i >= data.len() { break; }
            val = (val << 8) | data[pos + 2 + i] as i32;
        }
        val
    }
}
