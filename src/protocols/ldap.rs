use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct LdapProtocol;

fn ber_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn ber_integer(value: i32) -> Vec<u8> {
    let bytes = if value < 0x80 {
        vec![value as u8]
    } else if value < 0x8000 {
        vec![(value >> 8) as u8, value as u8]
    } else {
        vec![(value >> 24) as u8, (value >> 16) as u8, (value >> 8) as u8, value as u8]
    };
    let mut result = vec![0x02u8];
    result.extend_from_slice(&ber_len(bytes.len()));
    result.extend_from_slice(&bytes);
    result
}

fn ber_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04u8];
    result.extend_from_slice(&ber_len(data.len()));
    result.extend_from_slice(data);
    result
}

fn ber_context_tag(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x80 | tag];
    result.extend_from_slice(&ber_len(data.len()));
    result.extend_from_slice(data);
    result
}

fn ber_sequence(items: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30u8];
    result.extend_from_slice(&ber_len(items.len()));
    result.extend_from_slice(items);
    result
}

fn ber_application(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x60 | tag];
    result.extend_from_slice(&ber_len(data.len()));
    result.extend_from_slice(data);
    result
}


fn build_bind_request(dn: &str, password: &str) -> Vec<u8> {
    let auth = ber_context_tag(0, password.as_bytes());
    let bind_content = {
        let mut b = ber_integer(3);
        b.extend_from_slice(&ber_octet_string(dn.as_bytes()));
        b.extend_from_slice(&auth);
        b
    };
    let bind_request = ber_application(0, &bind_content);
    let message = {
        let mut m = ber_integer(1);
        m.extend_from_slice(&bind_request);
        m
    };
    ber_sequence(&message)
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

        match timeout(timeout_dur, async {
            let addr = target.addr_string();
            let mut stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => TcpStream::connect(&addr).await
                    .map_err(|e| format!("Connect: {}", e))?,
            };

            let dn = credential.username.clone();
            let bind_req = build_bind_request(&dn, &credential.password);

            stream.write_all(&bind_req).await
                .map_err(|e| format!("Send bind: {}", e))?;
            stream.flush().await.ok();

            let result_code = read_ldap_response(&mut stream).await?;

            if result_code == 0 {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "ldap",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ))
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
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "ldap",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    if result_code == 49 { None } else { Some(err_msg.to_string()) },
                ))
            }
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
