use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use super::tcp::alloc_read_buf;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct SnmpProtocol;

fn ber_integer(value: i32) -> Vec<u8> {
    let bytes = if value == 0 {
        vec![0x00]
    } else if value > 0 {
        let mut v = value;
        let mut b = Vec::new();
        while v > 0 {
            b.push((v & 0xff) as u8);
            v >>= 8;
        }
        b.reverse();
        if b[0] & 0x80 != 0 {
            b.insert(0, 0x00);
        }
        b
    } else {
        let mut v = value;
        let mut b = Vec::new();
        for _ in 0..4 {
            b.push((v & 0xff) as u8);
            v >>= 8;
        }
        b.reverse();
        b
    };
    let mut result = vec![0x02u8];
    result.push(bytes.len() as u8);
    result.extend_from_slice(&bytes);
    result
}

fn ber_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04u8];
    result.push(data.len() as u8);
    result.extend_from_slice(data);
    result
}

fn ber_sequence(contents: &[u8]) -> Vec<u8> {
    let mut result = vec![0x30u8];
    if contents.len() < 128 {
        result.push(contents.len() as u8);
    } else {
        let len_bytes = (contents.len() as u16).to_be_bytes();
        result.push(0x82);
        result.extend_from_slice(&len_bytes);
    }
    result.extend_from_slice(contents);
    result
}

fn ber_null() -> Vec<u8> {
    vec![0x05u8, 0x00]
}

fn ber_oid(oid: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if oid.len() >= 2 {
        bytes.push((40 * oid[0] + oid[1]) as u8);
        for &val in &oid[2..] {
            if val < 128 {
                bytes.push(val as u8);
            } else {
                let mut v = val;
                let mut parts = Vec::new();
                parts.push((v & 0x7f) as u8);
                v >>= 7;
                while v > 0 {
                    parts.push((v & 0x7f | 0x80) as u8);
                    v >>= 7;
                }
                parts.reverse();
                bytes.extend_from_slice(&parts);
            }
        }
    }
    let mut result = vec![0x06u8];
    result.push(bytes.len() as u8);
    result.extend_from_slice(&bytes);
    result
}

fn ber_context_tag(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![0xA0 | tag];
    if contents.len() < 128 {
        result.push(contents.len() as u8);
    } else {
        let len_bytes = (contents.len() as u16).to_be_bytes();
        result.push(0x82);
        result.extend_from_slice(&len_bytes);
    }
    result.extend_from_slice(contents);
    result
}

fn build_snmp_get(community: &str, oid: &[u32], request_id: i32) -> Vec<u8> {
    let oid_enc = ber_oid(oid);
    let null_enc = ber_null();
    let varbind = ber_sequence(&[&oid_enc[..], &null_enc[..]].concat());
    let varbind_list = ber_sequence(&varbind);

    let pdu_contents = [
        &ber_integer(request_id)[..],
        &ber_integer(0)[..],
        &ber_integer(0)[..],
        &varbind_list[..],
    ].concat();
    let pdu = ber_context_tag(0, &pdu_contents);

    let message = ber_sequence(&[
        &ber_integer(0)[..],
        &ber_octet_string(community.as_bytes())[..],
        &pdu[..],
    ].concat());
    message
}

fn parse_snmp_response(data: &[u8]) -> Result<bool, String> {
    if data.len() < 10 || data[0] != 0x30 {
        return Err("Not an SNMP response".to_string());
    }
    let mut pos = 2;
    if data[1] >= 0x80 {
        let len_bytes = (data[1] & 0x0f) as usize;
        pos = 2 + len_bytes;
    }
    while pos < data.len() && data[pos] == 0x30 {
        pos += 1;
    }
    if pos >= data.len() || data[pos] != 0x02 {
        return Err("No version".to_string());
    }
    pos += 2;
    pos += 1;
    if pos >= data.len() || data[pos] != 0x04 {
        return Err("No community".to_string());
    }
    pos += 1;
    let comm_len = data[pos] as usize;
    pos += 1 + comm_len;
    if pos >= data.len() {
        return Err("No PDU".to_string());
    }
    let pdu_tag = data[pos];
    if pdu_tag == 0xA2 || pdu_tag == 0xA0 {
        let len_field = data[pos + 1];
        let pdu_start = if len_field < 0x80 {
            pos + 2
        } else {
            pos + 2 + (len_field & 0x0f) as usize
        };
        if pdu_start + 6 > data.len() {
            return Err("PDU too short".to_string());
        }
        if data[pdu_start] != 0x02 {
            return Err("No request-id in PDU".to_string());
        }
        let rid_len = data[pdu_start + 1] as usize;
        let err_pos = pdu_start + 2 + rid_len;
        if err_pos + 4 > data.len() {
            return Err("PDU too short for error fields".to_string());
        }
        if data[err_pos] != 0x02 {
            return Err("No error-status".to_string());
        }
        let err_status = data[err_pos + 2];
        if err_status != 0 {
            return Err(format!("SNMP error: {}", err_status));
        }
        if pdu_tag == 0xA2 {
            return Ok(true);
        }
        return Ok(false);
    }
    Err(format!("Unexpected PDU tag: 0x{:02x}", pdu_tag))
}

#[async_trait]
impl Protocol for SnmpProtocol {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn default_port(&self) -> u16 {
        161
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        _proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let community = if credential.username.is_empty() {
            &credential.password
        } else {
            &credential.username
        };

        match timeout(timeout_dur, async {
            let addr = target.addr_string();
            let bind_addr = if target.host.contains(':') {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let socket = UdpSocket::bind(bind_addr).await
                .map_err(|e| format!("Bind UDP: {}", e))?;
            socket.connect(&addr).await
                .map_err(|e| format!("Connect UDP: {}", e))?;

            let sys_descr_oid = &[1u32, 3, 6, 1, 2, 1, 1, 1, 0];
            let request_id: i32 = rand::random::<i32>().abs() % 100000 + 1;
            let packet = build_snmp_get(community, sys_descr_oid, request_id);

            socket.send(&packet).await
                .map_err(|e| format!("Send SNMP: {}", e))?;

            let mut buf = alloc_read_buf();
            let n = tokio::time::timeout(
                timeout_dur,
                socket.recv(&mut buf),
            ).await
                .map_err(|_| "Timeout waiting for SNMP response".to_string())?
                .map_err(|e| format!("Recv SNMP: {}", e))?;

            let response = &buf[..n];
            match parse_snmp_response(response) {
                Ok(true) => Ok(AuthResult::new(
                    target.host.clone(), target.port, "snmp",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                )),
                Ok(false) => Ok(AuthResult::new(
                    target.host.clone(), target.port, "snmp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("Unexpected PDU type".into()),
                )),
                Err(e) => Ok(AuthResult::new(
                    target.host.clone(), target.port, "snmp",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(e),
                )),
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "snmp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "snmp",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
