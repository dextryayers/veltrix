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
use super::tcp::{connect_optimized, tune_tcp};

pub struct MongoDbProtocol;

fn bson_document(elements: &[u8]) -> Vec<u8> {
    let mut doc = Vec::new();
    doc.extend_from_slice(&[0u8; 4]);
    doc.extend_from_slice(elements);
    doc.push(0x00);
    let len = doc.len() as i32;
    doc[..4].copy_from_slice(&len.to_le_bytes());
    doc
}

fn bson_string(name: &str, value: &str) -> Vec<u8> {
    let mut elem = Vec::new();
    elem.push(0x02);
    elem.extend_from_slice(name.as_bytes());
    elem.push(0x00);
    let value_bytes = value.as_bytes();
    let str_len = value_bytes.len() as i32 + 1;
    elem.extend_from_slice(&str_len.to_le_bytes());
    elem.extend_from_slice(value_bytes);
    elem.push(0x00);
    elem
}

fn bson_int32(name: &str, value: i32) -> Vec<u8> {
    let mut elem = Vec::new();
    elem.push(0x10);
    elem.extend_from_slice(name.as_bytes());
    elem.push(0x00);
    elem.extend_from_slice(&value.to_le_bytes());
    elem
}

fn build_op_query(full_collection: &str, query: &[u8]) -> Vec<u8> {
    let request_id: i32 = 1;
    let response_to: i32 = 0;
    let op_code: i32 = 2004;
    let flags: i32 = 0;
    let number_to_skip: i32 = 0;
    let number_to_return: i32 = -1;

    let mut msg = Vec::new();
    msg.extend_from_slice(&[0u8; 4]);
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&response_to.to_le_bytes());
    msg.extend_from_slice(&op_code.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(full_collection.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(&number_to_skip.to_le_bytes());
    msg.extend_from_slice(&number_to_return.to_le_bytes());
    msg.extend_from_slice(query);

    let len = msg.len() as i32;
    msg[..4].copy_from_slice(&len.to_le_bytes());
    msg
}

async fn read_op_reply(stream: &mut TcpStream, timeout_dur: Duration) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout_dur, stream.read_exact(&mut len_buf)).await
        .map_err(|_| "Timeout reading response length".to_string())?
        .map_err(|e| format!("Read response length: {}", e))?;

    let msg_len = i32::from_le_bytes(len_buf) as usize;
    if msg_len < 36 || msg_len > 1024 * 1024 {
        return Err(format!("Invalid message length: {}", msg_len));
    }

    let mut rest = vec![0u8; msg_len - 4];
    stream.read_exact(&mut rest).await
        .map_err(|e| format!("Read response body: {}", e))?;

    let mut full = Vec::with_capacity(msg_len);
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&rest);

    if full.len() < 36 {
        return Err("Response too short".to_string());
    }

    let read_i32 = |start: usize| -> Result<i32, String> {
        if start + 4 > full.len() {
            return Err(format!("Response too short at offset {}", start));
        }
        let arr: [u8; 4] = full[start..start+4].try_into()
            .map_err(|_| format!("Invalid slice at offset {}", start))?;
        Ok(i32::from_le_bytes(arr))
    };

    let op_code = read_i32(12)?;
    if op_code != 1 {
        return Err(format!("Unexpected opCode: {}", op_code));
    }

    let resp_flags = read_i32(16)?;
    if resp_flags & 0x01 != 0 {
        let doc_start = 36;
        if let Ok(dlen) = read_i32(doc_start).map(|v| v as usize) {
            if doc_start + dlen <= full.len() {
                let doc = full[doc_start..doc_start+dlen].to_vec();
                let errmsg = bson_find_string(&doc, "errmsg").unwrap_or_else(|| "QueryFailure".to_string());
                let code = bson_find_int(&doc, "code").unwrap_or(-1);
                return Err(format!("{} (code {})", errmsg, code));
            }
        }
        return Err("QueryFailure".to_string());
    }

    let num_returned = read_i32(32)?;
    if num_returned == 0 {
        return Err("No documents returned".to_string());
    }

    let doc_start = 36;
    let dlen = read_i32(doc_start)? as usize;
    if doc_start + dlen > full.len() {
        return Err("Document exceeds response".to_string());
    }

    Ok(full[doc_start..doc_start+dlen].to_vec())
}

fn bson_find_int(doc: &[u8], key: &str) -> Option<i32> {
    let mut pos = 4usize;
    let doc_end = doc.len().saturating_sub(1);
    while pos < doc_end {
        if pos >= doc.len() { return None; }
        let elem_type = doc[pos];
        pos += 1;
        let name_start = pos;
        while pos < doc.len() && doc[pos] != 0 { pos += 1; }
        if pos >= doc.len() { return None; }
        let name = std::str::from_utf8(&doc[name_start..pos]).ok()?;
        pos += 1;
        if name == key {
            match elem_type {
                0x10 => {
                    if pos + 4 <= doc.len() {
                        return Some(i32::from_le_bytes(doc[pos..pos+4].try_into().ok()?));
                    }
                }
                0x01 => {
                    if pos + 8 <= doc.len() {
                        return Some(f64::from_le_bytes(doc[pos..pos+8].try_into().ok()?) as i32);
                    }
                }
                _ => return None,
            }
        }
        match elem_type {
            0x01 => pos += 8,
            0x02 => {
                if pos + 4 <= doc.len() {
                    let slen = i32::from_le_bytes(doc[pos..pos+4].try_into().ok()?) as usize;
                    pos += 4 + slen;
                }
            }
            0x03 => {
                if pos + 4 <= doc.len() {
                    let dlen = i32::from_le_bytes(doc[pos..pos+4].try_into().ok()?) as usize;
                    pos += dlen;
                }
            }
            0x08 => pos += 1,
            0x0A => {}
            0x10 => pos += 4,
            0x12 => pos += 8,
            _ => { pos += 1; }
        }
    }
    None
}

fn bson_find_string(doc: &[u8], key: &str) -> Option<String> {
    let mut pos = 4usize;
    let doc_end = doc.len().saturating_sub(1);
    while pos < doc_end {
        if pos >= doc.len() { return None; }
        let elem_type = doc[pos];
        pos += 1;
        let name_start = pos;
        while pos < doc.len() && doc[pos] != 0 { pos += 1; }
        if pos >= doc.len() { return None; }
        let name = std::str::from_utf8(&doc[name_start..pos]).ok()?;
        pos += 1;
        if name == key && elem_type == 0x02 {
            if pos + 4 <= doc.len() {
                let slen = i32::from_le_bytes(doc[pos..pos+4].try_into().ok()?) as usize;
                pos += 4;
                if slen > 0 && pos + slen - 1 <= doc.len() {
                    let s = std::str::from_utf8(&doc[pos..pos+slen-1]).ok()?;
                    return Some(s.to_string());
                }
            }
        }
        match elem_type {
            0x01 => pos += 8,
            0x02 => {
                if pos + 4 <= doc.len() {
                    let slen = i32::from_le_bytes(doc[pos..pos+4].try_into().ok()?) as usize;
                    pos += 4 + slen;
                }
            }
            0x03 => {
                if pos + 4 <= doc.len() {
                    let dlen = i32::from_le_bytes(doc[pos..pos+4].try_into().ok()?) as usize;
                    pos += dlen;
                }
            }
            0x08 => pos += 1,
            0x0A => {}
            0x10 => pos += 4,
            0x12 => pos += 8,
            _ => { pos += 1; }
        }
    }
    None
}

#[async_trait]
impl Protocol for MongoDbProtocol {
    fn name(&self) -> &'static str {
        "mongodb"
    }

    fn default_port(&self) -> u16 {
        27017
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

            let nonce_elems = bson_int32("getNonce", 1);
            let get_nonce = bson_document(&nonce_elems);
            let query = build_op_query("admin.$cmd", &get_nonce);
            stream.write_all(&query).await
                .map_err(|e| format!("Send getNonce: {}", e))?;
            stream.flush().await
                .map_err(|e| format!("Flush: {}", e))?;

            let doc = read_op_reply(&mut stream, timeout_dur).await?;
            let nonce = bson_find_string(&doc, "nonce")
                .ok_or_else(|| "No nonce in response".to_string())?;

            let inner = format!("{}:mongo:{}", credential.username, credential.password);
            let inner_hash = format!("{:x}", md5::compute(inner.as_bytes()));
            let key_input = format!("{}{}", inner_hash, nonce);
            let key = format!("{:x}", md5::compute(key_input.as_bytes()));

            let auth_elems = [
                &bson_int32("authenticate", 1)[..],
                &bson_string("user", &credential.username)[..],
                &bson_string("nonce", &nonce)[..],
                &bson_string("key", &key)[..],
            ].concat();
            let auth_doc = bson_document(&auth_elems);
            let auth_query = build_op_query("admin.$cmd", &auth_doc);

            stream.write_all(&auth_query).await
                .map_err(|e| format!("Send auth: {}", e))?;
            stream.flush().await
                .map_err(|e| format!("Flush: {}", e))?;

            let auth_resp = read_op_reply(&mut stream, timeout_dur).await?;
            let ok = bson_find_int(&auth_resp, "ok").unwrap_or(0);

            if ok == 1 {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "mongodb",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ))
            } else {
                let errmsg = bson_find_string(&auth_resp, "errmsg")
                    .unwrap_or_else(|| "Authentication failed".to_string());
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "mongodb",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some(errmsg),
                ))
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "mongodb",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "mongodb",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
