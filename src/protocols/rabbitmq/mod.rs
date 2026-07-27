use async_trait::async_trait;
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::core::credential::Credential;
use crate::core::engine::connect_tcp;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct RabbitmqProtocol;

fn amqp_field_table(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (k, v) in entries {
        data.push(0x73);
        data.extend_from_slice(&(k.len() as u8).to_be_bytes());
        data.extend_from_slice(k.as_bytes());
        data.push(0x73);
        data.extend_from_slice(&(v.len() as u32).to_be_bytes());
        data.extend_from_slice(v.as_bytes());
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&data);
    buf
}

fn amqp_method(class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
    let payload_len = 4 + args.len();
    let mut buf = Vec::new();
    buf.push(0x01);
    buf.extend_from_slice(&0x0000u16.to_be_bytes());
    buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
    buf.extend_from_slice(&class_id.to_be_bytes());
    buf.extend_from_slice(&method_id.to_be_bytes());
    buf.extend_from_slice(args);
    buf.push(0xce);
    buf
}

#[async_trait]
impl Protocol for RabbitmqProtocol {
    fn name(&self) -> &'static str {
        "rabbitmq"
    }

    fn default_port(&self) -> u16 {
        5672
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
            let mut stream = connect_tcp(&target.addr_string(), timeout_dur, proxy).await?;
            let header = b"AMQP\x00\x00\x09\x01";
            stream.write_all(header).await.map_err(|e| format!("Write header: {}", e))?;
            let mut buf = vec![0u8; 7];
            stream.read_exact(&mut buf, timeout_dur).await?;
            if buf[0] != 0x01 {
                return Ok(AuthResult::new(
                    target.host.clone(), target.port, "rabbitmq",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(), Some("Unexpected frame type".into()),
                ));
            }
            let frame_len = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
            if frame_len > 0 {
                let _body = stream.read_exact_vec(frame_len, timeout_dur).await?;
            }
            let mut frame_end = [0u8; 1];
            stream.read_exact(&mut frame_end, timeout_dur).await.ok();
            let mut start_ok_args = Vec::new();
            let client_props = amqp_field_table(&[("product", "Veltrix"), ("version", "1.0")]);
            start_ok_args.extend_from_slice(&client_props);
            start_ok_args.push(0x03);
            let auth_data = format!("PLAIN\0{}\0{}", credential.username, credential.password);
            start_ok_args.extend_from_slice(&(auth_data.len() as u32).to_be_bytes());
            start_ok_args.extend_from_slice(auth_data.as_bytes());
            let zeros = [0u8; 132];
            start_ok_args.extend_from_slice(&zeros);
            let start_ok = amqp_method(0x000a, 0x000b, &start_ok_args);
            stream.write_all(&start_ok).await.map_err(|e| format!("Write start-ok: {}", e))?;
            let mut tune_header = vec![0u8; 7];
            stream.read_exact(&mut tune_header, timeout_dur).await?;
            let tune_len = u32::from_be_bytes([tune_header[3], tune_header[4], tune_header[5], tune_header[6]]) as usize;
            if tune_len > 0 {
                let _body = stream.read_exact_vec(tune_len, timeout_dur).await?;
            }
            stream.read_exact(&mut frame_end, timeout_dur).await.ok();
            let tune_ok = amqp_method(0x000a, 0x000d, &[0u8; 12]);
            stream.write_all(&tune_ok).await.map_err(|e| format!("Write tune-ok: {}", e))?;
            let mut open_args = [0u8; 156];
            open_args[4] = 0x01;
            open_args[5] = 0x2f;
            let open_method = amqp_method(0x000a, 0x0028, &open_args);
            stream.write_all(&open_method).await.map_err(|e| format!("Write open: {}", e))?;
            let mut open_resp = vec![0u8; 7];
            stream.read_exact(&mut open_resp, timeout_dur).await?;
            if open_resp[0] == 0x01 {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "rabbitmq",
                    credential.username.clone(), credential.password.clone(),
                    true, start.elapsed(), None,
                ))
            } else {
                Ok(AuthResult::new(
                    target.host.clone(), target.port, "rabbitmq",
                    credential.username.clone(), credential.password.clone(),
                    false, start.elapsed(),
                    Some("Connection not opened".into()),
                ))
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "rabbitmq",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "rabbitmq",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
