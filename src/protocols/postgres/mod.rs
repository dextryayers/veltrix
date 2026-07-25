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

pub struct PostgresProtocol;

fn md5_hash(input: &str) -> String {
    let mut hasher = md5::Context::new();
    hasher.consume(input.as_bytes());
    let digest = hasher.finalize();
    format!("{:x}", digest)
}

fn pg_md5(password: &str, user: &str, salt: &[u8]) -> String {
    let inner = format!("{}{}", md5_hash(&format!("{}{}", password, user)), user);
    let mut hasher = md5::Context::new();
    hasher.consume(inner.as_bytes());
    hasher.consume(salt);
    let digest = hasher.finalize();
    format!("md5{:x}", digest)
}

async fn pg_authenticate_inner(
    stream: TcpStream,
    host: &str,
    port: u16,
    credential: &Credential,
    start: Instant,
) -> Result<AuthResult, String> {
    let ssl_request: [u8; 8] = [
        0x00, 0x00, 0x00, 0x08,
        0x04, 0xD2, 0x16, 0x2F,
    ];
    let mut owned = stream;
    owned.write_all(&ssl_request).await
        .map_err(|e| format!("SSL request: {}", e))?;
    owned.flush().await.ok();

    let mut ssl_resp = [0u8; 1];
    if owned.read_exact(&mut ssl_resp).await.is_ok() && ssl_resp[0] == b'S' {
        let connector = TlsConnector::from(
            NativeTlsConnector::builder().build()
                .map_err(|e| format!("TLS build: {}", e))?
        );
        let mut tls_stream = connector.connect(host, owned).await
            .map_err(|e| format!("TLS connect: {}", e))?;

        return pg_auth_tls(&mut tls_stream, host, port, credential, start).await;
    }

    pg_auth_plain(&mut owned, host, port, credential, start).await
}

async fn pg_auth_tls(
    tls_stream: &mut tokio_native_tls::TlsStream<TcpStream>,
    host: &str,
    port: u16,
    credential: &Credential,
    start: Instant,
) -> Result<AuthResult, String> {
    let username = credential.username.clone();
    let password = credential.password.clone();

    let params = format!("\0user\0{}\0database\0{}\0\0", username, username);
    let payload_len = 4 + 4 + params.len() as u32;
    let mut startup = Vec::new();
    startup.extend_from_slice(&payload_len.to_be_bytes());
    startup.extend_from_slice(&(196608u32).to_be_bytes());
    startup.extend_from_slice(params.as_bytes());
    tls_stream.write_all(&startup).await
        .map_err(|e| format!("Startup: {}", e))?;
    tls_stream.flush().await.ok();

    let mut buf = vec![0u8; 8192];
    let n = tls_stream.read(&mut buf).await
        .map_err(|e| format!("Read auth: {}", e))?;
    if n < 5 {
        return Err("Short auth response".into());
    }

    let msg_type = buf[0] as char;

    if msg_type == 'R' {
        let auth_type = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        match auth_type {
            0 => Ok(AuthResult::new(host.to_string(), port, "postgres",
                username, password, true, start.elapsed(), None)),
            3 => {
                let mut pw_buf = Vec::new();
                pw_buf.extend_from_slice(&(0u32.to_be_bytes()));
                pw_buf.extend_from_slice(password.as_bytes());
                pw_buf.push(0);
                let len = pw_buf.len() as u32 + 4;
                let mut pkt = vec!['p' as u8];
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.extend_from_slice(&pw_buf);
                tls_stream.write_all(&pkt).await.map_err(|e| format!("Password: {}", e))?;
                tls_stream.flush().await.ok();
                pg_read_auth_response(tls_stream, host, port, &username, &password, start).await
            }
            5 => {
                let salt = &buf[9..13];
                let hash = pg_md5(&password, &username, salt);
                let mut pw_bytes = hash.as_bytes().to_vec();
                pw_bytes.push(0);
                let len = pw_bytes.len() as u32 + 4;
                let mut pkt = vec!['p' as u8];
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.extend_from_slice(&pw_bytes);
                tls_stream.write_all(&pkt).await.map_err(|e| format!("MD5 password: {}", e))?;
                tls_stream.flush().await.ok();
                pg_read_auth_response(tls_stream, host, port, &username, &password, start).await
            }
            _ => Err(format!("Unsupported auth type: {}", auth_type)),
        }
    } else if msg_type == 'E' {
        let err_msg = String::from_utf8_lossy(&buf[..n.min(buf.len())]);
        Ok(AuthResult::new(host.to_string(), port, "postgres",
            username, password, false, start.elapsed(), Some(format!("Error: {}", err_msg.trim()))))
    } else {
        Err(format!("Unexpected msg type: {}", msg_type))
    }
}

async fn pg_auth_plain(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    credential: &Credential,
    start: Instant,
) -> Result<AuthResult, String> {
    let username = credential.username.clone();
    let password = credential.password.clone();

    let params = format!("\0user\0{}\0database\0{}\0\0", username, username);
    let payload_len = 4 + 4 + params.len() as u32;
    let mut startup = Vec::new();
    startup.extend_from_slice(&payload_len.to_be_bytes());
    startup.extend_from_slice(&(196608u32).to_be_bytes());
    startup.extend_from_slice(params.as_bytes());
    stream.write_all(&startup).await
        .map_err(|e| format!("Startup: {}", e))?;
    stream.flush().await.ok();

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await
        .map_err(|e| format!("Read auth: {}", e))?;
    if n < 5 {
        return Err("Short auth response".into());
    }

    let msg_type = buf[0] as char;

    if msg_type == 'R' {
        let auth_type = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        match auth_type {
            0 => Ok(AuthResult::new(host.to_string(), port, "postgres",
                username, password, true, start.elapsed(), None)),
            3 => {
                let mut pw_buf = Vec::new();
                pw_buf.extend_from_slice(&(0u32.to_be_bytes()));
                pw_buf.extend_from_slice(password.as_bytes());
                pw_buf.push(0);
                let len = pw_buf.len() as u32 + 4;
                let mut pkt = vec!['p' as u8];
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.extend_from_slice(&pw_buf);
                stream.write_all(&pkt).await.map_err(|e| format!("Password: {}", e))?;
                stream.flush().await.ok();
                pg_read_auth_response_plain(stream, host, port, &username, &password, start).await
            }
            5 => {
                let salt = &buf[9..13];
                let hash = pg_md5(&password, &username, salt);
                let mut pw_bytes = hash.as_bytes().to_vec();
                pw_bytes.push(0);
                let len = pw_bytes.len() as u32 + 4;
                let mut pkt = vec!['p' as u8];
                pkt.extend_from_slice(&len.to_be_bytes());
                pkt.extend_from_slice(&pw_bytes);
                stream.write_all(&pkt).await.map_err(|e| format!("MD5 password: {}", e))?;
                stream.flush().await.ok();
                pg_read_auth_response_plain(stream, host, port, &username, &password, start).await
            }
            _ => Err(format!("Unsupported auth type: {}", auth_type)),
        }
    } else if msg_type == 'E' {
        let err_msg = String::from_utf8_lossy(&buf[..n.min(buf.len())]);
        Ok(AuthResult::new(host.to_string(), port, "postgres",
            username, password, false, start.elapsed(), Some(format!("Error: {}", err_msg.trim()))))
    } else {
        Err(format!("Unexpected msg type: {}", msg_type))
    }
}

async fn pg_read_auth_response(
    tls_stream: &mut tokio_native_tls::TlsStream<TcpStream>,
    host: &str, port: u16, username: &str, password: &str, start: Instant,
) -> Result<AuthResult, String> {
    let mut buf = vec![0u8; 8192];
    let n = tls_stream.read(&mut buf).await.map_err(|e| format!("Read response: {}", e))?;
    if n < 5 { return Err("Short response".into()); }
    let resp_type = buf[0] as char;
    if resp_type == 'R' {
        let auth_ok = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        if auth_ok == 0 {
            Ok(AuthResult::new(host.to_string(), port, "postgres",
                username.to_string(), password.to_string(), true, start.elapsed(), None))
        } else {
            Err(format!("Auth failed code: {}", auth_ok))
        }
    } else if resp_type == 'E' {
        let err_msg = String::from_utf8_lossy(&buf[..n.min(buf.len())]);
        let is_auth = err_msg.contains("password") || err_msg.contains("authentication") || err_msg.contains("28P01");
        Ok(AuthResult::new(host.to_string(), port, "postgres",
            username.to_string(), password.to_string(), false, start.elapsed(),
            if is_auth { None } else { Some(err_msg.trim().to_string()) }))
    } else {
        Err(format!("Unexpected response: {}", resp_type))
    }
}

async fn pg_read_auth_response_plain(
    stream: &mut TcpStream,
    host: &str, port: u16, username: &str, password: &str, start: Instant,
) -> Result<AuthResult, String> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.map_err(|e| format!("Read response: {}", e))?;
    if n < 5 { return Err("Short response".into()); }
    let resp_type = buf[0] as char;
    if resp_type == 'R' {
        let auth_ok = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        if auth_ok == 0 {
            Ok(AuthResult::new(host.to_string(), port, "postgres",
                username.to_string(), password.to_string(), true, start.elapsed(), None))
        } else {
            Err(format!("Auth failed code: {}", auth_ok))
        }
    } else if resp_type == 'E' {
        let err_msg = String::from_utf8_lossy(&buf[..n.min(buf.len())]);
        let is_auth = err_msg.contains("password") || err_msg.contains("authentication") || err_msg.contains("28P01");
        Ok(AuthResult::new(host.to_string(), port, "postgres",
            username.to_string(), password.to_string(), false, start.elapsed(),
            if is_auth { None } else { Some(err_msg.trim().to_string()) }))
    } else {
        Err(format!("Unexpected response: {}", resp_type))
    }
}

#[async_trait]
impl Protocol for PostgresProtocol {
    fn name(&self) -> &'static str { "postgres" }
    fn default_port(&self) -> u16 { 5432 }

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
            let stream = match proxy {
                Some(p) => p.tcp_connect(&addr, timeout_dur).await
                    .map_err(|e| format!("Proxy connect: {}", e))?,
                None => {
                    let s = TcpStream::connect(&addr).await
                        .map_err(|e| format!("Connect: {}", e))?;
                    s.set_nodelay(true).ok();
                    s
                },
            };
            pg_authenticate_inner(stream, &target.host, target.port, credential, start).await
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(target.host.clone(), target.port, "postgres",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some(e)),
            Err(_) => AuthResult::new(target.host.clone(), target.port, "postgres",
                credential.username.clone(), credential.password.clone(), false, start.elapsed(), Some("Timeout".into())),
        }
    }
}
