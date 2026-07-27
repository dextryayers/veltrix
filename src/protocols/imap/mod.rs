use async_trait::async_trait;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::tcp::{connect_optimized, tune_tcp};
use super::conn;
use super::Protocol;

pub struct ImapProtocol;

async fn imap_auth_tls(
    host: &str, port: u16, username: &str, password: &str,
    start: Instant, stream: tokio::net::TcpStream,
) -> Result<AuthResult, String> {
    let connector = TlsConnector::from(
        NativeTlsConnector::builder().build()
            .map_err(|e| format!("TLS build: {}", e))?
    );
    let mut tls_stream = connector.connect(host, stream).await
        .map_err(|e| format!("TLS connect: {}", e))?;

    // Read greeting
    let mut buf = Vec::new();
    conn::read_line_tls(&mut tls_stream, &mut buf).await?;

    conn::write_line_tls(&mut tls_stream, &format!("a001 LOGIN {} {}\r\n", username, password)).await?;
    let mut resp = String::new();
    loop {
        let line = conn::read_line_tls(&mut tls_stream, &mut buf).await?;
        resp.push_str(&line);
        resp.push('\n');
        if line.contains("a001 ") { break; }
    }
    let resp_lower = resp.to_lowercase();
    let success = resp_lower.contains("a001 ok");

    conn::write_line_tls(&mut tls_stream, "a002 LOGOUT\r\n").await.ok();
    Ok(AuthResult::new(host.to_string(), port, "imap",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some("Auth denied".into()) }))
}

async fn imap_auth_plain(
    host: &str, port: u16, username: &str, password: &str,
    start: Instant, mut stream: tokio::net::TcpStream,
) -> Result<AuthResult, String> {
    let mut buf = Vec::new();

    // Read greeting
    let _greeting = conn::read_crlf_line(&mut stream, &mut buf).await?;

    // Check capabilities
    conn::write_line(&mut stream, "a001 CAPABILITY\r\n").await?;
    let caps = conn::read_crlf_line(&mut stream, &mut buf).await?;

    if caps.to_uppercase().contains("STARTTLS") {
        conn::write_line(&mut stream, "a002 STARTTLS\r\n").await?;
        let stls_resp = conn::read_crlf_line(&mut stream, &mut buf).await?;
        if stls_resp.starts_with("a002 OK") {
            let connector = TlsConnector::from(
                NativeTlsConnector::builder().build()
                    .map_err(|e| format!("TLS build: {}", e))?
            );
            return match connector.connect(host, stream).await {
                Ok(mut tls_stream) => {
                    // Read post-STARTTLS greeting
                    let mut tb = Vec::new();
                    conn::read_line_tls(&mut tls_stream, &mut tb).await.ok();

                    conn::write_line_tls(&mut tls_stream, &format!("a003 LOGIN {} {}\r\n", username, password)).await?;
                    let mut tresp = String::new();
                    loop {
                        let line = conn::read_line_tls(&mut tls_stream, &mut tb).await?;
                        tresp.push_str(&line);
                        tresp.push('\n');
                        if line.contains("a003 ") { break; }
                    }
                    let success = tresp.to_lowercase().contains("a003 ok");
                    Ok(AuthResult::new(host.to_string(), port, "imap",
                        username.to_string(), password.to_string(),
                        success, start.elapsed(),
                        if success { None } else { Some("Auth denied".into()) }))
                }
                Err(e) => Ok(AuthResult::new(host.to_string(), port, "imap",
                    username.to_string(), password.to_string(),
                    false, start.elapsed(), Some(format!("STARTTLS failed: {}", e)))),
            };
        }
    }

    conn::write_line(&mut stream, &format!("a003 LOGIN {} {}\r\n", username, password)).await?;
    let mut resp = String::new();
    loop {
        let line = conn::read_crlf_line(&mut stream, &mut buf).await?;
        resp.push_str(&line);
        resp.push('\n');
        if line.contains("a003 ") { break; }
    }
    conn::write_line(&mut stream, "a004 LOGOUT\r\n").await.ok();

    let resp_lower = resp.to_lowercase();
    let success = resp_lower.contains("a003 ok");

    Ok(AuthResult::new(host.to_string(), port, "imap",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some("Auth denied".into()) }))
}

#[async_trait]
impl Protocol for ImapProtocol {
    fn name(&self) -> &'static str { "imap" }
    fn default_port(&self) -> u16 { 143 }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();
        let addr = target.addr_string();
        let host = target.host.clone();
        let port = target.port;
        let username = credential.username.clone();
        let password = credential.password.clone();
        let use_tls = port == 993;

        match timeout(timeout_dur, async {
            let stream = match proxy {
                Some(p) => {
                    let s = p.tcp_connect(&addr, timeout_dur).await
                        .map_err(|e| format!("Connect: {}", e))?;
                    tune_tcp(&s);
                    s
                },
                None => connect_optimized(&addr, timeout_dur).await?,
            };

            if use_tls {
                imap_auth_tls(&host, port, &username, &password, start, stream).await
            } else {
                imap_auth_plain(&host, port, &username, &password, start, stream).await
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "imap",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "imap",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
