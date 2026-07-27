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

pub struct Pop3Protocol;

async fn pop3_auth_tls(
    host: &str, port: u16, username: &str, password: &str,
    start: Instant, stream: tokio::net::TcpStream,
) -> Result<AuthResult, String> {
    let connector = TlsConnector::from(
        NativeTlsConnector::builder().build()
            .map_err(|e| format!("TLS build: {}", e))?
    );
    let mut tls_stream = connector.connect(host, stream).await
        .map_err(|e| format!("TLS connect: {}", e))?;

    let mut buf = Vec::new();
    conn::write_line_tls(&mut tls_stream, &format!("USER {}\r\n", username)).await?;
    let user_resp = conn::read_line_tls(&mut tls_stream, &mut buf).await?;
    if !user_resp.starts_with("+OK") {
        return Ok(AuthResult::new(host.to_string(), port, "pop3",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp))));
    }

    conn::write_line_tls(&mut tls_stream, &format!("PASS {}\r\n", password)).await?;
    let pass_resp = conn::read_line_tls(&mut tls_stream, &mut buf).await?;
    let success = pass_resp.starts_with("+OK");

    Ok(AuthResult::new(host.to_string(), port, "pop3",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp) }))
}

async fn pop3_auth_plain(
    host: &str, port: u16, username: &str, password: &str,
    start: Instant, mut stream: tokio::net::TcpStream,
) -> Result<AuthResult, String> {
    let mut buf = Vec::new();

    let banner = conn::read_crlf_line(&mut stream, &mut buf).await?;
    if !banner.starts_with("+OK") {
        return Ok(AuthResult::new(host.to_string(), port, "pop3",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("Bad banner: {}", banner))));
    }

    conn::write_line(&mut stream, "STLS\r\n").await?;
    let stls_resp = conn::read_crlf_line(&mut stream, &mut buf).await?;
    if stls_resp.starts_with("+OK") {
        let connector = TlsConnector::from(
            NativeTlsConnector::builder().build()
                .map_err(|e| format!("TLS build: {}", e))?
        );
        return match connector.connect(host, stream).await {
            Ok(mut tls_stream) => {
                let mut tb = Vec::new();
                conn::write_line_tls(&mut tls_stream, &format!("USER {}\r\n", username)).await?;
                let user_resp = conn::read_line_tls(&mut tls_stream, &mut tb).await?;
                if !user_resp.starts_with("+OK") {
                    return Ok(AuthResult::new(host.to_string(), port, "pop3",
                        username.to_string(), password.to_string(),
                        false, start.elapsed(), Some(format!("User rejected: {}", user_resp))));
                }
                conn::write_line_tls(&mut tls_stream, &format!("PASS {}\r\n", password)).await?;
                let pass_resp = conn::read_line_tls(&mut tls_stream, &mut tb).await?;
                let success = pass_resp.starts_with("+OK");
                Ok(AuthResult::new(host.to_string(), port, "pop3",
                    username.to_string(), password.to_string(),
                    success, start.elapsed(),
                    if success { None } else { Some(pass_resp) }))
            }
            Err(_) => Ok(AuthResult::new(host.to_string(), port, "pop3",
                username.to_string(), password.to_string(),
                false, start.elapsed(), Some("STLS upgrade failed".into()))),
        };
    }

    conn::write_line(&mut stream, &format!("USER {}\r\n", username)).await?;
    let user_resp = conn::read_crlf_line(&mut stream, &mut buf).await?;
    if !user_resp.starts_with("+OK") {
        conn::write_line(&mut stream, "QUIT\r\n").await.ok();
        return Ok(AuthResult::new(host.to_string(), port, "pop3",
            username.to_string(), password.to_string(),
            false, start.elapsed(), Some(format!("User rejected: {}", user_resp))));
    }

    conn::write_line(&mut stream, &format!("PASS {}\r\n", password)).await?;
    let pass_resp = conn::read_crlf_line(&mut stream, &mut buf).await?;
    let success = pass_resp.starts_with("+OK");
    conn::write_line(&mut stream, "QUIT\r\n").await.ok();

    Ok(AuthResult::new(host.to_string(), port, "pop3",
        username.to_string(), password.to_string(),
        success, start.elapsed(),
        if success { None } else { Some(pass_resp) }))
}

#[async_trait]
impl Protocol for Pop3Protocol {
    fn name(&self) -> &'static str { "pop3" }
    fn default_port(&self) -> u16 { 110 }

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
        let use_tls = port == 995;

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
                pop3_auth_tls(&host, port, &username, &password, start, stream).await
            } else {
                pop3_auth_plain(&host, port, &username, &password, start, stream).await
            }
        }).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => AuthResult::new(
                target.host.clone(), target.port, "pop3",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some(e),
            ),
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "pop3",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
