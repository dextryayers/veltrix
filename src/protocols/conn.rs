use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsStream;

use super::tcp::{connect_optimized, tune_tcp};
use crate::proxy::ProxyConfig;

pub type TlsConnector = tokio_native_tls::TlsConnector;

pub fn build_tls_connector() -> Result<TlsConnector, String> {
    native_tls::TlsConnector::builder()
        .build()
        .map(tokio_native_tls::TlsConnector::from)
        .map_err(|e| format!("TLS build: {}", e))
}

pub async fn tcp_connect(
    addr: &str,
    timeout_dur: Duration,
    proxy: &Option<ProxyConfig>,
) -> Result<TcpStream, String> {
    match proxy {
        Some(p) => {
            let s = p
                .tcp_connect(addr, timeout_dur)
                .await
                .map_err(|e| format!("Proxy connect: {}", e))?;
            tune_tcp(&s);
            Ok(s)
        }
        None => connect_optimized(addr, timeout_dur).await,
    }
}

pub async fn read_crlf_line(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> Result<String, String> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        match timeout(Duration::from_secs(10), stream.read(&mut byte)).await {
            Ok(Ok(0)) => break,
            Err(_) => return Err("Read timeout".into()),
            Ok(Ok(_)) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
            Ok(Err(e)) => return Err(format!("Read: {}", e)),
        }
    }
    Ok(String::from_utf8_lossy(buf).trim().to_string())
}

pub async fn write_line(stream: &mut TcpStream, line: &str) -> Result<(), String> {
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("Write: {}", e))?;
    stream.flush().await.ok();
    Ok(())
}

pub async fn connect_and_banner(
    addr: &str,
    timeout_dur: Duration,
    proxy: &Option<ProxyConfig>,
    expected_prefix: &str,
) -> Result<(TcpStream, String), String> {
    let mut stream = tcp_connect(addr, timeout_dur, proxy).await?;
    let mut buf = Vec::new();
    let banner = read_crlf_line(&mut stream, &mut buf).await?;
    if !banner.starts_with(expected_prefix) {
        return Err(format!("Bad banner: {}", banner));
    }
    Ok((stream, banner))
}

pub async fn upgrade_to_tls(
    stream: TcpStream,
    hostname: &str,
) -> Result<TlsStream<TcpStream>, String> {
    let connector = build_tls_connector()?;
    connector
        .connect(hostname, stream)
        .await
        .map_err(|e| format!("TLS connect: {}", e))
}

pub async fn read_line_tls(
    tls_stream: &mut TlsStream<TcpStream>,
    buf: &mut Vec<u8>,
) -> Result<String, String> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        match timeout(Duration::from_secs(10), tls_stream.read(&mut byte)).await {
            Ok(Ok(0)) => break,
            Err(_) => return Err("TLS read timeout".into()),
            Ok(Ok(_)) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
            Ok(Err(e)) => return Err(format!("TLS read: {}", e)),
        }
    }
    Ok(String::from_utf8_lossy(buf).trim().to_string())
}

pub async fn write_line_tls(
    tls_stream: &mut TlsStream<TcpStream>,
    line: &str,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    tls_stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("TLS write: {}", e))?;
    tls_stream.flush().await.ok();
    Ok(())
}

pub async fn read_until_tls(
    tls_stream: &mut TlsStream<TcpStream>,
    buf: &mut Vec<u8>,
    delimiter: u8,
) -> Result<(), String> {
    let mut byte = [0u8; 1];
    loop {
        match timeout(Duration::from_secs(10), tls_stream.read(&mut byte)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(_)) => {
                buf.push(byte[0]);
                if byte[0] == delimiter {
                    break;
                }
            }
            Ok(Err(e)) => return Err(format!("TLS read: {}", e)),
        }
    }
    Ok(())
}
