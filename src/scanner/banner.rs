use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_BANNER_BYTES: usize = 16384;
const MAX_BANNER_LINES: usize = 30;
const BANNER_TIMEOUT: Duration = Duration::from_secs(2);

pub struct BannerGrabber;

impl BannerGrabber {
    pub async fn grab(
        stream: &mut TcpStream,
        port: u16,
        _connect_timeout: Duration,
    ) -> Result<String, String> {
        let probe = probe_for_port(port);
        if let Some(probe_bytes) = probe {
            let _ = timeout(BANNER_TIMEOUT, stream.write_all(&probe_bytes)).await;
            let wait = wait_for_port(port);
            tokio::time::sleep(wait).await;
        }

        let mut buf = vec![0u8; MAX_BANNER_BYTES];
        let mut collected = Vec::new();

        match timeout(BANNER_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                collected.extend_from_slice(&buf[..n]);

                if should_try_second_read(port) {
                    let wait2 = if n as usize >= 4096 {
                        Duration::from_millis(50)
                    } else {
                        Duration::from_millis(100)
                    };
                    tokio::time::sleep(wait2).await;
                    if let Ok(Ok(m)) = timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
                        if m > 0 {
                            collected.extend_from_slice(&buf[..m]);
                        }
                    }
                }

                if should_try_third_read(port) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if let Ok(Ok(m)) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                        if m > 0 {
                            collected.extend_from_slice(&buf[..m]);
                        }
                    }
                }
            }
            Ok(Ok(_)) => return Ok(String::new()),
            Ok(Err(e)) => return Err(format!("Read error: {}", e)),
            Err(_) => return Ok(String::new()),
        }

        if collected.is_empty() {
            return try_passive_read(stream, BANNER_TIMEOUT).await;
        }

        let cleaned = clean_banner(&collected);
        Ok(cleaned)
    }
}

async fn try_passive_read(stream: &mut TcpStream, _timeout_dur: Duration) -> Result<String, String> {
    let mut buf = vec![0u8; MAX_BANNER_BYTES];
    tokio::time::sleep(Duration::from_millis(200)).await;
    match timeout(BANNER_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Ok(clean_banner(&buf[..n])),
        _ => Ok(String::new()),
    }
}

fn should_try_second_read(port: u16) -> bool {
    matches!(
        port,
        80 | 443 | 8080 | 8443 | 8000 | 8008
            | 25 | 587 | 465
            | 21
            | 143 | 993
            | 110 | 995
            | 23
            | 22
            | 389 | 636
            | 3306
            | 5432
            | 27017 | 27018
            | 6379 | 6380
    )
}

fn should_try_third_read(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443 | 25 | 587 | 23 | 22)
}

fn wait_for_port(port: u16) -> Duration {
    match port {
        23 | 22 => Duration::from_millis(200),
        3306 | 5432 => Duration::from_millis(100),
        389 | 636 | 27017 | 27018 => Duration::from_millis(150),
        80 | 443 | 8080 | 8443 => Duration::from_millis(50),
        _ => Duration::from_millis(75),
    }
}

fn clean_banner(raw: &[u8]) -> String {
    let truncated = if raw.len() > MAX_BANNER_BYTES {
        &raw[..MAX_BANNER_BYTES]
    } else {
        raw
    };

    let mut lines = Vec::new();
    let mut current_line = Vec::new();

    for &b in truncated {
        if b == b'\n' {
            if !current_line.is_empty() {
                let line = String::from_utf8_lossy(&current_line).trim().to_string();
                if !line.is_empty() {
                    lines.push(line);
                }
                current_line.clear();
            }
            if lines.len() >= MAX_BANNER_LINES {
                break;
            }
        } else if b == b'\r' {
        } else if b == b'\0' && current_line.is_empty() {
        } else if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            if current_line.len() < 512 {
                current_line.push(b);
            }
        } else {
            if !current_line.is_empty() {
                current_line.push(b'.');
            }
        }
    }

    if !current_line.is_empty() && lines.len() < MAX_BANNER_LINES {
        let line = String::from_utf8_lossy(&current_line).trim().to_string();
        if !line.is_empty() {
            lines.push(line);
        }
    }

    lines.join("\n")
}

fn probe_for_port(port: u16) -> Option<Vec<u8>> {
    match port {
        21 => Some(b"SYST\r\nFEAT\r\n".to_vec()),
        25 | 587 | 465 => Some(b"EHLO scan.veltrix.local\r\n".to_vec()),
        80 | 443 | 8080 | 8443 | 8000 | 8008 | 8009 => {
            Some(
                b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0\r\nAccept: */*\r\n\r\n".to_vec()
            )
        }
        110 | 995 => Some(b"CAPA\r\n".to_vec()),
        143 | 993 => Some(b"a001 CAPABILITY\r\n".to_vec()),
        389 | 636 => {
            let msg = &[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
                0x01, 0x03, 0x04, 0x00, 0x04, 0x00,
            ];
            Some(msg.to_vec())
        }
        6379 | 6380 => Some(b"INFO\r\nPING\r\n".to_vec()),
        11211 => Some(b"stats\r\nversion\r\n".to_vec()),
        27017 | 27018 => {
            let msg = &[
                0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69,
                0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ];
            Some(msg.to_vec())
        }
        3306 => Some(b"\x00".to_vec()),
        5432 => {
            let msg = &[
                0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f,
            ];
            Some(msg.to_vec())
        }
        3389 => Some(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec()),
        5900 | 5901 | 5902 | 5903 => Some(b"RFB 003.008\n".to_vec()),
        23 => Some(b"\r\n".to_vec()),
        22 => None,
        445 => None,
        161 | 162 => None,
        8530 | 8531 => Some(b"GET / HTTP/1.0\r\n\r\n".to_vec()),
        8444 | 8445 | 8446 | 8447 | 8448 | 8449 => Some(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()),
        9200 | 9201 | 9202 => Some(b"GET / HTTP/1.0\r\n\r\n".to_vec()),
        5601 => Some(b"GET / HTTP/1.0\r\n\r\n".to_vec()),
        3000 | 3001 => Some(b"GET / HTTP/1.0\r\n\r\n".to_vec()),
        _ => Some(b"\r\n".to_vec()),
    }
}
