use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_BANNER_BYTES: usize = 8192;
const MAX_BANNER_LINES: usize = 20;

pub struct BannerGrabber;

impl BannerGrabber {
    pub async fn grab(
        stream: &mut TcpStream,
        port: u16,
        timeout_dur: Duration,
    ) -> Result<String, String> {
        let probe = probe_for_port(port);
        if let Some(probe_bytes) = probe {
            let _ = timeout(timeout_dur, stream.write_all(&probe_bytes)).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        let mut buf = vec![0u8; MAX_BANNER_BYTES];
        let mut collected = Vec::new();

        match timeout(timeout_dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                collected.extend_from_slice(&buf[..n]);

                if should_try_second_read(port) && n as usize == MAX_BANNER_BYTES {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if let Ok(Ok(m)) = timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
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
            return Ok(String::new());
        }

        let cleaned = clean_banner(&collected);
        Ok(cleaned)
    }
}

fn should_try_second_read(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443 | 8000 | 25 | 587 | 21)
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
                lines.push(String::from_utf8_lossy(&current_line).trim().to_string());
                current_line.clear();
            }
            if lines.len() >= MAX_BANNER_LINES {
                break;
            }
        } else if b == b'\r' {
            // skip CR
        } else if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            if current_line.len() < 512 {
                current_line.push(b);
            }
        } else if current_line.is_empty() && b == b'\0' {
            // skip leading nulls
        } else {
            current_line.push(b'.');
        }
    }

    if !current_line.is_empty() && lines.len() < MAX_BANNER_LINES {
        lines.push(String::from_utf8_lossy(&current_line).trim().to_string());
    }

    lines.join("\n")
}

fn probe_for_port(port: u16) -> Option<Vec<u8>> {
    match port {
        21 => Some(b"FEAT\r\n".to_vec()),
        25 | 587 => Some(b"EHLO scanner\r\n".to_vec()),
        80 | 443 | 8080 | 8443 | 8000 | 8008 | 8009 => {
            Some(b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n".to_vec())
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
        6379 | 6380 => Some(b"PING\r\n".to_vec()),
        11211 => Some(b"stats\r\n".to_vec()),
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
        22 => None,
        23 => None,
        445 => None,
        161 | 162 => None,
        _ => None,
    }
}
