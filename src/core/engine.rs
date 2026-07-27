use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsStream;

const MAX_FRAME_BYTES: usize = 256 * 1024;

pub struct ProtocolStream<S> {
    inner: S,
}

impl ProtocolStream<TcpStream> {
    pub fn new(stream: TcpStream) -> Self {
        ProtocolStream { inner: stream }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> ProtocolStream<S> {
    pub fn from_tls(stream: S) -> Self {
        ProtocolStream { inner: stream }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: tokio::io::AsyncRead + Unpin> ProtocolStream<S> {
    pub async fn read_until_delim(
        &mut self,
        buf: &mut Vec<u8>,
        delimiter: u8,
        timeout_dur: Duration,
        max_bytes: usize,
    ) -> Result<String, String> {
        buf.clear();
        let mut byte = [0u8; 1];
        loop {
            if buf.len() >= max_bytes {
                return Err("Response exceeded maximum size".into());
            }
            match timeout(timeout_dur, self.inner.read(&mut byte)).await {
                Ok(Ok(0)) => {
                    if buf.is_empty() {
                        return Err("Connection closed".into());
                    }
                    break;
                }
                Err(_) => {
                    if buf.is_empty() {
                        return Err("Response timeout".into());
                    }
                    break;
                }
                Ok(Ok(_)) => {
                    if byte[0] == delimiter {
                        break;
                    }
                    buf.push(byte[0]);
                }
                Ok(Err(e)) => return Err(format!("Read: {}", e)),
            }
        }
        Ok(String::from_utf8_lossy(buf).trim().to_string())
    }

    pub async fn read_line(
        &mut self,
        buf: &mut Vec<u8>,
        timeout_dur: Duration,
    ) -> Result<String, String> {
        self.read_until_delim(buf, b'\n', timeout_dur, MAX_FRAME_BYTES).await
    }

    pub async fn read_exact(
        &mut self,
        buf: &mut [u8],
        timeout_dur: Duration,
    ) -> Result<(), String> {
        timeout(timeout_dur, self.inner.read_exact(buf)).await
            .map_err(|_| "Read exact timeout".to_string())?
            .map_err(|e| format!("Read exact: {}", e))?;
        Ok(())
    }

    pub async fn read_exact_vec(
        &mut self,
        len: usize,
        timeout_dur: Duration,
    ) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf, timeout_dur).await?;
        Ok(buf)
    }

    pub async fn read_frame_4le(
        &mut self,
        timeout_dur: Duration,
    ) -> Result<Vec<u8>, String> {
        let len_bytes = self.read_exact_vec(4, timeout_dur).await?;
        let payload_len = u32::from_le_bytes(
            len_bytes.as_slice().try_into().map_err(|_| "Bad length")?
        ) as usize;
        if payload_len > MAX_FRAME_BYTES {
            return Err(format!("Frame too large: {}", payload_len));
        }
        if payload_len == 0 {
            return Ok(Vec::new());
        }
        self.read_exact_vec(payload_len, timeout_dur).await
    }

    pub async fn read_frame_4be(
        &mut self,
        timeout_dur: Duration,
    ) -> Result<Vec<u8>, String> {
        let len_bytes = self.read_exact_vec(4, timeout_dur).await?;
        let payload_len = u32::from_be_bytes(
            len_bytes.as_slice().try_into().map_err(|_| "Bad length")?
        ) as usize;
        if payload_len > MAX_FRAME_BYTES {
            return Err(format!("Frame too large: {}", payload_len));
        }
        if payload_len == 0 {
            return Ok(Vec::new());
        }
        self.read_exact_vec(payload_len, timeout_dur).await
    }

    pub async fn read_some(
        &mut self,
        buf: &mut [u8],
        timeout_dur: Duration,
    ) -> Result<usize, String> {
        timeout(timeout_dur, self.inner.read(buf)).await
            .map_err(|_| "Read timeout".to_string())?
            .map_err(|e| format!("Read: {}", e))
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> ProtocolStream<S> {
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), String> {
        self.inner.write_all(data).await
            .map_err(|e| format!("Write: {}", e))?;
        self.inner.flush().await
            .map_err(|e| format!("Flush: {}", e))
    }

    pub async fn write_str(&mut self, s: &str) -> Result<(), String> {
        self.write_all(s.as_bytes()).await
    }

    pub async fn write_line(&mut self, line: &str) -> Result<(), String> {
        let s = if line.ends_with("\r\n") {
            line.to_string()
        } else if line.ends_with('\n') {
            format!("{}\r", line.trim_end_matches('\n'))
        } else {
            format!("{}\r\n", line)
        };
        self.write_str(&s).await
    }
}

pub type TcpProtocolStream = ProtocolStream<TcpStream>;
pub type TlsProtocolStream = ProtocolStream<TlsStream<TcpStream>>;

pub async fn connect_tcp(
    addr: &str,
    timeout_dur: Duration,
    proxy: &Option<crate::proxy::ProxyConfig>,
) -> Result<TcpProtocolStream, String> {
    use crate::protocols::tcp::{connect_optimized, tune_tcp};
    let stream = match proxy {
        Some(p) => {
            let s = p.tcp_connect(addr, timeout_dur).await
                .map_err(|e| format!("Connect: {}", e))?;
            tune_tcp(&s);
            s
        },
        None => connect_optimized(addr, timeout_dur).await?,
    };
    Ok(ProtocolStream::new(stream))
}

pub async fn upgrade_tls(
    stream: TcpProtocolStream,
    hostname: &str,
) -> Result<TlsProtocolStream, String> {
    let tls_connector = tokio_native_tls::TlsConnector::from(
        native_tls::TlsConnector::builder().build()
            .map_err(|e| format!("TLS build: {}", e))?
    );
    let tls = tls_connector.connect(hostname, stream.inner).await
        .map_err(|e| format!("TLS connect: {}", e))?;
    Ok(ProtocolStream::from_tls(tls))
}

pub async fn connect_tcp_tls(
    addr: &str,
    hostname: &str,
    timeout_dur: Duration,
    proxy: &Option<crate::proxy::ProxyConfig>,
) -> Result<TlsProtocolStream, String> {
    let tcp = connect_tcp(addr, timeout_dur, proxy).await?;
    upgrade_tls(tcp, hostname).await
}

pub struct ResponseBuffer {
    buf: Vec<u8>,
    pos: usize,
}

impl ResponseBuffer {
    pub fn new() -> Self {
        ResponseBuffer { buf: Vec::new(), pos: 0 }
    }

    pub fn new_with_capacity(cap: usize) -> Self {
        ResponseBuffer { buf: Vec::with_capacity(cap), pos: 0 }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_slice()).unwrap_or("")
    }

    pub fn as_lowercase(&self) -> String {
        self.as_str().to_lowercase()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.len() <= self.pos
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.pos = 0;
    }

    pub fn len(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn contains(&self, pattern: &str) -> bool {
        self.as_str().contains(pattern)
    }

    pub fn contains_lower(&self, pattern: &str) -> bool {
        self.as_lowercase().contains(pattern)
    }

    pub fn contains_any(&self, patterns: &[&str]) -> bool {
        let s = self.as_lowercase();
        patterns.iter().any(|p| s.contains(p))
    }

    pub fn contains_all(&self, patterns: &[&str]) -> bool {
        let s = self.as_lowercase();
        patterns.iter().all(|p| s.contains(p))
    }
}
