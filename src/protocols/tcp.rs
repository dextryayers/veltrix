use std::time::Duration;
use tokio::net::TcpStream;
use socket2::{SockRef, TcpKeepalive};

pub fn tune_tcp(stream: &TcpStream) {
    let sock_ref = SockRef::from(stream);
    let _ = sock_ref.set_tcp_nodelay(true);
    let _ = sock_ref.set_keepalive(true);
    let _ = sock_ref.set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(30)));
    let _ = sock_ref.set_recv_buffer_size(262_144);
    let _ = sock_ref.set_send_buffer_size(65_536);
}

pub async fn connect_optimized(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await
        .map_err(|_| format!("Timeout connecting to {}", addr))?
        .map_err(|e| format!("Connect: {}", e))?;

    tune_tcp(&stream);
    Ok(stream)
}

pub fn alloc_read_buf() -> Vec<u8> {
    vec![0u8; 65536]
}
