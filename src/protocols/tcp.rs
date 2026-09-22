use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
use tokio::net::TcpStream;
use socket2::{SockRef, TcpKeepalive};

/// ANON: egress source IP override (lihat --source-ip).
/// First-wins per proses seperti globals lain; None = perilaku default OS.
static SOURCE_IP: OnceLock<RwLock<Option<IpAddr>>> = OnceLock::new();

fn source_cell() -> &'static RwLock<Option<IpAddr>> {
    SOURCE_IP.get_or_init(|| RwLock::new(None))
}

/// Set IP sumber untuk semua socket egress baru (atau None = default).
pub fn set_source_ip(ip: Option<IpAddr>) {
    *source_cell().write().unwrap() = ip;
}

pub fn source_ip() -> Option<IpAddr> {
    *source_cell().read().unwrap()
}

/// Connect yang menghormati --source-ip. Tanpa override, identik dengan
/// TcpStream::connect biasa (tanpa overhead spawn_blocking).
pub async fn connect_bound(addr: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    match source_ip() {
        None => tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?,
        Some(src) => {
            let addr = addr.to_string();
            tokio::task::spawn_blocking(move || connect_from_blocking(&addr, src, timeout))
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("join: {}", e)))?
        }
    }
}

fn connect_from_blocking(addr: &str, src: IpAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let mut last_err = std::io::Error::new(std::io::ErrorKind::Other, "no compatible address");
    let src_v4 = src.is_ipv4();
    for a in addr.to_socket_addrs()? {
        if a.ip().is_ipv4() != src_v4 {
            continue; // keluarga harus cocok dengan source IP
        }
        let domain = if a.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
        let sock = match socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) {
            Ok(s) => s,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let _ = sock.set_reuse_address(true);
        if let Err(e) = sock.bind(&std::net::SocketAddr::new(src, 0).into()) {
            last_err = e;
            continue;
        }
        if let Err(e) = sock.connect_timeout(&a.into(), timeout) {
            last_err = e;
            continue;
        }
        let _ = sock.set_nonblocking(true);
        let std_stream: std::net::TcpStream = sock.into();
        return TcpStream::from_std(std_stream);
    }
    Err(last_err)
}

pub fn tune_tcp(stream: &TcpStream) {
    let sock_ref = SockRef::from(stream);
    let _ = sock_ref.set_tcp_nodelay(true);
    let _ = sock_ref.set_keepalive(true);
    let _ = sock_ref.set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(Duration::from_secs(15))
            .with_interval(Duration::from_secs(5))
            .with_retries(3)
    );
    let _ = sock_ref.set_recv_buffer_size(524_288);
    let _ = sock_ref.set_send_buffer_size(131_072);
}

pub async fn connect_optimized(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let stream = connect_bound(addr, timeout).await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                format!("Timeout connecting to {}", addr)
            } else {
                format!("Connect: {}", e)
            }
        })?;

    tune_tcp(&stream);
    Ok(stream)
}

/// Try to connect to a host by resolving all IPs and racing them.
/// Falls back to direct connect_optimized for efficiency.
pub async fn connect_race(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let addr_str = format!("{}:{}", host, port);
    connect_optimized(&addr_str, timeout).await
}

pub fn alloc_read_buf() -> Vec<u8> {
    vec![0u8; 131072]
}
