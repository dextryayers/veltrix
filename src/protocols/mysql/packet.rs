use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub async fn read_packet(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await
        .map_err(|e| format!("Read header: {}", e))?;
    let len = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await
            .map_err(|e| format!("Read payload: {}", e))?;
    }
    Ok(payload)
}
