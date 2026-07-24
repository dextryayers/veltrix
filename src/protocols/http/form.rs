use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::core::credential::Credential;
use crate::core::target::Target;
use super::{HTTP_USERFIELD, HTTP_PASSFIELD, HTTP_SUCCESS};

pub async fn authenticate_form(
    reader: &mut (impl AsyncReadExt + Unpin),
    writer: &mut (impl AsyncWriteExt + Unpin),
    target: &Target,
    credential: &Credential,
) -> Result<bool, String> {
    let userfield = HTTP_USERFIELD.get().cloned().unwrap_or_else(|| "username".to_string());
    let passfield = HTTP_PASSFIELD.get().cloned().unwrap_or_else(|| "password".to_string());
    let success_str = HTTP_SUCCESS.get().cloned().unwrap_or_else(|| "success".to_string());

    let body = format!(
        "{}={}&{}={}",
        userfield, credential.username,
        passfield, credential.password
    );

    let request = format!(
        "POST /login HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        target.host, body.len(), body
    );

    writer.write_all(request.as_bytes()).await
        .map_err(|e| format!("Write: {}", e))?;
    writer.flush().await.map_err(|e| format!("Flush: {}", e))?;

    let mut response = Vec::new();
    reader.read_to_end(&mut response).await
        .map_err(|e| format!("Read: {}", e))?;
    let resp_str = String::from_utf8_lossy(&response);

    Ok(resp_str.to_lowercase().contains(&success_str.to_lowercase()))
}
