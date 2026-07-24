use sha1::{Sha1, Digest};
use base64::Engine;

pub fn parse_digest_challenge(www_auth: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();
    if let Some(stripped) = www_auth.strip_prefix("Digest ") {
        for part in stripped.split(',') {
            if let Some(eq) = part.find('=') {
                let key = part[..eq].trim().to_string();
                let value = part[eq + 1..].trim().trim_matches('"').to_string();
                params.push((key, value));
            }
        }
    }
    params
}

pub fn calculate_digest_response(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    let ha1 = format!("{:x}", Sha1::digest(format!("{}:{}:{}", username, realm, password).as_bytes()));
    let ha2 = format!("{:x}", Sha1::digest(format!("{}:{}", method, uri).as_bytes()));
    format!("{:x}", Sha1::digest(format!("{}:{}:{}", ha1, nonce, ha2).as_bytes()))
}
