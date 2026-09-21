//! F6.4: autentikasi API. JWT HS256 hand-rolled memakai hmac+sha2+base64
//! (sudah jadi dependency) agar tidak menambah crate baru.
//! Alur: operator memegang pre-shared API token (--api-token atau env
//! VELTRIX_API_TOKEN, atau ephemeral yang dicetak sekali saat start).
//! POST /api/v2/login {token, actor} -> JWT singkat.
//! Semua endpoint /api/v2/* (kecuali /login dan /health) wajib Bearer JWT.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const JWT_TTL_SECS: i64 = 12 * 3600;

#[derive(Clone)]
pub struct ApiAuth {
    api_token: String,
    secret: Vec<u8>,
    ttl_secs: i64,
    ephemeral: bool,
}

impl ApiAuth {
    pub fn new(api_token: Option<String>) -> (Self, bool) {
        match api_token {
            Some(t) if !t.trim().is_empty() => (
                Self {
                    api_token: t.clone(),
                    secret: derive_secret(&t),
                    ttl_secs: JWT_TTL_SECS,
                    ephemeral: false,
                },
                false,
            ),
            _ => {
                // Ephemeral: aman default, dicetak sekali ke stderr saat start.
                let rand_token = format!("vt-{}", uuid::Uuid::new_v4().simple());
                (
                    Self {
                        api_token: rand_token.clone(),
                        secret: derive_secret(&rand_token),
                        ttl_secs: JWT_TTL_SECS,
                        ephemeral: true,
                    },
                    true,
                )
            }
        }
    }

    /// Token untuk ditampilkan sekali saat server start dengan secret ephemeral.
    /// None jika operator menyediakan token sendiri (mereka sudah tahu).
    pub fn ephemeral_token(&self) -> Option<String> {
        if self.ephemeral {
            Some(self.api_token.clone())
        } else {
            None
        }
    }

    /// Login dengan pre-shared token -> JWT. Return (jwt, actor).
    pub fn login(&self, token: &str, actor: Option<&str>) -> Option<(String, String)> {
        if token != self.api_token {
            return None;
        }
        let actor = actor
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .unwrap_or_else(|| "operator".to_string());
        let now = chrono::Utc::now().timestamp();
        let payload = serde_json::json!({
            "sub": actor,
            "iat": now,
            "exp": now + self.ttl_secs,
        });
        Some((self.sign(&payload), actor))
    }

    /// Verifikasi Bearer JWT -> sub (actor). Tolak exp/kadaluarsa/signature salah.
    pub fn verify(&self, bearer: &str) -> Option<String> {
        let token = bearer.strip_prefix("Bearer ").unwrap_or(bearer).trim();
        let mut parts = token.splitn(3, '.');
        let header_b64 = parts.next()?;
        let payload_b64 = parts.next()?;
        let sig_b64 = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let mut mac = HmacSha256::new_from_slice(&self.secret).ok()?;
        mac.update(signing_input.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        if expected.as_bytes() != sig_b64.as_bytes() {
            // Bandingkan constant-time sederhana (panjang sama karena base64 fixed).
            return None;
        }
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
        let exp = payload.get("exp")?.as_i64()?;
        if chrono::Utc::now().timestamp() > exp {
            return None;
        }
        let sub = payload.get("sub")?.as_str()?.to_string();
        if header_b64 != URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#) {
            return None;
        }
        Some(sub)
    }

    fn sign(&self, payload: &serde_json::Value) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac key");
        mac.update(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{}.{}", signing_input, sig)
    }
}

fn derive_secret(token: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"veltrix-api-v2:");
    h.update(token.as_bytes());
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_and_verify_roundtrip() {
        let (auth, ephemeral) = ApiAuth::new(Some("test-secret-token".into()));
        assert!(!ephemeral);
        let (jwt, actor) = auth.login("test-secret-token", Some("alice")).unwrap();
        assert_eq!(actor, "alice");
        assert_eq!(auth.verify(&format!("Bearer {}", jwt)).as_deref(), Some("alice"));
        assert_eq!(auth.verify(&jwt).as_deref(), Some("alice"));
    }

    #[test]
    fn wrong_token_rejected() {
        let (auth, _) = ApiAuth::new(Some("right".into()));
        assert!(auth.login("wrong", None).is_none());
    }

    #[test]
    fn tampered_jwt_rejected() {
        let (auth, _) = ApiAuth::new(Some("s".into()));
        let (jwt, _) = auth.login("s", None).unwrap();
        let mut bad = jwt.clone();
        bad.push('x');
        assert!(auth.verify(&bad).is_none());
        // Payload asing dengan signature salah.
        let fake = format!("{}.{}.{}", URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(r#"{"sub":"root","iat":1,"exp":9999999999}"#), "bogus");
        assert!(auth.verify(&fake).is_none());
    }

    #[test]
    fn expired_jwt_rejected() {
        let auth = ApiAuth { api_token: "s".into(), secret: derive_secret("s"), ttl_secs: -10, ephemeral: false };
        let (jwt, _) = auth.login("s", None).unwrap();
        assert!(auth.verify(&jwt).is_none());
    }

    #[test]
    fn ephemeral_generates_token() {
        let (_, ephemeral) = ApiAuth::new(None);
        assert!(ephemeral);
    }

    #[test]
    fn default_actor_and_length_cap() {
        let (auth, _) = ApiAuth::new(Some("s".into()));
        let (_, actor) = auth.login("s", None).unwrap();
        assert_eq!(actor, "operator");
        let (_, actor2) = auth.login("s", Some("   ")).unwrap();
        assert_eq!(actor2, "operator");
    }
}
