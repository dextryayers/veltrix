use async_trait::async_trait;
use std::time::{Duration, Instant};
use mysql_async::prelude::*;
use mysql_async::{OptsBuilder, SslOpts};

use crate::core::credential::Credential;
use crate::core::result::AuthResult;
use crate::core::target::Target;
use crate::proxy::ProxyConfig;
use super::Protocol;

pub struct MySqlProtocol;

#[async_trait]
impl Protocol for MySqlProtocol {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn default_port(&self) -> u16 {
        3306
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_dur: Duration,
        _proxy: &Option<ProxyConfig>,
    ) -> AuthResult {
        let start = Instant::now();

        let opts = OptsBuilder::default()
            .ip_or_hostname(target.host.clone())
            .tcp_port(target.port)
            .user(Some(credential.username.clone()))
            .pass(Some(credential.password.clone()))
            .ssl_opts(SslOpts::default().with_danger_skip_domain_validation(true));

        match tokio::time::timeout(timeout_dur, async {
            let pool = mysql_async::Pool::new(opts);
            let conn = pool.get_conn().await;
            match conn {
                Ok(mut c) => {
                    let _ = c.query_drop("SELECT 1").await;
                    let _ = pool.disconnect().await;
                    AuthResult::new(
                        target.host.clone(), target.port, "mysql",
                        credential.username.clone(), credential.password.clone(),
                        true, start.elapsed(), None,
                    )
                }
                Err(e) => {
                    let _ = pool.disconnect().await;
                    let err_str = e.to_string();
                    let is_auth = err_str.contains("Access denied") || err_str.contains("1045")
                        || err_str.contains("password") || err_str.contains("auth");
                    AuthResult::new(
                        target.host.clone(), target.port, "mysql",
                        credential.username.clone(), credential.password.clone(),
                        false, start.elapsed(),
                        if is_auth { None } else { Some(err_str) },
                    )
                }
            }
        }).await {
            Ok(r) => r,
            Err(_) => AuthResult::new(
                target.host.clone(), target.port, "mysql",
                credential.username.clone(), credential.password.clone(),
                false, start.elapsed(), Some("Timeout".into()),
            ),
        }
    }
}
