pub mod banner;
pub mod scanner;
pub mod service_db;

pub use scanner::Scanner;
pub use banner::BannerGrabber;
pub use service_db::ServiceDb;

use std::fmt;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub open: bool,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub latency_ms: u64,
}

impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.open {
            write!(
                f,
                "{:21} {}/open {}{}{}",
                self.host,
                self.port,
                self.service,
                self.product.as_ref().map(|p| format!(" {}", p)).unwrap_or_default(),
                self.version.as_ref().map(|v| format!(" {}", v)).unwrap_or_default(),
            )
        } else {
            write!(f, "{:21} {}/filtered", self.host, self.port)
        }
    }
}
