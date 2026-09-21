use std::time::{Duration, Instant};

pub struct RateLimiter {
    max_per_second: u64,
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(max_per_second: Option<u64>) -> Self {
        RateLimiter {
            max_per_second: max_per_second.unwrap_or(u64::MAX),
            tokens: max_per_second.unwrap_or(u64::MAX) as f64,
            last_update: Instant::now(),
        }
    }

    pub async fn wait_if_needed(&mut self) {
        if self.max_per_second == u64::MAX {
            return;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        let tokens_to_add = elapsed.as_secs_f64() * self.max_per_second as f64;
        self.tokens = (self.tokens + tokens_to_add).min(self.max_per_second as f64);
        self.last_update = now;

        if self.tokens < 1.0 {
            let wait_dur = Duration::from_secs_f64((1.0 - self.tokens) / self.max_per_second as f64);
            tokio::time::sleep(wait_dur).await;
            self.tokens = 0.0;
        } else {
            self.tokens -= 1.0;
        }
    }
}

pub struct JitterDelay {
    base_delay: Duration,
    jitter_ms: u64,
}
impl JitterDelay {
    pub fn new(base_delay: Duration, jitter_ms: u64) -> Self {
        JitterDelay { base_delay, jitter_ms }
    }

    pub async fn delay(&self) {
        if self.base_delay.is_zero() && self.jitter_ms == 0 {
            return;
        }
        let jitter = if self.jitter_ms > 0 {
            std::time::Duration::from_millis(rand_jitter(self.jitter_ms))
        } else {
            Duration::ZERO
        };
        tokio::time::sleep(self.base_delay + jitter).await;
    }
}

/// F4.1: throttle per-key (per-target / per-user).
/// Menjamin jeda minimum antar attempt untuk key yang sama.
/// Submission loop berjalan sekuensial sehingga DashMap tanpa lock tambahan aman.
pub struct KeyedThrottle {
    min_interval: Duration,
    last: dashmap::DashMap<String, Instant>,
}

impl KeyedThrottle {
    pub fn new(min_interval: Duration) -> Self {
        Self { min_interval, last: dashmap::DashMap::new() }
    }

    pub fn disabled() -> Self {
        Self::new(Duration::ZERO)
    }

    pub fn is_enabled(&self) -> bool {
        !self.min_interval.is_zero()
    }

    pub async fn wait(&self, key: &str) {
        if self.min_interval.is_zero() {
            return;
        }
        loop {
            let now = Instant::now();
            match self.last.entry(key.to_string()) {
                dashmap::mapref::entry::Entry::Occupied(mut e) => {
                    let elapsed = now.duration_since(*e.get());
                    if elapsed >= self.min_interval {
                        e.insert(now);
                        return;
                    }
                    let sleep_for = self.min_interval - elapsed;
                    drop(e);
                    tokio::time::sleep(sleep_for).await;
                }
                dashmap::mapref::entry::Entry::Vacant(e) => {
                    e.insert(now);
                    return;
                }
            }
        }
    }
}

/// F4.2: jeda antar spray round (satu password ke semua user = satu round).
/// Interval + jitter persen agar pola tidak mekanis dan terdeteksi.
pub struct SprayCadence {
    interval: Duration,
    jitter_pct: u8,
}

impl SprayCadence {
    pub fn new(interval: Duration, jitter_pct: u8) -> Self {
        Self { interval, jitter_pct: jitter_pct.min(100) }
    }

    pub fn disabled() -> Self {
        Self::new(Duration::ZERO, 0)
    }

    pub fn is_enabled(&self) -> bool {
        !self.interval.is_zero()
    }

    pub async fn wait_round(&self, round: u64) {
        if self.interval.is_zero() || round == 0 {
            return;
        }
        let base_ms = self.interval.as_millis() as u64;
        // Symmetric jitter: base +/- (base * pct / 100).
        let span = base_ms * self.jitter_pct as u64 / 100;
        let delta = if span == 0 {
            0i64
        } else {
            rand_jitter(span * 2) as i64 - span as i64
        };
        let actual = (base_ms as i64 + delta).max(1) as u64;
        log::info!(
            "Spray round {} complete, cooling down {:.1}s before next password",
            round,
            actual as f64 / 1000.0
        );
        tokio::time::sleep(Duration::from_millis(actual)).await;
    }
}

/// Parse durasi manusiawi: "500", "500ms", "10s", "30m", "2h".
/// Angka polos dianggap milidetik untuk --delay, detik untuk interval?
/// Di sini angka polos = milidetik agar konsisten dengan --delay.
pub fn parse_interval_ms(s: &str) -> Result<u64, String> {
    let t = s.trim().to_lowercase();
    if t.is_empty() {
        return Err("empty duration".into());
    }
    let (num_part, mult): (&str, u64) = if let Some(v) = t.strip_suffix("ms") {
        (v, 1)
    } else if let Some(v) = t.strip_suffix('h') {
        (v, 3_600_000)
    } else if let Some(v) = t.strip_suffix('m') {
        (v, 60_000)
    } else if let Some(v) = t.strip_suffix('s') {
        (v, 1_000)
    } else {
        (t.as_str(), 1)
    };
    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration '{}', use e.g. 500ms, 30s, 30m, 2h", s))?;
    Ok(n.saturating_mul(mult))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_unlimited() {
        let rl = RateLimiter::new(None);
        assert_eq!(rl.max_per_second, u64::MAX);
        assert_eq!(rl.tokens, u64::MAX as f64);
    }

    #[test]
    fn test_rate_limiter_with_limit() {
        let rl = RateLimiter::new(Some(10));
        assert_eq!(rl.max_per_second, 10);
        assert_eq!(rl.tokens, 10.0);
    }

    #[test]
    fn test_rate_limiter_initial_tokens() {
        let rl = RateLimiter::new(Some(100));
        assert!((rl.tokens - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jitter_delay_zero() {
        let jd = JitterDelay::new(Duration::ZERO, 0);
        assert!(jd.base_delay.is_zero());
        assert_eq!(jd.jitter_ms, 0);
    }

    #[test]
    fn test_jitter_delay_with_values() {
        let jd = JitterDelay::new(Duration::from_millis(500), 100);
        assert_eq!(jd.base_delay, Duration::from_millis(500));
        assert_eq!(jd.jitter_ms, 100);
    }

    #[test]
    fn test_parse_interval_ms() {
        assert_eq!(parse_interval_ms("500").unwrap(), 500);
        assert_eq!(parse_interval_ms("500ms").unwrap(), 500);
        assert_eq!(parse_interval_ms("10s").unwrap(), 10_000);
        assert_eq!(parse_interval_ms("30m").unwrap(), 1_800_000);
        assert_eq!(parse_interval_ms("2h").unwrap(), 7_200_000);
        assert_eq!(parse_interval_ms(" 5S ").unwrap(), 5_000);
        assert!(parse_interval_ms("abc").is_err());
        assert!(parse_interval_ms("").is_err());
    }

    #[tokio::test]
    async fn test_keyed_throttle_disabled_is_free() {
        let t = KeyedThrottle::disabled();
        assert!(!t.is_enabled());
        t.wait("anything").await;
    }

    #[tokio::test]
    async fn test_keyed_throttle_enforces_gap() {
        let t = KeyedThrottle::new(Duration::from_millis(50));
        t.wait("k").await;
        let start = Instant::now();
        t.wait("k").await;
        assert!(start.elapsed() >= Duration::from_millis(40));
        // Key lain tidak ikut antre.
        t.wait("other").await;
    }

    #[test]
    fn test_spray_cadence_disabled() {
        let s = SprayCadence::disabled();
        assert!(!s.is_enabled());
    }
}

fn rand_jitter(max_ms: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos % (max_ms as u128 + 1)) as u64
}
