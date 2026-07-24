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
}

fn rand_jitter(max_ms: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos % (max_ms as u128 + 1)) as u64
}
