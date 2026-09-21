use std::time::Instant;

/// Metrik ringan untuk Fase 1: EMA rate, latensi kasar, dan rasio timeout.
/// Tidak memakai lock, cukup dipanggil dari loop orchestrator.
#[derive(Debug)]
pub struct AttackMetrics {
    start: Instant,
    attempts: u64,
    successes: u64,
    timeouts: u64,
    errors: u64,
    ema_rate: f64,
    last_tick: Instant,
    last_count: u64,
    lat_samples_ms: Vec<u64>,
}

impl AttackMetrics {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            attempts: 0,
            successes: 0,
            timeouts: 0,
            errors: 0,
            ema_rate: 0.0,
            last_tick: now,
            last_count: 0,
            lat_samples_ms: Vec::with_capacity(128),
        }
    }

    pub fn record_attempt(&mut self, duration_ms: u64, success: bool, timeout: bool, error: bool) {
        self.attempts += 1;
        if success {
            self.successes += 1;
        }
        if timeout {
            self.timeouts += 1;
        }
        if error {
            self.errors += 1;
        }
        if self.lat_samples_ms.len() < 128 {
            self.lat_samples_ms.push(duration_ms);
        } else {
            // Reservoir sederhana: ganti slot round-robin agar p50 tetap segar.
            let idx = (self.attempts as usize) % 128;
            self.lat_samples_ms[idx] = duration_ms;
        }
        self.tick_rate();
    }

    fn tick_rate(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f64();
        if dt >= 1.0 {
            let delta = self.attempts.saturating_sub(self.last_count) as f64;
            let instant = delta / dt;
            if self.ema_rate == 0.0 {
                self.ema_rate = instant;
            } else {
                self.ema_rate = self.ema_rate * 0.7 + instant * 0.3;
            }
            self.last_tick = now;
            self.last_count = self.attempts;
        }
    }

    pub fn rate_per_sec(&self) -> f64 {
        if self.ema_rate > 0.0 {
            return self.ema_rate;
        }
        let dt = self.start.elapsed().as_secs_f64().max(0.001);
        self.attempts as f64 / dt
    }

    pub fn timeout_ratio(&self) -> f64 {
        if self.attempts == 0 {
            return 0.0;
        }
        self.timeouts as f64 / self.attempts as f64
    }

    /// Rekomendasi adaptif sederhana untuk orchestrator.
    /// - Naikkan batch saat timeout rendah dan rate stabil.
    /// - Turunkan batch saat timeout tinggi agar tidak overload.
    pub fn suggested_batch(&self, current: usize) -> usize {
        let r = self.timeout_ratio();
        if r > 0.3 {
            (current / 2).max(64)
        } else if r > 0.15 {
            ((current as f64 * 0.75) as usize).max(64)
        } else if r < 0.02 && self.attempts > 1_000 {
            (current + 128).min(2048)
        } else {
            current
        }
    }

    pub fn p50_ms(&self) -> u64 {
        percentile(&self.lat_samples_ms, 50)
    }

    pub fn summary_line(&self) -> String {
        format!(
            "{} attempts, {:.1}/s, p50 {}ms, timeout {:.1}%",
            self.attempts,
            self.rate_per_sec(),
            self.p50_ms(),
            self.timeout_ratio() * 100.0
        )
    }
}

impl Default for AttackMetrics {
    fn default() -> Self {
        Self::new()
    }
}

fn percentile(samples: &[u64], p: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    let idx = ((p as f64 / 100.0) * v.len() as f64) as usize;
    v[idx.min(v.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_counts() {
        let mut m = AttackMetrics::new();
        m.record_attempt(100, true, false, false);
        m.record_attempt(200, false, true, true);
        assert_eq!(m.attempts, 2);
        assert!((m.timeout_ratio() - 0.5).abs() < 0.01);
    }

    #[test]
    fn batch_shrinks_on_timeout_storm() {
        let mut m = AttackMetrics::new();
        for _ in 0..100 {
            m.record_attempt(5000, false, true, true);
        }
        assert!(m.suggested_batch(512) < 512);
    }

    #[test]
    fn percentile_math() {
        assert_eq!(percentile(&[10, 20, 30, 40], 50), 30);
        assert_eq!(percentile(&[], 50), 0);
    }
}
