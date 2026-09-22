use std::time::Duration;

/// Rencana attack yang dihitung tanpa menjalankan network I/O.
/// Dipakai untuk `--dry-run` dan progress adaptif.
#[derive(Debug, Clone)]
pub struct AttackPlan {
    pub targets: usize,
    pub credentials: u64,
    pub total: u64,
    pub threads: usize,
    pub timeout: Duration,
    pub rate_limit: Option<u64>,
    pub batch_size: usize,
    pub estimated_seconds: Option<f64>,
    /// Catatan operator, mis. ringkasan ekspansi --rule (F8.1).
    pub note: String,
}

impl AttackPlan {
    pub fn new(
        targets: usize,
        credentials: u64,
        threads: usize,
        timeout: Duration,
        rate_limit: Option<u64>,
    ) -> Self {
        let total = targets as u64 * credentials;
        let batch_size = default_batch_size(total, threads);
        let estimated_seconds = estimate_seconds(total, threads, rate_limit, timeout);
        Self {
            targets,
            credentials,
            total,
            threads,
            timeout,
            rate_limit,
            batch_size,
            estimated_seconds,
            note: String::new(),
        }
    }

    /// Tambah catatan satu baris untuk dry-run (builder style).
    pub fn with_note(mut self, note: String) -> Self {
        self.note = note;
        self
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Targets: {} | Credentials: {} | Total: {}\n",
            self.targets, self.credentials, self.total
        ));
        out.push_str(&format!(
            "Threads: {} | Batch: {} | Timeout: {:?}",
            self.threads, self.batch_size, self.timeout
        ));
        if let Some(r) = self.rate_limit {
            out.push_str(&format!(" | Rate: {}/s", r));
        }
        if let Some(s) = self.estimated_seconds {
            out.push_str(&format!("\nEstimated: {:.1}s ({:.1} min)", s, s / 60.0));
        } else {
            out.push_str("\nEstimated: unknown (no rate info)");
        }
        if self.total > 1_000_000 {
            out.push_str("\nWarning: >1M combinations. Consider --dry-run review, resume file, and safe rate limits.");
        }
        if !self.note.is_empty() {
            out.push_str(&format!("\nRules: {}", self.note));
        }
        out
    }
}

fn default_batch_size(total: u64, threads: usize) -> usize {
    if total < 1_000 {
        64
    } else if total < 100_000 {
        256
    } else {
        // Batch lebih besar untuk run raksasa agar channel tidak jadi bottleneck,
        // tapi tetap dibatasi agar memori stabil.
        (threads * 16).clamp(256, 2048)
    }
}

fn estimate_seconds(
    total: u64,
    threads: usize,
    rate_limit: Option<u64>,
    timeout: Duration,
) -> Option<f64> {
    if total == 0 || threads == 0 {
        return Some(0.0);
    }
    // Jika ada rate limit global, itu yang dominan.
    if let Some(r) = rate_limit {
        if r > 0 {
            return Some(total as f64 / r as f64);
        }
    }
    // Tanpa rate limit, estimasi optimis: asumsikan tiap worker butuh
    // sekitar 10% dari timeout sebagai waktu rata-rata per attempt di lab.
    // Ini hanya estimasi, bukan janji.
    let avg = (timeout.as_secs_f64() * 0.1).max(0.05);
    Some(total as f64 * avg / threads as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_total_math() {
        let p = AttackPlan::new(10, 100, 10, Duration::from_secs(10), None);
        assert_eq!(p.total, 1_000);
    }

    #[test]
    fn plan_rate_estimate() {
        let p = AttackPlan::new(1, 100, 10, Duration::from_secs(10), Some(10));
        assert_eq!(p.estimated_seconds, Some(10.0));
    }

    #[test]
    fn plan_batch_scales() {
        let small = AttackPlan::new(1, 10, 10, Duration::from_secs(5), None);
        let big = AttackPlan::new(100, 100_000, 50, Duration::from_secs(5), None);
        assert!(big.batch_size >= small.batch_size);
    }

    #[test]
    fn plan_note_renders_rules_line() {
        let p = AttackPlan::new(1, 10, 10, Duration::from_secs(5), None)
            .with_note("2 rule(s) expand 3 base -> 33 estimated (cap 500)".into());
        assert!(p.render().contains("Rules: 2 rule(s)"));
        let plain = AttackPlan::new(1, 10, 10, Duration::from_secs(5), None);
        assert!(!plain.render().contains("Rules:"));
    }
}
