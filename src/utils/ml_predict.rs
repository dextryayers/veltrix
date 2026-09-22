use std::collections::HashMap;

pub struct MarkovChain {
    order: usize,
    transitions: HashMap<String, HashMap<char, usize>>,
    total: usize,
    rng: fastrand::Rng,
}

impl MarkovChain {
    pub fn new(order: usize) -> Self {
        Self {
            order,
            transitions: HashMap::new(),
            total: 0,
            rng: fastrand::Rng::new(),
        }
    }

    pub fn train(&mut self, passwords: &[String]) {
        for pwd in passwords {
            let s = format!("^{}", pwd);
            for i in 0..s.len().saturating_sub(self.order) {
                let key = s[i..i + self.order].to_string();
                let next = s.chars().nth(i + self.order).unwrap_or('$');
                self.transitions.entry(key).or_default().entry(next).and_modify(|c| *c += 1).or_insert(1);
                self.total += 1;
            }
            let key = s[s.len().saturating_sub(self.order)..].to_string();
            self.transitions.entry(key).or_default().entry('$').and_modify(|c| *c += 1).or_insert(1);
            self.total += 1;
        }
    }

    fn pick_char(&mut self, key: &str) -> Option<char> {
        let probs = self.transitions.get(key)?;
        let total: usize = probs.values().sum();
        if total == 0 {
            return None;
        }
        let roll: usize = self.rng.usize(0..total);
        let mut cum = 0;
        for (ch, count) in probs {
            cum += count;
            if roll < cum {
                return Some(*ch);
            }
        }
        None
    }

    pub fn generate(&mut self, max_len: usize) -> String {
        let mut result = String::new();
        let mut key = "^".repeat(self.order);

        for _ in 0..max_len {
            match self.pick_char(&key) {
                Some('$') | None => break,
                Some(c) => {
                    result.push(c);
                    key.push(c);
                    key = key[key.len().saturating_sub(self.order)..].to_string();
                }
            }
        }
        result
    }

    pub fn generate_many(&mut self, count: usize, max_len: usize) -> Vec<String> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.generate(max_len));
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn complexity_score(&self, password: &str) -> f64 {
        if password.len() < 4 {
            return 0.0;
        }
        let s = format!("^{}", password);
        let mut log_prob = 0.0f64;
        for i in 0..s.len().saturating_sub(self.order) {
            let key = s[i..i + self.order].to_string();
            let next = s.chars().nth(i + self.order).unwrap_or('$');
            if let Some(probs) = self.transitions.get(&key) {
                let total: usize = probs.values().sum();
                let count = probs.get(&next).copied().unwrap_or(1);
                log_prob += (count as f64 / total as f64).ln();
            } else {
                log_prob += (1.0f64 / self.total.max(1) as f64).ln();
            }
        }
        -log_prob
    }

    /// F8.3: ranking probable-first. Skor rendah = mirip distribusi training =
    /// dicoba lebih dulu. Deterministik (tanpa RNG) sehingga reproducible.
    /// Mengembalikan (password, skor) terurut menaik; `top` memotong hasil.
    pub fn rank(&self, passwords: &[String], top: Option<usize>) -> Vec<(String, f64)> {
        let mut scored: Vec<(String, f64)> = passwords
            .iter()
            .map(|p| (p.clone(), self.complexity_score(p)))
            .collect();
        scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        if let Some(n) = top {
            scored.truncate(n);
        }
        scored
    }

    /// F8.4: precision@K deterministik. `ranked` harus sudah terurut oleh rank(),
    /// `relevant` adalah himpunan password yang dianggap hit (mis. held-out).
    pub fn precision_at_k(ranked: &[(String, f64)], relevant: &std::collections::HashSet<String>, k: usize) -> f64 {
        if k == 0 || ranked.is_empty() {
            return 0.0;
        }
        let n = k.min(ranked.len());
        let hits = ranked.iter().take(n).filter(|(p, _)| relevant.contains(p)).count();
        hits as f64 / n as f64
    }
}

/// F8.4: parse daftar K dari `--k "10,20,50"`. Non-angka dilewati dengan
/// warning string; kosong total = error.
pub fn parse_k_list(s: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<usize>() {
            Ok(n) if n > 0 => out.push(n),
            _ => bad.push(t.to_string()),
        }
    }
    if out.is_empty() {
        return Err(format!("--k '{}' tidak menghasilkan nilai K valid (contoh: 10,20,50)", s));
    }
    if !bad.is_empty() {
        log::warn!("eval: skipping invalid K values: {:?}", bad);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// F8.4: parse isi file ranked untuk `wordlist eval`.
/// Baris didukung: `pass<TAB>skor` (output rank), `pass: skor` (output
/// --ml-score), atau `pass` polos (skor 0). Baris kosong dilewati.
pub fn parse_ranked_lines(raw: &str) -> Vec<(String, f64)> {
    let mut ranked = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (p, s) = if let Some((a, b)) = line.split_once('\t') {
            (a.trim(), b.trim().split_whitespace().next().unwrap_or("0"))
        } else if let Some((a, b)) = line.split_once(':') {
            (a.trim(), b.trim().split_whitespace().next().unwrap_or("0"))
        } else {
            (line, "0")
        };
        if p.is_empty() {
            continue;
        }
        ranked.push((p.to_string(), s.parse::<f64>().unwrap_or(0.0)));
    }
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn train_family() -> MarkovChain {
        // Keluarga "adminNN": pola digit-akhir yang kuat.
        let train: Vec<String> = (0..50).map(|i| format!("admin{:02}", i)).collect();
        let mut mc = MarkovChain::new(3);
        mc.train(&train);
        mc
    }

    #[test]
    fn rank_puts_family_first() {
        let mc = train_family();
        let candidates: Vec<String> = vec![
            "xqzt!kvv".into(), "admin07".into(), "zzz#qqq".into(), "admin42".into(),
        ];
        let ranked = mc.rank(&candidates, None);
        assert_eq!(ranked.len(), 4);
        // Skor terurut menaik.
        for w in ranked.windows(2) {
            assert!(w[0].1 <= w[1].1);
        }
        // Anggota keluarga di 2 teratas.
        let top2: Vec<&str> = ranked.iter().take(2).map(|(p, _)| p.as_str()).collect();
        assert!(top2.contains(&"admin07"));
        assert!(top2.contains(&"admin42"));
    }

    #[test]
    fn rank_top_truncates() {
        let mc = train_family();
        let cands: Vec<String> = (0..100).map(|i| format!("cand{}", i)).collect();
        assert_eq!(mc.rank(&cands, Some(10)).len(), 10);
        assert_eq!(mc.rank(&cands, None).len(), 100);
    }

    #[test]
    fn precision_at_k_family_vs_junk() {
        let mc = train_family();
        // 10 held-out keluarga + 90 junk acak deterministik.
        let mut candidates: Vec<String> =
            (50..60).map(|i| format!("admin{:02}", i)).collect();
        let mut seed: u64 = 0x12345678;
        let mut next_rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..90 {
            let s: String = (0..8)
                .map(|_| (b'a' + (next_rnd() % 26) as u8) as char)
                .collect();
            candidates.push(s);
        }
        // Kocok deterministik agar urutan input tidak membantu.
        for i in (1..candidates.len()).rev() {
            let j = (next_rnd() as usize) % (i + 1);
            candidates.swap(i, j);
        }
        let relevant: HashSet<String> =
            (50..60).map(|i| format!("admin{:02}", i)).collect();
        let ranked = mc.rank(&candidates, None);
        let p10 = MarkovChain::precision_at_k(&ranked, &relevant, 10);
        let p20 = MarkovChain::precision_at_k(&ranked, &relevant, 20);
        // Keluarga harus mendominasi puncak ranking.
        assert!(p10 >= 0.8, "precision@10 = {}", p10);
        assert!(p20 >= 0.4, "precision@20 = {}", p20);
    }

    #[test]
    fn precision_at_k_edge_cases() {
        let empty: Vec<(String, f64)> = vec![];
        let rel: HashSet<String> = HashSet::new();
        assert_eq!(MarkovChain::precision_at_k(&empty, &rel, 10), 0.0);
        assert_eq!(MarkovChain::precision_at_k(&[("a".into(), 1.0)], &rel, 0), 0.0);
    }

    #[test]
    fn complexity_score_deterministic() {
        let mc = train_family();
        assert_eq!(mc.complexity_score("admin01"), mc.complexity_score("admin01"));
        assert!(mc.complexity_score("admin01") < mc.complexity_score("xqzt!kvv9"));
    }

    #[test]
    fn parse_k_list_ok_and_sorted_dedup() {
        assert_eq!(parse_k_list("10,20,50").unwrap(), vec![10, 20, 50]);
        assert_eq!(parse_k_list("50, 10,10,20 ").unwrap(), vec![10, 20, 50]);
    }

    #[test]
    fn parse_k_list_rejects_garbage() {
        assert!(parse_k_list("").is_err());
        assert!(parse_k_list("0,abc").is_err());
        // Campuran valid + sampah: valid lolos.
        assert_eq!(parse_k_list("10,abc,20").unwrap(), vec![10, 20]);
    }

    #[test]
    fn parse_ranked_lines_all_formats() {
        let raw = "admin07\t9.61\nadmin08: 10.2\nplainpass\n\n:5\n";
        let r = parse_ranked_lines(raw);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].0, "admin07");
        assert!((r[0].1 - 9.61).abs() < 1e-9);
        assert_eq!(r[1].0, "admin08");
        assert_eq!(r[2], ("plainpass".to_string(), 0.0));
    }
}
