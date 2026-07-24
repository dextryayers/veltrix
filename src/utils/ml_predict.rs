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
}
