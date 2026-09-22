use std::path::Path;

/// Rule engine v2 (F8.1).
///
/// Sintaks per baris (token dipisah spasi, `#` mulai komentar):
/// - `$n`   append angka 0..=n, mis. `$99` -> pass0..pass99
/// - `^n`   prepend angka 0..=n
/// - `@str` append string literal, mis. `@123`, `@!`
/// - `!str` prepend string literal
/// - `~m`   case: 0 lower, 1 UPPER, 2 Title
/// - `&a:b` leet: ganti char a menjadi b
/// - `D`    duplicate: kata + kata (pass -> passpass)
/// - `R`    reverse: balik kata (pass -> ssap)
/// - `Tn`   truncate ke n char pertama (pass123 -> pass, dengan T4)
///
/// Ekspansi dibatasi `max_mutations` global (lihat apply_rules) dan
/// `dry_count` memberi estimasi akurat sebelum eksekusi.
#[derive(Debug, Clone)]
pub enum RuleOp {
    AppendNumber(u64),
    PrependNumber(u64),
    AppendString(String),
    PrependString(String),
    Capitalize(u8),
    LeetSpeak { from: char, to: char },
    Duplicate,
    Reverse,
    Truncate(usize),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub ops: Vec<RuleOp>,
}

impl Rule {
    pub fn apply(&self, word: &str) -> Vec<String> {
        let mut results = vec![word.to_string()];
        for op in &self.ops {
            results = apply_op(&results, op);
        }
        results
    }
}

fn apply_op(words: &[String], op: &RuleOp) -> Vec<String> {
    match op {
        RuleOp::AppendNumber(n) => {
            words.iter().flat_map(|w| {
                (0..=*n).map(|i| format!("{}{}", w, i)).collect::<Vec<_>>()
            }).collect()
        }
        RuleOp::PrependNumber(n) => {
            words.iter().flat_map(|w| {
                (0..=*n).map(|i| format!("{}{}", i, w)).collect::<Vec<_>>()
            }).collect()
        }
        RuleOp::AppendString(s) => {
            words.iter().map(|w| format!("{}{}", w, s)).collect()
        }
        RuleOp::PrependString(s) => {
            words.iter().map(|w| format!("{}{}", s, w)).collect()
        }
        RuleOp::Capitalize(mode) => {
            words.iter().map(|w| match mode {
                0 => w.to_lowercase(),
                1 => w.to_uppercase(),
                2 => {
                    let mut c = w.chars();
                    match c.next() {
                        Some(f) => f.to_uppercase().to_string() + c.as_str(),
                        None => w.clone(),
                    }
                }
                _ => w.clone(),
            }).collect()
        }
        RuleOp::LeetSpeak { from, to } => {
            words.iter().map(|w| w.replace(*from, to.to_string().as_str())).collect()
        }
        RuleOp::Duplicate => {
            words.iter().map(|w| format!("{}{}", w, w)).collect()
        }
        RuleOp::Reverse => {
            words.iter().map(|w| w.chars().rev().collect()).collect()
        }
        RuleOp::Truncate(n) => {
            words.iter().map(|w| w.chars().take(*n).collect()).collect()
        }
    }
}

/// Faktor ekspansi satu op per kata input (untuk dry count).
/// Append/PrependNumber(n) -> n+1, lainnya -> 1.
pub fn op_factor(op: &RuleOp) -> u64 {
    match op {
        RuleOp::AppendNumber(n) | RuleOp::PrependNumber(n) => n.saturating_add(1),
        _ => 1,
    }
}

pub fn parse_rule_line(line: &str) -> Option<Rule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut ops = Vec::new();
    for token in line.split_whitespace() {
        if token.is_empty() || token.starts_with('#') {
            break;
        }
        if let Some(op) = parse_token(token) {
            ops.push(op);
        }
    }

    if ops.is_empty() { None } else { Some(Rule { ops }) }
}

fn parse_token(token: &str) -> Option<RuleOp> {
    if token.is_empty() {
        return None;
    }
    let (op_type, arg) = token.split_at(1);
    match op_type {
        "$" => arg.parse::<u64>().ok().map(RuleOp::AppendNumber),
        "^" => arg.parse::<u64>().ok().map(RuleOp::PrependNumber),
        "@" if !arg.is_empty() => Some(RuleOp::AppendString(arg.to_string())),
        "!" if !arg.is_empty() => Some(RuleOp::PrependString(arg.to_string())),
        "~" => arg.parse::<u8>().ok().map(RuleOp::Capitalize),
        "&" => {
            let parts: Vec<&str> = arg.splitn(2, ':').collect();
            if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                let from = parts[0].chars().next().unwrap();
                let to = parts[1].chars().next().unwrap();
                Some(RuleOp::LeetSpeak { from, to })
            } else {
                None
            }
        }
        "D" if arg.is_empty() => Some(RuleOp::Duplicate),
        "R" if arg.is_empty() => Some(RuleOp::Reverse),
        "T" => arg.parse::<usize>().ok().filter(|&n| n > 0).map(RuleOp::Truncate),
        _ => None,
    }
}

pub fn load_rules(path: &Path) -> Result<Vec<Rule>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file: {}", e))?;
    let mut rules = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match parse_rule_line(t) {
            Some(rule) => {
                // Guard pro: `$2024` = 2025 mutasi, hampir pasti maksudnya
                // literal `@2024`. Jangan gagal, tapi beri tahu operator.
                for op in &rule.ops {
                    if let RuleOp::AppendNumber(n) | RuleOp::PrependNumber(n) = op {
                        if *n > 366 {
                            log::warn!(
                                "rules: range ${} expands to {} mutations per word; \
                                 if you meant literal \"{}\", use @{}$ instead",
                                n,
                                n + 1,
                                n,
                                n
                            );
                            break;
                        }
                    }
                }
                rules.push(rule);
            }
            None => {
                skipped += 1;
                log::warn!("rules: skipping unparsable line: {:?}", t);
            }
        }
    }
    if skipped > 0 {
        log::warn!("rules: {} invalid line(s) skipped in {}", skipped, path.display());
    }
    Ok(rules)
}

pub fn apply_rules(base_words: &[String], rules: &[Rule], max_mutations: usize) -> Vec<String> {
    if max_mutations == 0 {
        return Vec::new();
    }
    if rules.is_empty() {
        let mut out = base_words.to_vec();
        out.truncate(max_mutations);
        return out;
    }
    // Rantai mutasi sekuensial (replace) seperti sebelumnya...
    let mut chained: Vec<String> = base_words.to_vec();
    for rule in rules {
        let mut new_words: Vec<String> = Vec::new();
        for word in &chained {
            let mutations = rule.apply(word);
            new_words.extend(mutations);
            if new_words.len() >= max_mutations {
                new_words.truncate(max_mutations);
                break;
            }
        }
        chained = new_words;
        if chained.len() >= max_mutations {
            chained.truncate(max_mutations);
            break;
        }
    }
    // ...tapi kata dasar SELALU dipertahankan paling depan (paling probable).
    // Tanpa ini, password mentah tidak pernah dicoba saat --rule dipakai.
    let mut seen = std::collections::HashSet::with_capacity(base_words.len() + chained.len());
    let mut result = Vec::with_capacity(max_mutations.min(base_words.len() + chained.len()));
    for w in base_words.iter().chain(chained.iter()) {
        if seen.insert(w.as_str()) {
            result.push(w.clone());
            if result.len() >= max_mutations {
                break;
            }
        }
    }
    result
}

/// Estimasi akurat jumlah mutasi TANPA ekspansi (F8.1 dry count).
/// Model: base dipertahankan + rantai replace per aturan, dipotong
/// max_mutations — sama persis dengan batas yang dipakai apply_rules.
/// Eksak bila tidak ada tabrakan string (kasus umum); bila ada tabrakan,
/// estimasi sedikit di atas aktual (aman untuk perencanaan, tidak undercount).
pub fn dry_count_rules(base_count: usize, rules: &[Rule], max_mutations: usize) -> usize {
    if max_mutations == 0 {
        return 0;
    }
    if rules.is_empty() {
        return base_count.min(max_mutations);
    }
    let mut chained = base_count as u64;
    for rule in rules {
        // fold saturating: product() polos bisa overflow-panic di debug
        // untuk baris seperti `$99999 $99999`.
        let factor: u64 = rule.ops.iter().map(op_factor).fold(1u64, |a, b| a.saturating_mul(b));
        chained = chained.saturating_mul(factor).min(max_mutations as u64);
        if chained >= max_mutations as u64 {
            break;
        }
    }
    // Union base + chained (asumsi tanpa tabrakan), dipotong cap.
    (base_count as u64 + chained).min(max_mutations as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_number() {
        let r = Rule { ops: vec![RuleOp::AppendNumber(3)] };
        let res = r.apply("pass");
        assert_eq!(res.len(), 4);
        assert!(res.contains(&"pass0".into()));
        assert!(res.contains(&"pass3".into()));
    }

    #[test]
    fn test_prepend_number() {
        let r = Rule { ops: vec![RuleOp::PrependNumber(2)] };
        let res = r.apply("pass");
        assert_eq!(res.len(), 3);
        assert!(res.contains(&"0pass".into()));
    }

    #[test]
    fn test_append_string() {
        let r = Rule { ops: vec![RuleOp::AppendString("123".into())] };
        let res = r.apply("pass");
        assert_eq!(res, vec!["pass123"]);
    }

    #[test]
    fn test_prepend_string() {
        let r = Rule { ops: vec![RuleOp::PrependString("super".into())] };
        let res = r.apply("pass");
        assert_eq!(res, vec!["superpass"]);
    }

    #[test]
    fn test_capitalize_upper() {
        let r = Rule { ops: vec![RuleOp::Capitalize(1)] };
        let res = r.apply("password");
        assert_eq!(res, vec!["PASSWORD"]);
    }

    #[test]
    fn test_capitalize_title() {
        let r = Rule { ops: vec![RuleOp::Capitalize(2)] };
        let res = r.apply("admin");
        assert_eq!(res, vec!["Admin"]);
    }

    #[test]
    fn test_leet_speak() {
        let r = Rule { ops: vec![RuleOp::LeetSpeak { from: 'a', to: '4' }] };
        let res = r.apply("password");
        assert_eq!(res, vec!["p4ssword"]);
    }

    #[test]
    fn test_multi_ops() {
        let r = Rule {
            ops: vec![
                RuleOp::Capitalize(2),
                RuleOp::AppendString("123".into()),
            ],
        };
        let res = r.apply("admin");
        assert_eq!(res, vec!["Admin123"]);
    }

    #[test]
    fn test_parse_rule_line() {
        let r = parse_rule_line("@123").unwrap();
        assert_eq!(r.ops.len(), 1);

        let r = parse_rule_line("$2024 ~1").unwrap();
        assert_eq!(r.ops.len(), 2);

        assert!(parse_rule_line("").is_none());
        assert!(parse_rule_line("# comment").is_none());
    }

    #[test]
    fn test_parse_leet_token() {
        let op = parse_token("&a:4").unwrap();
        match op {
            RuleOp::LeetSpeak { from, to } => {
                assert_eq!(from, 'a');
                assert_eq!(to, '4');
            }
            _ => panic!("Expected LeetSpeak"),
        }
    }

    #[test]
    fn test_new_ops_duplicate_reverse_truncate() {
        let r = Rule { ops: vec![RuleOp::Duplicate] };
        assert_eq!(r.apply("pass"), vec!["passpass"]);
        let r = Rule { ops: vec![RuleOp::Reverse] };
        assert_eq!(r.apply("pass"), vec!["ssap"]);
        let r = Rule { ops: vec![RuleOp::Truncate(4)] };
        assert_eq!(r.apply("password"), vec!["pass"]);
    }

    #[test]
    fn test_parse_new_tokens() {
        assert!(matches!(parse_token("D"), Some(RuleOp::Duplicate)));
        assert!(matches!(parse_token("R"), Some(RuleOp::Reverse)));
        assert!(matches!(parse_token("T4"), Some(RuleOp::Truncate(4))));
        assert!(parse_token("T0").is_none());
        assert!(parse_token("@").is_none());
        assert!(parse_token("$").is_none());
        assert!(parse_token("Z9").is_none());
        let r = parse_rule_line("~2 @123 D").unwrap();
        assert_eq!(r.ops.len(), 3);
    }

    #[test]
    fn test_dry_count_matches_apply() {
        let rules = vec![
            parse_rule_line("$9").unwrap(),   // x10
            parse_rule_line("@!").unwrap(),   // x1
            parse_rule_line("D").unwrap(),    // x1
        ];
        let base = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let est = dry_count_rules(base.len(), &rules, 10_000);
        let actual = apply_rules(&base, &rules, 10_000).len();
        assert_eq!(est, actual);
        // 3 kata dasar dipertahankan + 30 rantai (3x10x1x1).
        assert_eq!(est, 33);
    }

    #[test]
    fn test_base_words_always_kept() {
        // Tanpa union, "password" mentah hilang saat --rule dipakai.
        let rules = vec![parse_rule_line("@123").unwrap()];
        let base = vec!["password".to_string()];
        let out = apply_rules(&base, &rules, 10_000);
        assert!(out.contains(&"password".to_string()));
        assert!(out.contains(&"password123".to_string()));
        // Kata dasar paling depan = dicoba paling dulu.
        assert_eq!(out[0], "password");
    }

    #[test]
    fn test_dry_count_respects_cap() {
        let rules = vec![parse_rule_line("$9999").unwrap()];
        let base = vec!["a".to_string()];
        assert_eq!(dry_count_rules(base.len(), &rules, 500), 500);
        assert_eq!(apply_rules(&base, &rules, 500).len(), 500);
    }

    #[test]
    fn test_dry_count_empty() {
        assert_eq!(dry_count_rules(0, &[], 500), 0);
        assert_eq!(dry_count_rules(10, &[], 500), 10);
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    const TOKENS: &[&str] = &["$", "^", "@", "!", "~", "&", "D", "R", "T", "0", "1", "9", "abc", ":", " ", "#", "4", "123"];

    #[test]
    fn fuzz_rule_parse_never_panics() {
        let mut rng = Rng(0x601E);
        for _ in 0..5000 {
            let n = 1 + rng.below(5);
            let mut s = String::new();
            for i in 0..n {
                if i > 0 {
                    s.push(' ');
                }
                s.push_str(TOKENS[rng.below(TOKENS.len())]);
            }
            // Token angka kecil saja agar apply() tetap murah di test ini.
            let _ = parse_rule_line(&s);
        }
    }

    #[test]
    fn fuzz_rule_apply_bounded() {
        // Aturan dari token kecil: ekspansi apply_rules harus sama dengan
        // dry count bila tidak ada tabrakan (atau dry sedikit di atas).
        let mut rng = Rng(0xA991);
        for _ in 0..500 {
            let line = format!("${} @{}{}", rng.below(4), "x", rng.below(3));
            if let Some(rule) = parse_rule_line(&line) {
                let base = vec!["pw".to_string()];
                let actual = apply_rules(&base, &[rule.clone()], usize::MAX / 2).len();
                let est = dry_count_rules(1, &[rule], usize::MAX / 2);
                assert!(est >= actual, "dry undercount on {:?}", line);
                assert!(est - actual <= 1, "dry overcount too big on {:?}", line);
            }
        }
    }
}
