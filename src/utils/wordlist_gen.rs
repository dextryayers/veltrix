use std::collections::BTreeSet;

pub struct WordlistConfig {
    pub name: Option<String>,
    pub company: Option<String>,
    pub dob: Option<String>,
    pub keywords: Vec<String>,
    pub min_len: usize,
    pub max_len: usize,
    pub leet: bool,
    /// F8.2: 0 = mati (legacy), 1 = substitusi tunggal, 2 = kombinasi (default), 3 = + varian case.
    pub leet_level: u8,
    /// F8.2: sertakan basis musim (spring/summer/...) + tahun.
    pub seasons: bool,
    /// F8.2: sertakan keyboard walks umum (qwerty, 123456, ...).
    pub keyboard: bool,
}

impl Default for WordlistConfig {
    fn default() -> Self {
        Self {
            name: None,
            company: None,
            dob: None,
            keywords: Vec::new(),
            min_len: 4,
            max_len: 32,
            leet: true,
            leet_level: 2,
            seasons: true,
            keyboard: true,
        }
    }
}

pub fn generate_wordlist(cfg: &WordlistConfig) -> BTreeSet<String> {
    let mut words = BTreeSet::new();

    let name_parts = cfg.name.as_deref().unwrap_or("").split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>();
    let first_name = name_parts.first().cloned().unwrap_or_default();
    let last_name = name_parts.get(1).cloned().unwrap_or_default();

    let years = extract_years(cfg.dob.as_deref().unwrap_or(""));
    let company = cfg.company.as_deref().unwrap_or("").to_string();

    let bases: Vec<String> = {
        let mut b = Vec::new();
        if !first_name.is_empty() { b.push(first_name.clone()); }
        if !last_name.is_empty() { b.push(last_name.clone()); }
        if !company.is_empty() { b.push(company.clone()); }
        for kw in &cfg.keywords { b.push(kw.clone()); }
        b
    };

    let separators = ["", ".", "_", "-", "@", "#"];

    for base in &bases {
        insert(&mut words, &[base.clone()], &years, &separators, cfg);
    }

    // F8.2: basis musim + tahun (spring2024, Summer123, ...).
    if cfg.seasons {
        for season in SEASONS {
            insert(&mut words, &[season.to_string()], &years, &separators, cfg);
            for kw in bases.iter().chain(cfg.keywords.iter()) {
                for sep in &separators {
                    insert(&mut words, &[format!("{}{}{}", kw, sep, season)], &years, &separators, cfg);
                }
            }
        }
    }

    // F8.2: keyboard walks umum + reversed + suffix angka.
    if cfg.keyboard {
        for walk in KEYBOARD_WALKS {
            insert(&mut words, &[walk.to_string()], &years, &separators, cfg);
            insert(&mut words, &[walk.chars().rev().collect::<String>()], &years, &separators, cfg);
        }
    }

    if !first_name.is_empty() && !last_name.is_empty() {
        for sep in &separators {
            let combined = format!("{}{}{}", first_name, sep, last_name);
            insert(&mut words, &[combined], &years, &separators, cfg);

            let combined2 = format!("{}{}{}", last_name, sep, first_name);
            insert(&mut words, &[combined2], &years, &separators, cfg);

            let combined3 = format!("{}{}{}", first_name.to_lowercase(), sep, last_name.to_lowercase());
            insert(&mut words, &[combined3], &years, &separators, cfg);
        }
    }

    if !first_name.is_empty() && !company.is_empty() {
        for sep in &separators {
            let combined = format!("{}{}{}", first_name, sep, company);
            insert(&mut words, &[combined], &years, &separators, cfg);
        }
    }

    words
}

fn insert(words: &mut BTreeSet<String>, stems: &[String], years: &[String], separators: &[&str], cfg: &WordlistConfig) {
    let suffixes = ["", "!", "@", "#", "123", "123!", "!", "2024", "2025", "2026", "2027", "2028"];

    for stem in stems {
        for s in suffixes {
            let cand = format!("{}{}", stem, s);
            if cand.len() >= cfg.min_len && cand.len() <= cfg.max_len {
                words.insert(cand.clone());
                if cfg.leet {
                    for leet in leet_variants_level(&cand, cfg.leet_level) {
                        if leet.len() >= cfg.min_len && leet.len() <= cfg.max_len {
                            words.insert(leet);
                        }
                    }
                }
            }
        }

        let lower = stem.to_lowercase();
        let caps = {
            let mut c = String::new();
            let mut upper = true;
            for ch in lower.chars() {
                if upper {
                    c.push(ch.to_ascii_uppercase());
                    upper = false;
                } else {
                    c.push(ch);
                }
            }
            c
        };

        for s in suffixes {
            let cand = format!("{}{}", caps, s);
            if cand.len() >= cfg.min_len && cand.len() <= cfg.max_len {
                words.insert(cand.clone());
            }
            let cand = format!("{}{}", lower, s);
            if cand.len() >= cfg.min_len && cand.len() <= cfg.max_len {
                words.insert(cand.clone());
            }
        }

        for year in years {
            for sep in separators {
                let cand = format!("{}{}{}", stem, sep, year);
                if cand.len() >= cfg.min_len && cand.len() <= cfg.max_len {
                    words.insert(cand.clone());
                    if cfg.leet {
                        for leet in leet_variants_level(&cand, cfg.leet_level) {
                            if leet.len() >= cfg.min_len && leet.len() <= cfg.max_len {
                                words.insert(leet);
                            }
                        }
                    }
                }
            }
        }

        for sep in separators {
            for s2 in &["!", "@", "#", "123", "2024", "2025", "2026"] {
                let cand = format!("{}{}{}", stem, sep, s2);
                if cand.len() >= cfg.min_len && cand.len() <= cfg.max_len {
                    words.insert(cand.clone());
                }
            }
        }
    }
}

fn extract_years(dob: &str) -> Vec<String> {
    let mut years = Vec::new();
    if dob.is_empty() {
        years.extend(["2024", "2025", "2026", "2027", "2028"].map(String::from));
        return years;
    }

    let digits: String = dob.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 {
        if let Ok(year) = digits[digits.len() - 4..].parse::<i32>() {
            years.push(year.to_string());
            years.push((year % 100).to_string());
            years.push(format!("{:02}", year % 100));
        }
    }

    if let Ok(month) = digits[..digits.len().saturating_sub(4)].parse::<i32>() {
        if month >= 1 && month <= 12 {
            years.push(format!("{:02}", month));
            years.push(month.to_string());
        }
    }

    years.extend(["2024", "2025", "2026", "2027", "2028"].map(String::from));
    years.sort();
    years.dedup();
    years
}

/// F8.2: basis musim dan keyboard walks.
pub const SEASONS: &[&str] = &["spring", "summer", "autumn", "fall", "winter", "monsoon", "rainy", "dry"];
pub const KEYBOARD_WALKS: &[&str] = &[
    "qwerty", "asdfgh", "zxcvbn", "123456", "123456789", "1q2w3e", "1qaz2wsx",
    "qazwsx", "qweasd", "zaq12wsx", "123qwe", "qwerty123", "abc123",
];

fn leet_variants(s: &str) -> Vec<String> {
    leet_variants_level(s, 1)
}

/// F8.2: varian leet berlevel.
/// - 0: mati. 1: satu substitusi per kata (legacy). 2: + kombinasi pasangan
///   substitusi (cap 24). 3: + varian Title/UPPER dari semua hasil.
pub fn leet_variants_level(s: &str, level: u8) -> Vec<String> {
    if level == 0 {
        return Vec::new();
    }
    let mut results = leet_single(s);
    if level >= 2 {
        // Kombinasi dua substitusi berbeda: aplikasikan peta kedua ke hasil level 1.
        let mut combo = Vec::new();
        for v in &results {
            for second in leet_single(v) {
                if second != *v && !results.contains(&second) && !combo.contains(&second) {
                    combo.push(second);
                    if combo.len() >= 24 {
                        break;
                    }
                }
            }
            if combo.len() >= 24 {
                break;
            }
        }
        results.extend(combo);
    }
    if level >= 3 {
        let mut cased = Vec::new();
        for v in results.clone() {
            let mut chars = v.chars();
            if let Some(f) = chars.next() {
                let title: String = f.to_uppercase().collect::<String>() + chars.as_str();
                if title != v {
                    cased.push(title);
                }
            }
            let upper = v.to_uppercase();
            if upper != v {
                cased.push(upper);
            }
            if cased.len() >= 32 {
                break;
            }
        }
        results.extend(cased);
    }
    results.sort();
    results.dedup();
    results
}

/// Substitusi tunggal legacy (satu peta per kata).
fn leet_single(s: &str) -> Vec<String> {
    let mut results = Vec::new();
    let leet_map: Vec<(char, &str)> = vec![
        ('a', "@"), ('a', "4"), ('e', "3"), ('i', "1"), ('i', "!"),
        ('o', "0"), ('s', "$"), ('s', "5"), ('t', "7"),
        ('b', "8"), ('g', "9"), ('l', "1"),
    ];

    for &(ch, replacement) in &leet_map {
        if s.contains(ch) || s.contains(ch.to_ascii_uppercase()) {
            let mut alt = s.replace(ch, replacement);
            alt = alt.replace(ch.to_ascii_uppercase(), replacement);
            if alt != s {
                results.push(alt);
            }

            let alt2 = s.replace(ch.to_ascii_uppercase(), replacement);
            if alt2 != s && alt2 != results.last().map(|s| s.as_str()).unwrap_or("") {
                results.push(alt2);
            }
        }
    }

    results.sort();
    results.dedup();
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str) -> WordlistConfig {
        WordlistConfig {
            name: Some(name.into()),
            company: None,
            dob: None,
            keywords: vec![],
            min_len: 4,
            max_len: 32,
            leet: true,
            leet_level: 2,
            seasons: true,
            keyboard: true,
        }
    }

    #[test]
    fn seasons_and_keyboard_included() {
        let words = generate_wordlist(&cfg("John"));
        assert!(words.iter().any(|w| w.to_lowercase().contains("spring")), "season base missing");
        assert!(words.contains("qwerty"), "keyboard walk missing");
        assert!(words.iter().any(|w| w.contains("John")), "name base missing");
    }

    #[test]
    fn seasons_keyboard_can_be_disabled() {
        let mut c = cfg("John");
        c.seasons = false;
        c.keyboard = false;
        c.leet = false;
        let words = generate_wordlist(&c);
        assert!(!words.iter().any(|w| w.to_lowercase().contains("spring")));
        assert!(!words.contains("qwerty"));
        assert!(words.iter().any(|w| w.contains("John")));
    }

    #[test]
    fn leet_levels_monotonic() {
        let l1 = leet_variants_level("password", 1);
        let l2 = leet_variants_level("password", 2);
        let l3 = leet_variants_level("password", 3);
        assert!(leet_variants_level("password", 0).is_empty());
        assert!(!l1.is_empty());
        assert!(l2.len() >= l1.len());
        assert!(l3.len() >= l2.len());
        assert!(l1.contains(&"p4ssword".to_string()));
        assert!(l2.iter().any(|w| w.contains('4') && w.contains('0') || w.contains('$')));
    }

    #[test]
    fn leet_level3_adds_case() {
        let l3 = leet_variants_level("admin", 3);
        assert!(l3.iter().any(|w| w == "ADMIN" || w.chars().next().unwrap().is_uppercase()));
    }

    #[test]
    fn generation_respects_length_bounds() {
        let mut c = cfg("A");
        c.min_len = 8;
        c.max_len = 12;
        for w in generate_wordlist(&c) {
            assert!(w.len() >= 8 && w.len() <= 12, "out of bounds: {}", w);
        }
    }

    #[test]
    fn season_year_combos_present() {
        let mut c = cfg("x");
        c.keyboard = false;
        c.min_len = 4;
        let words = generate_wordlist(&c);
        assert!(words.iter().any(|w| {
            let l = w.to_lowercase();
            (l.contains("spring") || l.contains("winter")) && l.chars().any(|ch| ch.is_ascii_digit())
        }));
    }
}
