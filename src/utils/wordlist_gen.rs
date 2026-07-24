use std::collections::BTreeSet;

pub struct WordlistConfig {
    pub name: Option<String>,
    pub company: Option<String>,
    pub dob: Option<String>,
    pub keywords: Vec<String>,
    pub min_len: usize,
    pub max_len: usize,
    pub leet: bool,
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
                    for leet in leet_variants(&cand) {
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
                        for leet in leet_variants(&cand) {
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

fn leet_variants(s: &str) -> Vec<String> {
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
