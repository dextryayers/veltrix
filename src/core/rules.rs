use std::path::Path;

#[derive(Debug, Clone)]
pub enum RuleOp {
    AppendNumber(u64),
    PrependNumber(u64),
    AppendString(String),
    PrependString(String),
    Capitalize(u8),
    LeetSpeak { from: char, to: char },
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
    if token.len() < 2 {
        return None;
    }
    let (op_type, arg) = token.split_at(1);
    match op_type {
        "$" => arg.parse::<u64>().ok().map(RuleOp::AppendNumber),
        "^" => arg.parse::<u64>().ok().map(RuleOp::PrependNumber),
        "@" => Some(RuleOp::AppendString(arg.to_string())),
        "!" => Some(RuleOp::PrependString(arg.to_string())),
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
        _ => None,
    }
}

pub fn load_rules(path: &Path) -> Result<Vec<Rule>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file: {}", e))?;
    let mut rules = Vec::new();
    for line in content.lines() {
        if let Some(rule) = parse_rule_line(line) {
            rules.push(rule);
        }
    }
    Ok(rules)
}

pub fn apply_rules(base_words: &[String], rules: &[Rule], max_mutations: usize) -> Vec<String> {
    let mut result: Vec<String> = base_words.to_vec();
    for rule in rules {
        let mut new_words: Vec<String> = Vec::new();
        for word in &result {
            let mutations = rule.apply(word);
            new_words.extend(mutations);
            if new_words.len() >= max_mutations {
                new_words.truncate(max_mutations);
                break;
            }
        }
        result = new_words;
        if result.len() >= max_mutations {
            result.truncate(max_mutations);
            break;
        }
    }
    result
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
}
