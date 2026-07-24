use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn new(username: String, password: String) -> Self {
        Credential { username, password }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_combo_line(line: &str) -> Option<Credential> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let username = parts[0].trim().to_string();
            let password = parts[1].trim().to_string();
            if !username.is_empty() && !password.is_empty() {
                return Some(Credential::new(username, password));
            }
        }
        None
    }

    #[test]
    fn test_credential_new() {
        let c = Credential::new("admin".into(), "password".into());
        assert_eq!(c.username, "admin");
        assert_eq!(c.password, "password");
    }

    #[test]
    fn test_parse_combo_line_valid() {
        let c = parse_combo_line("admin:password").unwrap();
        assert_eq!(c.username, "admin");
        assert_eq!(c.password, "password");
    }

    #[test]
    fn test_parse_combo_line_with_spaces() {
        let c = parse_combo_line("  admin : password  ").unwrap();
        assert_eq!(c.username, "admin");
        assert_eq!(c.password, "password");
    }

    #[test]
    fn test_parse_combo_line_password_with_colon() {
        let c = parse_combo_line("user:pass:word").unwrap();
        assert_eq!(c.username, "user");
        assert_eq!(c.password, "pass:word");
    }

    #[test]
    fn test_parse_combo_line_empty() {
        assert!(parse_combo_line("").is_none());
    }

    #[test]
    fn test_parse_combo_line_comment() {
        assert!(parse_combo_line("# this is a comment").is_none());
    }

    #[test]
    fn test_parse_combo_line_no_password() {
        assert!(parse_combo_line("admin:").is_none());
    }

    #[test]
    fn test_parse_combo_line_no_username() {
        assert!(parse_combo_line(":password").is_none());
    }
}
