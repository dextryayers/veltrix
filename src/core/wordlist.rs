use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

pub async fn load_wordlist(path: &Path) -> Result<Vec<String>, String> {
    let file = File::open(path).await
        .map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut stream = reader.lines();

    while let Some(line) = stream.next_line().await
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?
    {
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed);
        }
    }
    Ok(lines)
}

pub async fn load_combo_list(path: &Path) -> Result<Vec<(String, String)>, String> {
    let file = File::open(path).await
        .map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let mut combos = Vec::new();
    let mut stream = reader.lines();

    while let Some(line) = stream.next_line().await
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?
    {
        let line = line.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let user = parts[0].trim().to_string();
            let pass = parts[1].trim().to_string();
            if !user.is_empty() && !pass.is_empty() {
                combos.push((user, pass));
            }
        }
    }
    Ok(combos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_combo_list() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_combos.txt");
        std::fs::write(&path, "admin:password\nroot:123456\n# comment\nuser:pass\n").unwrap();

        let combos = load_combo_list(&path).await.unwrap();
        assert_eq!(combos.len(), 3);
        assert_eq!(combos[0], ("admin".into(), "password".into()));
        assert_eq!(combos[1], ("root".into(), "123456".into()));
        assert_eq!(combos[2], ("user".into(), "pass".into()));

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_load_wordlist() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_wordlist.txt");
        std::fs::write(&path, "admin\nroot\n# comment\n\nuser\n").unwrap();

        let words = load_wordlist(&path).await.unwrap();
        assert_eq!(words.len(), 3);
        assert_eq!(words[0], "admin");
        assert_eq!(words[1], "root");
        assert_eq!(words[2], "user");

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_load_nonexistent_file() {
        let result = load_wordlist(std::path::Path::new("/nonexistent/file.txt")).await;
        assert!(result.is_err());
    }
}
