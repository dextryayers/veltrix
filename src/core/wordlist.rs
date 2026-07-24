use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

use super::error::AttackError;

pub async fn load_wordlist(path: &Path) -> Result<Vec<String>, AttackError> {
    let file = File::open(path).await
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut stream = reader.lines();

    while let Some(line) = stream.next_line().await
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), format!("Read error: {}", e)))?
    {
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed);
        }
    }
    log::info!("Loaded {} lines from {}", lines.len(), path.display());
    Ok(lines)
}

pub async fn load_combo_list(path: &Path) -> Result<Vec<(String, String)>, AttackError> {
    let file = File::open(path).await
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
    let reader = BufReader::new(file);
    let mut combos = Vec::new();
    let mut stream = reader.lines();

    while let Some(line) = stream.next_line().await
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), format!("Read error: {}", e)))?
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
    log::info!("Loaded {} combos from {}", combos.len(), path.display());
    Ok(combos)
}

#[allow(dead_code)]
pub struct StreamingWordlist {
    path: std::path::PathBuf,
    buffer: Vec<String>,
    position: usize,
}

#[allow(dead_code)]
impl StreamingWordlist {
    pub fn new(path: &std::path::Path) -> Self {
        StreamingWordlist {
            path: path.to_path_buf(),
            buffer: Vec::new(),
            position: 0,
        }
    }

    pub async fn load_chunk(&mut self, _chunk_size: usize) -> Result<bool, AttackError> {
        if self.position == 0 && self.buffer.is_empty() {
            let file = File::open(&self.path).await
                .map_err(|e| AttackError::wordlist(self.path.clone(), e.to_string()))?;
            let reader = BufReader::new(file);
            let mut stream = reader.lines();
            while let Some(line) = stream.next_line().await
                .map_err(|e| AttackError::wordlist(self.path.clone(), format!("Read error: {}", e)))?
            {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    self.buffer.push(trimmed);
                }
            }
            return Ok(!self.buffer.is_empty());
        }
        Ok(false)
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_combo_list() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_combos_unit.txt");
        std::fs::write(&path, "admin:password\nroot:123456\n# comment\nuser:pass\n").unwrap();

        let combos = load_combo_list(&path).await.unwrap();
        assert_eq!(combos.len(), 3);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_load_wordlist() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_words_unit.txt");
        std::fs::write(&path, "admin\nroot\n# comment\n\nuser\n").unwrap();

        let words = load_wordlist(&path).await.unwrap();
        assert_eq!(words.len(), 3);

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn test_load_nonexistent_file() {
        let result = load_wordlist(std::path::Path::new("/nonexistent/file.txt")).await;
        assert!(result.is_err());
    }
}
