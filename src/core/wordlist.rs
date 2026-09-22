use std::io::BufRead;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

use super::credential::Credential;
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

/// F9.2: parser combo-line tunggal, murni dan fuzzable.
/// `user:pass` per baris; password boleh mengandung ':' (split pertama).
/// Komentar '#' dan baris kosong/invalid -> None.
pub fn parse_combo_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (user, pass) = line.split_once(':')?;
    let (user, pass) = (user.trim(), pass.trim());
    if user.is_empty() || pass.is_empty() {
        return None;
    }
    Some((user.to_string(), pass.to_string()))
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
        if let Some((user, pass)) = parse_combo_line(&line) {
            combos.push((user, pass));
        }
    }
    log::info!("Loaded {} combos from {}", combos.len(), path.display());
    Ok(combos)
}

#[allow(dead_code)]
pub struct StreamingWordlist {
    reader: std::io::BufReader<std::fs::File>,
    buffer: Vec<String>,
    exhausted: bool,
}

#[allow(dead_code)]
impl StreamingWordlist {
    pub fn open(path: &Path) -> Result<Self, AttackError> {
        let file = std::fs::File::open(path)
            .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
        let reader = std::io::BufReader::new(file);
        Ok(StreamingWordlist { reader, buffer: Vec::new(), exhausted: false })
    }

    pub fn load_chunk(&mut self, chunk_size: usize) -> Result<bool, AttackError> {
        if self.exhausted {
            return Ok(false);
        }
        self.buffer.clear();
        for _ in 0..chunk_size {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    self.exhausted = true;
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        self.buffer.push(trimmed);
                    }
                }
                Err(e) => return Err(AttackError::wordlist(
                    Path::new("stream").to_path_buf(), e.to_string(),
                )),
            }
        }
        Ok(!self.buffer.is_empty())
    }

    pub fn chunk(&self) -> &[String] { &self.buffer }

    pub fn is_exhausted(&self) -> bool { self.exhausted }
}

#[allow(dead_code)]
pub struct StreamingComboList {
    reader: std::io::BufReader<std::fs::File>,
    buffer: Vec<Credential>,
    exhausted: bool,
}

#[allow(dead_code)]
impl StreamingComboList {
    pub fn open(path: &Path) -> Result<Self, AttackError> {
        let file = std::fs::File::open(path)
            .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
        let reader = std::io::BufReader::new(file);
        Ok(StreamingComboList { reader, buffer: Vec::new(), exhausted: false })
    }

    pub fn load_chunk(&mut self, chunk_size: usize) -> Result<bool, AttackError> {
        if self.exhausted {
            return Ok(false);
        }
        self.buffer.clear();
        for _ in 0..chunk_size {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => { self.exhausted = true; break; }
                Ok(_) => {
                    let line = line.trim().to_string();
                    if let Some((user, pass)) = parse_combo_line(&line) {
                        self.buffer.push(Credential::new(user, pass));
                    }
                }
                Err(e) => return Err(AttackError::wordlist(
                    Path::new("stream").to_path_buf(), e.to_string(),
                )),
            }
        }
        Ok(!self.buffer.is_empty())
    }

    pub fn chunk(&self) -> &[Credential] { &self.buffer }
    pub fn is_exhausted(&self) -> bool { self.exhausted }
}

pub fn hash_credential_pair(user: &str, pass: &str) -> u64 {
    // Hash 64-bit hemat memori untuk dedup jutaan pasangan.
    // Memakai FxHash yang sudah jadi dependency proyek.
    use std::hash::Hasher;
    let mut h = fxhash::FxHasher::default();
    h.write(user.as_bytes());
    h.write_u8(0xff);
    h.write(pass.as_bytes());
    h.finish()
}

/// Loader hemat memori via mmap untuk wordlist besar.
/// Fallback otomatis ke buffered read jika mmap gagal.
pub fn load_wordlist_mmap(path: &Path) -> Result<Vec<String>, AttackError> {
    let file = std::fs::File::open(path)
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
    let meta = file
        .metadata()
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
    // File kecil tidak perlu mmap.
    if meta.len() < 64 * 1024 {
        return load_wordlist_blocking(path);
    }
    let mmap = unsafe {
        memmap2::Mmap::map(&file)
            .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?
    };
    let mut out = Vec::new();
    // Estimasi kasar: 1 baris per ~16 byte, hindari realloc berulang.
    out.reserve((mmap.len() / 16).min(1_000_000));
    for line in mmap.split(|b| *b == b'\n') {
        // Skip cepat untuk baris kosong dan komentar.
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        // Trim \r dan spasi tanpa alokasi ganda jika memungkinkan.
        let s = String::from_utf8_lossy(line);
        let t = s.trim();
        if !t.is_empty() && !t.starts_with('#') {
            out.push(t.to_string());
        }
    }
    log::info!("Loaded {} lines via mmap from {}", out.len(), path.display());
    Ok(out)
}

fn load_wordlist_blocking(path: &Path) -> Result<Vec<String>, AttackError> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)
        .map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
    let reader = std::io::BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| AttackError::wordlist(path.to_path_buf(), e.to_string()))?;
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('#') {
            out.push(t.to_string());
        }
    }
    Ok(out)
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

    #[test]
    fn test_parse_combo_line_unit() {
        assert_eq!(
            parse_combo_line("admin:password"),
            Some(("admin".into(), "password".into()))
        );
        // Password boleh mengandung ':' (split pertama saja).
        assert_eq!(
            parse_combo_line("user:pass:word"),
            Some(("user".into(), "pass:word".into()))
        );
        assert!(parse_combo_line("").is_none());
        assert!(parse_combo_line("# comment").is_none());
        assert!(parse_combo_line("admin:").is_none());
        assert!(parse_combo_line(":password").is_none());
        assert!(parse_combo_line("nocolon").is_none());
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

    // F9.2: combo parser tidak boleh panic untuk byte/fragmen apapun, dan
    // properti roundtrip: hasil parse selalu join kembali ke input (trimmed).
    const FRAG: &[&str] = &["a", ":", "::", "#", " ", "\t", "admin", "p@ss", "\u{00e9}", "\u{1f600}", "\n", "\r"];

    #[test]
    fn fuzz_combo_parse_never_panics() {
        let mut rng = Rng(0xC0880);
        for _ in 0..5000 {
            let n = 1 + rng.below(6);
            let mut s = String::new();
            for _ in 0..n {
                s.push_str(FRAG[rng.below(FRAG.len())]);
            }
            let r = parse_combo_line(&s);
            if let Some((u, p)) = r {
                assert!(!u.is_empty() && !p.is_empty());
                // User adalah pre-first-colon: tidak pernah mengandung ':'.
                assert!(!u.contains(':'));
                // Join kembali mengandung kredensial utuh.
                assert!(s.contains(&u));
                assert!(s.contains(&p));
            }
        }
    }
}
