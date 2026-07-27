use memmap2::Mmap;
use std::path::Path;
use std::sync::Arc;

pub struct MemMappedWordlist {
    mmap: Arc<Mmap>,
    lines: Vec<(usize, usize)>,
    total: usize,
}

impl MemMappedWordlist {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("Failed to open wordlist '{}': {}", path.display(), e))?;
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| format!("Failed to mmap '{}': {}", path.display(), e))?;
        let mmap = Arc::new(mmap);

        let mut lines: Vec<(usize, usize)> = Vec::new();
        let mut start = 0usize;
        for (i, &byte) in mmap.iter().enumerate() {
            if byte == b'\n' {
                let end = if i > 0 && mmap[i - 1] == b'\r' { i - 1 } else { i };
                if end > start {
                    let slice = &mmap[start..end];
                    if !slice.is_empty() && slice[0] != b'#' {
                        lines.push((start, end));
                    }
                }
                start = i + 1;
            }
        }
        if start < mmap.len() {
            let end = mmap.len();
            let slice = &mmap[start..end];
            if !slice.is_empty() && slice[0] != b'#' && slice.iter().any(|&b| !b.is_ascii_whitespace()) {
                lines.push((start, end));
            }
        }

        let total = lines.len();
        Ok(MemMappedWordlist { mmap, lines, total })
    }

    pub fn get_line(&self, index: usize) -> Option<&[u8]> {
        if index >= self.lines.len() {
            return None;
        }
        let (start, end) = self.lines[index];
        Some(&self.mmap[start..end])
    }

    pub fn get_line_str(&self, index: usize) -> Option<&str> {
        self.get_line(index)
            .and_then(|s| std::str::from_utf8(s).ok())
    }

    pub fn iter(&self) -> MemMapIter<'_> {
        MemMapIter { mmap: &self.mmap, lines: &self.lines, pos: 0 }
    }

    pub fn len(&self) -> usize { self.total }
    pub fn is_empty(&self) -> bool { self.total == 0 }

    pub fn into_vec_string(&self) -> Vec<String> {
        self.lines.iter().filter_map(|&(start, end)| {
            std::str::from_utf8(&self.mmap[start..end]).ok().map(|s| s.to_string())
        }).collect()
    }
}

pub struct MemMapIter<'a> {
    mmap: &'a Mmap,
    lines: &'a [(usize, usize)],
    pos: usize,
}

impl<'a> Iterator for MemMapIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.lines.len() {
            return None;
        }
        let (start, end) = self.lines[self.pos];
        self.pos += 1;
        Some(&self.mmap[start..end])
    }
}

impl<'a> IntoIterator for &'a MemMappedWordlist {
    type Item = &'a [u8];
    type IntoIter = MemMapIter<'a>;
    fn into_iter(self) -> Self::IntoIter { self.iter() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memmap_wordlist() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_memmap.txt");
        std::fs::write(&path, "admin\nroot\n# comment\nuser\n").unwrap();

        let wl = MemMappedWordlist::open(&path).unwrap();
        assert_eq!(wl.len(), 3);
        assert_eq!(wl.get_line_str(0), Some("admin"));
        assert_eq!(wl.get_line_str(1), Some("root"));
        assert_eq!(wl.get_line_str(2), Some("user"));
        assert!(wl.get_line_str(3).is_none());

        let lines: Vec<&[u8]> = wl.iter().collect();
        assert_eq!(lines.len(), 3);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_memmap_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_memmap_empty.txt");
        std::fs::write(&path, "").unwrap();
        let wl = MemMappedWordlist::open(&path).unwrap();
        assert_eq!(wl.len(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_memmap_nonexistent() {
        assert!(MemMappedWordlist::open(Path::new("/nonexistent/file.txt")).is_err());
    }

    #[test]
    fn test_memmap_into_vec() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_memmap_vec.txt");
        std::fs::write(&path, "hello\nworld\n").unwrap();
        let wl = MemMappedWordlist::open(&path).unwrap();
        let vec = wl.into_vec_string();
        assert_eq!(vec, vec!["hello", "world"]);
        std::fs::remove_file(&path).ok();
    }
}
