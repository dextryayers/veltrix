use blake3::Hasher;

pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub fn blake3_keyed(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key_bytes = {
        let mut k = [0u8; 32];
        let len = key.len().min(32);
        k[..len].copy_from_slice(&key[..len]);
        k
    };
    let mut hasher = blake3::Hasher::new_keyed(&key_bytes);
    hasher.update(data);
    hasher.finalize().into()
}

pub struct IncrementalHash {
    hasher: Hasher,
}

impl IncrementalHash {
    pub fn new() -> Self {
        IncrementalHash { hasher: Hasher::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }

    pub fn finalize_hex(self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

pub fn fast_fingerprint(data: &[u8]) -> u64 {
    let hash = blake3::hash(data);
    let bytes = hash.as_bytes();
    u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])
}

pub fn blake3_xof(data: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let mut out = vec![0u8; len];
    hasher.finalize_xof().fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let result = blake3_hash(b"hello");
        assert_eq!(result.len(), 32);
        let hex = blake3_hex(b"hello");
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_blake3_consistency() {
        let h1 = blake3_hash(b"test data");
        let h2 = blake3_hash(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_blake3_different() {
        let h1 = blake3_hash(b"data1");
        let h2 = blake3_hash(b"data2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_incremental_hash() {
        let mut h = IncrementalHash::new();
        h.update(b"hello ");
        h.update(b"world");
        let full = blake3_hash(b"hello world");
        assert_eq!(h.finalize(), full);
    }

    #[test]
    fn test_blake3_keyed() {
        let h = blake3_keyed(b"key", b"data");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_fast_fingerprint() {
        let f1 = fast_fingerprint(b"data");
        let f2 = fast_fingerprint(b"data");
        let f3 = fast_fingerprint(b"different");
        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
    }

    #[test]
    fn test_blake3_xof() {
        let result = blake3_xof(b"test", 64);
        assert_eq!(result.len(), 64);
        let result32 = blake3_xof(b"test", 32);
        assert_eq!(result32.len(), 32);
        assert_eq!(result32.as_slice(), blake3_hash(b"test").as_slice());
    }
}
