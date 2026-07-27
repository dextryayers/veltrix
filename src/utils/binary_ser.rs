use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use std::path::Path;

pub fn to_binary<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bincode::serialize(value)
        .map_err(|e| format!("Bincode encode: {}", e))
}

pub fn from_binary<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    bincode::deserialize(bytes)
        .map_err(|e| format!("Bincode decode: {}", e))
}

pub fn save_binary<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = to_binary(value)?;
    std::fs::write(path, &bytes)
        .map_err(|e| format!("Failed to write '{}': {}", path.display(), e))
}

pub fn load_binary<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
    from_binary(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestData {
        version: u32,
        name: String,
        values: Vec<u64>,
    }

    #[test]
    fn test_binary_roundtrip() {
        let data = TestData {
            version: 1,
            name: "test".to_string(),
            values: vec![1, 2, 3, 100, 999],
        };
        let bytes = to_binary(&data).unwrap();
        let decoded: TestData = from_binary(&bytes).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_binary_file_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_binary_file.bin");
        let data = TestData {
            version: 42,
            name: "hello".to_string(),
            values: vec![7, 8, 9],
        };
        save_binary(&path, &data).unwrap();
        let loaded: TestData = load_binary(&path).unwrap();
        assert_eq!(data, loaded);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_binary_empty() {
        let data: Vec<u64> = vec![];
        let bytes = to_binary(&data).unwrap();
        let decoded: Vec<u64> = from_binary(&bytes).unwrap();
        assert!(decoded.is_empty());
    }
}
