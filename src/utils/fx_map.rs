use fxhash::{FxHashMap, FxHashSet};
use std::hash::Hash;

pub type FastMap<K, V> = FxHashMap<K, V>;
pub type FastSet<K> = FxHashSet<K>;

pub struct DedupSet<T: Hash + Eq> {
    inner: FastSet<T>,
}

impl<T: Hash + Eq> DedupSet<T> {
    pub fn new() -> Self {
        DedupSet { inner: FastSet::default() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        DedupSet { inner: FastSet::with_capacity_and_hasher(cap, Default::default()) }
    }

    pub fn insert(&mut self, value: T) -> bool {
        self.inner.insert(value)
    }

    pub fn contains(&self, value: &T) -> bool {
        self.inner.contains(value)
    }

    pub fn len(&self) -> usize { self.inner.len() }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
    pub fn clear(&mut self) { self.inner.clear(); }

    pub fn into_inner(self) -> FastSet<T> { self.inner }
}

pub struct FastCounter<T: Hash + Eq> {
    inner: FastMap<T, u64>,
}

impl<T: Hash + Eq> FastCounter<T> {
    pub fn new() -> Self {
        FastCounter { inner: FastMap::default() }
    }

    pub fn increment(&mut self, key: T) {
        *self.inner.entry(key).or_insert(0) += 1;
    }

    pub fn get(&self, key: &T) -> u64 {
        self.inner.get(key).copied().unwrap_or(0)
    }

    pub fn entries(&self) -> &FastMap<T, u64> { &self.inner }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_set() {
        let mut set = DedupSet::new();
        assert!(set.insert("hello"));
        assert!(!set.insert("hello"));
        assert!(set.insert("world"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_fast_counter() {
        let mut c = FastCounter::new();
        c.increment("a");
        c.increment("a");
        c.increment("b");
        assert_eq!(c.get(&"a"), 2);
        assert_eq!(c.get(&"b"), 1);
        assert_eq!(c.get(&"c"), 0);
    }
}
