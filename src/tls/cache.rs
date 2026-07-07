use std::time::{Duration, Instant};

use dashmap::DashMap;

pub struct TokenCache {
    entries: DashMap<String, (Vec<u8>, Instant)>,
    ttl: Duration,
}

impl TokenCache {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        return Self {
            entries: DashMap::new(),
            ttl,
        };
    }

    pub fn insert(&self, fingerprint: String, token: Vec<u8>) {
        self.entries.insert(fingerprint, (token, Instant::now()));
    }

    #[must_use]
    pub fn get(&self, fingerprint: &str) -> Option<Vec<u8>> {
        match self.entries.get(fingerprint) {
            Some(entry) => {
                let (token, inserted_at) = entry.value();
                if inserted_at.elapsed() >= self.ttl {
                    drop(entry);
                    self.entries.remove(fingerprint);
                    return None;
                }
                return Some(token.clone());
            }
            None => return None,
        }
    }

    pub fn invalidate(&self, fingerprint: &str) {
        self.entries.remove(fingerprint);
    }

    pub fn invalidate_all(&self) {
        self.entries.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        return self.entries.len();
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        return self.entries.is_empty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
        cache.insert("cert-abc".to_string(), vec![1, 2, 3]);

        let token: Option<Vec<u8>> = cache.get("cert-abc");
        assert_eq!(token, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_get_missing() {
        let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_explicit_invalidation() {
        let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
        cache.insert("cert-abc".to_string(), vec![1, 2, 3]);

        cache.invalidate("cert-abc");
        assert!(cache.get("cert-abc").is_none());
    }

    #[test]
    fn test_invalidate_all() {
        let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
        cache.insert("cert-1".to_string(), vec![1]);
        cache.insert("cert-2".to_string(), vec![2]);

        assert_eq!(cache.len(), 2);
        cache.invalidate_all();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_ttl_expiry() {
        let cache: TokenCache = TokenCache::new(Duration::from_millis(1));
        cache.insert("cert-abc".to_string(), vec![1, 2, 3]);

        std::thread::sleep(Duration::from_millis(10));

        assert!(cache.get("cert-abc").is_none());
    }

    #[test]
    fn test_overwrite_entry() {
        let cache: TokenCache = TokenCache::new(Duration::from_secs(300));
        cache.insert("cert-abc".to_string(), vec![1, 2, 3]);
        cache.insert("cert-abc".to_string(), vec![4, 5, 6]);

        assert_eq!(cache.get("cert-abc"), Some(vec![4, 5, 6]));
    }
}
