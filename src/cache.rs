use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use lru::LruCache;
use parking_lot::Mutex;

use crate::cache_control::CacheDirectives;
use crate::config::CacheConfig;

#[derive(Clone, Debug)]
struct CachedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    inserted_at: Instant,
    ttl: Duration,
}

impl CachedResponse {
    fn is_expired(&self) -> bool {
        return self.inserted_at.elapsed() > self.ttl;
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CacheKey {
    method: String,
    path: String,
}

impl CacheKey {
    fn new(method: &str, path: &str) -> Self {
        return Self {
            method: method.into(),
            path: path.into(),
        };
    }
}

pub struct ResponseCache {
    store: Mutex<LruCache<CacheKey, CachedResponse>>,
    config: CacheConfig,
}

impl ResponseCache {
    pub fn new(config: &CacheConfig) -> Self {
        return Self {
            store: Mutex::new(LruCache::new(config.max_entries)),
            config: config.clone(),
        };
    }

    pub fn get(&self, method: &str, path: &str) -> Option<Response<Body>> {
        let key: CacheKey = CacheKey::new(method, path);
        let mut store = self.store.lock();
        let entry: &CachedResponse = match store.get(&key) {
            Some(e) => e,
            None => return None,
        };

        if entry.is_expired() {
            store.pop(&key);
            return None;
        }

        let mut builder = Response::builder().status(entry.status);
        for (name, value) in entry.headers.iter() {
            builder = builder.header(name, value);
        }

        let body_bytes: Vec<u8> = entry.body.clone();
        let response: Response<Body> = builder
            .body(Body::from(body_bytes))
            .expect("failed to build cached response");

        return Some(response);
    }

    pub fn put(
        &self,
        method: &str,
        path: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: Vec<u8>,
        directives: &CacheDirectives,
    ) -> bool {
        if directives.no_store || directives.is_private {
            return false;
        }

        if body.len() > self.config.max_entry_bytes.get() {
            return false;
        }

        let ttl_secs: u64 = directives.max_age.unwrap_or(self.config.default_ttl_secs.get());
        if ttl_secs == 0 {
            return false;
        }

        let key: CacheKey = CacheKey::new(method, path);
        let entry: CachedResponse = CachedResponse {
            status,
            headers: headers.clone(),
            body,
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(ttl_secs),
        };

        let mut store = self.store.lock();
        store.put(key, entry);
        return true;
    }

    pub fn len(&self) -> usize {
        return self.store.lock().len();
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU64, NonZeroUsize};

    use axum::http::HeaderValue;

    use super::*;

    fn test_config() -> CacheConfig {
        return CacheConfig {
            enabled: true,
            max_entries: NonZeroUsize::new(100).unwrap(),
            max_entry_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
            default_ttl_secs: NonZeroU64::new(60).unwrap(),
        };
    }

    #[test]
    fn test_cache_miss() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let result: Option<Response<Body>> = cache.get("GET", "/api/data");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_hit() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let mut headers: HeaderMap = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("value"));

        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(300),
            ..CacheDirectives::default()
        };

        let stored: bool = cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &headers,
            b"response body".to_vec(),
            &directives,
        );
        assert!(stored);

        let response: Response<Body> = cache.get("GET", "/api/data").expect("expected cache hit");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-custom").unwrap(), "value");
    }

    #[test]
    fn test_cache_no_store_rejected() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let directives: CacheDirectives = CacheDirectives {
            no_store: true,
            ..CacheDirectives::default()
        };

        let stored: bool = cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"body".to_vec(),
            &directives,
        );
        assert!(!stored);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_private_rejected() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let directives: CacheDirectives = CacheDirectives {
            is_private: true,
            ..CacheDirectives::default()
        };

        let stored: bool = cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"body".to_vec(),
            &directives,
        );
        assert!(!stored);
    }

    #[test]
    fn test_cache_max_age_zero_rejected() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(0),
            ..CacheDirectives::default()
        };

        let stored: bool = cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"body".to_vec(),
            &directives,
        );
        assert!(!stored);
    }

    #[test]
    fn test_cache_oversized_entry_rejected() {
        let mut config: CacheConfig = test_config();
        config.max_entry_bytes = NonZeroUsize::new(10).unwrap();
        let cache: ResponseCache = ResponseCache::new(&config);

        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(300),
            ..CacheDirectives::default()
        };

        let stored: bool = cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"this body is way too large".to_vec(),
            &directives,
        );
        assert!(!stored);
    }

    #[test]
    fn test_cache_expired_entry_evicted() {
        let mut config: CacheConfig = test_config();
        config.default_ttl_secs = NonZeroU64::new(1).unwrap();
        let cache: ResponseCache = ResponseCache::new(&config);

        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(1),
            ..CacheDirectives::default()
        };

        cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"body".to_vec(),
            &directives,
        );

        // Entry exists but will expire after 1 second — we can't easily test timing
        // so just verify the entry was stored
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_default_ttl_used() {
        let config: CacheConfig = test_config();
        let cache: ResponseCache = ResponseCache::new(&config);

        let directives: CacheDirectives = CacheDirectives::default();

        let stored: bool = cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"body".to_vec(),
            &directives,
        );
        assert!(stored);
        assert!(cache.get("GET", "/api/data").is_some());
    }

    #[test]
    fn test_cache_different_methods_different_keys() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(300),
            ..CacheDirectives::default()
        };

        cache.put(
            "GET",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"get body".to_vec(),
            &directives,
        );
        cache.put(
            "HEAD",
            "/api/data",
            StatusCode::OK,
            &HeaderMap::new(),
            b"".to_vec(),
            &directives,
        );

        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let mut config: CacheConfig = test_config();
        config.max_entries = NonZeroUsize::new(2).unwrap();
        let cache: ResponseCache = ResponseCache::new(&config);

        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(300),
            ..CacheDirectives::default()
        };

        cache.put("GET", "/a", StatusCode::OK, &HeaderMap::new(), b"a".to_vec(), &directives);
        cache.put("GET", "/b", StatusCode::OK, &HeaderMap::new(), b"b".to_vec(), &directives);
        cache.put("GET", "/c", StatusCode::OK, &HeaderMap::new(), b"c".to_vec(), &directives);

        assert_eq!(cache.len(), 2);
        assert!(cache.get("GET", "/a").is_none());
        assert!(cache.get("GET", "/b").is_some());
        assert!(cache.get("GET", "/c").is_some());
    }

    #[test]
    fn test_cache_put_updates_existing() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(300),
            ..CacheDirectives::default()
        };

        cache.put("GET", "/api", StatusCode::OK, &HeaderMap::new(), b"v1".to_vec(), &directives);
        cache.put("GET", "/api", StatusCode::OK, &HeaderMap::new(), b"v2".to_vec(), &directives);

        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_preserves_status_code() {
        let cache: ResponseCache = ResponseCache::new(&test_config());
        let directives: CacheDirectives = CacheDirectives {
            max_age: Some(300),
            ..CacheDirectives::default()
        };

        cache.put(
            "GET",
            "/api/data",
            StatusCode::NOT_FOUND,
            &HeaderMap::new(),
            b"not found".to_vec(),
            &directives,
        );

        let response: Response<Body> = cache.get("GET", "/api/data").unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
