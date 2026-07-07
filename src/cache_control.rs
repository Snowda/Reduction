use axum::http::Response;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheDirectives {
    pub no_store: bool,
    pub no_transform: bool,
    pub is_private: bool,
    pub max_age: Option<u64>,
}

impl CacheDirectives {
    pub fn from_response<B>(response: &Response<B>) -> Self {
        let header_value: &str = match response.headers().get("cache-control") {
            Some(v) => match v.to_str() {
                Ok(s) => s,
                Err(_) => return Self::default(),
            },
            None => return Self::default(),
        };

        return Self::parse(header_value);
    }

    #[must_use]
    pub fn parse(header: &str) -> Self {
        let mut directives: CacheDirectives = CacheDirectives::default();

        for part in header.split(',') {
            let trimmed: &str = part.trim();
            let lower: String = trimmed.to_ascii_lowercase();

            if lower == "no-store" {
                directives.no_store = true;
            } else if lower == "no-transform" {
                directives.no_transform = true;
            } else if lower == "private" {
                directives.is_private = true;
            } else if let Some(value) = lower.strip_prefix("max-age=") {
                directives.max_age = value.trim().parse::<u64>().ok();
            }
        }

        return directives;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Response;

    #[test]
    fn test_parse_empty() {
        let d: CacheDirectives = CacheDirectives::parse("");
        assert_eq!(d, CacheDirectives::default());
    }

    #[test]
    fn test_parse_no_store() {
        let d: CacheDirectives = CacheDirectives::parse("no-store");
        assert!(d.no_store);
        assert!(!d.no_transform);
        assert!(!d.is_private);
        assert_eq!(d.max_age, None);
    }

    #[test]
    fn test_parse_no_transform() {
        let d: CacheDirectives = CacheDirectives::parse("no-transform");
        assert!(d.no_transform);
    }

    #[test]
    fn test_parse_private() {
        let d: CacheDirectives = CacheDirectives::parse("private");
        assert!(d.is_private);
    }

    #[test]
    fn test_parse_max_age() {
        let d: CacheDirectives = CacheDirectives::parse("max-age=3600");
        assert_eq!(d.max_age, Some(3600));
    }

    #[test]
    fn test_parse_max_age_invalid() {
        let d: CacheDirectives = CacheDirectives::parse("max-age=notanumber");
        assert_eq!(d.max_age, None);
    }

    #[test]
    fn test_parse_multiple_directives() {
        let d: CacheDirectives = CacheDirectives::parse("no-store, no-transform, max-age=60");
        assert!(d.no_store);
        assert!(d.no_transform);
        assert_eq!(d.max_age, Some(60));
    }

    #[test]
    fn test_parse_mixed_case() {
        let d: CacheDirectives = CacheDirectives::parse("No-Store, NO-TRANSFORM, Max-Age=120");
        assert!(d.no_store);
        assert!(d.no_transform);
        assert_eq!(d.max_age, Some(120));
    }

    #[test]
    fn test_parse_extra_whitespace() {
        let d: CacheDirectives = CacheDirectives::parse("  no-store ,  max-age = 300  ");
        assert!(d.no_store);
        assert_eq!(d.max_age, None); // "= 300" won't parse because strip_prefix expects "max-age="
    }

    #[test]
    fn test_parse_max_age_with_trimmed_value() {
        let d: CacheDirectives = CacheDirectives::parse("max-age= 300");
        assert_eq!(d.max_age, Some(300));
    }

    #[test]
    fn test_parse_unknown_directives_ignored() {
        let d: CacheDirectives = CacheDirectives::parse("public, must-revalidate, no-store");
        assert!(d.no_store);
        assert!(!d.no_transform);
        assert!(!d.is_private);
    }

    #[test]
    fn test_parse_all_directives() {
        let d: CacheDirectives = CacheDirectives::parse("private, no-store, no-transform, max-age=0");
        assert!(d.is_private);
        assert!(d.no_store);
        assert!(d.no_transform);
        assert_eq!(d.max_age, Some(0));
    }

    #[test]
    fn test_from_response_no_header() {
        let resp: Response<Body> = Response::builder()
            .body(Body::empty())
            .unwrap();
        let d: CacheDirectives = CacheDirectives::from_response(&resp);
        assert_eq!(d, CacheDirectives::default());
    }

    #[test]
    fn test_from_response_with_header() {
        let resp: Response<Body> = Response::builder()
            .header("cache-control", "no-transform, max-age=600")
            .body(Body::empty())
            .unwrap();
        let d: CacheDirectives = CacheDirectives::from_response(&resp);
        assert!(d.no_transform);
        assert_eq!(d.max_age, Some(600));
    }

    #[test]
    fn test_from_response_invalid_utf8_returns_default() {
        let resp: Response<Body> = Response::builder()
            .header("cache-control", &b"\xff\xfe"[..])
            .body(Body::empty())
            .unwrap();
        let d: CacheDirectives = CacheDirectives::from_response(&resp);
        assert_eq!(d, CacheDirectives::default());
    }
}
