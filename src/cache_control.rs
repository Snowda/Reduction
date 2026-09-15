use axum::http::Response;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheDirectives {
	pub no_store: bool,
	pub no_transform: bool,
	pub is_private: bool,
	// `public` explicitly authorizes a shared cache to store the response even when it would
	// otherwise be held back (e.g. a request carrying Authorization). RFC 7234 §3.2.
	pub is_public: bool,
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
		let mut directives: Self = Self::default();

		// Compare each directive in place (case-insensitive) rather than lowercasing into an owned String
		// per part — this runs on every cache hit, so an allocation here is per-request heap churn.
		for part in header.split(',') {
			let trimmed: &str = part.trim();

			if trimmed.eq_ignore_ascii_case("no-store") {
				directives.no_store = true;
			} else if trimmed.eq_ignore_ascii_case("no-transform") {
				directives.no_transform = true;
			} else if trimmed.eq_ignore_ascii_case("private") {
				directives.is_private = true;
			} else if trimmed.eq_ignore_ascii_case("public") {
				directives.is_public = true;
			} else if let Some(value) = strip_prefix_ci(trimmed, "max-age=") {
				directives.max_age = value.trim().parse::<u64>().ok();
			}
		}

		return directives;
	}
}

// Case-insensitive, allocation-free prefix strip (std `strip_prefix` is case-sensitive). Returns the
// remainder after `prefix` when `s` begins with it ignoring ASCII case, else None. `split_at_checked`
// yields None for a too-short or non-char-boundary split, which is correctly treated as no match.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
	let (head, rest): (&str, &str) = s.split_at_checked(prefix.len())?;
	if head.eq_ignore_ascii_case(prefix) {
		return Some(rest);
	}
	return None;
}

#[cfg(test)]
mod tests {
	use axum::body::Body;
	use axum::http::Response;

	use super::*;

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
	fn test_parse_public() {
		let d: CacheDirectives = CacheDirectives::parse("public, max-age=300");
		assert!(d.is_public);
		assert!(!d.is_private);
		assert_eq!(d.max_age, Some(300));
	}

	#[test]
	fn test_parse_unknown_directives_ignored() {
		let d: CacheDirectives = CacheDirectives::parse("public, must-revalidate, no-store");
		assert!(d.no_store);
		assert!(d.is_public);
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
		let resp: Response<Body> = Response::builder().body(Body::empty()).unwrap();
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
