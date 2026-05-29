use arrayvec::ArrayString;

use crate::config::RouteConfig;

#[derive(Clone)]
pub struct Route {
    pub path_prefix: ArrayString<64>,
    pub backend_id: ArrayString<256>,
    pub timeout_secs: Option<u64>,
}

pub struct RouteMatch<'a> {
    pub backend_id: &'a ArrayString<256>,
    pub timeout_secs: Option<u64>,
}

#[derive(Clone)]
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub fn new(route_configs: &[RouteConfig]) -> Self {
        let mut routes: Vec<Route> = route_configs
            .iter()
            .map(|rc| Route {
                path_prefix: rc.path_prefix.clone(),
                backend_id: rc.backend_id,
                timeout_secs: rc.timeout_secs,
            })
            .collect();

        // Sort by prefix length descending so longer prefixes match first
        routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));

        return Self { routes };
    }

    #[tracing::instrument(skip_all)]
    pub fn match_route(&self, path: &str) -> Option<RouteMatch<'_>> {
        for route in &self.routes {
            if path.starts_with(route.path_prefix.as_str()) {
                if path.len() == route.path_prefix.len()
                    || route.path_prefix.ends_with('/')
                    || path.as_bytes()[route.path_prefix.len()] == b'/'
                {
                    return Some(RouteMatch {
                        backend_id: &route.backend_id,
                        timeout_secs: route.timeout_secs,
                    });
                }
            }
        }
        return None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_routes(pairs: &[(&str, &str)]) -> Vec<RouteConfig> {
        return pairs
            .iter()
            .map(|(prefix, id)| RouteConfig {
                path_prefix: ArrayString::from(prefix).unwrap(),
                backend_id: ArrayString::from(id).unwrap(),
                timeout_secs: None,
            })
            .collect();
    }

    fn assert_match(router: &Router, path: &str, expected_backend: &str) {
        let m: RouteMatch<'_> = router.match_route(path).expect("expected a route match");
        assert_eq!(m.backend_id.as_str(), expected_backend);
    }

    fn assert_no_match(router: &Router, path: &str) {
        assert!(router.match_route(path).is_none());
    }

    #[test]
    fn test_exact_prefix_match() {
        let routes: Vec<RouteConfig> = make_routes(&[("/api", "api-backend")]);
        let router: Router = Router::new(&routes);

        assert_match(&router, "/api/users", "api-backend");
        assert_match(&router, "/api", "api-backend");
    }

    #[test]
    fn test_longest_prefix_wins() {
        let routes: Vec<RouteConfig> = make_routes(&[
            ("/api", "api-general"),
            ("/api/v2", "api-v2"),
        ]);
        let router: Router = Router::new(&routes);

        assert_match(&router, "/api/v2/users", "api-v2");
        assert_match(&router, "/api/v1/users", "api-general");
    }

    #[test]
    fn test_no_match() {
        let routes: Vec<RouteConfig> = make_routes(&[("/api", "api-backend")]);
        let router: Router = Router::new(&routes);

        assert_no_match(&router, "/health");
        assert_no_match(&router, "/");
    }

    #[test]
    fn test_root_catch_all() {
        let routes: Vec<RouteConfig> = make_routes(&[
            ("/", "default"),
            ("/api", "api-backend"),
        ]);
        let router: Router = Router::new(&routes);

        assert_match(&router, "/api/test", "api-backend");
        assert_match(&router, "/other", "default");
    }

    #[test]
    fn test_empty_routes() {
        let routes: Vec<RouteConfig> = make_routes(&[]);
        let router: Router = Router::new(&routes);

        assert_no_match(&router, "/anything");
    }

    #[test]
    fn test_prefix_boundary_rejects_partial_segment() {
        let routes: Vec<RouteConfig> = make_routes(&[("/api", "api-backend")]);
        let router: Router = Router::new(&routes);

        assert_no_match(&router, "/api-internal");
        assert_no_match(&router, "/api-v2/foo");
        assert_match(&router, "/api/v2/foo", "api-backend");
        assert_match(&router, "/api", "api-backend");
    }

    #[test]
    fn test_trailing_slash_prefix_matches_subpaths() {
        let routes: Vec<RouteConfig> = make_routes(&[("/static/", "static-backend")]);
        let router: Router = Router::new(&routes);

        assert_match(&router, "/static/img.png", "static-backend");
        assert_no_match(&router, "/static");
    }

    #[test]
    fn test_per_route_timeout_returned() {
        let routes: Vec<RouteConfig> = vec![
            RouteConfig {
                path_prefix: ArrayString::from("/slow").unwrap(),
                backend_id: ArrayString::from("slow-backend").unwrap(),
                timeout_secs: Some(120),
            },
            RouteConfig {
                path_prefix: ArrayString::from("/fast").unwrap(),
                backend_id: ArrayString::from("fast-backend").unwrap(),
                timeout_secs: Some(5),
            },
            RouteConfig {
                path_prefix: ArrayString::from("/").unwrap(),
                backend_id: ArrayString::from("default").unwrap(),
                timeout_secs: None,
            },
        ];
        let router: Router = Router::new(&routes);

        let slow: RouteMatch<'_> = router.match_route("/slow/report").unwrap();
        assert_eq!(slow.timeout_secs, Some(120));

        let fast: RouteMatch<'_> = router.match_route("/fast/ping").unwrap();
        assert_eq!(fast.timeout_secs, Some(5));

        let default: RouteMatch<'_> = router.match_route("/other").unwrap();
        assert_eq!(default.timeout_secs, None);
    }
}
