use crate::config::RouteConfig;

#[derive(Clone)]
pub struct Route {
    pub path_prefix: String,
    pub backend_id: String,
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
                backend_id: rc.backend_id.clone(),
            })
            .collect();

        // Sort by prefix length descending so longer prefixes match first
        routes.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));

        return Self { routes };
    }

    pub fn match_route(&self, path: &str) -> Option<&str> {
        for route in &self.routes {
            if path.starts_with(&route.path_prefix) {
                return Some(&route.backend_id);
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
                path_prefix: prefix.to_string(),
                backend_id: id.to_string(),
            })
            .collect();
    }

    #[test]
    fn test_exact_prefix_match() {
        let routes: Vec<RouteConfig> = make_routes(&[("/api", "api-backend")]);
        let router: Router = Router::new(&routes);

        assert_eq!(router.match_route("/api/users"), Some("api-backend"));
        assert_eq!(router.match_route("/api"), Some("api-backend"));
    }

    #[test]
    fn test_longest_prefix_wins() {
        let routes: Vec<RouteConfig> = make_routes(&[
            ("/api", "api-general"),
            ("/api/v2", "api-v2"),
        ]);
        let router: Router = Router::new(&routes);

        assert_eq!(router.match_route("/api/v2/users"), Some("api-v2"));
        assert_eq!(router.match_route("/api/v1/users"), Some("api-general"));
    }

    #[test]
    fn test_no_match() {
        let routes: Vec<RouteConfig> = make_routes(&[("/api", "api-backend")]);
        let router: Router = Router::new(&routes);

        assert_eq!(router.match_route("/health"), None);
        assert_eq!(router.match_route("/"), None);
    }

    #[test]
    fn test_root_catch_all() {
        let routes: Vec<RouteConfig> = make_routes(&[
            ("/", "default"),
            ("/api", "api-backend"),
        ]);
        let router: Router = Router::new(&routes);

        assert_eq!(router.match_route("/api/test"), Some("api-backend"));
        assert_eq!(router.match_route("/other"), Some("default"));
    }

    #[test]
    fn test_empty_routes() {
        let routes: Vec<RouteConfig> = make_routes(&[]);
        let router: Router = Router::new(&routes);

        assert_eq!(router.match_route("/anything"), None);
    }
}
