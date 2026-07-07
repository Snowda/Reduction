// Benchmark harness code is exempt from the production lint gate the same way #[cfg(test)]
// modules are (the gate lints only --lib --bins). unwrap/expect on synthetic fixtures is fine here.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use arrayvec::ArrayString;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use reduction::config::RouteConfig;
use reduction::proxy::Router;

fn make_routes(count: usize) -> Vec<RouteConfig> {
    return (0..count)
        .map(|i| RouteConfig {
            path_prefix: ArrayString::from(&format!("/api/v{i}/service")).unwrap(),
            backend_id: ArrayString::from(&format!("backend-{i}")).unwrap(),
            timeout_secs: None,
        })
        .collect();
}

fn bench_match_route(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_match");

    for route_count in [1, 10, 50] {
        let routes: Vec<RouteConfig> = make_routes(route_count);
        let router: Router = Router::new(&routes);

        group.bench_with_input(
            BenchmarkId::new("hit_first", route_count),
            &route_count,
            |b, _| {
                b.iter(|| router.match_route("/api/v0/service/users"));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("hit_last", route_count),
            &route_count,
            |b, count| {
                let path: String = format!("/api/v{}/service/data", count - 1);
                b.iter(|| router.match_route(&path));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("miss", route_count),
            &route_count,
            |b, _| {
                b.iter(|| router.match_route("/health/check"));
            },
        );
    }

    group.finish();
}

fn bench_router_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_construction");

    for route_count in [1, 10, 50] {
        let routes: Vec<RouteConfig> = make_routes(route_count);
        group.bench_with_input(
            BenchmarkId::from_parameter(route_count),
            &routes,
            |b, routes| {
                b.iter(|| Router::new(routes));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_match_route, bench_router_construction);
criterion_main!(benches);
