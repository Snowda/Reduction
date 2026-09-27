use super::{
	Arc, ArrayString, ArrayVec, BackendConfig, BackendPool, Body, ConnPool, DashMap, HealthState, IpAddr,
	KeyValue, MAX_BACKENDS, ReductionError, ReloadableState, Response, Result, RouteMatch, StatusCode,
	StringValue, error, error_response, watch,
};

// Record a backend as tried-and-failed; dedup bounds the set by distinct-backend count so try_push never overflows.
#[inline]
pub fn mark_failed(failed: &mut ArrayVec<ArrayString<256>, MAX_BACKENDS>, id: ArrayString<256>) {
	if !failed.contains(&id) {
		let _ = failed.try_push(id);
	}
}

// Intern one ("backend", id) metric label per backend id. Read-first, so the hot path takes only a shard
// read-lock and the clone is an Arc<str> refcount bump; the entry path (Arc<str> alloc) runs once per id ever.
pub fn backend_label(labels: &DashMap<ArrayString<256>, KeyValue>, id: &ArrayString<256>) -> KeyValue {
	if let Some(existing) = labels.get(id.as_str()) {
		return existing.clone();
	}
	return labels
		.entry(*id)
		.or_insert_with(|| KeyValue::new("backend", StringValue::from(Arc::<str>::from(id.as_str()))))
		.clone();
}

// Label resolution for record_completion, which holds only a &str ("" on no-backend reject paths). Real ids
// are interned upstream so the read-first branch hits; "" maps to a static empty label, a cold miss is a defensive intern.
pub fn completion_backend_label(labels: &DashMap<ArrayString<256>, KeyValue>, backend_str: &str) -> KeyValue {
	if let Some(existing) = labels.get(backend_str) {
		return existing.clone();
	}
	if backend_str.is_empty() {
		return KeyValue::new("backend", "");
	}
	return KeyValue::new("backend", StringValue::from(Arc::<str>::from(backend_str)));
}

// Select a backend, passing over any id in `excluded` (already tried and failed this request) so a retry
// lands on a different healthy member. BackendUnavailable once all are excluded. Synchronous so the watch::Ref never crosses an await.
pub fn select_backend_excluding(
	pool: &BackendPool,
	client_ip: IpAddr,
	health_rx: &watch::Receiver<HealthState>,
	conn_pool: &ConnPool,
	excluded: &[ArrayString<256>],
) -> Result<BackendConfig> {
	let health: watch::Ref<'_, HealthState> = health_rx.borrow();
	// The balancer hands each candidate's own BackendConfig, so read max_connections directly (a per-candidate lookup made selection O(n²)).
	let pressure_fn = |b: &BackendConfig| -> f64 {
		return conn_pool.connection_pressure(b.id.as_str(), b.max_connections);
	};
	return match pool.select_with_pressure_excluding(client_ip, &health, &pressure_fn, excluded) {
		Some(backend) => Ok(backend.clone()),
		None => Err(ReductionError::BackendUnavailable),
	};
}

pub struct ResolvedRoute {
	pub backend_id: ArrayString<256>,
	pub pool: BackendPool,
	pub timeout_secs: Option<u64>,
}

// Resolve route and backend pool from reloadable state before any await point. The Err path returns a
// fully-formed HTTP error Response, so boxing it to shrink the variant would violate the no-Box convention.
#[allow(clippy::result_large_err)]
pub fn resolve_backend_pool(
	reloadable: &watch::Receiver<ReloadableState>,
	path: &str,
) -> std::result::Result<ResolvedRoute, Response<Body>> {
	let state: watch::Ref<'_, ReloadableState> = reloadable.borrow();

	let route_match: RouteMatch<'_> = match state.router.match_route(path) {
		Some(m) => m,
		None => {
			return Err(error_response(StatusCode::NOT_FOUND, "no route matched"));
		}
	};

	let pool: &BackendPool = match state.backend_pools.get(route_match.backend_id.as_str()) {
		Some(p) => p,
		None => {
			error!(
				backend_id = route_match.backend_id.as_str(),
				"route matched but no backend pool found"
			);
			return Err(error_response(StatusCode::BAD_GATEWAY, "backend pool not found"));
		}
	};

	return Ok(ResolvedRoute {
		backend_id: *route_match.backend_id,
		pool: pool.clone(),
		timeout_secs: route_match.timeout_secs,
	});
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use opentelemetry::Value;

	use super::*;
	use crate::acl::AccessControl;
	use crate::config::{RouteConfig, TransportKind};
	use crate::proxy::router::Router;

	// Pointer to a backend label's backing string bytes. Two KeyValues sharing this pointer are backed
	// by the same Arc<str> allocation (an interned reuse), not independently heap-allocated.
	fn label_str_ptr(kv: &KeyValue) -> *const u8 {
		return match &kv.value {
			Value::String(s) => s.as_str().as_ptr(),
			_ => panic!("backend label value was not a string"),
		};
	}

	// The interned label must equal the naive construction so the exported metric series is identical (OtelString compares by content).
	#[test]
	fn backend_label_equals_uninterned_construction() {
		let labels: DashMap<ArrayString<256>, KeyValue> = DashMap::new();
		let id: ArrayString<256> = ArrayString::from("backend-db").unwrap();
		let interned: KeyValue = backend_label(&labels, &id);
		assert_eq!(interned, KeyValue::new("backend", "backend-db"));
		assert_eq!(interned, KeyValue::new("backend", String::from("backend-db")));
	}

	// Repeated lookups for one id reuse a single Arc<str> (same pointer); the control asserts the pre-intern
	// path allocated distinct pointers, so this fails against the old code rather than being a tautology.
	#[test]
	fn backend_label_reuses_one_allocation_per_id() {
		let labels: DashMap<ArrayString<256>, KeyValue> = DashMap::new();
		let id: ArrayString<256> = ArrayString::from("backend-db").unwrap();

		let first: KeyValue = backend_label(&labels, &id);
		let second: KeyValue = backend_label(&labels, &id);
		// Interned: both clones point at the same Arc<str> heap buffer.
		assert_eq!(label_str_ptr(&first), label_str_ptr(&second));
		// One entry created despite two lookups.
		assert_eq!(labels.len(), 1);

		// Control — the pre-intern path (fresh String per label) allocates twice: distinct buffers. Both
		// kept alive so the allocator cannot reuse the first address for the second.
		let naive_a: KeyValue = KeyValue::new("backend", String::from("backend-db"));
		let naive_b: KeyValue = KeyValue::new("backend", String::from("backend-db"));
		assert_ne!(label_str_ptr(&naive_a), label_str_ptr(&naive_b));

		// A distinct id gets its own entry.
		let other: ArrayString<256> = ArrayString::from("backend-cache").unwrap();
		let _ = backend_label(&labels, &other);
		assert_eq!(labels.len(), 2);
	}

	// completion_backend_label by borrow: "" maps to a static empty label, a known id resolves to the same interned Arc.
	#[test]
	fn completion_label_handles_empty_and_interned_ids() {
		let labels: DashMap<ArrayString<256>, KeyValue> = DashMap::new();
		let empty: KeyValue = completion_backend_label(&labels, "");
		assert_eq!(empty, KeyValue::new("backend", ""));
		assert_eq!(labels.len(), 0);

		let id: ArrayString<256> = ArrayString::from("backend-db").unwrap();
		let interned: KeyValue = backend_label(&labels, &id);
		let via_completion: KeyValue = completion_backend_label(&labels, "backend-db");
		assert_eq!(via_completion, KeyValue::new("backend", "backend-db"));
		assert_eq!(label_str_ptr(&interned), label_str_ptr(&via_completion));
	}

	fn make_reloadable_state(
		routes: &[(&str, &str)],
		backends: Vec<BackendConfig>,
	) -> watch::Receiver<ReloadableState> {
		let route_configs: Vec<RouteConfig> = routes
			.iter()
			.map(|(prefix, id)| RouteConfig {
				path_prefix: ArrayString::from(prefix).unwrap(),
				backend_id: ArrayString::from(id).unwrap(),
				timeout_secs: None,
			})
			.collect();

		let router = Router::new(&route_configs);
		let mut grouped: HashMap<ArrayString<256>, Vec<BackendConfig>> = HashMap::new();
		for b in backends {
			let key: ArrayString<256> = ArrayString::from(b.pool.as_str()).unwrap();
			grouped.entry(key).or_default().push(b);
		}
		let backend_pools: HashMap<ArrayString<256>, BackendPool> = grouped
			.into_iter()
			.map(|(id, bs)| (id, BackendPool::new(bs).unwrap()))
			.collect();

		let state = ReloadableState {
			router,
			backend_pools,
			acl: AccessControl::new(vec![], vec![]),
		};
		let (_tx, rx) = watch::channel(state);
		return rx;
	}

	#[test]
	fn test_resolve_backend_pool_success() {
		let backend = BackendConfig::new("api", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		let rx = make_reloadable_state(&[("/api", "api")], vec![backend]);
		let result = resolve_backend_pool(&rx, "/api/test");
		assert!(result.is_ok());
		let resolved = result.unwrap();
		assert_eq!(resolved.backend_id.as_str(), "api");
		assert_eq!(resolved.pool.backends.len(), 1);
		assert_eq!(resolved.timeout_secs, None);
	}

	#[test]
	fn test_resolve_backend_pool_no_route() {
		let backend = BackendConfig::new("api", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		let rx = make_reloadable_state(&[("/api", "api")], vec![backend]);
		let result = resolve_backend_pool(&rx, "/health");
		let resp = match result {
			Err(r) => r,
			Ok(_) => panic!("expected error response"),
		};
		assert_eq!(resp.status(), StatusCode::NOT_FOUND);
	}

	#[test]
	fn test_resolve_backend_pool_route_but_no_pool() {
		let route_configs = vec![RouteConfig {
			path_prefix: ArrayString::from("/api").unwrap(),
			backend_id: ArrayString::from("missing-pool").unwrap(),
			timeout_secs: None,
		}];
		let router = Router::new(&route_configs);
		let state = ReloadableState {
			router,
			backend_pools: HashMap::new(),
			acl: AccessControl::new(vec![], vec![]),
		};
		let (_tx, rx) = watch::channel(state);
		let result = resolve_backend_pool(&rx, "/api/test");
		let resp = match result {
			Err(r) => r,
			Ok(_) => panic!("expected error response"),
		};
		assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
	}

	#[test]
	fn test_select_backend_success() {
		let backend = BackendConfig::new("api", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		let pool = BackendPool::new(vec![backend]).unwrap();
		let health = HealthState::new();
		let (_tx, health_rx) = watch::channel(health);
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let conn_pool = ConnPool::new();

		let result = select_backend_excluding(&pool, ip, &health_rx, &conn_pool, &[]);
		assert!(result.is_ok());
		assert_eq!(result.unwrap().id.as_str(), "api");
	}

	#[test]
	fn test_mark_failed_dedupes_and_never_overflows() {
		let mut failed: ArrayVec<ArrayString<256>, MAX_BACKENDS> = ArrayVec::new();
		let id: ArrayString<256> = ArrayString::from("api").unwrap();
		// Far more pushes than capacity — dedup must keep the set at one entry and never panic.
		for _ in 0..(MAX_BACKENDS * 4) {
			mark_failed(&mut failed, id);
		}
		assert_eq!(failed.len(), 1);
		assert!(failed.contains(&id));
	}

	#[test]
	fn test_select_backend_excludes_tried() {
		let a = BackendConfig::new("api-a", "127.0.0.1:8080".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		let b = BackendConfig::new("api-b", "127.0.0.1:8081".parse().unwrap(), 1.0, TransportKind::Tcp).unwrap();
		let pool = BackendPool::new(vec![a, b]).unwrap();
		let health = HealthState::new();
		let (_tx, health_rx) = watch::channel(health);
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let conn_pool = ConnPool::new();

		let first: ArrayString<256> = select_backend_excluding(&pool, ip, &health_rx, &conn_pool, &[])
			.unwrap()
			.id;
		let second: ArrayString<256> = select_backend_excluding(&pool, ip, &health_rx, &conn_pool, &[first])
			.unwrap()
			.id;
		assert_ne!(first, second, "excluded backend was reselected");

		// Both excluded: no backend left to try.
		let none = select_backend_excluding(&pool, ip, &health_rx, &conn_pool, &[first, second]);
		assert!(none.is_err());
	}

	#[test]
	fn test_select_backend_empty_pool() {
		let pool = BackendPool::new(vec![]).unwrap();
		let health = HealthState::new();
		let (_tx, health_rx) = watch::channel(health);
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let conn_pool = ConnPool::new();

		let result = select_backend_excluding(&pool, ip, &health_rx, &conn_pool, &[]);
		assert!(result.is_err());
	}
}
