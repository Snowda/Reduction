// Backend-list fixtures shared by the balancer and balancer::limits unit tests.
use std::net::SocketAddr;

use crate::config::{BackendConfig, TransportKind};

const BACKEND_PORT: u16 = 8080;

// Backend i sits at 10.0.(i / 256).(i % 256), so the first 65536 backends get distinct addresses.
pub fn make_backends(count: usize) -> Result<Vec<BackendConfig>, String> {
	return (0..=u8::MAX)
		.flat_map(|a: u8| (0..=u8::MAX).map(move |b: u8| SocketAddr::from(([10, 0, a, b], BACKEND_PORT))))
		.take(count)
		.enumerate()
		.map(|(i, addr): (usize, SocketAddr)| -> Result<BackendConfig, String> {
			return match BackendConfig::new(&format!("backend-{i}"), addr, 1.0, TransportKind::Tcp) {
				Ok(value) => Ok(value),
				Err(err) => Err(format!("BackendConfig::new(backend-{i}): {err:?}")),
			};
		})
		.collect();
}
