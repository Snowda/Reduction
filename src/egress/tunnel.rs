// Resolve a vetted target once, refuse internal addresses, dial what passed, and splice the bytes.
use std::net::SocketAddr;
use std::result::Result as StdResult;
use std::time::Duration;

use arrayvec::ArrayVec;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::authority::Target;
use super::denial::Denial;
use super::internal::InternalGuard;
use crate::error::Result;
use crate::proxy::relay::{RelayStats, relay_bidirectional};

// Addresses kept from one lookup. Only these are vetted, and only vetted addresses are dialed.
pub const MAX_RESOLVED_ADDRS: usize = 16;

// One internal address refuses the whole answer. A name with public and internal addresses is a DNS
// rebind attempt or a bad record, and the gateway does not pick a side.
pub fn vet(
	resolved: impl IntoIterator<Item = SocketAddr>,
	guard: &InternalGuard,
) -> StdResult<ArrayVec<SocketAddr, MAX_RESOLVED_ADDRS>, Denial> {
	let addrs: ArrayVec<SocketAddr, MAX_RESOLVED_ADDRS> = resolved.into_iter().take(MAX_RESOLVED_ADDRS).collect();
	if addrs.is_empty() {
		return Err(Denial::ResolveFailed);
	}
	if !addrs.iter().all(|addr| guard.admits(addr.ip())) {
		return Err(Denial::PrivateAddress);
	}
	return Ok(addrs);
}

// The only lookup for this tunnel: the dial uses these addresses and never resolves the name again.
pub async fn resolve(
	target: &Target,
	guard: &InternalGuard,
) -> StdResult<ArrayVec<SocketAddr, MAX_RESOLVED_ADDRS>, Denial> {
	let resolved = lookup_host((target.host.as_str(), target.port.get())).await.map_err(|err| {
		debug!(%target, error = %err, "egress lookup failed");
		return Denial::ResolveFailed;
	})?;
	return vet(resolved, guard);
}

// Try each vetted address in order. `limit` bounds the whole attempt, not each address.
pub async fn dial(addrs: &[SocketAddr], limit: Duration) -> StdResult<TcpStream, Denial> {
	let attempt = async {
		for addr in addrs {
			match TcpStream::connect(addr).await {
				Ok(stream) => return Some(stream),
				Err(err) => debug!(%addr, error = %err, "egress dial failed"),
			}
		}
		return None;
	};
	return match timeout(limit, attempt).await {
		Ok(Some(stream)) => Ok(stream),
		Ok(None) => Err(Denial::ConnectFailed),
		Err(_) => Err(Denial::ConnectTimeout),
	};
}

// Client bytes are `a`, so `bytes_a_to_b` counts the upload and `bytes_b_to_a` the download.
pub async fn splice<U: AsyncRead + AsyncWrite + Unpin>(
	client: Upgraded,
	upstream: U,
	idle_timeout: Duration,
	shutdown: CancellationToken,
) -> Result<RelayStats> {
	return relay_bidirectional(TokioIo::new(client), upstream, idle_timeout, shutdown).await;
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr};
	use std::num::NonZeroU16;
	use std::result::Result;
	use std::str::FromStr;

	use arrayvec::ArrayString;
	use ipnet::IpNet;
	use tokio::net::TcpListener;

	use server_utils::ctx::Ctx;

	use super::*;

	// TEST-NET addresses are internal; these two are public and never dialed by `vet`.
	const PUBLIC_A: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
	const PUBLIC_B: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
	const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
	// TEST-NET-1 (RFC 5737) never answers a SYN, so a dial to it waits until its limit.
	const BLACKHOLE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
	// Windows retries a refused connect for about 2 s per address, so the limit leaves room for two.
	const SHORT_LIMIT: Duration = Duration::from_secs(10);

	fn target(host: &str, port: u16) -> Result<Target, String> {
		return Ok(Target {
			host: ArrayString::from(host).ctx("host")?,
			port: NonZeroU16::new(port).ok_or("zero port")?,
		});
	}

	#[test]
	fn vet_keeps_public_answers_in_order() -> Result<(), String> {
		let vetted = vet([PUBLIC_A, PUBLIC_B], &InternalGuard::default()).map_err(|d| format!("{d:?}"))?;
		assert_eq!(vetted.as_slice(), &[PUBLIC_A, PUBLIC_B]);
		return Ok(());
	}

	#[test]
	fn one_internal_answer_refuses_the_name() {
		assert_eq!(vet([PUBLIC_A, LOOPBACK], &InternalGuard::default()), Err(Denial::PrivateAddress));
		assert_eq!(vet([LOOPBACK], &InternalGuard::default()), Err(Denial::PrivateAddress));
	}

	#[test]
	fn an_exception_lets_its_internal_answer_through() -> Result<(), String> {
		let guard: InternalGuard = InternalGuard::new(vec![IpNet::from_str("127.0.0.1/32").map_err(|err| format!("{err}"))?]);
		let vetted = vet([LOOPBACK], &guard).map_err(|d| format!("{d:?}"))?;
		assert_eq!(vetted.as_slice(), &[LOOPBACK]);
		return Ok(());
	}

	#[test]
	fn an_empty_answer_is_a_resolve_failure_and_extras_are_dropped() -> Result<(), String> {
		assert_eq!(vet([], &InternalGuard::default()), Err(Denial::ResolveFailed));
		let many = vet([PUBLIC_A; MAX_RESOLVED_ADDRS + 4], &InternalGuard::default()).map_err(|d| format!("{d:?}"))?;
		assert_eq!(many.len(), MAX_RESOLVED_ADDRS, "the answer is capped, not a panic");
		return Ok(());
	}

	// The cap applies before the vet. An internal answer past the cap is not kept, so it is never dialed.
	#[test]
	fn an_internal_answer_past_the_cap_is_dropped_not_vetted() -> Result<(), String> {
		let mut answer: Vec<SocketAddr> = vec![PUBLIC_A; MAX_RESOLVED_ADDRS];
		answer.push(LOOPBACK);
		let vetted: ArrayVec<SocketAddr, MAX_RESOLVED_ADDRS> = match vet(answer, &InternalGuard::default()) {
			Ok(kept) => kept,
			Err(denial) => return Err(format!("the capped answer is all public, got {denial:?}")),
		};
		assert_eq!(vetted.len(), MAX_RESOLVED_ADDRS, "only the first answers are kept");
		assert!(!vetted.contains(&LOOPBACK), "the answer past the cap is not in the dial list");

		let mut inside: Vec<SocketAddr> = vec![PUBLIC_A; MAX_RESOLVED_ADDRS - 1];
		inside.push(LOOPBACK);
		assert_eq!(vet(inside, &InternalGuard::default()), Err(Denial::PrivateAddress), "the last kept answer is vetted");
		return Ok(());
	}

	// A name that resolves to loopback is refused even though resolution itself works.
	#[tokio::test]
	async fn localhost_resolves_and_is_refused_as_private() -> Result<(), String> {
		let outcome = resolve(&target("localhost", 443)?, &InternalGuard::default()).await;
		assert_eq!(outcome, Err(Denial::PrivateAddress));
		return Ok(());
	}

	#[tokio::test]
	async fn an_unresolvable_name_is_a_resolve_failure() -> Result<(), String> {
		let outcome = resolve(&target("no-such-host.invalid", 443)?, &InternalGuard::default()).await;
		assert_eq!(outcome, Err(Denial::ResolveFailed));
		return Ok(());
	}

	#[tokio::test]
	async fn dial_skips_a_dead_address_and_reaches_the_live_one() -> Result<(), String> {
		let live: TcpListener = TcpListener::bind("127.0.0.1:0").await.ctx("bind live")?;
		let live_addr: SocketAddr = live.local_addr().ctx("live addr")?;
		let dead: TcpListener = TcpListener::bind("127.0.0.1:0").await.ctx("bind dead")?;
		let dead_addr: SocketAddr = dead.local_addr().ctx("dead addr")?;
		drop(dead);
		let stream: TcpStream = dial(&[dead_addr, live_addr], SHORT_LIMIT).await.map_err(|d| format!("dial: {d:?}"))?;
		assert_eq!(stream.peer_addr().ctx("peer")?, live_addr);
		return Ok(());
	}

	#[tokio::test]
	async fn dial_with_every_address_dead_is_a_connect_failure() -> Result<(), String> {
		let dead: TcpListener = TcpListener::bind("127.0.0.1:0").await.ctx("bind")?;
		let dead_addr: SocketAddr = dead.local_addr().ctx("addr")?;
		drop(dead);
		assert_eq!(dial(&[dead_addr], SHORT_LIMIT).await.err(), Some(Denial::ConnectFailed));
		assert_eq!(dial(&[], SHORT_LIMIT).await.err(), Some(Denial::ConnectFailed));
		return Ok(());
	}

	// A zero limit raced a real dial. Paused time jumps to the limit while the SYN gets no answer.
	#[tokio::test(start_paused = true)]
	async fn dial_past_its_limit_is_a_connect_timeout() {
		assert_eq!(dial(&[BLACKHOLE], SHORT_LIMIT).await.err(), Some(Denial::ConnectTimeout));
	}
}
