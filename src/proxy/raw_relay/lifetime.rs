use std::net::IpAddr;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::proxy::handler::ReloadableState;
use crate::tls::PeerIdentity;
use crate::tunnel::revocation::RevocationSet;

// Cancel `token` once `identity` is revoked (admission checks it only once); exits cleanly on cancel or sender drop.
pub async fn cancel_on_revocation(
	mut revocation_rx: watch::Receiver<RevocationSet>,
	identity: PeerIdentity,
	token: CancellationToken,
) {
	loop {
		let revoked: bool = revocation_rx.borrow().is_revoked(&identity);
		if revoked {
			token.cancel();
			return;
		}
		tokio::select! {
			_ = token.cancelled() => return,
			changed = revocation_rx.changed() => {
				if changed.is_err() {
					return;
				}
			}
		}
	}
}

// Cancel `token` once an [access] hot-reload denies `client_ip`; watches the reloadable channel, exits cleanly on cancel/drop.
pub async fn cancel_on_acl_denial(
	mut reloadable_rx: watch::Receiver<ReloadableState>,
	client_ip: IpAddr,
	token: CancellationToken,
) {
	loop {
		let denied: bool = reloadable_rx.borrow().acl.check(client_ip).is_err();
		if denied {
			token.cancel();
			return;
		}
		tokio::select! {
			_ = token.cancelled() => return,
			changed = reloadable_rx.changed() => {
				if changed.is_err() {
					return;
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::time::Duration;

	use tokio::time::timeout;

	use super::super::testutil::some_identity;
	use super::*;
	use crate::acl::AccessControl;
	use crate::proxy::router::Router;

	// Must cancel the relay token the moment the identity lands on the set (raw-path revocation-bypass fix).
	#[tokio::test]
	async fn test_cancel_on_revocation_fires_when_identity_revoked() {
		let identity: PeerIdentity = some_identity(); // CN "device-1"
		let (tx, rx) = watch::channel(RevocationSet::default());
		let token: CancellationToken = CancellationToken::new();
		let handle = tokio::spawn(cancel_on_revocation(rx, identity, token.clone()));

		// Empty set: the relay token stays live.
		assert!(!token.is_cancelled(), "an unrevoked identity must not cancel the relay");

		// Publish a set revoking device-1; the watcher must cancel the relay token.
		tx.send(RevocationSet::parse("[[revoked]]\nbackend_id = \"device-1\"\nreason = \"clone\"\n").unwrap())
			.unwrap();

		timeout(Duration::from_secs(5), token.cancelled())
			.await
			.expect("relay token must be cancelled once the identity is revoked");
		assert!(token.is_cancelled());
		let _ = handle.await;
	}

	// When the relay ends it cancels the token; the watcher must then exit, not linger (no task leak per completed relay).
	#[tokio::test]
	async fn test_cancel_on_revocation_exits_when_relay_ends() {
		let identity: PeerIdentity = some_identity();
		let (_tx, rx) = watch::channel(RevocationSet::default());
		let token: CancellationToken = CancellationToken::new();
		let handle = tokio::spawn(cancel_on_revocation(rx, identity, token.clone()));

		token.cancel(); // simulate the relay completing
		timeout(Duration::from_secs(5), handle)
			.await
			.expect("watcher must exit promptly when the relay token is cancelled")
			.unwrap();
	}

	// A non-revoking update (different device) must NOT cancel the token — the watcher cancels only on this identity.
	#[tokio::test]
	async fn test_cancel_on_revocation_ignores_unrelated_update() {
		let identity: PeerIdentity = some_identity(); // CN "device-1"
		let (tx, rx) = watch::channel(RevocationSet::default());
		let token: CancellationToken = CancellationToken::new();
		let handle = tokio::spawn(cancel_on_revocation(rx, identity, token.clone()));

		tx.send(RevocationSet::parse("[[revoked]]\nbackend_id = \"other-device\"\nreason = \"x\"\n").unwrap())
			.unwrap();

		// Give the watcher a moment to process the update, then assert it did not cancel.
		tokio::time::sleep(Duration::from_millis(100)).await;
		assert!(
			!token.is_cancelled(),
			"revoking a different device must not tear down this relay"
		);

		token.cancel(); // clean up the watcher
		let _ = handle.await;
	}

	// Build a minimal ReloadableState carrying `acl` (empty router/pools) for the ACL-watcher tests.
	fn reloadable_with_acl(acl: AccessControl) -> ReloadableState {
		return ReloadableState {
			router: Router::new(&[]),
			backend_pools: HashMap::new(),
			acl,
		};
	}

	// Must cancel the relay token the moment a hot-reload denies its source IP (raw-path parallel to the HTTP re-check).
	#[tokio::test]
	async fn test_cancel_on_acl_denial_fires_when_ip_denied() {
		let client_ip: IpAddr = "10.0.0.1".parse().unwrap();
		let (tx, rx) = watch::channel(reloadable_with_acl(AccessControl::new(vec![], vec![])));
		let token: CancellationToken = CancellationToken::new();
		let handle = tokio::spawn(cancel_on_acl_denial(rx, client_ip, token.clone()));

		// Permissive ACL: the relay token stays live.
		assert!(!token.is_cancelled(), "a permitted IP must not cancel the relay");

		// Publish an ACL denying 10.0.0.0/8; the watcher must cancel the relay token.
		tx.send(reloadable_with_acl(AccessControl::new(
			vec![],
			vec!["10.0.0.0/8".parse().unwrap()],
		)))
		.unwrap();

		timeout(Duration::from_secs(5), token.cancelled())
			.await
			.expect("relay token must be cancelled once the IP is denied");
		assert!(token.is_cancelled());
		let _ = handle.await;
	}

	// When the relay ends it cancels the token; the watcher must then exit rather than linger until the
	// next config reload (no task leak per completed relay).
	#[tokio::test]
	async fn test_cancel_on_acl_denial_exits_when_relay_ends() {
		let client_ip: IpAddr = "10.0.0.1".parse().unwrap();
		let (_tx, rx) = watch::channel(reloadable_with_acl(AccessControl::new(vec![], vec![])));
		let token: CancellationToken = CancellationToken::new();
		let handle = tokio::spawn(cancel_on_acl_denial(rx, client_ip, token.clone()));

		token.cancel(); // simulate the relay completing
		timeout(Duration::from_secs(5), handle)
			.await
			.expect("watcher must exit promptly when the relay token is cancelled")
			.unwrap();
	}

	// A reload that does NOT deny this IP (still permissive) must not cancel the relay token — the watcher
	// fires only on a denial of this specific source IP.
	#[tokio::test]
	async fn test_cancel_on_acl_denial_ignores_permitting_reload() {
		let client_ip: IpAddr = "10.0.0.1".parse().unwrap();
		let (tx, rx) = watch::channel(reloadable_with_acl(AccessControl::new(vec![], vec![])));
		let token: CancellationToken = CancellationToken::new();
		let handle = tokio::spawn(cancel_on_acl_denial(rx, client_ip, token.clone()));

		// A reload denying a different subnet leaves 10.0.0.1 permitted.
		tx.send(reloadable_with_acl(AccessControl::new(
			vec![],
			vec!["192.168.0.0/16".parse().unwrap()],
		)))
		.unwrap();

		// Give the watcher a moment to process the update, then assert it did not cancel.
		tokio::time::sleep(Duration::from_millis(100)).await;
		assert!(
			!token.is_cancelled(),
			"denying a different subnet must not tear down this relay"
		);

		token.cancel(); // clean up the watcher
		let _ = handle.await;
	}
}
