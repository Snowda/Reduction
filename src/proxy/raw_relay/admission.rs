use std::net::IpAddr;

use crate::acl::AccessControl;
use crate::ratelimit::RateLimit;
use crate::tls::PeerIdentity;
use crate::tunnel::revocation::RevocationSet;

use super::{REJECT_REASON_ACL, REJECT_REASON_NO_IDENTITY, REJECT_REASON_RATE_LIMIT, REJECT_REASON_REVOKED};

// Pure admission policy for a raw relay stream (HTTP-path parity): returns the rejection reason or Ok, cheapest-first (ACL, rate limit, identity, revocation).
pub fn check_admission(
	acl: &AccessControl,
	rate_limiter: &RateLimit,
	client_ip: IpAddr,
	identity: Option<&PeerIdentity>,
	revocation: &RevocationSet,
) -> std::result::Result<(), &'static str> {
	if acl.check(client_ip).is_err() {
		return Err(REJECT_REASON_ACL);
	}
	if rate_limiter.check(client_ip).is_err() {
		return Err(REJECT_REASON_RATE_LIMIT);
	}
	// mTLS is mandatory, so a missing identity means the leaf CN was unparseable — refuse an unauthenticated peer.
	let Some(identity) = identity else {
		return Err(REJECT_REASON_NO_IDENTITY);
	};
	// Fleet-scale denial parity with the HTTP path: a revoked key SPKI or backend_id is refused even though the CA still trusts the cert.
	if revocation.is_revoked(identity) {
		return Err(REJECT_REASON_REVOKED);
	}
	return Ok(());
}

#[cfg(test)]
mod tests {
	use super::super::testutil::some_identity;
	use super::*;

	// A peer that clears every gate is admitted — the baseline; the rejection tests below differ from it.
	#[test]
	fn test_admission_allows_clean_peer() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rl: RateLimit = RateLimit::new(10).unwrap();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		assert!(check_admission(&acl, &rl, ip, Some(&some_identity()), &RevocationSet::default()).is_ok());
	}

	// An IP on the deny list is refused — the check the raw path used to skip entirely.
	#[test]
	fn test_admission_rejects_acl_blocked_ip() {
		let acl: AccessControl = AccessControl::new(vec![], vec!["10.0.0.0/8".parse().unwrap()]);
		let rl: RateLimit = RateLimit::new(10).unwrap();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		assert_eq!(
			check_admission(&acl, &rl, ip, Some(&some_identity()), &RevocationSet::default()).unwrap_err(),
			REJECT_REASON_ACL,
		);
	}

	// At 1 rps the first stream consumes the token and the second is throttled.
	#[test]
	fn test_admission_rejects_when_rate_limited() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rl: RateLimit = RateLimit::new(1).unwrap();
		let ip: IpAddr = "10.0.0.2".parse().unwrap();
		let id = some_identity();
		assert!(check_admission(&acl, &rl, ip, Some(&id), &RevocationSet::default()).is_ok());
		assert_eq!(
			check_admission(&acl, &rl, ip, Some(&id), &RevocationSet::default()).unwrap_err(),
			REJECT_REASON_RATE_LIMIT,
		);
	}

	// A peer whose mTLS leaf CN did not parse (no identity) is refused rather than relayed.
	#[test]
	fn test_admission_rejects_missing_identity() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rl: RateLimit = RateLimit::new(10).unwrap();
		let ip: IpAddr = "10.0.0.3".parse().unwrap();
		assert_eq!(
			check_admission(&acl, &rl, ip, None, &RevocationSet::default()).unwrap_err(),
			REJECT_REASON_NO_IDENTITY,
		);
	}

	// A revoked identity is refused (raw-relay revocation-bypass fix): some_identity()'s CN "device-1" is on the denylist.
	#[test]
	fn test_admission_rejects_revoked_identity() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rl: RateLimit = RateLimit::new(10).unwrap();
		let ip: IpAddr = "10.0.0.4".parse().unwrap();
		let revocation: RevocationSet =
			RevocationSet::parse("[[revoked]]\nbackend_id = \"device-1\"\nreason = \"clone detected\"\n").unwrap();
		assert_eq!(
			check_admission(&acl, &rl, ip, Some(&some_identity()), &revocation).unwrap_err(),
			REJECT_REASON_REVOKED,
		);
	}

	// Surgical: a non-revoked identity still admits even when the set is non-empty (names a different device).
	#[test]
	fn test_admission_admits_unrevoked_identity_with_nonempty_set() {
		let acl: AccessControl = AccessControl::new(vec![], vec![]);
		let rl: RateLimit = RateLimit::new(10).unwrap();
		let ip: IpAddr = "10.0.0.5".parse().unwrap();
		let revocation: RevocationSet =
			RevocationSet::parse("[[revoked]]\nbackend_id = \"some-other-device\"\nreason = \"x\"\n").unwrap();
		assert!(check_admission(&acl, &rl, ip, Some(&some_identity()), &revocation).is_ok());
	}

	// ACL precedes the rate limiter: a blocked IP reports the ACL reason even when a token is available.
	#[test]
	fn test_admission_acl_precedes_rate_limit() {
		let acl: AccessControl = AccessControl::new(vec![], vec!["10.0.0.0/8".parse().unwrap()]);
		let rl: RateLimit = RateLimit::new(1).unwrap();
		let ip: IpAddr = "10.0.0.9".parse().unwrap();
		assert_eq!(
			check_admission(&acl, &rl, ip, Some(&some_identity()), &RevocationSet::default()).unwrap_err(),
			REJECT_REASON_ACL,
		);
	}
}
