// Why the gateway refused a CONNECT, and the status each refusal answers with.
use http::StatusCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Denial {
	// The client address fails the `[access]` ACL.
	ClientNotAllowed = 0,
	// Any method but CONNECT: plain-HTTP forwarding is a non-goal.
	MethodNotAllowed = 1,
	// No authority, no port, a userinfo part, or a host that is not a DNS name.
	Malformed = 2,
	HostNotAllowed = 3,
	PortNotAllowed = 4,
	// The name resolved to a loopback, private, link-local or other internal address.
	PrivateAddress = 5,
	ResolveFailed = 6,
	ConnectFailed = 7,
	ConnectTimeout = 8,
	// `max_tunnels` tunnels are open.
	AtCapacity = 9,
	// The client went over its `[ratelimit]` share of CONNECT requests.
	RateLimited = 10,
	// The QUIC uplink to the remote gateway did not connect, open a stream or answer in time.
	UplinkUnavailable = 11,
}

impl Denial {
	pub const ALL: [Self; 12] = [
		Self::ClientNotAllowed,
		Self::MethodNotAllowed,
		Self::Malformed,
		Self::HostNotAllowed,
		Self::PortNotAllowed,
		Self::PrivateAddress,
		Self::ResolveFailed,
		Self::ConnectFailed,
		Self::ConnectTimeout,
		Self::AtCapacity,
		Self::RateLimited,
		Self::UplinkUnavailable,
	];

	// The refusal a remote gateway sent: its label body, at the status that label answers with.
	#[must_use]
	pub fn from_reply(status: StatusCode, label: &str) -> Option<Self> {
		return Self::ALL.into_iter().find(|denial| denial.label() == label && denial.status() == status);
	}

	#[must_use]
	pub const fn status(self) -> StatusCode {
		return match self {
			Self::ClientNotAllowed | Self::HostNotAllowed | Self::PortNotAllowed | Self::PrivateAddress => {
				StatusCode::FORBIDDEN
			}
			Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
			Self::Malformed => StatusCode::BAD_REQUEST,
			Self::ResolveFailed | Self::ConnectFailed | Self::UplinkUnavailable => StatusCode::BAD_GATEWAY,
			Self::ConnectTimeout => StatusCode::GATEWAY_TIMEOUT,
			Self::AtCapacity => StatusCode::SERVICE_UNAVAILABLE,
			Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
		};
	}

	// Stable label for the audit log and the `reason` attribute of the denial metric.
	#[must_use]
	pub const fn label(self) -> &'static str {
		return match self {
			Self::ClientNotAllowed => "client_not_allowed",
			Self::MethodNotAllowed => "method_not_allowed",
			Self::Malformed => "malformed",
			Self::HostNotAllowed => "host_not_allowed",
			Self::PortNotAllowed => "port_not_allowed",
			Self::PrivateAddress => "private_address",
			Self::ResolveFailed => "resolve_failed",
			Self::ConnectFailed => "connect_failed",
			Self::ConnectTimeout => "connect_timeout",
			Self::AtCapacity => "at_capacity",
			Self::RateLimited => "rate_limited",
			Self::UplinkUnavailable => "uplink_unavailable",
		};
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const ALL: [Denial; 12] = Denial::ALL;

	// Every policy refusal is a 403, so a client cannot tell a denied host from a denied address.
	#[test]
	fn policy_refusals_are_forbidden_and_failures_are_gateway_errors() {
		let statuses: [u16; 12] = ALL.map(|denial| denial.status().as_u16());
		assert_eq!(statuses, [403, 405, 400, 403, 403, 403, 502, 502, 504, 503, 429, 502]);
	}

	#[test]
	fn a_reply_maps_back_only_at_its_own_status() {
		ALL.iter().for_each(|denial| {
			assert_eq!(Denial::from_reply(denial.status(), denial.label()), Some(*denial), "{denial:?} round-trips");
		});
		assert_eq!(Denial::from_reply(StatusCode::BAD_GATEWAY, "host_not_allowed"), None, "a label at the wrong status");
		assert_eq!(Denial::from_reply(StatusCode::FORBIDDEN, "no_such_reason"), None, "an unknown label");
	}

	#[test]
	fn labels_are_unique_snake_case() {
		let labels: [&str; 12] = ALL.map(Denial::label);
		labels.iter().enumerate().for_each(|(index, label)| {
			assert!(label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "'{label}' is not snake_case");
			assert!(!labels[..index].contains(label), "'{label}' is used twice");
		});
	}
}
