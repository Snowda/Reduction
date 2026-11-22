// The host and port policy a CONNECT target must pass before the gateway resolves it.
use std::num::NonZeroU16;

use super::authority::Target;
use super::denial::Denial;
use crate::config::{EgressConfig, HostPattern};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
	hosts: Vec<HostPattern>,
	ports: Vec<NonZeroU16>,
}

impl Allowlist {
	#[must_use]
	pub const fn new(hosts: Vec<HostPattern>, ports: Vec<NonZeroU16>) -> Self {
		return Self { hosts, ports };
	}

	#[must_use]
	pub fn from_config(config: &EgressConfig) -> Self {
		return Self::new(config.allow_hosts.clone(), config.allow_ports.clone());
	}

	// True when no target can pass: no host or no port is listed.
	#[must_use]
	pub const fn is_empty(&self) -> bool {
		return self.hosts.is_empty() || self.ports.is_empty();
	}

	#[must_use]
	pub const fn host_count(&self) -> usize {
		return self.hosts.len();
	}

	// The host is checked first, so a denied host is logged as such whatever its port.
	pub fn check(&self, target: &Target) -> Result<(), Denial> {
		if !self.hosts.iter().any(|pattern| pattern.matches(target.host.as_str())) {
			return Err(Denial::HostNotAllowed);
		}
		if !self.ports.contains(&target.port) {
			return Err(Denial::PortNotAllowed);
		}
		return Ok(());
	}
}

#[cfg(test)]
mod tests {
	use std::result::Result;

	use super::*;
	use crate::config::DEFAULT_EGRESS_PORT;

	fn allowlist(hosts: &[&str], ports: &[u16]) -> Result<Allowlist, String> {
		let hosts: Vec<HostPattern> = hosts.iter().map(|raw| HostPattern::parse(raw)).collect::<Result<_, String>>()?;
		let ports: Vec<NonZeroU16> =
			ports.iter().map(|port| NonZeroU16::new(*port).ok_or_else(|| format!("port {port} is zero"))).collect::<Result<_, String>>()?;
		return Ok(Allowlist::new(hosts, ports));
	}

	fn verdict(list: &Allowlist, authority: &str) -> Result<Result<(), Denial>, String> {
		let target: Target = Target::parse(authority).map_err(|denial| format!("parse '{authority}': {denial:?}"))?;
		return Ok(list.check(&target));
	}

	#[test]
	fn allowed_host_on_an_allowed_port_passes() -> Result<(), String> {
		let list: Allowlist = allowlist(&["github.com", "*.crates.io"], &[443])?;
		assert_eq!(verdict(&list, "github.com:443")?, Ok(()));
		assert_eq!(verdict(&list, "index.crates.io:443")?, Ok(()));
		assert_eq!(verdict(&list, "GitHub.COM:443")?, Ok(()), "the CONNECT host is case-folded before matching");
		return Ok(());
	}

	#[test]
	fn unlisted_host_is_refused_whatever_its_port() -> Result<(), String> {
		let list: Allowlist = allowlist(&["github.com"], &[443])?;
		assert_eq!(verdict(&list, "gitlab.com:443")?, Err(Denial::HostNotAllowed));
		assert_eq!(verdict(&list, "gitlab.com:22")?, Err(Denial::HostNotAllowed));
		assert_eq!(verdict(&list, "api.github.com:443")?, Err(Denial::HostNotAllowed));
		assert_eq!(verdict(&list, "crates.io:443")?, Err(Denial::HostNotAllowed));
		return Ok(());
	}

	#[test]
	fn allowed_host_on_another_port_is_refused() -> Result<(), String> {
		let list: Allowlist = allowlist(&["github.com"], &[443])?;
		assert_eq!(verdict(&list, "github.com:22")?, Err(Denial::PortNotAllowed));
		assert_eq!(verdict(&list, "github.com:80")?, Err(Denial::PortNotAllowed));
		let both: Allowlist = allowlist(&["github.com"], &[443, 8443])?;
		assert_eq!(verdict(&both, "github.com:8443")?, Ok(()));
		return Ok(());
	}

	#[test]
	fn from_config_keeps_the_hosts_and_the_default_port() -> Result<(), String> {
		let config: EgressConfig = toml::from_str("listen = \"127.0.0.1:3128\"\nallow_hosts = [\"github.com\"]")
			.map_err(|err| format!("parse: {err}"))?;
		let list: Allowlist = Allowlist::from_config(&config);
		assert_eq!(list, allowlist(&["github.com"], &[DEFAULT_EGRESS_PORT.get()])?);
		assert_eq!(verdict(&list, "github.com:443")?, Ok(()));
		assert_eq!(list.host_count(), 1);
		return Ok(());
	}

	#[test]
	fn a_list_without_hosts_or_ports_is_empty() -> Result<(), String> {
		assert!(allowlist(&[], &[443])?.is_empty(), "no host");
		assert!(allowlist(&["github.com"], &[])?.is_empty(), "no port");
		assert!(!allowlist(&["github.com"], &[443])?.is_empty());
		return Ok(());
	}
}
