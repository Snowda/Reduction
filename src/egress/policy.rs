// The checks a config reload can change: the client ACL, the host and port allowlist, and the
// internal-range exceptions. The listen address, timeouts and tunnel cap need a restart.
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::allowlist::Allowlist;
use super::internal::InternalGuard;
use crate::acl::AccessControl;
use crate::config::ReductionConfig;

#[derive(Clone)]
pub struct Policy {
	pub access: AccessControl,
	pub allowlist: Allowlist,
	pub guard: InternalGuard,
}

impl Policy {
	// A config without `[egress]` allows no host, so a reload that removes the section closes the gateway.
	#[must_use]
	pub fn from_config(config: &ReductionConfig) -> Self {
		let access: AccessControl = AccessControl::new(config.access.allow.iter().copied(), config.access.deny.iter().copied());
		return match config.egress.as_ref() {
			Some(egress) => Self {
				access,
				allowlist: Allowlist::from_config(egress),
				guard: InternalGuard::new(egress.allow_private_cidrs.clone()),
			},
			None => Self { access, allowlist: Allowlist::new(Vec::new(), Vec::new()), guard: InternalGuard::default() },
		};
	}
}

// Publish a new policy for each config the watcher sends. The watcher sends only configs that validated.
#[must_use]
pub fn spawn_policy_reload(
	mut config_rx: watch::Receiver<ReductionConfig>,
	policy_tx: watch::Sender<Arc<Policy>>,
	shutdown: &'static CancellationToken,
) -> JoinHandle<()> {
	return tokio::spawn(async move {
		loop {
			tokio::select! {
				changed = config_rx.changed() => {
					if changed.is_err() {
						return;
					}
				}
				() = shutdown.cancelled() => return,
			}
			let policy: Policy = Policy::from_config(&config_rx.borrow_and_update());
			if policy.allowlist.is_empty() {
				warn!("[egress] is gone from the reloaded config: the gateway refuses every tunnel until restart");
			} else {
				info!(hosts = policy.allowlist.host_count(), "egress policy reloaded");
			}
			if policy_tx.send(Arc::new(policy)).is_err() {
				return;
			}
		}
	});
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr};
	use std::time::Duration;

	use tokio::time::timeout;

	use super::*;
	use crate::egress::authority::Target;
	use crate::egress::denial::Denial;

	const STEP_TIMEOUT: Duration = Duration::from_secs(5);

	const BASE_TOML: &str = r#"
[listen]
address = "127.0.0.1:8443"
transport = "quic"

[tls.server.manual]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"
"#;

	fn config(extra: &str) -> Result<ReductionConfig, String> {
		return toml::from_str(&format!("{BASE_TOML}\n{extra}")).map_err(|err| format!("parse: {err}"));
	}

	fn egress(hosts: &str) -> String {
		return format!("[egress]\nlisten = \"127.0.0.1:3128\"\nallow_hosts = [{hosts}]\n");
	}

	fn verdict(policy: &Policy, authority: &str) -> Result<Result<(), Denial>, String> {
		let target: Target = Target::parse(authority).map_err(|denial| format!("parse '{authority}': {denial:?}"))?;
		return Ok(policy.allowlist.check(&target));
	}

	// A reload task and the channel ends that drive it.
	struct Reload {
		config_tx: watch::Sender<ReductionConfig>,
		policy_rx: watch::Receiver<Arc<Policy>>,
		shutdown: &'static CancellationToken,
		task: JoinHandle<()>,
	}

	fn reload(first: &ReductionConfig) -> Reload {
		let (config_tx, config_rx): (watch::Sender<ReductionConfig>, watch::Receiver<ReductionConfig>) =
			watch::channel(first.clone());
		let (policy_tx, policy_rx): (watch::Sender<Arc<Policy>>, watch::Receiver<Arc<Policy>>) =
			watch::channel(Arc::new(Policy::from_config(first)));
		let shutdown: &'static CancellationToken = Box::leak(Box::new(CancellationToken::new()));
		let task: JoinHandle<()> = spawn_policy_reload(config_rx, policy_tx, shutdown);
		return Reload { config_tx, policy_rx, shutdown, task };
	}

	fn send(config_tx: &watch::Sender<ReductionConfig>, config: ReductionConfig) -> Result<(), String> {
		return config_tx.send(config).map_err(|_| "the reload task dropped its receiver".to_owned());
	}

	async fn republished(policy_rx: &mut watch::Receiver<Arc<Policy>>) -> Result<Arc<Policy>, String> {
		timeout(STEP_TIMEOUT, policy_rx.changed())
			.await
			.map_err(|_| "no policy was republished".to_owned())?
			.map_err(|_| "the policy sender closed".to_owned())?;
		return Ok(Arc::clone(&policy_rx.borrow_and_update()));
	}

	// The task must stop once `cause` happens.
	async fn ends(task: JoinHandle<()>, cause: &str) -> Result<(), String> {
		return timeout(STEP_TIMEOUT, task)
			.await
			.map_err(|_| format!("the task outlived {cause}"))?
			.map_err(|err| format!("join: {err}"));
	}

	#[test]
	fn from_config_carries_every_reloadable_check() -> Result<(), String> {
		let fenced: String = format!("[access]\ndeny = [\"10.0.0.0/8\"]\n{}allow_private_cidrs = [\"10.1.0.0/16\"]\n", egress("\"github.com\""));
		let policy: Policy = Policy::from_config(&config(&fenced)?);
		assert_eq!(verdict(&policy, "github.com:443")?, Ok(()));
		assert_eq!(verdict(&policy, "gitlab.com:443")?, Err(Denial::HostNotAllowed));
		assert!(policy.access.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_err(), "the [access] deny list is in the policy");
		assert!(policy.guard.admits(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), "the exception is in the policy");
		assert!(!policy.guard.admits(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))), "only the excepted range passes");
		return Ok(());
	}

	#[test]
	fn without_an_egress_section_no_host_is_allowed() -> Result<(), String> {
		let policy: Policy = Policy::from_config(&config("")?);
		assert!(policy.allowlist.is_empty(), "no section, no allowed host");
		assert_eq!(verdict(&policy, "github.com:443")?, Err(Denial::HostNotAllowed));
		return Ok(());
	}

	// A sent config becomes the published policy, and the published policy then admits the new host.
	#[tokio::test]
	async fn a_reloaded_config_republishes_the_policy() -> Result<(), String> {
		let mut reload: Reload = reload(&config(&egress("\"github.com\""))?);
		assert_eq!(verdict(&reload.policy_rx.borrow_and_update(), "gitlab.com:443")?, Err(Denial::HostNotAllowed));
		send(&reload.config_tx, config(&egress("\"gitlab.com\""))?)?;
		let reloaded: Arc<Policy> = republished(&mut reload.policy_rx).await?;
		assert_eq!(verdict(&reloaded, "gitlab.com:443")?, Ok(()), "the new host is allowed");
		assert_eq!(verdict(&reloaded, "github.com:443")?, Err(Denial::HostNotAllowed), "the old host is not");

		reload.shutdown.cancel();
		return ends(reload.task, "shutdown").await;
	}

	// A reload that removes [egress] closes the gateway. It does not keep the old allowlist.
	#[tokio::test]
	async fn a_reload_without_egress_publishes_a_policy_that_allows_no_host() -> Result<(), String> {
		let mut reload: Reload = reload(&config(&egress("\"github.com\""))?);
		send(&reload.config_tx, config("")?)?;
		let reloaded: Arc<Policy> = republished(&mut reload.policy_rx).await?;
		assert!(reloaded.allowlist.is_empty(), "the old allowlist must not survive the section");
		assert_eq!(verdict(&reloaded, "github.com:443")?, Err(Denial::HostNotAllowed));
		return Ok(());
	}

	// No config can arrive after the watcher closes, so the task stops.
	#[tokio::test]
	async fn the_reload_task_ends_when_the_config_sender_drops() -> Result<(), String> {
		let reload: Reload = reload(&config(&egress("\"github.com\""))?);
		drop(reload.config_tx);
		return ends(reload.task, "its config sender").await;
	}

	// No one can read a policy after the last receiver drops, so the next reload stops the task.
	#[tokio::test]
	async fn the_reload_task_ends_when_no_one_reads_the_policy() -> Result<(), String> {
		let reload: Reload = reload(&config(&egress("\"github.com\""))?);
		drop(reload.policy_rx);
		send(&reload.config_tx, config(&egress("\"gitlab.com\""))?)?;
		return ends(reload.task, "its last policy reader").await;
	}
}
