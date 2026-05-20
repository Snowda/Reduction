use std::net::IpAddr;

use ipnet::IpNet;
use tracing::warn;

use crate::error::{ReductionError, Result};

pub struct AccessControl {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
    mode: AclMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclMode {
    /// No rules configured — allow everything.
    Disabled,
    /// Allow list present — default-deny, only listed CIDRs pass.
    AllowList,
    /// Deny list only — default-allow, listed CIDRs blocked.
    DenyList,
    /// Both lists present — deny checked first, then allow, default-deny.
    Both,
}

impl AccessControl {
    pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Self {
        let mode: AclMode = match (allow.is_empty(), deny.is_empty()) {
            (true, true) => AclMode::Disabled,
            (false, true) => AclMode::AllowList,
            (true, false) => AclMode::DenyList,
            (false, false) => AclMode::Both,
        };
        return Self { allow, deny, mode };
    }

    pub fn check(&self, ip: IpAddr) -> Result<()> {
        return match self.mode {
            AclMode::Disabled => Ok(()),
            AclMode::AllowList => {
                if self.is_allowed(ip) {
                    Ok(())
                } else {
                    warn!(%ip, "access denied: not in allow list");
                    Err(ReductionError::AccessDenied)
                }
            }
            AclMode::DenyList => {
                if self.is_denied(ip) {
                    warn!(%ip, "access denied: in deny list");
                    Err(ReductionError::AccessDenied)
                } else {
                    Ok(())
                }
            }
            AclMode::Both => {
                if self.is_denied(ip) {
                    warn!(%ip, "access denied: in deny list");
                    Err(ReductionError::AccessDenied)
                } else if self.is_allowed(ip) {
                    Ok(())
                } else {
                    warn!(%ip, "access denied: not in allow list");
                    Err(ReductionError::AccessDenied)
                }
            }
        };
    }

    fn is_allowed(&self, ip: IpAddr) -> bool {
        return self.allow.iter().any(|net| net.contains(&ip));
    }

    fn is_denied(&self, ip: IpAddr) -> bool {
        return self.deny.iter().any(|net| net.contains(&ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_net(s: &str) -> IpNet {
        return s.parse().unwrap();
    }

    #[test]
    fn test_disabled_allows_everything() {
        let acl: AccessControl = AccessControl::new(vec![], vec![]);
        assert!(acl.check("10.0.0.1".parse().unwrap()).is_ok());
        assert!(acl.check("192.168.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_allowlist_permits_matching_ip() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.0/24")],
            vec![],
        );
        assert!(acl.check("10.0.0.1".parse().unwrap()).is_ok());
        assert!(acl.check("10.0.0.254".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_allowlist_rejects_non_matching_ip() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.0/24")],
            vec![],
        );
        assert!(acl.check("192.168.1.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_denylist_blocks_matching_ip() {
        let acl: AccessControl = AccessControl::new(
            vec![],
            vec![parse_net("10.0.0.0/24")],
        );
        assert!(acl.check("10.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_denylist_allows_non_matching_ip() {
        let acl: AccessControl = AccessControl::new(
            vec![],
            vec![parse_net("10.0.0.0/24")],
        );
        assert!(acl.check("192.168.1.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_both_deny_takes_precedence() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.0/16")],
            vec![parse_net("10.0.1.0/24")],
        );
        // In allow range but also in deny range — deny wins
        assert!(acl.check("10.0.1.5".parse().unwrap()).is_err());
        // In allow range, not in deny range — allowed
        assert!(acl.check("10.0.0.5".parse().unwrap()).is_ok());
    }

    #[test]
    fn test_both_rejects_unlisted() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.0/24")],
            vec![parse_net("192.168.0.0/16")],
        );
        // Not in either list — default-deny
        assert!(acl.check("172.16.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_single_host_cidr() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.1/32")],
            vec![],
        );
        assert!(acl.check("10.0.0.1".parse().unwrap()).is_ok());
        assert!(acl.check("10.0.0.2".parse().unwrap()).is_err());
    }

    #[test]
    fn test_ipv6_allowlist() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("fd00::/64")],
            vec![],
        );
        assert!(acl.check("fd00::1".parse().unwrap()).is_ok());
        assert!(acl.check("fe80::1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_mixed_ipv4_ipv6() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.0/8"), parse_net("fd00::/64")],
            vec![],
        );
        assert!(acl.check("10.1.2.3".parse().unwrap()).is_ok());
        assert!(acl.check("fd00::1".parse().unwrap()).is_ok());
        assert!(acl.check("192.168.1.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_multiple_allow_ranges() {
        let acl: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.0/24"), parse_net("172.16.0.0/12")],
            vec![],
        );
        assert!(acl.check("10.0.0.5".parse().unwrap()).is_ok());
        assert!(acl.check("172.20.1.1".parse().unwrap()).is_ok());
        assert!(acl.check("192.168.1.1".parse().unwrap()).is_err());
    }

    #[test]
    fn test_mode_detection() {
        let disabled: AccessControl = AccessControl::new(vec![], vec![]);
        assert_eq!(disabled.mode, AclMode::Disabled);

        let allow_only: AccessControl = AccessControl::new(vec![parse_net("10.0.0.0/8")], vec![]);
        assert_eq!(allow_only.mode, AclMode::AllowList);

        let deny_only: AccessControl = AccessControl::new(vec![], vec![parse_net("10.0.0.0/8")]);
        assert_eq!(deny_only.mode, AclMode::DenyList);

        let both: AccessControl = AccessControl::new(
            vec![parse_net("10.0.0.0/8")],
            vec![parse_net("192.168.0.0/16")],
        );
        assert_eq!(both.mode, AclMode::Both);
    }
}
