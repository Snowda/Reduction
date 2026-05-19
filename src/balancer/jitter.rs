use std::hash::{Hash, Hasher, DefaultHasher};
use std::net::IpAddr;

use arrayvec::ArrayVec;

use super::MAX_BACKENDS;

// Generate a deterministic jitter multiplier from a client IP.
// Returns a value in the range [1 - factor, 1 + factor].
pub fn ip_jitter(client_ip: IpAddr, backend_id: &str, factor: f64) -> f64 {
    let mut hasher: DefaultHasher = DefaultHasher::new();
    client_ip.hash(&mut hasher);
    backend_id.hash(&mut hasher);
    // Use a different seed than rendezvous by mixing in a constant
    0xDEAD_BEEF_u64.hash(&mut hasher);
    let hash: u64 = hasher.finish();

    let normalized: f64 = (hash as f64) / (u64::MAX as f64);

    // Map [0, 1) to [1 - factor, 1 + factor]
    return 1.0 + factor * (2.0 * normalized - 1.0);
}

// Apply jitter to a set of base weights for a given client IP.
pub fn apply_jitter(
    client_ip: IpAddr,
    backend_ids: &[&str],
    base_weights: &[f64],
    jitter_factor: f64,
) -> ArrayVec<f64, MAX_BACKENDS> {
    return backend_ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let base: f64 = base_weights.get(i).copied().unwrap_or(1.0);
            let jitter: f64 = ip_jitter(client_ip, id, jitter_factor);
            return base * jitter;
        })
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_deterministic() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let j1: f64 = ip_jitter(ip, "backend-a", 0.1);
        let j2: f64 = ip_jitter(ip, "backend-a", 0.1);
        assert_eq!(j1, j2);
    }

    #[test]
    fn test_jitter_in_range() {
        let factor: f64 = 0.1;
        for i in 0..100u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let j: f64 = ip_jitter(ip, "test", factor);
            assert!(j >= 1.0 - factor, "jitter {j} below minimum");
            assert!(j <= 1.0 + factor, "jitter {j} above maximum");
        }
    }

    #[test]
    fn test_jitter_varies_by_ip() {
        let mut values: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for i in 0..50u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let j: f64 = ip_jitter(ip, "test", 0.1);
            values.insert(j.to_bits());
        }
        assert!(values.len() > 10);
    }

    #[test]
    fn test_apply_jitter_preserves_count() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ids: Vec<&str> = vec!["a", "b", "c"];
        let weights: Vec<f64> = vec![1.0, 2.0, 3.0];

        let jittered: ArrayVec<f64, MAX_BACKENDS> = apply_jitter(ip, &ids, &weights, 0.05);
        assert_eq!(jittered.len(), 3);
    }

    #[test]
    fn test_zero_jitter_preserves_weights() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ids: Vec<&str> = vec!["a", "b"];
        let weights: Vec<f64> = vec![1.0, 2.0];

        let jittered: ArrayVec<f64, MAX_BACKENDS> = apply_jitter(ip, &ids, &weights, 0.0);
        assert!((jittered[0] - 1.0).abs() < f64::EPSILON);
        assert!((jittered[1] - 2.0).abs() < f64::EPSILON);
    }
}
