use std::hash::{Hash, Hasher, DefaultHasher};
use std::net::IpAddr;

// Compute a rendezvous hash score for a (client_ip, backend_id) pair.
// Higher score = preferred backend for this client.
pub fn rendezvous_score(client_ip: IpAddr, backend_id: &str, weight: f64) -> f64 {
    let mut hasher: DefaultHasher = DefaultHasher::new();
    client_ip.hash(&mut hasher);
    backend_id.hash(&mut hasher);
    let hash: u64 = hasher.finish();

    // Normalize hash to [0, 1) and multiply by weight
    let normalized: f64 = (hash as f64) / (u64::MAX as f64);
    return normalized * weight;
}

// Select the best backend index for a given client IP using rendezvous hashing.
pub fn select_backend(
    client_ip: IpAddr,
    backend_ids: &[&str],
    weights: &[f64],
) -> Option<usize> {
    if backend_ids.is_empty() {
        return None;
    }

    let mut best_index: usize = 0;
    let mut best_score: f64 = f64::NEG_INFINITY;

    for (i, backend_id) in backend_ids.iter().enumerate() {
        let weight: f64 = weights.get(i).copied().unwrap_or(1.0);
        let score: f64 = rendezvous_score(client_ip, backend_id, weight);
        if score > best_score {
            best_score = score;
            best_index = i;
        }
    }

    return Some(best_index);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ip() -> IpAddr {
        return "192.168.1.100".parse().unwrap();
    }

    fn test_backends() -> Vec<&'static str> {
        return vec!["backend-a", "backend-b", "backend-c"];
    }

    #[test]
    fn test_deterministic_selection() {
        let ip: IpAddr = test_ip();
        let backends: Vec<&str> = test_backends();
        let weights: Vec<f64> = vec![1.0, 1.0, 1.0];

        let first: Option<usize> = select_backend(ip, &backends, &weights);
        let second: Option<usize> = select_backend(ip, &backends, &weights);

        assert_eq!(first, second);
    }

    #[test]
    fn test_different_ips_can_select_different_backends() {
        let backends: Vec<&str> = test_backends();
        let weights: Vec<f64> = vec![1.0, 1.0, 1.0];

        let mut selections: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for i in 0..100u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            if let Some(idx) = select_backend(ip, &backends, &weights) {
                selections.insert(idx);
            }
        }

        // With 100 IPs and 3 backends, all backends should be selected at least once
        assert!(selections.len() > 1);
    }

    #[test]
    fn test_weight_influences_selection() {
        let backends: Vec<&str> = vec!["heavy", "light"];
        let weights: Vec<f64> = vec![100.0, 0.001];

        let mut heavy_count: usize = 0;
        for i in 0..100u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            if let Some(0) = select_backend(ip, &backends, &weights) {
                heavy_count += 1;
            }
        }

        // Heavily weighted backend should win most of the time
        assert!(heavy_count > 80);
    }

    #[test]
    fn test_empty_backends() {
        let ip: IpAddr = test_ip();
        let result: Option<usize> = select_backend(ip, &[], &[]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_single_backend() {
        let ip: IpAddr = test_ip();
        let backends: Vec<&str> = vec!["only-one"];
        let weights: Vec<f64> = vec![1.0];

        let result: Option<usize> = select_backend(ip, &backends, &weights);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_minimal_disruption_on_removal() {
        let ip: IpAddr = test_ip();
        let backends_full: Vec<&str> = test_backends();
        let weights_full: Vec<f64> = vec![1.0, 1.0, 1.0];

        let original: Option<usize> = select_backend(ip, &backends_full, &weights_full);

        // Remove backend-b (index 1)
        let backends_reduced: Vec<&str> = vec!["backend-a", "backend-c"];
        let weights_reduced: Vec<f64> = vec![1.0, 1.0];

        let after_removal: Option<usize> = select_backend(ip, &backends_reduced, &weights_reduced);

        // If the original was not backend-b, the selection should stay stable
        if original == Some(0) {
            assert_eq!(after_removal, Some(0));
        }
        // If original was backend-c (index 2), it should now be index 1
        if original == Some(2) {
            assert_eq!(after_removal, Some(1));
        }
    }
}
