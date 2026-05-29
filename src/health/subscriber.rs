use tokio::sync::watch;
use tracing::{info, warn};

use super::state::{HealthBroadcast, HealthState};

pub struct HealthSubscriber {
    health_tx: watch::Sender<HealthState>,
}

impl HealthSubscriber {
    pub fn new(health_tx: watch::Sender<HealthState>) -> Self {
        return Self { health_tx };
    }

    pub fn handle_message(&self, data: &[u8]) {
        match bitcode::decode::<HealthBroadcast>(data) {
            Ok(broadcast) => {
                let backend_count: usize = broadcast.entries.len();
                self.health_tx.send_modify(|state| {
                    state.update(broadcast);
                });
                info!(backend_count, "updated health state");
            }
            Err(e) => {
                warn!(error = %e, "failed to decode health broadcast");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use arrayvec::ArrayString;

    use super::*;
    use crate::health::state::{Availability, BackendHealth, HealthBroadcast};

    #[test]
    fn test_subscriber_handle_valid_message() {
        let (tx, rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
            watch::channel(HealthState::new());
        let subscriber: HealthSubscriber = HealthSubscriber::new(tx);

        let broadcast: HealthBroadcast = HealthBroadcast {
            entries: vec![BackendHealth {
                backend_id: ArrayString::from("api").unwrap(),
                load: 0.5,
                latency_ms: 100,
                availability: Availability::Online,
            }],
        };

        let encoded: Vec<u8> = bitcode::encode(&broadcast);
        subscriber.handle_message(&encoded);

        let health_ref: watch::Ref<'_, HealthState> = rx.borrow();
        let health: &BackendHealth = health_ref.get("api").unwrap();
        assert!(health.availability.is_online());
        assert_eq!(health.load, 0.5);
    }

    #[test]
    fn test_subscriber_handle_invalid_message() {
        let (tx, rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
            watch::channel(HealthState::new());
        let subscriber: HealthSubscriber = HealthSubscriber::new(tx);

        subscriber.handle_message(&[0xFF, 0xFE, 0xFD]);

        let health_ref: watch::Ref<'_, HealthState> = rx.borrow();
        assert!(health_ref.get("api").is_none());
    }

    #[test]
    fn test_subscriber_multiple_updates() {
        let (tx, rx): (watch::Sender<HealthState>, watch::Receiver<HealthState>) =
            watch::channel(HealthState::new());
        let subscriber: HealthSubscriber = HealthSubscriber::new(tx);

        let broadcast1: HealthBroadcast = HealthBroadcast {
            entries: vec![BackendHealth {
                backend_id: ArrayString::from("api").unwrap(),
                load: 0.3,
                latency_ms: 50,
                availability: Availability::Online,
            }],
        };

        let broadcast2: HealthBroadcast = HealthBroadcast {
            entries: vec![BackendHealth {
                backend_id: ArrayString::from("api").unwrap(),
                load: 0.9,
                latency_ms: 500,
                availability: Availability::Online,
            }],
        };

        subscriber.handle_message(&bitcode::encode(&broadcast1));
        subscriber.handle_message(&bitcode::encode(&broadcast2));

        let health_ref: watch::Ref<'_, HealthState> = rx.borrow();
        let health: &BackendHealth = health_ref.get("api").unwrap();
        assert_eq!(health.load, 0.9);
    }
}
