use std::io;

#[derive(Debug, thiserror::Error)]
pub enum ReductionError {
    #[error("config: {0}")]
    Config(String),

    #[error("config parse: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("transport: {0}")]
    Transport(String),

    #[error("backend unavailable")]
    BackendUnavailable,

    #[error("queue full")]
    QueueFull,

    #[error("rate limited")]
    RateLimited,

    #[error("forward: {0}")]
    Forward(String),
}

pub type Result<T> = std::result::Result<T, ReductionError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_config() {
        let err: ReductionError = ReductionError::Config("bad path".to_string());
        assert_eq!(format!("{err}"), "config: bad path");
    }

    #[test]
    fn test_error_display_transport() {
        let err: ReductionError = ReductionError::Transport("connection refused".to_string());
        assert_eq!(format!("{err}"), "transport: connection refused");
    }

    #[test]
    fn test_error_display_backend_unavailable() {
        let err: ReductionError = ReductionError::BackendUnavailable;
        assert_eq!(format!("{err}"), "backend unavailable");
    }

    #[test]
    fn test_error_display_queue_full() {
        let err: ReductionError = ReductionError::QueueFull;
        assert_eq!(format!("{err}"), "queue full");
    }

    #[test]
    fn test_error_display_rate_limited() {
        let err: ReductionError = ReductionError::RateLimited;
        assert_eq!(format!("{err}"), "rate limited");
    }

    #[test]
    fn test_error_from_io() {
        let io_err: io::Error = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err: ReductionError = ReductionError::from(io_err);
        assert!(format!("{err}").contains("not found"));
    }
}
