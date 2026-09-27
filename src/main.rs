use std::env;
use std::path::PathBuf;

use reduction::config::{self, ReductionConfig};
use reduction::error::{ReductionError, Result};

// Config hot-reload machinery (pool rebuild, state publish, backend drain) lives in a submodule.
mod config_reload;
// All process startup wiring (TLS, balancing, background tasks, serve/shutdown) lives in a submodule.
mod startup;

#[tokio::main]
async fn main() -> Result<()> {
	rustls::crypto::aws_lc_rs::default_provider()
		.install_default()
		.map_err(|_| ReductionError::Config("failed to install crypto provider".into()))?;

	// Program name plus a single config-path argument.
	const EXPECTED_ARG_COUNT: usize = 2;
	let args: Vec<String> = env::args().collect();

	if args.len() != EXPECTED_ARG_COUNT {
		return Err(ReductionError::Config("usage: reduction <config.toml>".into()));
	}

	let config_path: PathBuf = PathBuf::from(&args[1]);
	let config: ReductionConfig = config::load_config(&config_path)?;

	let tracer_provider = reduction::tracing_init::init_tracing(&config.tracing)?;

	let result = startup::run(config_path, config).await;

	reduction::tracing_init::shutdown_tracing(tracer_provider);

	return result;
}
