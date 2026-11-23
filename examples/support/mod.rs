// The examples share this module. It adds error context for `?` and makes the log layer for the demo text.

use std::fmt::Display;

use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer, fmt};

// The demo text (the crate target of the example) shows at info; the caller picks the level for library logs.
const NARRATION_LEVEL: &str = "info";

/// Add the name of the failed step to an error, so that the `main` of a demo can return it as `Err(String)`.
pub trait Context<T> {
	fn context(self, what: &str) -> Result<T, String>;
}

impl<T, E: Display> Context<T> for Result<T, E> {
	#[inline]
	fn context(self, what: &str) -> Result<T, String> {
		return match self {
			Ok(value) => Ok(value),
			Err(e) => Err(format!("{what}: {e}")),
		};
	}
}

impl<T> Context<T> for Option<T> {
	#[inline]
	fn context(self, what: &str) -> Result<T, String> {
		return match self {
			Some(value) => Ok(value),
			None => Err(format!("{what}: missing")),
		};
	}
}

/// The stdout layer for the demo text. The lints deny `println!`, so the demos write through tracing.
pub fn output_layer<S>(library_level: &str) -> impl Layer<S>
where
	S: Subscriber + for<'span> LookupSpan<'span>,
{
	let filter: EnvFilter = EnvFilter::new(format!(
		"{library_level},{}={NARRATION_LEVEL}",
		env!("CARGO_CRATE_NAME")
	));
	return fmt::layer().with_target(false).without_time().with_filter(filter);
}
