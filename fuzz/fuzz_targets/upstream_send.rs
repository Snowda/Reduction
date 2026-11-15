// A backend selector byte, then a raw request through the connection pool; see reduction_fuzz::upstream::check.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::upstream_send(data);
});

#[cfg(not(fuzzing))]
fn main() {}
