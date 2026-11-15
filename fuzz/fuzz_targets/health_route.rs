// Raw bytes on a connection to the Ready health endpoint; see reduction_fuzz::probed::check.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::health_route(data);
});

#[cfg(not(fuzzing))]
fn main() {}
