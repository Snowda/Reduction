// A raw HTTP/1.1 request through the whole proxy; reduction_fuzz::proxied::check states the invariant.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::proxy_request(data);
});

#[cfg(not(fuzzing))]
fn main() {}
