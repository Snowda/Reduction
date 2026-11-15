// Raw backend bytes through fastlane's response-head parser and body framing, checked against hyper's client.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::fastlane_response(data);
});

#[cfg(not(fuzzing))]
fn main() {}
