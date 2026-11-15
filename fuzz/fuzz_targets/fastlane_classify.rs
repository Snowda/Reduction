// A raw client head through fastlane's request classifier, checked against hyper's server and forward path.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::fastlane_classify(data);
});

#[cfg(not(fuzzing))]
fn main() {}
