// Raw chunked body bytes through fastlane's ChunkedDecoder, checked against itself split and against hyper.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::fastlane_chunked(data);
});

#[cfg(not(fuzzing))]
fn main() {}
