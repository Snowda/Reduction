// Raw bytes on a connection to the HTTP to HTTPS redirect listener; see reduction_fuzz::redirected::check.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::redirect(data);
});

#[cfg(not(fuzzing))]
fn main() {}
