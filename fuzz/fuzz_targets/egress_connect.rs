// Raw bytes to the egress CONNECT gateway. `$PORT` in the input names the echo port.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::egress_connect(data);
});

#[cfg(not(fuzzing))]
fn main() {}
