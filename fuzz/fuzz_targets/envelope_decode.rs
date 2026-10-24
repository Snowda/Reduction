// Any input is refused with an Err or decodes to an Envelope that round-trips exactly; a panic or abort is the bug.
// Without `--cfg fuzzing` this is an empty main, so the workspace builds and tests on stable.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
	reduction_fuzz::envelope_decode(data);
});

#[cfg(not(fuzzing))]
fn main() {}
