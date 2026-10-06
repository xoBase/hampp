#![no_main]
use hampp_core::{verify_text, SingleKey, Status};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let v = verify_text(data, &SingleKey([7u8; 32]), 0);
    assert_ne!(v.status, Status::Authenticated);
});
