//! Fuzz target: the CSV report parser (mta `postmaster::snds::parse_csv`).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_tests::fuzz_api::csv_report(&String::from_utf8_lossy(data));
});
