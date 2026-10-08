//! What a scan needs out of angora/fuzzer/check_dep: the ASAN probe.
//!
//! `check_dep()` itself -- core_pattern, the target-binary and io-dir checks,
//! the fast/track instrumentation probes -- ran once from fuzz_main before the
//! fuzzing loop started. A scan never calls it, so only `check_asan` and the
//! two helpers under it are here. Both are unchanged.
//!
//! CommandOpt still asks whether the target is ASAN-built, because that
//! decides its memory limit.

use memmap;
use std::fs::File;
use twoway;

fn mmap_file(target: &str) -> memmap::Mmap {
    let file = File::open(target).expect("Unable to open file");
    unsafe {
        memmap::MmapOptions::new()
            .map(&file)
            .expect("unable to mmap file")
    }
}

fn containt_string(f_data: &memmap::Mmap, s: &str) -> bool {
    twoway::find_bytes(&f_data[..], s.as_bytes()).is_some()
}

pub fn check_asan(target: &str) -> bool {
    let f_data = mmap_file(target);
    containt_string(&f_data, "libasan.so") || containt_string(&f_data, "__msan_init")
}
