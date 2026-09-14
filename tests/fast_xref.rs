//! Plan §13.11 — fast method callers ≡ slow callers.

use dex_decompiler::xref::{find_method_callers, find_method_callers_fast};
use dex_parser::DexFile;
use std::collections::HashSet;
use std::path::PathBuf;

fn fixture_dex() -> DexFile {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/androguard_test_classes.dex");
    let data = std::fs::read(&p).unwrap_or_else(|_| panic!("missing {}", p.display()));
    DexFile::parse(&data).expect("parse fixture")
}

#[test]
fn find_method_callers_fast_matches_slow() {
    let dex = fixture_dex();
    let n = dex.header.method_ids_size.min(200);
    for idx in 0..n {
        let slow = find_method_callers(&dex, idx).expect("slow");
        let fast = find_method_callers_fast(&dex, idx).expect("fast");
        let slow_set: HashSet<(u32, u32)> = slow
            .callers
            .iter()
            .map(|c| (c.caller_method_idx, c.callee_method_idx))
            .collect();
        let fast_set: HashSet<(u32, u32)> = fast
            .callers
            .iter()
            .map(|c| (c.caller_method_idx, c.callee_method_idx))
            .collect();
        assert_eq!(
            slow_set, fast_set,
            "caller set mismatch for method_idx={idx}"
        );
    }
}
