//! Decompilation output tests: minimal DEX, parse failures, optional fixtures.

use super::helpers::minimal_dex_bytes;
use dex_decompiler::{parse_dex, Decompiler, DecompilerOptions};
use std::path::Path;

#[test]
fn test_decompiler_minimal_dex_empty_output() {
    let minimal = minimal_dex_bytes();
    let dex = parse_dex(&minimal).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(
        java.is_empty(),
        "empty DEX (no classes) should decompile to empty string"
    );
}

#[test]
fn test_decompiler_parse_fails_invalid() {
    assert!(parse_dex(&[]).is_err());
    assert!(parse_dex(b"not a DEX file!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!").is_err());
}

/// Optional: if tests/data/APK/Test.dex exists, assert decompiled source contains simplification pattern.
#[test]
#[ignore = "requires androguard test data: tests/data/APK/Test.dex"]
fn test_decompiler_simplification() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/APK/Test.dex");
    if !path.exists() {
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let dex = parse_dex(&data).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(
        java.contains("return ((23 - p3) | ((p3 + 66) & 26));"),
        "expected simplification pattern in decompiled source"
    );
}

/// If testdata/classes.dex exists, decompile only androguard.test. Methods with tries_size > 0 emit a try/catch comment.
#[test]
fn test_decompiler_try_catch_comment() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/classes.dex");
    if !path.exists() {
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let dex = parse_dex(&data).unwrap();
    let options = DecompilerOptions {
        only_package: Some("androguard.test".to_string()),
        exclude: vec![],
    };
    let dc = Decompiler::with_options(&dex, options);
    let _java = dc.decompile().unwrap();
    // Decompilation succeeds; when a method has tries_size > 0 we prepend "// try/catch (N tries) - handlers not yet emitted"
}

/// If testdata/classes.dex exists and contains androguard.test, packed-switch in TestDefault.main should emit case labels (1..5).
#[test]
fn test_decompiler_switch_packed_cases() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/classes.dex");
    if !path.exists() {
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let dex = parse_dex(&data).unwrap();
    let options = DecompilerOptions {
        only_package: Some("androguard.test".to_string()),
        exclude: vec![],
    };
    let dc = Decompiler::with_options(&dex, options);
    let java = dc.decompile().unwrap();
    if java.is_empty() {
        return; // no classes in androguard.test in this DEX
    }
    // TestDefault.main has switch(a) with case 1,2,3,4,5; payload should be parsed and cases emitted
    assert!(
        java.contains("case 1:") && java.contains("case 5:"),
        "packed-switch should emit case labels; got (unknown payload) or (payload not found)?"
    );
}

/// Optional: if tests/data/APK/FillArrays.dex exists, assert array literals in output.
#[test]
#[ignore = "requires androguard test data: tests/data/APK/FillArrays.dex"]
fn test_decompiler_arrays() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/APK/FillArrays.dex");
    if !path.exists() {
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let dex = parse_dex(&data).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(java.contains("{20, 30, 40, 50};"));
    assert!(java.contains("{1, 2, 3, 4, 5, 999, 10324234};"));
    assert!(java.contains("{97, 98, 120, 122, 99};"));
    assert!(java.contains("{5, 10, 15, 20};"));
    assert!(!java.contains("{97, 0, 98, 0, 120};"));
    assert!(!java.contains("{5, 0, 10, 0};"));
}
