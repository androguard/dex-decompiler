//! Regression: Kotlin `use` / `CloseableKt.closeFinally` must not drop `Log.d`
//! on the success path of `mastgTestMediaStore` (MASTG-DEMO-0001).
//!
//! Fixture: `testdata/mastg_demo_0001/MastgTest.dex` (sliced from the demo APK).

use dex_decompiler::{getclass_java, DecompilationMode, DecompilerOptions};
use std::path::PathBuf;

fn fixture_dex() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/mastg_demo_0001/MastgTest.dex")
}

fn method_body<'a>(java: &'a str, name: &str) -> &'a str {
    let marker = format!("void {name}");
    let start = java.find(&marker).unwrap_or_else(|| panic!("missing {name}"));
    let rest = &java[start..];
    let end = rest.find("\n    public ").unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn mastg_demo_0001_mediastore_keeps_log_d() {
    let dex_path = fixture_dex();
    assert!(
        dex_path.exists(),
        "missing fixture {}",
        dex_path.display()
    );
    let bytes = std::fs::read(&dex_path).expect("read fixture dex");
    let java = getclass_java(
        &bytes,
        "org.owasp.mastestapp.MastgTest",
        DecompilerOptions {
            mode: DecompilationMode::Restructure,
            ..DecompilerOptions::default()
        },
    )
    .expect("getclass");
    let body = method_body(&java, "mastgTestMediaStore");
    assert!(
        body.contains("Log.d") || body.contains("android.util.Log.d"),
        "Log.d missing from restructure output:\n{body}"
    );
    assert!(
        body.contains("File written to external storage successfully"),
        "success log message missing:\n{body}"
    );
}
