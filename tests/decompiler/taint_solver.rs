//! Tests for the Mariana-Trench–style taint solver.

use dex_decompiler::{default_config, TaintConfig};

#[test]
fn default_config_parses_and_has_rules() {
    let cfg = default_config();
    assert!(!cfg.sources.is_empty());
    assert!(!cfg.sinks.is_empty());
    assert!(!cfg.propagations.is_empty());
    assert!(!cfg.rules.is_empty());
    assert!(cfg.find_source("android.app.Activity.getIntent").is_some());
    assert!(cfg.find_sink("java.lang.Runtime.exec").is_some());
    let rules = cfg.matching_rules("ActivityUserInput", "CodeExecution");
    assert!(!rules.is_empty());
}

#[test]
fn merge_configs() {
    let mut base = default_config();
    let extra = TaintConfig::from_json_str(
        r#"{
          "sources": [{"patterns": ["MyApi.secret"], "kind": "CustomSource"}],
          "sinks": [{"patterns": ["MyApi.leak"], "port": {"argument": {"index": 0}}, "kind": "CustomSink"}],
          "rules": [{"name": "custom", "code": 99, "sources": ["CustomSource"], "sinks": ["CustomSink"]}]
        }"#,
    )
    .unwrap();
    base.merge(extra);
    assert!(base.find_source("com.foo.MyApi.secret").is_some());
    assert!(base.find_sink("com.foo.MyApi.leak").is_some());
    assert!(base.rules.iter().any(|r| r.code == 99));
}

#[test]
fn sanitizer_and_propagation_lookup() {
    let cfg = default_config();
    assert!(cfg.find_sanitizer("MessageDigest.digest").is_some());
    assert!(!cfg.find_propagations("StringBuilder.append").is_empty());
}
