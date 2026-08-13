//! Vulnerability detectors: one module per detector, shared types and run_all.
//!
//! Each detector lives in its own `.rs` file. Use `run_all_detectors` to run
//! every detector (except PendingIntent, which has its own finding type and CLI flag).

mod hardcoded_secrets;
mod insecure_logging;
mod intent_spoofing;
mod ipc_intent_validation;
mod path_traversal;
pub mod pending_intent;
mod rce_dynamic_loading;
mod sql_injection;
mod types;
mod unsafe_deserialization;
mod weak_crypto;
mod webview;

pub use hardcoded_secrets::scan_hardcoded_secrets;
pub use insecure_logging::scan_insecure_logging;
pub use intent_spoofing::scan_intent_spoofing;
pub use ipc_intent_validation::scan_ipc_intent_validation;
pub use path_traversal::scan_path_traversal;
pub use pending_intent::{scan_pending_intents, PendingIntentFinding};
pub use rce_dynamic_loading::scan_rce_dynamic_loading;
pub use sql_injection::scan_sql_injection;
pub use types::{
    category_meta, invoke_scan, method_matches_any, source_sink_scan, CategoryMeta, VulnFinding,
    VulnTraceStep,
};
pub use unsafe_deserialization::scan_unsafe_deserialization;
pub use weak_crypto::scan_weak_crypto;
pub use webview::scan_webview_unsafe;

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::decompile::Decompiler;
use crate::java::descriptor_to_java;
use dex_parser::{DexFile, EncodedMethod};
use rayon::prelude::*;
use std::collections::HashSet;

/// True for Android platform / AndroidX / common SDK library classes (not app code).
/// Used so vuln detectors do not flag androidx.* / android.* noise.
pub fn is_library_class(class_name: &str) -> bool {
    let n = class_name.trim();
    n == "android"
        || n.starts_with("android.")
        || n == "androidx"
        || n.starts_with("androidx.")
        || n.starts_with("android.support.")
        || n == "java"
        || n.starts_with("java.")
        || n == "javax"
        || n.starts_with("javax.")
        || n == "kotlin"
        || n.starts_with("kotlin.")
        || n == "kotlinx"
        || n.starts_with("kotlinx.")
        || n.starts_with("dalvik.")
        || n.starts_with("libcore.")
        || n.starts_with("sun.")
        || n.starts_with("com.android.")
        || n.starts_with("com.google.android.")
        || n.starts_with("com.google.common.")
        || n.starts_with("com.google.gson.")
        || n.starts_with("com.google.protobuf.")
        || n.starts_with("com.google.firebase.")
        || n.starts_with("com.fasterxml.")
        || n.starts_with("okhttp3.")
        || n.starts_with("okio.")
        || n.starts_with("retrofit2.")
        || n.starts_with("com.squareup.")
        || n.starts_with("io.reactivex.")
        || n.starts_with("org.apache.")
        || n.starts_with("org.jetbrains.")
        || n.starts_with("org.json.")
        || n.starts_with("org.xmlpull.")
        || n.starts_with("org.bouncycastle.")
        || n.starts_with("org.chromium.")
        || n.starts_with("com.facebook.react.")
        || n.starts_with("com.facebook.fresco.")
        || n.starts_with("com.facebook.imagepipeline.")
        || n.starts_with("com.facebook.yoga.")
        || n.starts_with("com.facebook.soloader.")
        || n.starts_with("com.facebook.jni.")
        || n.starts_with("com.facebook.common.")
        || n.starts_with("com.facebook.infer.")
}

/// One method with enough metadata to run detectors in parallel.
#[derive(Clone)]
struct MethodJob {
    class_name: String,
    method_name: String,
    encoded: EncodedMethod,
}

fn collect_method_jobs(dex: &DexFile) -> Vec<MethodJob> {
    let mut jobs = Vec::new();
    for class_result in dex.class_defs() {
        let Ok(class_def) = class_result else { continue };
        let Ok(class_type) = dex.get_type(class_def.class_idx) else { continue };
        let class_name = descriptor_to_java(&class_type);
        if is_library_class(&class_name) {
            continue;
        }
        let Ok(Some(class_data)) = dex.get_class_data(&class_def) else { continue };
        for encoded in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            if encoded.code_off == 0 {
                continue;
            }
            let Ok(method_info) = dex.get_method_info(encoded.method_idx) else {
                continue;
            };
            jobs.push(MethodJob {
                class_name: class_name.clone(),
                method_name: method_info.name.to_string(),
                encoded: encoded.clone(),
            });
        }
    }
    jobs
}

/// Run all detectors (except PendingIntent) and return findings, deduplicated by category+class+method+sink_offset.
pub fn run_all_detectors(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
    logging_sources: Option<&[String]>,
) -> Vec<VulnFinding> {
    let mut all = Vec::new();
    all.extend(scan_intent_spoofing(owned, class_name, method_name));
    all.extend(scan_rce_dynamic_loading(owned, class_name, method_name));
    all.extend(scan_insecure_logging(owned, class_name, method_name, logging_sources));
    all.extend(scan_sql_injection(owned, class_name, method_name));
    all.extend(scan_webview_unsafe(owned, class_name, method_name));
    all.extend(scan_hardcoded_secrets(owned, class_name, method_name));
    all.extend(scan_ipc_intent_validation(owned, class_name, method_name));
    all.extend(scan_path_traversal(owned, class_name, method_name));
    all.extend(scan_weak_crypto(owned, class_name, method_name));
    all.extend(scan_unsafe_deserialization(owned, class_name, method_name));
    let mut seen: HashSet<(String, String, String, u32)> = HashSet::new();
    all.into_iter()
        .filter(|f| {
            let key = (
                f.category.clone(),
                f.class_name.clone(),
                f.method_name.clone(),
                f.sink_offset,
            );
            seen.insert(key)
        })
        .collect()
}

/// Parallel scan of every method with code in `dex` using the standard detectors.
///
/// Each rayon worker creates its own [`Decompiler`] (`!Sync` caches).
pub fn scan_dex_parallel(
    dex: &DexFile,
    logging_sources: Option<&[String]>,
) -> Vec<VulnFinding> {
    let jobs = collect_method_jobs(dex);
    let logging = logging_sources.map(|s| s.to_vec());
    jobs.par_iter()
        .flat_map(|job| {
            let decompiler = Decompiler::new(dex);
            let Ok(owned) = decompiler.value_flow_analysis(&job.encoded) else {
                return Vec::new();
            };
            run_all_detectors(
                &owned,
                &job.class_name,
                &job.method_name,
                logging.as_deref(),
            )
        })
        .collect()
}

/// Parallel PendingIntent scan over every method with code in `dex`.
pub fn scan_pending_intents_dex_parallel(dex: &DexFile) -> Vec<PendingIntentFinding> {
    let jobs = collect_method_jobs(dex);
    jobs.par_iter()
        .flat_map(|job| {
            let decompiler = Decompiler::new(dex);
            let Ok(owned) = decompiler.value_flow_analysis(&job.encoded) else {
                return Vec::new();
            };
            scan_pending_intents(&owned, &job.class_name, &job.method_name)
        })
        .collect()
}
