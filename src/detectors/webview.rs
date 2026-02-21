//! WebView: user input → loadUrl/loadDataWithBaseURL; and addJavascriptInterface.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{invoke_scan, source_sink_scan, VulnFinding};

const WEBVIEW_SOURCES: &[&str] = &[
    "getStringExtra",
    "getText",
    "getData",
    "getDataString",
];
const WEBVIEW_SINKS: &[&str] = &[
    "loadUrl",
    "loadDataWithBaseURL",
    "loadData",
];
const JAVASCRIPT_INTERFACE_PATTERNS: &[&str] = &["addJavascriptInterface"];

pub fn scan_webview_unsafe(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<VulnFinding> {
    let mut out = source_sink_scan(
        owned,
        class_name,
        method_name,
        "webview_unsafe_url",
        WEBVIEW_SOURCES,
        WEBVIEW_SINKS,
    );
    let js = invoke_scan(
        owned,
        class_name,
        method_name,
        "webview_javascript_interface",
        JAVASCRIPT_INTERFACE_PATTERNS,
    );
    out.extend(js);
    out
}
