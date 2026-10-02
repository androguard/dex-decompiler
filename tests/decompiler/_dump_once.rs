use super::fixture_harness::{decompile_fixtures_dex, method_region};

#[test]
fn dump_focus_methods() {
    let java = decompile_fixtures_dex();
    for m in [
        "assignTernary",
        "breakInLoop",
        "xorStream",
        "constantTimeEquals",
        "switchOnString",
        "merge",
        "bubbleSort",
        "castsAndInstanceof",
        "doubleConst",
        "tryFinally",
        "builderChain",
        "demoAlgorithms",
    ] {
        eprintln!("===== {m} =====\n{}\n", method_region(&java, m));
    }
}
