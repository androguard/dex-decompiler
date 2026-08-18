//! Decompiler integration tests.
//!
//! - `equivalence`: decompilation output (minimal DEX, parse failures, optional fixtures).
//! - `control_flow`: return, if/else, while via minimal DEX with hand-crafted bytecode.
//! - `jadx_parity`: jadx integration-test style regression (conditions/loops/switch/try/generics/inner).
//! - `dataflow`: expected A/R, def_to_loc, du, ud, group_variables (same as androguard).

mod control_flow;
mod dataflow;
mod equivalence;
mod filters;
mod helpers;
mod imports;
mod jadx_parity;
mod pending_intent;
mod privacy_vuln_demo;
mod renames;
mod taint_solver;
mod value_flow;
