//! Decompiler integration tests.
//!
//! - `equivalence`: decompilation output (minimal DEX, parse failures, optional fixtures).
//! - `control_flow`: return, if/else, while via minimal DEX with hand-crafted bytecode.
//! - `dataflow`: expected A/R, def_to_loc, du, ud, group_variables (same as androguard).

mod control_flow;
mod dataflow;
mod equivalence;
mod filters;
mod helpers;
mod value_flow;
