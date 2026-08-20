//! Post-process decompiled method body to simplify invoke + move-result + return patterns.

mod util;
mod repair;
mod cleanup;
mod conditions;
mod loops;
mod try_catch;
mod expr;
mod pipeline;
mod format;
mod string_switch;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

pub use pipeline::simplify_method_body;
pub use format::{normalize_java_indent, simplify_synchronized_blocks};
pub use string_switch::{restore_string_switch, java_string_hash_code};
pub use try_catch::merge_duplicate_finally;
