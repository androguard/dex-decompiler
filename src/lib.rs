//! DEX to Java decompiler in pure Rust.
//! Uses dex-bytecode for Dalvik instruction disassembly and dex-parser for DEX parsing.

pub mod error;
pub mod decompile;
pub mod java;

pub use dex_parser::{ClassDef, CodeItem, DexFile, EncodedMethod};
pub use error::{DexDecompilerError, Result};
pub use decompile::{
    CfgEdgeInfo, CfgNodeInfo, Decompiler, DecompilerOptions, MethodBytecodeRow,
};
pub use decompile::value_flow::{ValueFlowAnalysis, ValueFlowAnalysisOwned, ValueFlowResult};
pub use decompile::pending_intent::{PendingIntentFinding, scan_pending_intents};

/// Parse a DEX file from raw bytes. Returns decompiler Result (maps parser errors to Parse).
pub fn parse_dex(data: &[u8]) -> Result<DexFile> {
    DexFile::parse(data).map_err(|e| DexDecompilerError::Parse(e.to_string()))
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn parse_empty_fails() {
        let r = parse_dex(&[]);
        assert!(r.is_err());
    }

    #[test]
    fn parse_garbage_fails() {
        let r = parse_dex(b"not a DEX file!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        assert!(r.is_err());
    }
}
