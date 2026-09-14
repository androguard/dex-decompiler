//! Plan §13.10 — slice decompile vs full DEX.

use dex_bytecode::decode_all;
use dex_decompiler::{
    getclass_java, parse_dex, slice_class_from_input, to_dalvik_descriptor, Decompiler,
    DecompilerOptions,
};
use dex_parser::DexFile;
use std::path::PathBuf;

fn fixtures_dex() -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/decompiler_fixtures/classes.dex");
    std::fs::read(&p).unwrap_or_else(|_| panic!("missing {}", p.display()))
}

fn resolved_disasm(dex: &DexFile, data: &[u8], code_off: u32) -> Vec<String> {
    let code = dex.get_code_item(code_off).unwrap();
    let insns = code.insns_slice(data);
    decode_all(insns, 0)
        .unwrap()
        .into_iter()
        .map(|insn| {
            let o = insn.offset as usize;
            let extra = match insn.opcode {
                0x1a => {
                    let idx = u16::from_le_bytes([insns[o + 2], insns[o + 3]]) as u32;
                    format!(" string={}", dex.get_string(idx).unwrap_or_default())
                }
                0x1b => {
                    let idx = u32::from_le_bytes(insns[o + 2..o + 6].try_into().unwrap());
                    format!(" string={}", dex.get_string(idx).unwrap_or_default())
                }
                0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25 => {
                    let idx = u16::from_le_bytes([insns[o + 2], insns[o + 3]]) as u32;
                    format!(" type={}", dex.get_type(idx).unwrap_or_default())
                }
                0x52..=0x6d => {
                    let idx = u16::from_le_bytes([insns[o + 2], insns[o + 3]]) as u32;
                    let f = dex.get_field_info(idx).unwrap();
                    format!(" field={}->{}:{}", f.class, f.name, f.typ)
                }
                0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb => {
                    let idx = u16::from_le_bytes([insns[o + 2], insns[o + 3]]) as u32;
                    let m = dex.get_method_info(idx).unwrap();
                    format!(
                        " method={}->{}({}){}",
                        m.class,
                        m.name,
                        m.params.join(""),
                        m.return_type
                    )
                }
                _ => String::new(),
            };
            // Strip pool indices from operands for stable compare: keep mnemonic + regs only.
            let ops = insn
                .operands
                .split(',')
                .map(|p| {
                    let p = p.trim();
                    if p.contains('@') {
                        // drop string@N / method@N style tails if present
                        p.split_whitespace()
                            .filter(|t| !t.contains('@'))
                            .collect::<Vec<_>>()
                            .join(" ")
                    } else {
                        p.to_string()
                    }
                })
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} {}{}", insn.mnemonic, ops, extra)
        })
        .collect()
}

#[test]
fn slice_resolved_insns_match_source() {
    let data = fixtures_dex();
    let src = parse_dex(&data).unwrap();
    for r in src.class_defs() {
        let cd = r.unwrap();
        let desc = src.get_type(cd.class_idx).unwrap();
        let sliced = match slice_class_from_input(&data, &desc) {
            Ok(b) => b,
            Err(e) if e.to_string().contains("UnsupportedRef") || e.to_string().contains("unsupported") => {
                continue;
            }
            Err(e) => panic!("slice {desc}: {e}"),
        };
        let out = DexFile::parse(&sliced).unwrap();
        let out_cd = out.get_class_def(0).unwrap();
        let src_data = src.get_class_data(&cd).unwrap();
        let out_data = out.get_class_data(&out_cd).unwrap();
        let (Some(a), Some(b)) = (src_data, out_data) else { continue };
        for (sm, om) in a
            .direct_methods
            .iter()
            .chain(a.virtual_methods.iter())
            .zip(b.direct_methods.iter().chain(b.virtual_methods.iter()))
        {
            if sm.code_off == 0 {
                continue;
            }
            let si = src.get_method_info(sm.method_idx).unwrap();
            let left = resolved_disasm(&src, &data, sm.code_off);
            let right = resolved_disasm(&out, &sliced, om.code_off);
            assert_eq!(left, right, "{desc}#{} resolved insns", si.name);
        }
    }
}

#[test]
fn getclass_java_matches_on_stable_classes() {
    let data = fixtures_dex();
    let opts = DecompilerOptions {
        use_debug_names: false,
        ..DecompilerOptions::default()
    };
    let stable = [
        "com.androguard.decompilefixtures.ConstFixtures",
        "com.androguard.decompilefixtures.ArrayFixtures",
        "com.androguard.decompilefixtures.MainActivity",
        "com.androguard.decompilefixtures.LambdaFixtures",
        "com.androguard.decompilefixtures.EnumFixtures$Color",
    ];
    let dex = parse_dex(&data).unwrap();
    let full = Decompiler::with_options(&dex, opts.clone());
    for name in stable {
        let desc = to_dalvik_descriptor(name);
        let cd = dex
            .class_defs()
            .find_map(|r| {
                let c = r.ok()?;
                (dex.get_type(c.class_idx).ok()?.as_str() == desc).then_some(c)
            })
            .unwrap_or_else(|| panic!("missing {name}"));
        let from_full = full.decompile_class(&cd).unwrap();
        let from_slice = getclass_java(&data, name, opts.clone()).unwrap();
        assert_eq!(from_slice, from_full, "Java mismatch for {name}");
    }
}
