//! Parse DEX try_item and encoded_catch_handler to emit try/catch blocks.
//! CodeItem in dex-parser does not expose tries/handlers; we parse from raw bytes.

use dex_parser::CodeItem;
use std::convert::TryInto;

/// One try range: [start_addr, start_addr + insn_count) in 16-bit code units.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

/// One catch: exception type (type_idx) and handler bytecode address (16-bit units).
#[derive(Debug, Clone)]
pub struct EncodedTypeAddr {
    pub type_idx: u32,
    pub addr: u32,
}

/// One encoded_catch_handler: list of typed catches and optional catch-all.
#[derive(Debug, Clone)]
pub struct EncodedCatchHandler {
    pub handlers: Vec<EncodedTypeAddr>,
    pub catch_all_addr: Option<u32>,
}

fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        if *pos >= data.len() {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    Some(result)
}

fn read_sleb128(data: &[u8], pos: &mut usize) -> Option<i32> {
    let mut result: i32 = 0;
    let mut shift = 0;
    let mut size = 0;
    loop {
        if *pos >= data.len() {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        size += 1;
        result |= ((b & 0x7f) as i32) << shift;
        if b & 0x80 == 0 {
            if shift < 32 && (b & 0x40) != 0 {
                result |= !0 << (shift + 7);
            }
            break;
        }
        shift += 7;
        if size >= 5 {
            return None;
        }
    }
    Some(result)
}

/// Parse try_item array and encoded_catch_handler_list from code_item.
/// code_off is the file offset where the code_item starts.
pub fn parse_tries_and_handlers(
    data: &[u8],
    code_off: u32,
    code: &CodeItem,
) -> Option<(Vec<TryItem>, Vec<EncodedCatchHandler>)> {
    if code.tries_size == 0 {
        return Some((vec![], vec![]));
    }
    let code_off = code_off as usize;
    let insns_len = (code.insns_size as usize).saturating_mul(2);
    let mut tries_start = code_off + 16 + insns_len;
    if (code.insns_size as usize) % 2 == 1 {
        tries_start += 2;
    }
    if tries_start + (code.tries_size as usize) * 8 > data.len() {
        return None;
    }
    let mut try_items = Vec::with_capacity(code.tries_size as usize);
    for i in 0..(code.tries_size as usize) {
        let off = tries_start + i * 8;
        let start_addr = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        let insn_count = u16::from_le_bytes(data[off + 4..off + 6].try_into().ok()?);
        let handler_off = u16::from_le_bytes(data[off + 6..off + 8].try_into().ok()?);
        try_items.push(TryItem {
            start_addr,
            insn_count,
            handler_off,
        });
    }
    let handlers_start = tries_start + (code.tries_size as usize) * 8;
    let mut pos = handlers_start;
    if pos >= data.len() {
        return Some((try_items, vec![]));
    }
    let list_size = read_uleb128(data, &mut pos)?;
    let mut handlers = Vec::with_capacity(list_size as usize);
    for _ in 0..list_size {
        let size_signed = read_sleb128(data, &mut pos)?;
        let size_abs = size_signed.unsigned_abs() as usize;
        let has_catch_all = size_signed <= 0;
        let mut type_addrs = Vec::with_capacity(size_abs);
        for _ in 0..size_abs {
            let type_idx = read_uleb128(data, &mut pos)?;
            let addr = read_uleb128(data, &mut pos)?;
            type_addrs.push(EncodedTypeAddr { type_idx, addr });
        }
        let catch_all_addr = if has_catch_all {
            Some(read_uleb128(data, &mut pos)?)
        } else {
            None
        };
        handlers.push(EncodedCatchHandler {
            handlers: type_addrs,
            catch_all_addr,
        });
    }
    Some((try_items, handlers))
}

/// Try and handler ranges in byte offsets (relative to start of insns, i.e. base_offset=0).
/// try_start_byte, try_end_byte: [try_start_byte, try_end_byte) is the try range.
/// handler_ranges: for each (type_idx, start_byte, end_byte), [start_byte, end_byte) is that handler's code.
pub fn try_and_handler_byte_ranges(
    try_item: &TryItem,
    handler: &EncodedCatchHandler,
    insns_size_16bit: u32,
) -> (u32, u32, Vec<(u32, u32, u32)>) {
    let try_start_byte = try_item.start_addr * 2;
    let try_end_byte = (try_item.start_addr + try_item.insn_count as u32) * 2;
    let code_end_byte = insns_size_16bit * 2;
    let mut boundaries: Vec<u32> = handler
        .handlers
        .iter()
        .map(|h| h.addr * 2)
        .collect();
    if let Some(a) = handler.catch_all_addr {
        boundaries.push(a * 2);
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    boundaries.push(code_end_byte);
    let mut handler_ranges = Vec::new();
    for type_addr in &handler.handlers {
        let start_byte = type_addr.addr * 2;
        let end_byte = boundaries
            .iter()
            .find(|&&b| b > start_byte)
            .copied()
            .unwrap_or(code_end_byte);
        handler_ranges.push((type_addr.type_idx, start_byte, end_byte));
    }
    (try_start_byte, try_end_byte, handler_ranges)
}

/// Pairs of (try_item, its encoded_catch_handler) for emission.
pub fn try_handler_pairs(
    data: &[u8],
    code_off: u32,
    code: &CodeItem,
) -> Option<Vec<(TryItem, EncodedCatchHandler)>> {
    let (try_items, handlers) = parse_tries_and_handlers(data, code_off, code)?;
    let code_off = code_off as usize;
    let insns_len = (code.insns_size as usize).saturating_mul(2);
    let mut tries_end = code_off + 16 + insns_len;
    if (code.insns_size as usize) % 2 == 1 {
        tries_end += 2;
    }
    let list_start = tries_end + (code.tries_size as usize) * 8;
    let mut pos = list_start;
    if pos >= data.len() {
        return Some(vec![]);
    }
    let list_size = read_uleb128(data, &mut pos)? as usize;
    let mut handler_starts: Vec<usize> = Vec::with_capacity(list_size);
    for _ in 0..list_size {
        handler_starts.push(pos);
        let size_signed = read_sleb128(data, &mut pos)?;
        let size_abs = size_signed.unsigned_abs() as usize;
        for _ in 0..size_abs {
            read_uleb128(data, &mut pos)?;
            read_uleb128(data, &mut pos)?;
        }
        if size_signed <= 0 {
            read_uleb128(data, &mut pos)?;
        }
    }
    let mut out = Vec::new();
    for try_item in try_items {
        let off = list_start + (try_item.handler_off as usize);
        if let Some(idx) = handler_starts.iter().position(|&s| s == off) {
            if idx < handlers.len() {
                out.push((try_item, handlers[idx].clone()));
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{EncodedCatchHandler, EncodedTypeAddr, TryItem, try_and_handler_byte_ranges};

    #[test]
    fn try_and_handler_byte_ranges_try_from_zero() {
        let try_item = TryItem {
            start_addr: 0,
            insn_count: 16,
            handler_off: 0,
        };
        let handler = EncodedCatchHandler {
            handlers: vec![EncodedTypeAddr {
                type_idx: 1,
                addr: 31,
            }],
            catch_all_addr: None,
        };
        let (try_start, try_end, handler_ranges) =
            try_and_handler_byte_ranges(&try_item, &handler, 64);
        assert_eq!(try_start, 0, "try starts at byte 0");
        assert_eq!(try_end, 32, "try ends at byte 32 (16 * 2)");
        assert_eq!(handler_ranges.len(), 1);
        assert_eq!(handler_ranges[0].0, 1);
        assert_eq!(handler_ranges[0].1, 62, "handler start 31 * 2 = 62");
        assert_eq!(handler_ranges[0].2, 128, "handler end = code_end 64*2");
    }

    #[test]
    fn try_and_handler_byte_ranges_multiple_handlers() {
        let try_item = TryItem {
            start_addr: 0,
            insn_count: 10,
            handler_off: 0,
        };
        let handler = EncodedCatchHandler {
            handlers: vec![
                EncodedTypeAddr {
                    type_idx: 1,
                    addr: 20,
                },
                EncodedTypeAddr {
                    type_idx: 2,
                    addr: 25,
                },
            ],
            catch_all_addr: Some(30),
        };
        let (try_start, try_end, handler_ranges) =
            try_and_handler_byte_ranges(&try_item, &handler, 20);
        assert_eq!(try_start, 0);
        assert_eq!(try_end, 20);
        assert_eq!(handler_ranges.len(), 2);
        assert_eq!(handler_ranges[0], (1, 40, 50), "first handler 20..25 in bytes");
        assert_eq!(handler_ranges[1], (2, 50, 60), "second handler 25..30 in bytes");
    }
}
