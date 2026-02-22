//! Parse DEX annotations (annotation_set_item, annotation_item) for class/method/field.
//! class_def.annotations_off points to annotations_directory_item; we read class_annotations_off.

use dex_parser::ClassDef;

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

fn read_u32(data: &[u8], pos: usize) -> Option<u32> {
    if pos + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?))
}

/// Parse class_def.annotations_off: points to annotations_directory_item.
/// Return list of type_idx for the class's direct annotations (for @Override etc.).
pub fn class_annotation_type_ids(data: &[u8], class_def: &ClassDef) -> Option<Vec<u32>> {
    if class_def.annotations_off == 0 {
        return Some(vec![]);
    }
    let off = class_def.annotations_off as usize;
    if off + 4 > data.len() {
        return None;
    }
    let class_annotations_off = read_u32(data, off)?;
    if class_annotations_off == 0 {
        return Some(vec![]);
    }
    annotation_set_type_ids(data, class_annotations_off as usize)
}

/// At offset to annotation_set_item: size (uint), then size x annotation_off (uint).
/// For each annotation_off, read annotation_item: visibility (1 byte), type_idx (uleb128), skip rest.
/// Return vec of type_idx.
fn annotation_set_type_ids(data: &[u8], set_off: usize) -> Option<Vec<u32>> {
    if set_off + 4 > data.len() {
        return None;
    }
    let size = read_u32(data, set_off)? as usize;
    let mut type_ids = Vec::with_capacity(size);
    for i in 0..size {
        let entry_off = set_off + 4 + i * 4;
        if entry_off + 4 > data.len() {
            break;
        }
        let annotation_off = read_u32(data, entry_off)? as usize;
        if annotation_off >= data.len() {
            continue;
        }
        let mut pos = annotation_off;
        if pos + 1 > data.len() {
            continue;
        }
        pos += 1;
        if let Some(type_idx) = read_uleb128(data, &mut pos) {
            type_ids.push(type_idx);
        }
    }
    Some(type_ids)
}
