//! Method index across one or more DEX files.

use dex_parser::{DexFile, EncodedMethod};

use crate::java::descriptor_to_java;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MethodId(pub usize);

#[derive(Clone, Debug)]
pub struct MethodRef {
    pub id: MethodId,
    pub class_name: String,
    pub method_name: String,
    pub proto: String,
    pub dex_index: usize,
    pub encoded: EncodedMethod,
}

#[derive(Debug, Default)]
pub struct MethodIndex {
    pub methods: Vec<MethodRef>,
    /// `Class#method` → first matching MethodId (name-only; proto-ambiguous OK for v1).
    by_class_method: std::collections::HashMap<String, Vec<MethodId>>,
}

impl MethodIndex {
    pub fn from_dexes(dexes: &[&DexFile]) -> Self {
        let mut idx = MethodIndex::default();
        for (dex_index, dex) in dexes.iter().enumerate() {
            for class_result in dex.class_defs() {
                let Ok(class_def) = class_result else { continue };
                let Ok(class_type) = dex.get_type(class_def.class_idx) else { continue };
                let class_name = descriptor_to_java(&class_type);
                let Ok(Some(class_data)) = dex.get_class_data(&class_def) else { continue };
                for encoded in class_data
                    .direct_methods
                    .iter()
                    .chain(class_data.virtual_methods.iter())
                {
                    if encoded.code_off == 0 {
                        continue;
                    }
                    let Ok(info) = dex.get_method_info(encoded.method_idx) else { continue };
                    let method_name = info.name.to_string();
                    let params: String = info.params.concat();
                    let proto = format!("({}){}", params, info.return_type);
                    let id = MethodId(idx.methods.len());
                    let key = format!("{class_name}#{method_name}");
                    idx.by_class_method.entry(key).or_default().push(id);
                    idx.methods.push(MethodRef {
                        id,
                        class_name: class_name.clone(),
                        method_name,
                        proto,
                        dex_index,
                        encoded: encoded.clone(),
                    });
                }
            }
        }
        idx
    }

    pub fn get(&self, id: MethodId) -> Option<&MethodRef> {
        self.methods.get(id.0)
    }

    pub fn callable_name(&self, id: MethodId) -> String {
        self.get(id)
            .map(|m| format!("{}#{}", m.class_name, m.method_name))
            .unwrap_or_else(|| format!("method#{}", id.0))
    }

    /// Resolve a callee from an invoke method ref like `com.foo.Bar.doThing`.
    /// Requires a class-qualified match — no simple-name fallback (avoids MT false edges).
    pub fn resolve_callee(&self, method_ref: &str) -> Option<MethodId> {
        let bare = method_ref.split('(').next().unwrap_or(method_ref).trim();
        if let Some((cls, name)) = bare.rsplit_once('.') {
            let key = format!("{cls}#{name}");
            if let Some(ids) = self.by_class_method.get(&key) {
                return ids.first().copied();
            }
            let java_cls = cls
                .replace('/', ".")
                .trim_start_matches('L')
                .trim_end_matches(';')
                .to_string();
            let key2 = format!("{java_cls}#{name}");
            if let Some(ids) = self.by_class_method.get(&key2) {
                return ids.first().copied();
            }
        }
        None
    }
}
