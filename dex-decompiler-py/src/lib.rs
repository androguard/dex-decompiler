//! Python bindings for dex-decompiler (DEX to Java decompiler).

use ::dex_decompiler::{
    parse_dex, Decompiler, DecompilerOptions, DexFile, EncodedMethod,
};
use ::dex_decompiler::java;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::path::Path;

/// Find the first EncodedMethod in the DEX that belongs to the given class and method name.
fn find_method(dex: &DexFile, class_name: &str, method_name: &str) -> Option<EncodedMethod> {
    for class_def_result in dex.class_defs() {
        let class_def = class_def_result.ok()?;
        let class_type = dex.get_type(class_def.class_idx).ok()?;
        let name = java::descriptor_to_java(&class_type);
        if name != class_name {
            continue;
        }
        let class_data_opt = dex.get_class_data(&class_def).ok()?;
        let class_data = class_data_opt.as_ref()?;
        for encoded in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            let info = dex.get_method_info(encoded.method_idx).ok()?;
            if info.name == method_name {
                return Some(encoded.clone());
            }
        }
    }
    None
}

/// Parse raw DEX bytes and return a DexFile wrapper.
#[pyfunction(name = "parse_dex")]
fn parse_dex_py(data: &[u8]) -> PyResult<DexFileWrapper> {
    Ok(DexFileWrapper {
        data: data.to_vec(),
    })
}

/// Python-exposed wrapper: holds DEX bytes and re-parses on each operation.
#[pyclass]
struct DexFileWrapper {
    data: Vec<u8>,
}

#[pymethods]
impl DexFileWrapper {
    /// Decompile the entire DEX to a single Java source string.
    fn decompile(&self) -> PyResult<String> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let decompiler = Decompiler::new(&dex);
        decompiler.decompile().map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Decompile with optional package filter and exclude list.
    /// only_package: if set, only classes in this package (or exact class) are decompiled.
    /// exclude: list of package/class prefixes to exclude.
    #[pyo3(signature = (only_package=None, exclude=None))]
    fn decompile_with_options(
        &self,
        only_package: Option<&str>,
        exclude: Option<Vec<String>>,
    ) -> PyResult<String> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let options = DecompilerOptions {
            only_package: only_package.map(String::from),
            exclude: exclude
                .unwrap_or_default()
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let decompiler = Decompiler::with_options(&dex, options);
        decompiler.decompile().map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Decompile the DEX into a directory with package structure (e.g. out/com/example/MyClass.java).
    fn decompile_to_dir(&self, base_path: &str) -> PyResult<()> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let decompiler = Decompiler::new(&dex);
        decompiler
            .decompile_to_dir(Path::new(base_path))
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Return list of string values in the DEX string pool (by index order).
    fn strings(&self) -> PyResult<Vec<String>> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let list: Vec<String> = (0..dex.header.string_ids_size)
            .filter_map(|idx| dex.get_string(idx).ok())
            .collect();
        Ok(list)
    }

    /// Return list of class names (Java form, e.g. com.example.MainActivity).
    fn class_names(&self) -> PyResult<Vec<String>> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let mut list = Vec::new();
        for class_def_result in dex.class_defs() {
            let class_def = class_def_result.map_err(|e| PyValueError::new_err(e.to_string()))?;
            let class_type = dex
                .get_type(class_def.class_idx)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            list.push(java::descriptor_to_java(&class_type));
        }
        Ok(list)
    }

    /// Decompile a single method by class name and method name.
    /// Raises ValueError if the class or method is not found.
    fn decompile_method(&self, class_name: &str, method_name: &str) -> PyResult<String> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let encoded = find_method(&dex, class_name, method_name)
            .ok_or_else(|| PyValueError::new_err(format!("method not found: {}#{}", class_name, method_name)))?;
        let decompiler = Decompiler::new(&dex);
        let class_simple_opt = if method_name == "<init>" {
            Some(class_name.rsplit('.').next().unwrap_or(class_name))
        } else {
            None
        };
        decompiler
            .decompile_method(&encoded, class_simple_opt, Some(class_name))
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Get bytecode listing and CFG for a method. Returns (bytecode_rows, cfg_nodes, cfg_edges).
    /// Each row is a dict with "offset", "mnemonic", "operands". Nodes have "id", "start_offset", "end_offset", "label". Edges have "from_id", "to_id".
    fn get_method_bytecode_and_cfg(
        &self,
        class_name: &str,
        method_name: &str,
    ) -> PyResult<(Vec<PyObject>, Vec<PyObject>, Vec<PyObject>)> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let encoded = find_method(&dex, class_name, method_name)
            .ok_or_else(|| PyValueError::new_err(format!("method not found: {}#{}", class_name, method_name)))?;
        let decompiler = Decompiler::new(&dex);
        let (rows, nodes, edges) = decompiler
            .get_method_bytecode_and_cfg(&encoded)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        pyo3::Python::with_gil(|py| {
            let rows_py: Vec<PyObject> = rows
                .into_iter()
                .map(|r| {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("offset", r.offset).unwrap();
                    dict.set_item("mnemonic", r.mnemonic).unwrap();
                    dict.set_item("operands", r.operands).unwrap();
                    dict.into_py(py)
                })
                .collect();
            let nodes_py: Vec<PyObject> = nodes
                .into_iter()
                .map(|n| {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("id", n.id).unwrap();
                    dict.set_item("start_offset", n.start_offset).unwrap();
                    dict.set_item("end_offset", n.end_offset).unwrap();
                    dict.set_item("label", n.label).unwrap();
                    dict.into_py(py)
                })
                .collect();
            let edges_py: Vec<PyObject> = edges
                .into_iter()
                .map(|e| {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("from_id", e.from_id).unwrap();
                    dict.set_item("to_id", e.to_id).unwrap();
                    dict.into_py(py)
                })
                .collect();
            Ok((rows_py, nodes_py, edges_py))
        })
    }
}

/// Python module entry point.
#[pymodule]
fn dex_decompiler(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DexFileWrapper>()?;
    m.add_function(wrap_pyfunction!(parse_dex_py, m)?)?;
    Ok(())
}
