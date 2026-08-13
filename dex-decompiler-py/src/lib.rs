//! Python bindings for dex-decompiler (DEX to Java decompiler).

use ::dex_decompiler::{
    default_config, parse_dex, scan_dex_parallel, solve_dexes, Decompiler, DecompilerOptions,
    DexFile, EncodedMethod, RenameMap, SolveOptions,
};
use ::dex_decompiler::java;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};
use std::collections::HashMap;
use std::path::Path;

/// Build RenameMap from optional Python dicts. Keys/values must be str.
fn renames_from_py(
    py: Python<'_>,
    package: Option<&Bound<'_, PyAny>>,
    class: Option<&Bound<'_, PyAny>>,
    method: Option<&Bound<'_, PyAny>>,
    field: Option<&Bound<'_, PyAny>>,
    variable: Option<&Bound<'_, PyAny>>,
) -> PyResult<Option<RenameMap>> {
    fn str_map(d: &Bound<'_, PyAny>) -> PyResult<HashMap<String, String>> {
        let dict = d.downcast::<PyDict>().map_err(|_| PyValueError::new_err("expected dict of str -> str"))?;
        let mut out = HashMap::new();
        for (k, v) in dict.iter() {
            let k: String = k.extract()?;
            let v: String = v.extract()?;
            out.insert(k, v);
        }
        Ok(out)
    }
    fn var_map(d: &Bound<'_, PyAny>) -> PyResult<HashMap<String, HashMap<String, String>>> {
        let dict = d.downcast::<PyDict>().map_err(|_| PyValueError::new_err("variable_renames: expected dict of str -> dict"))?;
        let mut out = HashMap::new();
        for (k, v) in dict.iter() {
            let k: String = k.extract()?;
            let inner = str_map(&v)?;
            out.insert(k, inner);
        }
        Ok(out)
    }
    let has_any = package.is_some() || class.is_some() || method.is_some() || field.is_some() || variable.is_some();
    if !has_any {
        return Ok(None);
    }
    let mut r = RenameMap::default();
    if let Some(d) = package {
        r.package = str_map(d)?;
    }
    if let Some(d) = class {
        r.class = str_map(d)?;
    }
    if let Some(d) = method {
        r.method = str_map(d)?;
    }
    if let Some(d) = field {
        r.field = str_map(d)?;
    }
    if let Some(d) = variable {
        r.variable = var_map(d)?;
    }
    Ok(Some(r))
}

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

    /// Decompile with optional filters and renames. Rename dicts map old name -> new name.
    /// Method/field keys use "ClassName#memberName" (e.g. "com.example.Main#onCreate").
    /// variable_renames: dict of "ClassName#methodName" -> dict of old_var_name -> new_var_name.
    #[pyo3(signature = (only_package=None, exclude=None, package_renames=None, class_renames=None, method_renames=None, field_renames=None, variable_renames=None))]
    fn decompile_with_renames(
        &self,
        only_package: Option<&str>,
        exclude: Option<Vec<String>>,
        package_renames: Option<&Bound<'_, PyAny>>,
        class_renames: Option<&Bound<'_, PyAny>>,
        method_renames: Option<&Bound<'_, PyAny>>,
        field_renames: Option<&Bound<'_, PyAny>>,
        variable_renames: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<String> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let rename_map = Python::with_gil(|py| {
            renames_from_py(
                py,
                package_renames,
                class_renames,
                method_renames,
                field_renames,
                variable_renames,
            )
        })?;
        let options = DecompilerOptions {
            only_package: only_package.map(String::from),
            exclude: exclude.unwrap_or_default(),
            show_bytecode: false,
            rename_map,
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

    /// Run all vulnerability detectors; returns list of finding dicts.
    fn scan_vulns(&self) -> PyResult<Vec<PyObject>> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let findings = scan_dex_parallel(&dex, None);
        Python::with_gil(|py| {
            findings
                .into_iter()
                .map(|f| {
                    let dict = PyDict::new(py);
                    dict.set_item("category", f.category)?;
                    dict.set_item("title", f.title)?;
                    dict.set_item("severity", f.severity)?;
                    dict.set_item("message", f.message)?;
                    dict.set_item("problem", f.problem)?;
                    dict.set_item("recommendation", f.recommendation)?;
                    dict.set_item("cwe", f.cwe)?;
                    dict.set_item("class_name", f.class_name)?;
                    dict.set_item("method_name", f.method_name)?;
                    dict.set_item("source_offset", f.source_offset)?;
                    dict.set_item("source_reg", f.source_reg)?;
                    dict.set_item("source_desc", f.source_desc)?;
                    dict.set_item("sink_offset", f.sink_offset)?;
                    dict.set_item("sink_reg", f.sink_reg)?;
                    dict.set_item("sink_desc", f.sink_desc)?;
                    dict.set_item("evidence_offsets", f.evidence_offsets)?;
                    let trace_list = pyo3::types::PyList::empty(py);
                    for step in f.trace {
                        let s = PyDict::new(py);
                        s.set_item("offset", step.offset)?;
                        s.set_item("reg", step.reg)?;
                        s.set_item("kind", step.kind)?;
                        s.set_item("description", step.description)?;
                        trace_list.append(s)?;
                    }
                    dict.set_item("trace", trace_list)?;
                    Ok(dict.into_py(py))
                })
                .collect()
        })
    }

    /// Run Mariana-Trench–style taint solver; returns JSON string of issues.
    #[pyo3(signature = (config_json=None, max_iterations=None))]
    fn taint_solve(
        &self,
        config_json: Option<&str>,
        max_iterations: Option<usize>,
    ) -> PyResult<String> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let config = if let Some(s) = config_json {
            serde_json::from_str(s).map_err(|e| PyValueError::new_err(e.to_string()))?
        } else {
            default_config()
        };
        let opts = SolveOptions {
            max_iterations: max_iterations.unwrap_or(8),
            exclude_prefixes: SolveOptions::default_android().exclude_prefixes,
        };
        let result =
            solve_dexes(&[&dex], &config, &opts).map_err(|e| PyValueError::new_err(e.to_string()))?;
        serde_json::to_string_pretty(&result.report)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Export class inventory as JSON (optionally with method bodies).
    #[pyo3(signature = (include_bodies=false))]
    fn export_json(&self, include_bodies: bool) -> PyResult<String> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let decompiler = Decompiler::new(&dex);
        decompiler
            .export_json(include_bodies)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Emulate a method; returns final register snapshot as a dict.
    #[pyo3(signature = (class_name, method_name, max_steps=None))]
    fn emulate(
        &self,
        class_name: &str,
        method_name: &str,
        max_steps: Option<usize>,
    ) -> PyResult<PyObject> {
        let dex = parse_dex(&self.data).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let encoded = find_method(&dex, class_name, method_name)
            .ok_or_else(|| PyValueError::new_err("method not found"))?;
        let decompiler = Decompiler::new(&dex);
        let mut emu = decompiler
            .build_emulator(&encoded, vec![], vec![])
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        if let Some(n) = max_steps {
            emu.max_steps = n;
        }
        while !emu.finished && emu.step_count < emu.max_steps {
            if emu.step().is_err() {
                break;
            }
        }
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("steps", emu.step_count)?;
            dict.set_item("finished", emu.finished)?;
            let regs = PyDict::new(py);
            for (i, v) in emu.registers.iter().enumerate() {
                regs.set_item(i, v.display_short_hex())?;
            }
            dict.set_item("registers", regs)?;
            Ok(dict.into_py(py))
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
