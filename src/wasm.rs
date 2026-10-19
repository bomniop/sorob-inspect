//! Generic WASM module inspection backed by `wasmparser`.
//!
//! All parsing goes through `wasmparser` — we never hand-roll binary parsing,
//! so malformed/truncated input surfaces as typed errors instead of panics.

use serde::{Deserialize, Serialize};
use std::io;
use wasmparser::{CoreType, Parser, Payload, RecGroup, TypeRef, Validator, WasmFeatures};

/// Top-level inspection result for a WASM binary.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmReport {
    /// Number of bytes read from the input file.
    pub size_bytes: usize,
    /// Imported functions/memories/globals/tables.
    pub imports: Vec<ImportEntry>,
    /// Exported functions/memories/globals/tables.
    pub exports: Vec<ExportEntry>,
    /// Custom sections found in the module (name + byte length).
    pub custom_sections: Vec<CustomSection>,
    /// Function signatures declared locally (index → params/results).
    pub functions: Vec<FunctionSig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportEntry {
    pub module: String,
    pub name: String,
    pub kind: String,
    /// Raw type signature when the import is a function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_sig: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub kind: String,
    pub index: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomSection {
    pub name: String,
    pub len_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionSig {
    pub index: u32,
    pub params: Vec<String>,
    pub results: Vec<String>,
}

/// Errors that can occur during inspection.
#[derive(Debug)]
pub enum InspectError {
    /// File could not be read from disk.
    Io(io::Error),
    /// WASM binary was structurally invalid or truncated.
    Malformed(String),
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InspectError::Io(e) => write!(f, "io error: {e}"),
            InspectError::Malformed(msg) => write!(f, "malformed wasm: {msg}"),
        }
    }
}

impl std::error::Error for InspectError {}

impl From<io::Error> for InspectError {
    fn from(e: io::Error) -> Self {
        InspectError::Io(e)
    }
}

/// Walk the WASM module and collect structural facts without validating code bodies.
///
/// `validate` controls whether we also run the full validator, which is stricter
/// (checks function bodies, types, etc.) but slower.
pub fn inspect(bytes: &[u8], validate: bool) -> Result<WasmReport, InspectError> {
    let mut report = WasmReport {
        size_bytes: bytes.len(),
        imports: Vec::new(),
        exports: Vec::new(),
        custom_sections: Vec::new(),
        functions: Vec::new(),
    };

    // Collect all type signatures first so imports/exports can reference them.
    let mut types: Vec<String> = Vec::new();
    let mut func_type_idx: Vec<u32> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| InspectError::Malformed(e.to_string()))?;
        match payload {
            Payload::Version { .. } | Payload::End(_) => {}
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group = group.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    collect_type_sigs(&group, &mut types);
                }
            }
            Payload::CoreTypeSection(reader) => {
                for core_ty in reader {
                    let core_ty = core_ty.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    match &core_ty {
                        CoreType::Sub(sub) => collect_subtype_sigs(sub, &mut types),
                        CoreType::Module(_) => types.push("(module type)".to_string()),
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    let (kind, sig) = match import.ty {
                        TypeRef::Func(idx) => {
                            ("function".to_string(), types.get(idx as usize).cloned())
                        }
                        TypeRef::Table(_) => ("table".to_string(), None),
                        TypeRef::Memory(_) => ("memory".to_string(), None),
                        TypeRef::Global(_) => ("global".to_string(), None),
                        TypeRef::Tag(_) => ("tag".to_string(), None),
                    };
                    report.imports.push(ImportEntry {
                        module: import.module.to_string(),
                        name: import.name.to_string(),
                        kind,
                        type_sig: sig,
                    });
                }
            }
            Payload::FunctionSection(reader) => {
                for f in reader {
                    let idx = f.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    func_type_idx.push(idx);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    report.exports.push(ExportEntry {
                        name: export.name.to_string(),
                        kind: match export.kind {
                            wasmparser::ExternalKind::Func => "function".to_string(),
                            wasmparser::ExternalKind::Table => "table".to_string(),
                            wasmparser::ExternalKind::Memory => "memory".to_string(),
                            wasmparser::ExternalKind::Global => "global".to_string(),
                            wasmparser::ExternalKind::Tag => "tag".to_string(),
                        },
                        index: export.index,
                    });
                }
            }
            Payload::CustomSection(reader) => {
                report.custom_sections.push(CustomSection {
                    name: reader.name().to_string(),
                    len_bytes: reader.data().len(),
                });
            }
            _ => {}
        }
    }

    // Build function signatures: imported funcs come first in the index space.
    let imported_funcs = report
        .imports
        .iter()
        .filter(|i| i.kind == "function")
        .count() as u32;
    for (i, type_idx) in func_type_idx.iter().enumerate() {
        let index = imported_funcs + i as u32;
        let sig = types
            .get(*type_idx as usize)
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        report.functions.push(FunctionSig {
            index,
            params: vec![sig],
            results: Vec::new(),
        });
    }

    if validate {
        let mut validator = Validator::new_with_features(WasmFeatures::all());
        validator
            .validate_all(bytes)
            .map_err(|e| InspectError::Malformed(format!("validation failed: {e}")))?;
    }

    Ok(report)
}

/// Flatten a `RecGroup` into per-type signature strings, appended to `out`.
fn collect_type_sigs(group: &RecGroup, out: &mut Vec<String>) {
    for sub in group.types() {
        collect_subtype_sigs(sub, out);
    }
}

fn collect_subtype_sigs(sub: &wasmparser::SubType, out: &mut Vec<String>) {
    match &sub.composite_type {
        wasmparser::CompositeType::Func(ft) => out.push(format_func_sig(ft.params(), ft.results())),
        wasmparser::CompositeType::Array(_) => out.push("(array ...)".to_string()),
        wasmparser::CompositeType::Struct(_) => out.push("(struct ...)".to_string()),
    }
}

fn format_func_sig(params: &[wasmparser::ValType], results: &[wasmparser::ValType]) -> String {
    let fmt_types = |ts: &[wasmparser::ValType]| -> String {
        ts.iter()
            .map(|t| format!("{t:?}").to_lowercase())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("({}) -> ({})", fmt_types(params), fmt_types(results))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid WASM module: empty module, just magic + version.
    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn empty_module_parses() {
        let report = inspect(EMPTY_WASM, false).unwrap();
        assert_eq!(report.size_bytes, 8);
        assert!(report.imports.is_empty());
        assert!(report.exports.is_empty());
    }

    #[test]
    fn truncated_module_errors() {
        // Cut off mid-header.
        let result = inspect(&EMPTY_WASM[..5], false);
        assert!(matches!(result, Err(InspectError::Malformed(_))));
    }

    #[test]
    fn garbage_errors() {
        let result = inspect(&[0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03], false);
        assert!(matches!(result, Err(InspectError::Malformed(_))));
    }

    #[test]
    fn empty_module_validates() {
        let report = inspect(EMPTY_WASM, true).unwrap();
        assert_eq!(report.size_bytes, 8);
    }
}
