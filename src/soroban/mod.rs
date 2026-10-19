//! Soroban-specific inspection layered on top of the generic WASM parser.
//!
//! Contract-spec decoding uses the official `stellar-xdr` crate with the same
//! resource limits as `soroban-spec` (depth 500, len 16 MiB). We do not
//! hand-roll XDR parsing or guess the `contractspecv0` format.
//!
//! ABI compatibility is only assessed when both specs decode; otherwise the
//! verdict is `unknown`. See [`diff`].

pub mod diff;

use crate::wasm::{inspect, InspectError, WasmReport};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use stellar_xdr::{Limited, Limits, ReadXdr, ScSpecEntry, ScSpecTypeDef};

/// Maximum size of a `contractspecv0` payload we will attempt to decode.
const MAX_SPEC_LEN: usize = 0x1000000; // 16 MiB, matches soroban-spec Limits.len
/// Maximum XDR nesting depth, matches soroban-spec Limits.depth.
const MAX_SPEC_DEPTH: u32 = 500;

/// Outcome of a Soroban-specific validation pass.
#[derive(Debug, Serialize, Deserialize)]
pub struct SorobanReport {
    /// Underlying generic WASM report.
    pub wasm: WasmReport,
    /// `true` if a `contractspecv0` custom section was found.
    pub has_contract_spec: bool,
    /// `true` if a `contractenvmetav0` custom section was found.
    pub has_contract_env_meta: bool,
    /// Decoded contract spec, if present and parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<SpecReport>,
    /// Human-readable summary of Soroban-relevant observations.
    pub summary: String,
}

/// Decoded contract-spec contents.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpecReport {
    /// Exported contract functions from the spec.
    pub functions: Vec<SpecFunction>,
    /// User-defined type declarations (structs, unions, enums, error enums, events).
    pub types: Vec<SpecType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecFunction {
    pub name: String,
    /// Input parameter names and types.
    pub inputs: Vec<SpecInput>,
    /// Return types as human-readable strings.
    pub outputs: Vec<String>,
    /// Documentation string from the spec (trimmed).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub doc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecInput {
    pub name: String,
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecType {
    /// Kind of UDT: "struct", "union", "enum", "error_enum", or "event".
    pub kind: String,
    pub name: String,
}

/// Errors from Soroban inspection.
#[derive(Debug)]
pub enum SorobanError {
    /// Generic WASM parsing failed.
    Wasm(InspectError),
    /// `contractspecv0` section exists but its XDR payload is invalid.
    SpecDecode(String),
    /// Spec payload exceeds the resource limit.
    SpecTooLarge(usize),
}

impl std::fmt::Display for SorobanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SorobanError::Wasm(e) => write!(f, "{e}"),
            SorobanError::SpecDecode(msg) => write!(f, "contract spec decode failed: {msg}"),
            SorobanError::SpecTooLarge(n) => {
                write!(
                    f,
                    "contract spec too large: {n} bytes (limit {MAX_SPEC_LEN})"
                )
            }
        }
    }
}

impl std::error::Error for SorobanError {}

impl From<InspectError> for SorobanError {
    fn from(e: InspectError) -> Self {
        SorobanError::Wasm(e)
    }
}

/// Detect Soroban markers and, when possible, decode the contract spec.
///
/// # Errors
/// Propagates generic WASM parse errors and contract-spec decode errors.
pub fn inspect_soroban(bytes: &[u8], validate: bool) -> Result<SorobanReport, SorobanError> {
    let wasm = inspect(bytes, validate)?;
    let has_contract_spec = wasm
        .custom_sections
        .iter()
        .any(|s| s.name == "contractspecv0");
    let has_contract_env_meta = wasm
        .custom_sections
        .iter()
        .any(|s| s.name == "contractenvmetav0");

    let spec = if has_contract_spec {
        Some(decode_spec_from_wasm(bytes)?)
    } else {
        None
    };

    let summary = match (&spec, has_contract_spec, has_contract_env_meta) {
        (Some(s), true, true) => format!(
            "Soroban contract artifact: {} function(s), {} type(s) decoded from contractspecv0.",
            s.functions.len(),
            s.types.len()
        ),
        (_, true, true) => {
            "Soroban contract artifact detected (contractspecv0 + contractenvmetav0 present)."
                .to_string()
        }
        (_, true, false) | (_, false, true) => {
            "Partial Soroban markers — one of contractspecv0/contractenvmetav0 missing.".to_string()
        }
        (_, false, false) => {
            "No Soroban custom sections found — likely a generic WASM module.".to_string()
        }
    };

    Ok(SorobanReport {
        wasm,
        has_contract_spec,
        has_contract_env_meta,
        spec,
        summary,
    })
}

/// Extract and decode the `contractspecv0` payload from a WASM binary.
///
/// # Errors
/// `SpecTooLarge` when the section exceeds the limit, `SpecDecode` when the
/// section is missing or its XDR is invalid.
pub fn decode_spec_from_wasm(bytes: &[u8]) -> Result<SpecReport, SorobanError> {
    let raw = extract_spec_bytes(bytes)?;
    decode_spec_raw(&raw)
}

fn extract_spec_bytes(bytes: &[u8]) -> Result<Vec<u8>, SorobanError> {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload =
            payload.map_err(|e| SorobanError::Wasm(InspectError::Malformed(e.to_string())))?;
        if let wasmparser::Payload::CustomSection(section) = payload {
            if section.name() == "contractspecv0" {
                let data = section.data();
                if data.len() > MAX_SPEC_LEN {
                    return Err(SorobanError::SpecTooLarge(data.len()));
                }
                return Ok(data.to_vec());
            }
        }
    }
    Err(SorobanError::SpecDecode(
        "contractspecv0 section not found".to_string(),
    ))
}

/// Decode raw XDR spec bytes into structured entries.
///
/// # Errors
/// `SpecDecode` for malformed or truncated XDR, or when the entry count or
/// depth exceeds the configured limits.
pub fn decode_spec_raw(raw: &[u8]) -> Result<SpecReport, SorobanError> {
    let cursor = Cursor::new(raw);
    let mut limited = Limited::new(
        cursor,
        Limits {
            depth: MAX_SPEC_DEPTH,
            len: MAX_SPEC_LEN,
        },
    );
    let mut reader = ScSpecEntry::read_xdr_iter(&mut limited);

    let mut functions = Vec::new();
    let mut types = Vec::new();
    loop {
        match reader.next() {
            Some(Ok(entry)) => match entry {
                ScSpecEntry::FunctionV0(f) => functions.push(SpecFunction {
                    name: f.name.to_string(),
                    inputs: f
                        .inputs
                        .to_vec()
                        .into_iter()
                        .map(|i| SpecInput {
                            name: i.name.to_string(),
                            type_: format_type_def(&i.type_),
                        })
                        .collect(),
                    outputs: f
                        .outputs
                        .to_vec()
                        .into_iter()
                        .map(|o| format_type_def(&o))
                        .collect(),
                    doc: f.doc.to_string().trim().to_string(),
                }),
                ScSpecEntry::UdtStructV0(s) => types.push(SpecType {
                    kind: "struct".to_string(),
                    name: s.name.to_string(),
                }),
                ScSpecEntry::UdtUnionV0(u) => types.push(SpecType {
                    kind: "union".to_string(),
                    name: u.name.to_string(),
                }),
                ScSpecEntry::UdtEnumV0(e) => types.push(SpecType {
                    kind: "enum".to_string(),
                    name: e.name.to_string(),
                }),
                ScSpecEntry::UdtErrorEnumV0(e) => types.push(SpecType {
                    kind: "error_enum".to_string(),
                    name: e.name.to_string(),
                }),
                ScSpecEntry::EventV0(ev) => types.push(SpecType {
                    kind: "event".to_string(),
                    name: ev.name.to_string(),
                }),
            },
            Some(Err(e)) => return Err(SorobanError::SpecDecode(e.to_string())),
            None => break,
        }
    }

    Ok(SpecReport { functions, types })
}

/// Render an `ScSpecTypeDef` as a compact human-readable type string.
fn format_type_def(t: &ScSpecTypeDef) -> String {
    match t {
        ScSpecTypeDef::Val => "Val".into(),
        ScSpecTypeDef::Bool => "Bool".into(),
        ScSpecTypeDef::Void => "Void".into(),
        ScSpecTypeDef::Error => "Error".into(),
        ScSpecTypeDef::U32 => "U32".into(),
        ScSpecTypeDef::I32 => "I32".into(),
        ScSpecTypeDef::U64 => "U64".into(),
        ScSpecTypeDef::I64 => "I64".into(),
        ScSpecTypeDef::Timepoint => "Timepoint".into(),
        ScSpecTypeDef::Duration => "Duration".into(),
        ScSpecTypeDef::U128 => "U128".into(),
        ScSpecTypeDef::I128 => "I128".into(),
        ScSpecTypeDef::U256 => "U256".into(),
        ScSpecTypeDef::I256 => "I256".into(),
        ScSpecTypeDef::Bytes => "Bytes".into(),
        ScSpecTypeDef::String => "String".into(),
        ScSpecTypeDef::Symbol => "Symbol".into(),
        ScSpecTypeDef::Address => "Address".into(),
        ScSpecTypeDef::MuxedAddress => "MuxedAddress".into(),
        ScSpecTypeDef::BytesN(n) => format!("BytesN<{}>", n.n),
        ScSpecTypeDef::Option(o) => format!("Option<{}>", format_type_def(&o.value_type)),
        ScSpecTypeDef::Result(r) => format!(
            "Result<{}, {}>",
            format_type_def(&r.ok_type),
            format_type_def(&r.error_type)
        ),
        ScSpecTypeDef::Vec(v) => format!("Vec<{}>", format_type_def(&v.element_type)),
        ScSpecTypeDef::Map(m) => format!(
            "Map<{}, {}>",
            format_type_def(&m.key_type),
            format_type_def(&m.value_type)
        ),
        ScSpecTypeDef::Tuple(t) => {
            let elems: Vec<String> = t.value_types.to_vec().iter().map(format_type_def).collect();
            format!("Tuple<{}>", elems.join(", "))
        }
        ScSpecTypeDef::Udt(u) => u.name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn empty_module_is_not_soroban() {
        let report = inspect_soroban(EMPTY_WASM, false).unwrap();
        assert!(!report.has_contract_spec);
        assert!(!report.has_contract_env_meta);
        assert!(report.spec.is_none());
        assert!(report.summary.contains("No Soroban"));
    }

    #[test]
    fn malformed_input_errors() {
        let result = inspect_soroban(&[0xff, 0xff, 0xff], false);
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_spec_is_valid() {
        // Zero entries is valid under XDR framing.
        let report = decode_spec_raw(&[]).unwrap();
        assert!(report.functions.is_empty());
        assert!(report.types.is_empty());
    }

    #[test]
    fn decode_malformed_xdr_errors_cleanly() {
        let result = decode_spec_raw(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(result, Err(SorobanError::SpecDecode(_))));
    }

    #[test]
    fn decode_truncated_xdr_errors_cleanly() {
        // Valid discriminant, truncated body.
        let result = decode_spec_raw(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(result, Err(SorobanError::SpecDecode(_))));
    }
}
