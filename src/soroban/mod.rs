//! Soroban-specific inspection layered on top of the generic WASM parser.
//!
//! We deliberately do NOT invent custom-section formats. The only Soroban
//! section we decode by name is `contractspecv0`, and even that we treat as
//! opaque bytes for now — full ABI compatibility requires verified XDR types
//! and contract-spec decoding, which is a future phase.
//!
//! Today this module answers one question: "does this WASM look like a
//! Soroban contract at all?" — and reports what it can without guessing.

use crate::wasm::{inspect, InspectError, WasmReport};
use serde::{Deserialize, Serialize};

/// Outcome of a Soroban-specific validation pass.
#[derive(Debug, Serialize, Deserialize)]
pub struct SorobanReport {
    /// Underlying generic WASM report.
    pub wasm: WasmReport,
    /// `true` if a `contractspecv0` custom section was found.
    pub has_contract_spec: bool,
    /// `true` if a `contractenvmetav0` custom section was found.
    pub has_contract_env_meta: bool,
    /// Human-readable summary of Soroban-relevant observations.
    pub summary: String,
}

/// Errors from Soroban inspection (currently only re-uses the generic ones).
pub type SorobanError = InspectError;

/// Detect whether the WASM module carries Soroban contract markers.
///
/// This is a **structural** check, not a semantic one:
/// - We look for the presence of known Soroban custom section names.
/// - We do NOT decode the spec bytes or claim ABI compatibility.
///
/// # Errors
/// Propagates any generic WASM parsing errors.
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

    let summary = if has_contract_spec && has_contract_env_meta {
        "Soroban contract artifact detected (contractspecv0 + contractenvmetav0 present)."
            .to_string()
    } else if has_contract_spec || has_contract_env_meta {
        "Partial Soroban markers — one of contractspecv0/contractenvmetav0 missing.".to_string()
    } else {
        "No Soroban custom sections found — likely a generic WASM module.".to_string()
    };

    Ok(SorobanReport {
        wasm,
        has_contract_spec,
        has_contract_env_meta,
        summary,
    })
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
        assert!(report.summary.contains("No Soroban"));
    }

    #[test]
    fn malformed_input_errors() {
        let result = inspect_soroban(&[0xff, 0xff, 0xff], false);
        assert!(result.is_err());
    }
}
