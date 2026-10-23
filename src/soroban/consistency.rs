//! Contract-spec vs raw WASM export consistency.
//!
//! Compares the decoded contract spec against the module's raw WASM exports.
//! This module never decodes XDR and never reparses WASM: it consumes the
//! already-decoded [`SpecReport`] and the already-parsed [`WasmReport`].
//!
//! # The one rule implemented (and its evidence)
//!
//! A contract function named `X` in `contractspecv0` must be reachable as a
//! WASM export named `X`. The host resolves a contract invocation by looking
//! up the WASM export whose name equals the function symbol:
//!
//! * `soroban-env-host 28.0.2` `src/vm.rs:286-301` — `metered_func_call`
//!   calls `wasmi_instance.get_export(&store, func_ss.as_ref())` and, when it
//!   returns `None`, fails with `ScErrorCode::MissingValue` and the message
//!   "trying to invoke non-existent contract function".
//!
//! So the name equality between a spec function and a WASM export is the
//! convention the host actually enforces — not an assumption.
//!
//! One documented exception, also from the host: `__constructor`
//! (`src/host/lifecycle.rs:22`) is invoked with
//! `treat_missing_function_as_noop: constructor_args.is_empty()`
//! (`src/host/lifecycle.rs:121-131`), i.e. a contract is permitted to have no
//! `__constructor` export at all. It is therefore excluded from the
//! missing-export rule.
//!
//! # What is deliberately NOT implemented
//!
//! * Extra raw WASM exports are never flagged. Nothing in the host requires
//!   every export to be described by the spec; internal helper functions and
//!   linker-provided exports are normal. They are listed informationally.
//! * Parameter/return-type (ABI) comparison is not implemented. Name equality
//!   is enforced by the host, but signature compatibility is not something the
//!   repository can currently verify from the spec plus the WASM type section
//!   alone (the spec's type vocabulary and the WASM value types are different
//!   domains). Reported as `not_checked`, never guessed.

use crate::wasm::WasmReport;
use serde::{Deserialize, Serialize};

use super::SpecReport;

/// The host's constructor export name, allowed to be absent.
const CONSTRUCTOR_EXPORT: &str = "__constructor";

/// A single consistency observation with a stable code and explicit evidence.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ConsistencyFinding {
    /// Stable machine-readable code.
    pub code: String,
    /// `mismatch` or `not_checked`.
    pub severity: String,
    /// Concise human-readable explanation.
    pub message: String,
    /// The concrete input that produced this finding.
    pub evidence: String,
}

/// Result of comparing the contract spec with the raw WASM exports.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ConsistencyReport {
    /// `checked` when a spec was available and the comparison ran;
    /// `not_applicable` when there was no usable spec.
    pub status: String,
    /// Why the comparison did not run. Present only for `not_applicable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Number of functions declared in the contract spec.
    pub spec_function_count: usize,
    /// Number of raw WASM function exports.
    pub wasm_function_export_count: usize,
    /// Findings. Empty means no implemented rule reported a mismatch.
    pub findings: Vec<ConsistencyFinding>,
    /// Raw WASM function exports that no spec function names. Informational
    /// only — these are never findings (see module docs).
    pub unmatched_exports: Vec<String>,
    /// Comparison areas where a rule actually ran. Sorted.
    pub checked: Vec<String>,
    /// Comparison areas with no implemented rule. Sorted.
    pub not_checked: Vec<String>,
}

/// Compare a decoded contract spec against a parsed module's raw exports.
///
/// Pure function over already-decoded data: no XDR decoding, no WASM
/// reparsing. Passing `None` for `spec` yields a `not_applicable` report
/// rather than an error, because a module without a spec is a normal case.
pub fn check_spec_export_consistency(
    wasm: &WasmReport,
    spec: Option<&SpecReport>,
) -> ConsistencyReport {
    let wasm_function_exports: Vec<&str> = wasm
        .exports
        .iter()
        .filter(|e| e.kind == "function")
        .map(|e| e.name.as_str())
        .collect();

    // Areas with no implemented rule, always reported so an empty `findings`
    // list cannot be read as "the spec matches the module".
    let not_checked = vec![
        "export_signature_abi".to_string(),
        "export_kind_other_than_function".to_string(),
    ];

    let Some(spec) = spec else {
        return ConsistencyReport {
            status: "not_applicable".to_string(),
            reason: Some(
                "no decodable contractspecv0 section; nothing to compare against".to_string(),
            ),
            spec_function_count: 0,
            wasm_function_export_count: wasm_function_exports.len(),
            findings: Vec::new(),
            unmatched_exports: Vec::new(),
            checked: Vec::new(),
            not_checked,
        };
    };

    let mut findings: Vec<ConsistencyFinding> = Vec::new();

    // Rule: every spec function except the constructor must have a same-named
    // raw WASM function export.
    for f in &spec.functions {
        if f.name == CONSTRUCTOR_EXPORT {
            continue;
        }
        if !wasm_function_exports.contains(&f.name.as_str()) {
            findings.push(ConsistencyFinding {
                code: "spec_function_export_missing".to_string(),
                severity: "mismatch".to_string(),
                message: format!(
                    "contract spec declares function '{}' but the module has no same-named WASM function export; the host would fail the call with MissingValue (\"trying to invoke non-existent contract function\")",
                    f.name
                ),
                evidence: format!("contractspecv0 function '{}' not found in exports", f.name),
            });
        }
    }

    // Informational only: exports the spec does not name. Never a finding.
    let spec_names: Vec<&str> = spec.functions.iter().map(|f| f.name.as_str()).collect();
    let mut unmatched_exports: Vec<String> = wasm_function_exports
        .iter()
        .filter(|n| !spec_names.contains(*n))
        .map(|n| (*n).to_string())
        .collect();
    unmatched_exports.sort();
    unmatched_exports.dedup();

    // Deterministic: findings are emitted in spec declaration order already,
    // but sort defensively by code then evidence so output cannot depend on
    // spec ordering for modules with several findings.
    findings.sort_by(|a, b| {
        a.code
            .cmp(&b.code)
            .then_with(|| a.evidence.cmp(&b.evidence))
    });

    let mut checked = vec!["spec_function_export_presence".to_string()];
    checked.sort();

    ConsistencyReport {
        status: "checked".to_string(),
        reason: None,
        spec_function_count: spec.functions.len(),
        wasm_function_export_count: wasm_function_exports.len(),
        findings,
        unmatched_exports,
        checked,
        not_checked,
    }
}

/// Convenience wrapper: decode the spec from the module when a
/// `contractspecv0` section exists, then compare.
///
/// The spec is decoded at most once here, and the caller's `WasmReport` is
/// reused rather than the module being reparsed.
pub fn check_consistency_from_wasm(wasm: &WasmReport, bytes: &[u8]) -> ConsistencyReport {
    let has_spec = wasm
        .custom_sections
        .iter()
        .any(|s| s.name == "contractspecv0");
    if !has_spec {
        return check_spec_export_consistency(wasm, None);
    }
    match super::decode_spec_from_wasm(bytes) {
        Ok(spec) => check_spec_export_consistency(wasm, Some(&spec)),
        Err(e) => ConsistencyReport {
            status: "not_applicable".to_string(),
            reason: Some(format!("contractspecv0 present but not decodable: {e}")),
            spec_function_count: 0,
            wasm_function_export_count: wasm
                .exports
                .iter()
                .filter(|e| e.kind == "function")
                .count(),
            findings: Vec::new(),
            unmatched_exports: Vec::new(),
            checked: Vec::new(),
            not_checked: vec![
                "export_signature_abi".to_string(),
                "export_kind_other_than_function".to_string(),
            ],
        },
    }
}
