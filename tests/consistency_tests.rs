//! Consistency tests: contract spec vs raw WASM exports.

use sorob_inspect::soroban::consistency::check_spec_export_consistency;
use sorob_inspect::soroban::{SpecFunction, SpecInput, SpecReport};
use sorob_inspect::wasm::{inspect, ExportEntry, ImportEntry, WasmReport};

/// Build a `SpecReport` with the given function names.
fn spec_with(names: &[&str]) -> SpecReport {
    SpecReport {
        functions: names
            .iter()
            .map(|n| SpecFunction {
                name: (*n).to_string(),
                inputs: vec![SpecInput {
                    name: "a".to_string(),
                    type_: "I64".to_string(),
                }],
                outputs: vec!["I64".to_string()],
                doc: String::new(),
            })
            .collect(),
        types: Vec::new(),
        events: Vec::new(),
    }
}

/// Build a `WasmReport` with the given function export names.
fn wasm_with_exports(names: &[&str]) -> WasmReport {
    WasmReport {
        size_bytes: 0,
        imports: Vec::<ImportEntry>::new(),
        exports: names
            .iter()
            .map(|n| ExportEntry {
                name: (*n).to_string(),
                kind: "function".to_string(),
                index: 0,
                type_sig: None,
                type_index: None,
                memory: None,
                table: None,
                global: None,
            })
            .collect(),
        custom_sections: Vec::new(),
        custom_section_details: Vec::new(),
        code_body_metrics: Vec::new(),
        reachability: None,
        summary: sorob_inspect::wasm::AnalysisSummary {
            custom_section_count: 0,
            imported_function_count: 0,
            exported_function_count: 0,
            defined_function_count: 0,
            total_function_count: 0,
            total_body_bytes: 0,
            total_operator_count: 0,
            total_local_count: 0,
            instruction_family_totals: Vec::new().into_iter().collect(),
            has_contract_spec: false,
            structure: None,
            reachability: None,
            analysis_finding_count: None,
        },
        functions: Vec::new(),
        structure: None,
        analysis: None,
        interface: None,
    }
}

#[test]
fn test_consistency_matching_case() {
    let wasm = wasm_with_exports(&["init", "process"]);
    let spec = spec_with(&["init", "process"]);
    let r = check_spec_export_consistency(&wasm, Some(&spec));

    assert_eq!(r.status, "checked");
    assert!(
        r.findings.is_empty(),
        "matching spec/exports must have no findings"
    );
    assert_eq!(r.spec_function_count, 2);
    assert_eq!(r.wasm_function_export_count, 2);
    assert!(r.unmatched_exports.is_empty());
    assert_eq!(r.checked, vec!["spec_function_export_presence"]);
    assert!(
        !r.not_checked.is_empty(),
        "unchecked areas must be reported"
    );
}

#[test]
fn test_consistency_missing_export_mismatch() {
    // Spec declares `process` but the module exports only `init`.
    let wasm = wasm_with_exports(&["init"]);
    let spec = spec_with(&["init", "process"]);
    let r = check_spec_export_consistency(&wasm, Some(&spec));

    assert_eq!(r.findings.len(), 1);
    let f = &r.findings[0];
    assert_eq!(f.code, "spec_function_export_missing");
    assert_eq!(f.severity, "mismatch");
    assert!(
        f.evidence.contains("process"),
        "evidence must name the missing function"
    );
    assert!(
        f.message.contains("MissingValue"),
        "message must cite the host rule"
    );
}

#[test]
fn test_consistency_extra_exports_not_flagged() {
    // The module exports an internal helper the spec does not describe. This
    // is normal and must NOT produce a finding.
    let wasm = wasm_with_exports(&["init", "process", "_internal_helper"]);
    let spec = spec_with(&["init", "process"]);
    let r = check_spec_export_consistency(&wasm, Some(&spec));

    assert!(
        r.findings.is_empty(),
        "extra raw exports must never be flagged as mismatches"
    );
    assert_eq!(r.unmatched_exports, vec!["_internal_helper".to_string()]);
}

#[test]
fn test_consistency_constructor_absence_is_not_a_mismatch() {
    // The host permits a contract with no `__constructor` export
    // (soroban-env-host src/host/lifecycle.rs:121-131).
    let wasm = wasm_with_exports(&["init"]);
    let spec = spec_with(&["init", "__constructor"]);
    let r = check_spec_export_consistency(&wasm, Some(&spec));

    assert!(
        r.findings.is_empty(),
        "missing __constructor export is explicitly allowed by the host"
    );
}

#[test]
fn test_consistency_no_spec_is_not_applicable() {
    let wasm = wasm_with_exports(&["init"]);
    let r = check_spec_export_consistency(&wasm, None);

    assert_eq!(r.status, "not_applicable");
    assert!(r.reason.is_some());
    assert!(r.findings.is_empty());
    assert!(r.checked.is_empty());
    assert_eq!(
        r.wasm_function_export_count, 1,
        "export count still reported"
    );
    assert!(!r.not_checked.is_empty());
}

#[test]
fn test_consistency_deterministic_json_and_stable_codes() {
    let wasm = wasm_with_exports(&["init"]);
    let spec = spec_with(&["alpha", "beta", "gamma"]);
    let a = check_spec_export_consistency(&wasm, Some(&spec));
    let b = check_spec_export_consistency(&wasm, Some(&spec));

    // Deterministic: identical inputs → identical reports.
    assert_eq!(a, b);

    let ja = serde_json::to_string(&a).expect("serializes");
    let jb = serde_json::to_string(&b).expect("serializes");
    assert_eq!(ja, jb, "JSON must be byte-identical for identical input");

    // Stable codes, sorted by (code, evidence).
    let codes: Vec<&str> = a.findings.iter().map(|f| f.code.as_str()).collect();
    assert_eq!(
        codes,
        vec![
            "spec_function_export_missing",
            "spec_function_export_missing",
            "spec_function_export_missing"
        ]
    );
    let evidences: Vec<&str> = a.findings.iter().map(|f| f.evidence.as_str()).collect();
    let mut sorted = evidences.clone();
    sorted.sort_unstable();
    assert_eq!(
        evidences, sorted,
        "findings must be deterministically ordered"
    );

    // Round-trip through JSON.
    let back: sorob_inspect::soroban::consistency::ConsistencyReport =
        serde_json::from_str(&ja).expect("deserializes");
    assert_eq!(back, a);
}

#[test]
fn test_consistency_real_fixture_matches() {
    // The real Soroban fixture: every spec function has a same-named export.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/udt_contract_a.wasm");
    let bytes = std::fs::read(&path).expect("fixture readable");
    let wasm = inspect(&bytes, false).expect("valid wasm");
    let spec = sorob_inspect::soroban::decode_spec_from_wasm(&bytes).expect("spec decodes");
    let r = check_spec_export_consistency(&wasm, Some(&spec));

    assert_eq!(r.status, "checked");
    assert!(
        r.findings.is_empty(),
        "well-formed contract must report no mismatch"
    );
    assert_eq!(r.spec_function_count, 6);
    assert_eq!(r.wasm_function_export_count, 6);
}

#[test]
fn test_consistency_non_function_exports_ignored() {
    // A memory/global export must not be counted as a function export.
    let mut wasm = wasm_with_exports(&["init"]);
    wasm.exports.push(ExportEntry {
        name: "memory".to_string(),
        kind: "memory".to_string(),
        index: 0,
        type_sig: None,
        type_index: None,
        memory: None,
        table: None,
        global: None,
    });
    let spec = spec_with(&["init"]);
    let r = check_spec_export_consistency(&wasm, Some(&spec));

    assert_eq!(
        r.wasm_function_export_count, 1,
        "only function exports counted"
    );
    assert!(r.findings.is_empty());
    assert!(
        r.not_checked
            .contains(&"export_kind_other_than_function".to_string()),
        "non-function export comparison must be declared not_checked"
    );
}
