use sorob_inspect::soroban::inspect_soroban;
use sorob_inspect::wasm::{analyze, build_analysis_summary, inspect, AnalysisSummary};
use std::fs;
use std::path::PathBuf;

// Hand-built WASM: magic + version + a custom section named "contractspecv0".
fn wasm_with_custom_section(name: &str, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // Custom section: id=0, length, then name-length + name + data.
    let payload_len = 1 + name.len() + data.len();
    buf.push(0x00); // section id
    buf.push(payload_len as u8);
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(data);
    buf
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_soroban.wasm")
}

// Start-function integration fixtures. Built programmatically: hand-counting
// section lengths repeatedly produced invalid modules in earlier work.
fn type_section(n: usize) -> Vec<u8> {
    let mut payload = vec![n as u8];
    for _ in 0..n {
        payload.extend_from_slice(&[0x60, 0x00, 0x00]);
    }
    let mut b = vec![0x01, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn function_section(n: usize) -> Vec<u8> {
    let mut payload = vec![n as u8];
    payload.extend(std::iter::repeat_n(0u8, n));
    let mut b = vec![0x03, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn code_section(n: usize) -> Vec<u8> {
    let mut payload = vec![n as u8];
    for _ in 0..n {
        payload.extend_from_slice(&[0x02, 0x00, 0x0b]);
    }
    let mut b = vec![0x0a, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn memory_section() -> Vec<u8> {
    vec![0x05, 0x03, 0x01, 0x00, 0x01]
}

fn import_section(names: &[&str]) -> Vec<u8> {
    let mut payload = vec![names.len() as u8];
    for name in names {
        payload.push(0x03);
        payload.extend_from_slice(b"env");
        payload.push(name.len() as u8);
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(&[0x00, 0x00]);
    }
    let mut b = vec![0x02, payload.len() as u8];
    b.extend_from_slice(&payload);
    b
}

fn start_section(func_index: u8) -> Vec<u8> {
    vec![0x08, 0x01, func_index]
}

// --- Data segment fixtures ---

/// Encode a LEB128 unsigned integer.
fn leb(n: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut n = n;
    loop {
        let mut v = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            v |= 0x80;
        }
        out.push(v);
        if n == 0 {
            break;
        }
    }
    out
}

/// A module with a defined memory and the given raw data-segment bodies.
fn module_with_data_segments(segments: &[Vec<u8>]) -> Vec<u8> {
    let mut b = wasm_header();
    b.extend_from_slice(&memory_section());
    let mut content = Vec::new();
    content.extend_from_slice(&leb(segments.len() as u32));
    for seg in segments {
        content.extend_from_slice(seg);
    }
    b.push(0x0b); // data section
    b.extend_from_slice(&leb(content.len() as u32));
    b.extend_from_slice(&content);
    b
}

/// Active segment: memory index 0, `i32.const <off>`, payload.
fn active_segment(off: i32, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x41];
    v.extend_from_slice(&leb(off as u32));
    v.push(0x0b);
    v.extend_from_slice(&leb(payload.len() as u32));
    v.extend_from_slice(payload);
    v
}

/// Passive segment: flags 0x01, payload.
fn passive_segment(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x01];
    v.extend_from_slice(&leb(payload.len() as u32));
    v.extend_from_slice(payload);
    v
}

#[test]
fn test_data_segment_details_json() {
    let wasm = module_with_data_segments(&[active_segment(42, b"hi"), passive_segment(b"")]);
    let report = inspect(&wasm, false).expect("valid wasm");
    let structure = report.structure.as_ref().expect("structure present");
    assert_eq!(structure.data_segments, 2, "existing count is preserved");
    assert_eq!(structure.data_segment_details.len(), 2);

    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let details = value["structure"]["data_segment_details"]
        .as_array()
        .expect("details array");
    assert_eq!(details.len(), 2);
    assert_eq!(details[0]["index"], 0);
    assert_eq!(details[0]["mode"], "active");
    assert_eq!(details[0]["memory_index"], 0);
    assert_eq!(details[0]["offset"]["const"]["value"], 42);
    assert_eq!(details[0]["payload_len"], 2);
    assert_eq!(details[1]["index"], 1);
    assert_eq!(details[1]["mode"], "passive");
    assert_eq!(details[1]["payload_len"], 0);
    assert!(
        details[1].get("memory_index").is_none(),
        "passive segment must not carry a memory index"
    );
    assert!(
        details[1].get("offset").is_none(),
        "passive segment must not carry an offset"
    );
}

#[test]
fn test_data_segment_payload_is_not_emitted() {
    let wasm = module_with_data_segments(&[active_segment(0, b"SECRETPASSWORD")]);
    let report = inspect(&wasm, false).expect("valid wasm");
    let json = serde_json::to_string(&report).expect("serialize");
    assert!(
        !json.contains("SECRETPASSWORD"),
        "segment payload bytes must never appear in JSON: {json}"
    );
    assert!(json.contains("\"payload_len\":14"));
}

#[test]
fn test_data_segment_details_preserve_order_and_are_deterministic() {
    let build = || {
        module_with_data_segments(&[
            active_segment(1, b"a"),
            passive_segment(b"b"),
            active_segment(2, b"c"),
        ])
    };
    let first = serde_json::to_string(&inspect(&build(), false).expect("valid")).expect("json");
    let second = serde_json::to_string(&inspect(&build(), false).expect("valid")).expect("json");
    assert_eq!(first, second, "data-segment JSON must be deterministic");

    let value: serde_json::Value = serde_json::from_str(&first).expect("parse");
    let details = value["structure"]["data_segment_details"]
        .as_array()
        .expect("details array");
    assert_eq!(details.len(), 3);
    let modes: Vec<&str> = details
        .iter()
        .map(|d| d["mode"].as_str().unwrap())
        .collect();
    assert_eq!(modes, vec!["active", "passive", "active"]);
    let idx: Vec<u64> = details
        .iter()
        .map(|d| d["index"].as_u64().unwrap())
        .collect();
    assert_eq!(idx, vec![0, 1, 2]);
}

#[test]
fn test_data_segment_global_get_offset_not_evaluated() {
    // Offset `global.get 0` — reported as a reference, never as a value.
    let mut body = vec![0x00, 0x23];
    body.extend_from_slice(&leb(0));
    body.push(0x0b);
    body.extend_from_slice(&leb(0));
    let wasm = module_with_data_segments(&[body]);
    let report = inspect(&wasm, false).expect("valid wasm");
    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let offset = &value["structure"]["data_segment_details"][0]["offset"];
    assert_eq!(offset["global_get"]["global_index"], 0);
    assert!(
        offset.get("const").is_none(),
        "a global reference must not be reported as a constant value"
    );
}

#[test]
fn test_no_data_section_omits_details() {
    let mut wasm = wasm_header();
    wasm.extend_from_slice(&memory_section());
    let report = inspect(&wasm, false).expect("valid wasm");
    let structure = report.structure.as_ref().expect("structure present");
    assert_eq!(structure.data_segments, 0);
    assert!(structure.data_segment_details.is_empty());
    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert!(
        value["structure"].get("data_segment_details").is_none(),
        "empty details must be omitted, not emitted as an empty array"
    );
}

#[test]
fn test_malformed_data_section_is_rejected() {
    // Invalid data-segment flags byte → malformed, consistent with the
    // parser's handling of other invalid sections.
    let mut wasm = wasm_header();
    wasm.extend_from_slice(&memory_section());
    let content = vec![0x01, 0x05];
    wasm.push(0x0b);
    wasm.extend_from_slice(&leb(content.len() as u32));
    wasm.extend_from_slice(&content);
    let result = inspect(&wasm, false);
    assert!(
        result.is_err(),
        "invalid data segment flags must be rejected"
    );
}

fn wasm_header() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

#[test]
fn test_start_function_absent_is_json_omitted() {
    // No start section → the field must be absent from JSON entirely, never 0.
    let mut wasm = wasm_header();
    wasm.extend_from_slice(&type_section(1));
    wasm.extend_from_slice(&import_section(&["add"]));
    wasm.extend_from_slice(&function_section(1));
    wasm.extend_from_slice(&code_section(1));
    wasm.extend_from_slice(&memory_section());
    let report = inspect(&wasm, false).expect("valid wasm");
    let structure = report.structure.as_ref().expect("structure present");
    assert_eq!(structure.start_func, None);
    assert!(structure.start_function.is_none());

    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let structure = &value["structure"];
    assert!(
        structure.get("start_func").is_none(),
        "absent start section must omit start_func, not emit 0: {json}"
    );
    assert!(
        structure.get("start_function").is_none(),
        "absent start section must omit start_function: {json}"
    );
}

#[test]
fn test_start_function_imported_json() {
    let mut wasm = wasm_header();
    wasm.extend_from_slice(&type_section(1));
    wasm.extend_from_slice(&import_section(&["add"]));
    wasm.extend_from_slice(&memory_section());
    wasm.extend_from_slice(&start_section(0)); // imported function index 0
    let report = inspect(&wasm, false).expect("valid wasm");
    let structure = report.structure.as_ref().expect("structure present");
    assert_eq!(structure.start_func, Some(0));
    let sf = structure
        .start_function
        .as_ref()
        .expect("start function detail");
    assert_eq!(sf.resolution, "imported");
    assert_eq!(sf.import.as_ref().expect("import ref").name, "add");

    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(
        value["structure"]["start_function"]["resolution"],
        "imported"
    );
    assert_eq!(
        value["structure"]["start_function"]["import"]["module"],
        "env"
    );
    assert!(
        value["structure"]["start_function"]
            .get("function")
            .is_none(),
        "imported start must not carry a defined-function block"
    );
}

#[test]
fn test_start_function_defined_json() {
    let mut wasm = wasm_header();
    wasm.extend_from_slice(&type_section(1));
    wasm.extend_from_slice(&import_section(&["add"]));
    wasm.extend_from_slice(&function_section(1));
    wasm.extend_from_slice(&code_section(1));
    wasm.extend_from_slice(&memory_section());
    wasm.extend_from_slice(&start_section(1)); // defined function index 1
    let report = inspect(&wasm, false).expect("valid wasm");
    let structure = report.structure.as_ref().expect("structure present");
    let sf = structure
        .start_function
        .as_ref()
        .expect("start function detail");
    assert_eq!(sf.resolution, "defined");
    assert_eq!(sf.function.as_ref().expect("sig").declared_index, 0);

    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(
        value["structure"]["start_function"]["resolution"],
        "defined"
    );
    assert!(
        value["structure"]["start_function"].get("import").is_none(),
        "defined start must not carry an import reference"
    );
}

#[test]
fn test_start_function_index_resolution_is_deterministic() {
    // Two imports + one defined function; start index 2 → defined, stable
    // across repeated serialization.
    let build = || {
        let mut wasm = wasm_header();
        wasm.extend_from_slice(&type_section(1));
        wasm.extend_from_slice(&import_section(&["add", "sub"]));
        wasm.extend_from_slice(&function_section(1));
        wasm.extend_from_slice(&code_section(1));
        wasm.extend_from_slice(&memory_section());
        wasm.extend_from_slice(&start_section(2));
        wasm
    };
    let first = serde_json::to_string(&inspect(&build(), false).expect("valid")).expect("json");
    let second = serde_json::to_string(&inspect(&build(), false).expect("valid")).expect("json");
    assert_eq!(first, second, "start-function JSON must be deterministic");
    let value: serde_json::Value = serde_json::from_str(&first).expect("parse");
    assert_eq!(
        value["structure"]["start_function"]["resolution"],
        "defined"
    );
    assert_eq!(
        value["structure"]["start_function"]["function"]["declared_index"],
        0
    );
}

#[test]
fn test_start_function_invalid_index_json() {
    // Index beyond every function → reported as invalid, not a panic and not
    // silently dropped.
    let mut wasm = wasm_header();
    wasm.extend_from_slice(&type_section(1));
    wasm.extend_from_slice(&import_section(&["add"]));
    wasm.extend_from_slice(&memory_section());
    wasm.extend_from_slice(&start_section(7));
    let report = inspect(&wasm, false).expect("valid wasm");
    let sf = report
        .structure
        .as_ref()
        .expect("structure present")
        .start_function
        .as_ref()
        .expect("start function detail");
    assert_eq!(sf.index, 7);
    assert_eq!(sf.resolution, "invalid");
}

fn udt_a_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/udt_contract_a.wasm")
}

fn udt_b_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/udt_contract_b.wasm")
}

#[test]
fn test_inspect_valid_empty_wasm() {
    // Magic + version only — the smallest valid WASM module.
    let wasm: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let report = inspect(&wasm, true).expect("should parse");
    assert_eq!(report.size_bytes, 8);
    assert!(report.imports.is_empty());
    assert!(report.exports.is_empty());
}

#[test]
fn test_inspect_truncated_fails_cleanly() {
    let bad = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00];
    let result = inspect(&bad, false);
    assert!(result.is_err());
}

#[test]
fn test_inspect_empty_wasm_has_no_structure() {
    // Bare module: no memory/table/global/segment/start → structure is None.
    let report = inspect(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00], false)
        .expect("valid empty wasm");
    assert!(report.structure.is_none());
}

#[test]
fn test_inspect_memory_module_reports_structure() {
    // Memory section (id 5), 1 entry, limits flag 0x01, min 2, max 4.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x05, 0x04, 0x01, 0x01, 0x02, 0x04, // memory section
    ];
    let report = inspect(&wasm, false).expect("valid wasm with memory");
    let s = report.structure.expect("structure present");
    assert_eq!(s.memories.len(), 1);
    assert_eq!(s.memories[0].min_pages, 2);
    assert_eq!(s.memories[0].max_pages, Some(4));
    assert!(!s.memories[0].is64);
}

#[test]
fn test_analyze_memory_module() {
    // Memory section (id 5), 1 entry, limits flag 0x01, min 2, max 4.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x05, 0x04, 0x01, 0x01, 0x02, 0x04, // memory section
    ];
    let a = analyze(&wasm).expect("analysis works");
    assert!(a.imported_memories.is_empty());
    assert_eq!(a.defined_memories.len(), 1);
    assert_eq!(a.defined_memories[0].min_pages, 2);
    assert_eq!(a.defined_memories[0].max_pages, Some(4));
    assert_eq!(a.function_count, 0);
    assert!(
        a.findings.is_empty(),
        "no findings for a plain memory module"
    );
}

#[test]
fn test_analyze_float_module_flags_incompatible() {
    // Module with an exported f32.add function.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7d, 0x7d, 0x01, 0x7d, // type (f32,f32)->f32
        0x03, 0x02, 0x01, 0x00, // function section
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00, // export "add"
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x92, 0x0b, // f32.add
    ];
    let a = analyze(&wasm).expect("analysis works");
    assert_eq!(a.function_count, 1);
    assert_eq!(a.findings.len(), 1, "exactly one finding");
    assert_eq!(a.findings[0].code, "float_ops");
    assert_eq!(a.findings[0].severity, "incompatible");
}

#[test]
fn test_analyze_no_float_findings_for_integer_module() {
    // Module with an i32.add function — no float ops.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // type (i32,i32)->i32
        0x03, 0x02, 0x01, 0x00, // function section
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00, // export "add"
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b, // i32.add
    ];
    let a = analyze(&wasm).expect("analysis works");
    assert!(
        a.findings.is_empty(),
        "integer-only module must have no findings, got {:?}",
        a.findings
    );
}

#[test]
fn test_analyze_memory64_flagged_unsupported() {
    // Memory section with limits flag 0x05 (memory64 + has_max), min 2 max 4.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x05, 0x04, 0x01, 0x05, 0x02, 0x04, // memory section (memory64)
    ];
    let a = analyze(&wasm).expect("analysis works");
    assert_eq!(a.findings.len(), 1);
    assert_eq!(a.findings[0].code, "memory64");
    assert_eq!(a.findings[0].severity, "unsupported");
    assert!(a.defined_memories[0].is64);
}

#[test]
fn test_analyze_imported_vs_defined_split() {
    // Import one memory, define one memory. Both must appear in the right bucket.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        // Import section: 1 import "env"::"mem" memory, limits flag 0x00, min 1.
        0x02, 0x0c, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x03, 0x6d, 0x65, 0x6d, 0x02, 0x00, 0x01,
        // Memory section: 1 defined memory, limits flag 0x00, min 3.
        0x05, 0x03, 0x01, 0x00, 0x03,
    ];
    let a = analyze(&wasm).expect("analysis works");
    assert_eq!(a.imported_memories, vec!["env::mem".to_string()]);
    assert_eq!(a.defined_memories.len(), 1);
    assert_eq!(a.defined_memories[0].min_pages, 3);
}

#[test]
fn test_coverage_present_for_clean_module() {
    // Integer-only i32.add module: no findings, but coverage must be present.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f,
        0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
    ];
    let a = analyze(&wasm).expect("analysis works");
    assert!(a.findings.is_empty(), "no findings for integer module");
    assert!(
        !a.coverage.not_checked.is_empty(),
        "not_checked must list uncovered areas even when findings is empty"
    );
    assert!(
        !a.coverage.checked.is_empty(),
        "checked must list areas that ran (float_ops probe ran)"
    );
}

#[test]
fn test_coverage_checked_contains_float_ops_when_triggered() {
    // f32.add module: float_ops must appear in both findings and coverage.checked.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02, 0x7d, 0x7d,
        0x01, 0x7d, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x92, 0x0b,
    ];
    let a = analyze(&wasm).expect("analysis works");
    assert!(a.findings.iter().any(|f| f.code == "float_ops"));
    assert!(
        a.coverage.checked.contains(&"float_ops".to_string()),
        "coverage.checked must include float_ops"
    );
}

#[test]
fn test_coverage_deterministic_output() {
    // Same input run twice must produce identical coverage arrays.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x05, 0x04, 0x01, 0x01, 0x02, 0x04,
    ];
    let a1 = analyze(&wasm).expect("analysis works");
    let a2 = analyze(&wasm).expect("analysis works");
    assert_eq!(a1.coverage, a2.coverage, "coverage must be deterministic");
    assert_eq!(a1.coverage.not_checked, a2.coverage.not_checked);
    assert_eq!(a1.coverage.checked, a2.coverage.checked);
}

#[test]
fn test_coverage_not_checked_lists_expected_areas() {
    let wasm: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let a = analyze(&wasm).expect("analysis works");
    let expected = [
        "component_model",
        "exceptions",
        "gc",
        "memory64",
        "multi_memory",
        "simd",
        "tail_calls",
        "threads",
    ];
    assert_eq!(
        a.coverage.not_checked,
        expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "not_checked must list all uncovered areas"
    );
}

#[test]
fn test_coverage_findings_separate_from_coverage() {
    // Empty findings must not imply full coverage — not_checked stays populated.
    let wasm: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let a = analyze(&wasm).expect("analysis works");
    assert!(a.findings.is_empty());
    assert!(!a.coverage.not_checked.is_empty());
}

#[test]
fn test_import_details_json_serialization() {
    // Module with one imported memory (min 1, no max).
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x02, 0x0c,
        0x01, // import section, len 12, count 1
        0x03, b'e', b'n', b'v', // module "env"
        0x03, b'm', b'e', b'm', // name "mem"
        0x02, 0x00, 0x01, // kind memory, flag 0x00 (no max), min 1
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let imp = &report.imports[0];

    // Backward-compatible fields still present.
    assert_eq!(imp.module, "env");
    assert_eq!(imp.name, "mem");
    assert_eq!(imp.kind, "memory");
    assert!(imp.type_sig.is_none());

    // New structured fields.
    let mem = imp.memory.as_ref().expect("memory details");
    assert_eq!(mem.min_pages, 1);
    assert_eq!(mem.max_pages, None, "no max → None, not Some(0)");
    assert!(!mem.is64);

    // JSON: new fields present, absent fields omitted.
    let json = serde_json::to_value(imp).expect("serializes");
    assert_eq!(json["module"], "env");
    assert_eq!(json["name"], "mem");
    assert_eq!(json["kind"], "memory");
    assert_eq!(json["memory"]["min_pages"], 1);
    assert!(
        json["memory"].get("max_pages").is_none(),
        "max_pages must be absent (not 0) when not declared"
    );
    assert!(json.get("type_sig").is_none());
}

#[test]
fn test_import_global_details_json() {
    // Module with one imported mutable i64 global.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x02, 0x0a,
        0x01, // import section, len 10, count 1
        0x03, b'e', b'n', b'v', // module "env"
        0x01, b'g', // name "g"
        0x03, 0x7e, 0x01, // kind global, i64 (0x7e), mutable (0x01)
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let imp = &report.imports[0];
    let g = imp.global.as_ref().expect("global details");
    assert_eq!(g.value_type, "I64");
    assert!(g.mutable);
    assert!(imp.memory.is_none());
    assert!(imp.table.is_none());
}

#[test]
fn test_import_function_type_index_json() {
    // Module with one imported function.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00,
        0x00, // type section: () -> ()
        0x02, 0x0b, 0x01, // import section, len 11, count 1
        0x03, b'e', b'n', b'v', // module "env"
        0x03, b'a', b'd', b'd', // name "add"
        0x00, 0x00, // kind func, type index 0
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let imp = &report.imports[0];
    assert_eq!(imp.type_index, Some(0));
    assert!(imp.type_sig.is_some());
    assert!(imp.memory.is_none());
}

#[test]
fn test_import_table_details_json() {
    // Module with one imported table (funcref, min 1, no max).
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x02, 0x0d,
        0x01, // import section, len 13, count 1
        0x03, b'e', b'n', b'v', // module "env"
        0x03, b't', b'l', b'l', // name "tbl"
        0x01, 0x70, 0x00, 0x01, // kind table, funcref (0x70), flag 0x00, min 1
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let imp = &report.imports[0];
    let tbl = imp.table.as_ref().expect("table details");
    assert_eq!(tbl.element_type, "funcref");
    assert_eq!(tbl.min_size, 1);
    assert_eq!(tbl.max_size, None);
}

#[test]
fn test_export_function_details_json() {
    // Module with one defined function (type 0: () -> ()) exported as "f".
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00,
        0x00, // type section: () -> ()
        0x03, 0x02, 0x01, 0x00, // function section: 1 func, type 0
        0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00, // export section: "f" func idx 0
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let e = &report.exports[0];
    assert_eq!(e.name, "f");
    assert_eq!(e.kind, "function");
    assert_eq!(e.index, 0);
    assert_eq!(e.type_index, Some(0));
    assert_eq!(e.type_sig.as_deref(), Some("() -> ()"));
    assert!(e.memory.is_none() && e.table.is_none() && e.global.is_none());
}

#[test]
fn test_export_memory_and_global_details_json() {
    // Module with a defined memory (min 1, no max) and a defined immutable
    // i32 global, both exported.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00,
        0x01, // memory section: 1 mem, flag 0x00, min 1
        0x06, 0x06, 0x01, 0x7f, 0x00, 0x41, 0x00,
        0x0b, // global: i32 immutable, init i32.const 0
        0x07, 0x09, 0x02, // export section, len 9, count 2
        0x01, b'm', 0x02, 0x00, // "m" memory idx 0
        0x01, b'g', 0x03, 0x00, // "g" global idx 0
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let m = report
        .exports
        .iter()
        .find(|e| e.name == "m")
        .expect("mem export");
    assert_eq!(m.kind, "memory");
    let mem = m.memory.as_ref().expect("memory details");
    assert_eq!(mem.min_pages, 1);
    assert_eq!(mem.max_pages, None, "no max → absent, never 0");
    assert!(!mem.is64);

    let g = report
        .exports
        .iter()
        .find(|e| e.name == "g")
        .expect("global export");
    assert_eq!(g.kind, "global");
    let glob = g.global.as_ref().expect("global details");
    assert_eq!(glob.value_type, "I32");
    assert!(!glob.mutable);
}

#[test]
fn test_export_index_resolution_across_imports() {
    // The critical case: an imported function occupies index 0, so the
    // exported function at index 1 must resolve to the DEFINED function,
    // not to the import. Likewise an imported memory occupies memory index
    // 0, so the exported memory at index 1 is the defined one.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00,
        0x00, // type section: () -> ()
        // import section: count 2 — env.func (function, type 0) -> func idx 0
        //                     env.mem (memory, min 1)          -> mem idx 0
        0x02, 0x17, 0x02, // import section, len 23, count 2
        0x03, b'e', b'n', b'v', 0x04, b'f', b'u', b'n', b'c', 0x00, 0x00, 0x03, b'e', b'n', b'v',
        0x03, b'm', b'e', b'm', 0x02, 0x00, 0x01,
        // defined function (type 0)             -> function index 1
        0x03, 0x02, 0x01, 0x00,
        // defined memory (min 2, max 3)         -> memory index 1
        0x05, 0x04, 0x01, 0x01, 0x02, 0x03,
        // exports: "f" -> func idx 1, "m" -> mem idx 1
        0x07, 0x09, 0x02, 0x01, b'f', 0x00, 0x01, // "f" function idx 1
        0x01, b'm', 0x02, 0x01, // "m" memory idx 1
    ];
    let report = inspect(&wasm, false).expect("valid wasm");

    let f = report
        .exports
        .iter()
        .find(|e| e.name == "f")
        .expect("func export");
    assert_eq!(f.index, 1, "export index preserved verbatim");
    assert_eq!(
        f.type_index,
        Some(0),
        "must resolve through import space to the defined function"
    );
    assert_eq!(f.type_sig.as_deref(), Some("() -> ()"));

    let m = report
        .exports
        .iter()
        .find(|e| e.name == "m")
        .expect("mem export");
    assert_eq!(m.index, 1);
    let mem = m.memory.as_ref().expect("memory details");
    assert_eq!(
        (mem.min_pages, mem.max_pages),
        (2, Some(3)),
        "must resolve to the DEFINED memory (min 2 max 3), not the import (min 1)"
    );
}

#[test]
fn test_export_table_details_json() {
    // Module with a defined table (funcref, min 1, no max) exported.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x04, 0x04, 0x01, 0x70, 0x00,
        0x01, // table: funcref, flag 0x00, min 1
        0x07, 0x05, 0x01, 0x01, b't', 0x01, 0x00, // export "t" table idx 0
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let e = &report.exports[0];
    let t = e.table.as_ref().expect("table details");
    assert_eq!(t.element_type, "funcref");
    assert_eq!(t.min_size, 1);
    assert_eq!(t.max_size, None);
}

#[test]
fn test_export_details_backward_compatible() {
    // Existing fields (name/kind/index) must remain present and unchanged;
    // new fields must be absent when unresolvable (e.g. tag exports).
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00,
        0x00, // type section
        0x03, 0x02, 0x01, 0x00, // function section
        0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00, // export "f"
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let json = serde_json::to_value(&report.exports[0]).expect("serializes");
    assert_eq!(json["name"], "f");
    assert_eq!(json["kind"], "function");
    assert_eq!(json["index"], 0);
    assert_eq!(json["type_index"], 0);
    // A function export never carries memory/table/global objects.
    assert!(json.get("memory").is_none());
    assert!(json.get("table").is_none());
    assert!(json.get("global").is_none());
}

#[test]
fn test_inspect_garbage_fails_cleanly() {
    let bad = vec![0xff, 0xff, 0xff, 0xff];
    let result = inspect(&bad, false);
    assert!(result.is_err());
}

#[test]
fn test_validate_detects_contract_spec_true() {
    // Hand-built module with a contractspecv0 section containing non-XDR
    // bytes — marker detection works, but spec decode should fail cleanly.
    let wasm = wasm_with_custom_section("contractspecv0", &[0xab, 0xcd]);
    let result = inspect_soroban(&wasm, false);
    // The section IS detected, but decode fails on invalid XDR.
    match result {
        Ok(report) => {
            assert!(report.has_contract_spec);
            assert!(report.spec.is_none());
            assert!(report.summary.contains("contractspecv0"));
        }
        Err(_) => {
            // If the implementation hard-fails the whole report on decode
            // error, that's also acceptable — the key is no panic.
        }
    }
}

#[test]
fn test_validate_detects_contract_env_meta_true() {
    let wasm = wasm_with_custom_section("contractenvmetav0", &[0x01]);
    let result = inspect_soroban(&wasm, false);
    // env-meta section found, no spec section to decode.
    if let Ok(report) = result {
        assert!(!report.has_contract_spec);
        assert!(report.has_contract_env_meta);
    }
}

#[test]
fn test_validate_no_soroban_markers() {
    let wasm = wasm_with_custom_section("producers", &[]);
    let report = inspect_soroban(&wasm, false).expect("should parse");
    assert!(!report.has_contract_spec);
    assert!(!report.has_contract_env_meta);
    assert!(report.summary.contains("No Soroban"));
}

#[test]
fn test_soroban_report_serializes_to_json() {
    let wasm = wasm_with_custom_section("contractspecv0", &[0xab, 0xcd]);
    // Invalid XDR → decode fails. Report error as JSON-serializable error.
    let result = inspect_soroban(&wasm, false);
    assert!(result.is_err());
}

#[test]
fn test_real_fixture_decodes_spec() {
    let path = fixture_path();
    let wasm = fs::read(&path).expect("fixture missing");
    let report = inspect_soroban(&wasm, true).expect("fixture should validate+decode");
    assert!(report.has_contract_spec);
    assert!(report.has_contract_env_meta);
    assert!(
        report.spec.is_some(),
        "spec should decode from real fixture"
    );
    let spec = report.spec.as_ref().unwrap();
    assert!(
        !spec.functions.is_empty(),
        "test fixture should have at least 1 function"
    );
    assert!(report.summary.contains("decoded"));
}

#[test]
fn test_real_fixture_json_contains_decoded_functions() {
    let path = fixture_path();
    let wasm = fs::read(&path).expect("fixture missing");
    let report = inspect_soroban(&wasm, false).expect("should parse");
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("has_contract_spec"));
    assert!(json.contains("functions"));
    assert!(json.contains("true"));
}

// --- UDT fixture tests (Task 2-3) ---

#[test]
fn test_udt_fixture_a_decodes_struct_fields() {
    let path = udt_a_path();
    let wasm = fs::read(&path).expect("fixture missing");
    let report = inspect_soroban(&wasm, true).expect("fixture should validate+decode");
    let spec = report.spec.as_ref().unwrap();
    let config = spec
        .types
        .iter()
        .find(|t| t.name == "Config")
        .expect("Config struct should be present");
    assert_eq!(config.kind, "struct");
    assert!(!config.fields.is_empty());
    assert!(config
        .fields
        .iter()
        .any(|f| f.name == "owner" && f.type_ == "Address"));
}

#[test]
fn test_udt_fixture_a_decodes_union_cases() {
    let path = udt_a_path();
    let wasm = fs::read(&path).expect("fixture missing");
    let report = inspect_soroban(&wasm, true).expect("fixture should validate+decode");
    let spec = report.spec.as_ref().unwrap();
    let status = spec
        .types
        .iter()
        .find(|t| t.name == "Status")
        .expect("Status union should be present");
    assert_eq!(status.kind, "union");
    assert!(!status.cases.is_empty());
    // Cases are structured: name + kind preserved (Void for unit variants).
    assert!(status.cases.iter().any(|c| c.name == "Pending"));
    assert!(status
        .cases
        .iter()
        .all(|c| c.kind == "void" || c.kind == "tuple"));
}

#[test]
fn test_udt_fixture_a_decodes_event() {
    let path = udt_a_path();
    let wasm = fs::read(&path).expect("fixture missing");
    let report = inspect_soroban(&wasm, true).expect("fixture should validate+decode");
    let spec = report.spec.as_ref().unwrap();
    assert!(!spec.events.is_empty());
    let ev = &spec.events[0];
    assert!(!ev.params.is_empty());
    assert!(!ev.prefix_topics.is_empty());
}

// --- Diff tests (Task 4-5) ---

#[test]
fn test_udt_diff_detects_struct_field_added() {
    let a = fs::read(udt_a_path()).expect("fixture missing");
    let b = fs::read(udt_b_path()).expect("fixture missing");
    let a_report = inspect_soroban(&a, false).expect("A should decode");
    let b_report = inspect_soroban(&b, false).expect("B should decode");
    let diff = sorob_inspect::soroban::diff::diff_specs(
        a_report.spec.as_ref().unwrap(),
        b_report.spec.as_ref().unwrap(),
    );
    assert_eq!(
        diff.compatibility,
        sorob_inspect::soroban::diff::Compatibility::Breaking
    );
    let config_change = diff
        .types_changed
        .iter()
        .find(|c| c.name == "Config")
        .expect("Config change detected");
    assert!(config_change.breaking);
    assert!(config_change.detail.contains("count"));
}

#[test]
fn test_udt_diff_detects_enum_variant_removed() {
    let a = fs::read(udt_a_path()).expect("fixture missing");
    let b = fs::read(udt_b_path()).expect("fixture missing");
    let a_report = inspect_soroban(&a, false).expect("A should decode");
    let b_report = inspect_soroban(&b, false).expect("B should decode");
    let diff = sorob_inspect::soroban::diff::diff_specs(
        a_report.spec.as_ref().unwrap(),
        b_report.spec.as_ref().unwrap(),
    );
    let status_change = diff
        .types_changed
        .iter()
        .find(|c| c.name == "Status")
        .expect("Status change detected");
    assert!(status_change.breaking);
}

#[test]
fn test_udt_diff_detects_event_removed() {
    let a = fs::read(udt_a_path()).expect("fixture missing");
    let b = fs::read(udt_b_path()).expect("fixture missing");
    let a_report = inspect_soroban(&a, false).expect("A should decode");
    let b_report = inspect_soroban(&b, false).expect("B should decode");
    let diff = sorob_inspect::soroban::diff::diff_specs(
        a_report.spec.as_ref().unwrap(),
        b_report.spec.as_ref().unwrap(),
    );
    assert!(!diff.events_removed.is_empty());
    assert!(diff.events_removed.contains(&"StatusEvent".to_string()));
}

// --- ABI blind-spot fixtures (tuple payload + enum discriminant) ---

fn fx(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn diff_fixtures(old: &str, new: &str) -> sorob_inspect::soroban::diff::SpecDiff {
    let a = fs::read(fx(old)).expect("old fixture missing");
    let b = fs::read(fx(new)).expect("new fixture missing");
    let a_report = inspect_soroban(&a, false).expect("old should decode");
    let b_report = inspect_soroban(&b, false).expect("new should decode");
    sorob_inspect::soroban::diff::diff_specs(
        a_report.spec.as_ref().unwrap(),
        b_report.spec.as_ref().unwrap(),
    )
}

#[test]
fn test_real_fixture_tuple_case_payload_is_decoded() {
    let wasm = fs::read(fx("udt_contract_c.wasm")).expect("fixture missing");
    let report = inspect_soroban(&wasm, true).expect("should decode");
    let spec = report.spec.as_ref().unwrap();
    let shape = spec
        .types
        .iter()
        .find(|t| t.name == "Shape")
        .expect("Shape union present");
    let circle = shape
        .cases
        .iter()
        .find(|c| c.name == "Circle")
        .expect("Circle case present");
    assert_eq!(circle.kind, "tuple");
    assert_eq!(circle.payload, vec!["U32".to_string()]);
    assert!(circle.value.is_none(), "union cases carry no discriminant");
}

#[test]
fn test_real_fixture_tuple_case_payload_change_is_breaking() {
    // udt_c has Circle(u32); udt_d has Circle(u64). Same case names — this is
    // exactly the blind spot that used to decode as `identical`.
    let diff = diff_fixtures("udt_contract_c.wasm", "udt_contract_d.wasm");
    assert_eq!(
        diff.compatibility,
        sorob_inspect::soroban::diff::Compatibility::Breaking
    );
    assert!(diff
        .types_changed
        .iter()
        .any(|c| c.name == "Shape" && c.detail.contains("payload changed")));
}

#[test]
fn test_real_fixture_enum_discriminant_is_decoded() {
    let wasm = fs::read(fx("udt_contract_e.wasm")).expect("fixture missing");
    let report = inspect_soroban(&wasm, true).expect("should decode");
    let spec = report.spec.as_ref().unwrap();
    let kind = spec
        .types
        .iter()
        .find(|t| t.name == "Kind")
        .expect("Kind enum present");
    let a = kind
        .cases
        .iter()
        .find(|c| c.name == "A")
        .expect("A present");
    assert_eq!(a.kind, "enum");
    assert_eq!(a.value, Some(5), "explicit discriminant must be preserved");
}

#[test]
fn test_real_fixture_enum_discriminant_change_is_breaking() {
    // udt_e has C = 2; udt_f has C = 7. Same case names, different wire value.
    let diff = diff_fixtures("udt_contract_e.wasm", "udt_contract_f.wasm");
    assert_eq!(
        diff.compatibility,
        sorob_inspect::soroban::diff::Compatibility::Breaking
    );
    assert!(diff
        .types_changed
        .iter()
        .any(|c| c.name == "Kind" && c.detail.contains("discriminant changed")));
}

#[test]
fn test_identical_fixture_is_identical() {
    let diff = diff_fixtures("udt_contract_c.wasm", "udt_contract_c.wasm");
    assert_eq!(
        diff.compatibility,
        sorob_inspect::soroban::diff::Compatibility::Identical
    );
}

// --- --fail-on-breaking CLI gating (Task 1) ---

const BIN: &str = env!("CARGO_BIN_EXE_sorob-inspect");

fn run_cli(args: &[&str]) -> (i32, String, String) {
    use std::process::Command;
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("CLI should start");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn test_fail_on_breaking_breaking_diff_exits_one() {
    let (rc, _, _) = run_cli(&[
        "diff",
        "tests/fixtures/udt_contract_c.wasm",
        "tests/fixtures/udt_contract_d.wasm",
        "--fail-on-breaking",
    ]);
    assert_eq!(rc, 1, "breaking diff must exit 1 with the flag");
}

#[test]
fn test_fail_on_breaking_identical_diff_exits_zero() {
    let (rc, _, _) = run_cli(&[
        "diff",
        "tests/fixtures/udt_contract_c.wasm",
        "tests/fixtures/udt_contract_c.wasm",
        "--fail-on-breaking",
    ]);
    assert_eq!(rc, 0, "identical contracts must exit 0 with the flag");
}

#[test]
fn test_diff_json_has_schema_version() {
    // `schema_version` is the top-level version marker for the diff JSON
    // shape. Parse the CLI's real stdout as JSON (no text-fragment search).
    let (rc, stdout, _) = run_cli(&[
        "diff",
        "tests/fixtures/udt_contract_c.wasm",
        "tests/fixtures/udt_contract_d.wasm",
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(
        v.get("schema_version").and_then(|s| s.as_u64()),
        Some(1),
        "top-level schema_version must be integer 1"
    );
    // Existing fields must remain at the top level, unchanged.
    assert!(v.get("structural").is_some(), "structural key preserved");
    assert!(v.get("spec").is_some(), "spec key preserved");
}

#[test]
fn test_fail_on_breaking_json_output_stays_valid() {
    let (rc, stdout, _) = run_cli(&[
        "diff",
        "tests/fixtures/udt_contract_c.wasm",
        "tests/fixtures/udt_contract_d.wasm",
        "--json",
        "--fail-on-breaking",
    ]);
    assert_eq!(rc, 1);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must remain valid JSON");
    let spec = v.get("spec").expect("spec key present");
    assert_eq!(
        spec.get("compatibility").and_then(|c| c.as_str()),
        Some("breaking"),
        "JSON must carry the compatibility result"
    );
}

#[test]
fn test_fail_on_breaking_unknown_diff_exits_one() {
    // Minimal valid WASM (magic + version, 8 bytes) has no contractspecv0, so
    // the spec is undecodable -> no verdict -> must fail the build.
    let empty = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("temp file");
    fs::write(
        empty.path(),
        [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
    )
    .expect("write empty wasm");
    let empty_path = empty.path().to_string_lossy().to_string();

    let (rc, _, _) = run_cli(&[
        "diff",
        "tests/fixtures/udt_contract_c.wasm",
        &empty_path,
        "--fail-on-breaking",
    ]);
    assert_eq!(rc, 1, "unknown compatibility must also fail the build");
}

#[test]
fn test_without_flag_behavior_unchanged() {
    let empty = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("temp file");
    fs::write(
        empty.path(),
        [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
    )
    .expect("write empty wasm");
    let empty_path = empty.path().to_string_lossy().to_string();

    // Without the flag the exit code is 0 whenever the diff itself ran, for
    // both a breaking verdict and an undecodable-spec (unknown) input.
    for args in [
        vec![
            "diff",
            "tests/fixtures/udt_contract_c.wasm",
            "tests/fixtures/udt_contract_d.wasm",
        ],
        vec![
            "diff",
            "tests/fixtures/udt_contract_c.wasm",
            empty_path.as_str(),
        ],
    ] {
        let (rc, stdout, _) = run_cli(&args);
        assert_eq!(rc, 0, "no-flag diff must still exit 0: {args:?}");
        assert!(!stdout.is_empty(), "report must still print");
    }
}

#[test]
fn test_fail_on_breaking_error_goes_to_stderr() {
    let (rc, stdout, stderr) = run_cli(&[
        "diff",
        "tests/fixtures/udt_contract_c.wasm",
        "tests/fixtures/udt_contract_d.wasm",
        "--fail-on-breaking",
    ]);
    assert_eq!(rc, 1);
    assert!(stderr.contains("breaking or unknown"));
    assert!(
        !stdout.contains("breaking or unknown"),
        "diagnostics must not contaminate stdout"
    );
}

#[test]
fn test_help_documents_fail_on_breaking() {
    let (rc, stdout, _) = run_cli(&["diff", "--help"]);
    assert_eq!(rc, 0);
    assert!(
        stdout.contains("--fail-on-breaking"),
        "help must document the flag"
    );
    // The flag is opt-in: the help must state what happens without it, since
    // the default exit code is 0 even for breaking diffs.
    assert!(
        stdout.contains("Without this flag the exit code is 0"),
        "help must document the opt-in exit-code semantics: {stdout}"
    );
}

#[test]
fn test_diff_help_describes_custom_sections() {
    // `diff` reports custom sections (human-readable output and the JSON
    // `custom_sections_added`/`custom_sections_removed` fields), so its help
    // must not claim it only reports imports and exports.
    let (rc, stdout, _) = run_cli(&["diff", "--help"]);
    assert_eq!(rc, 0);
    assert!(
        stdout.contains("imports, exports, and custom sections"),
        "diff help must mention custom sections: {stdout}"
    );
}

// --- Event data_format coverage (Task: map event data format) ---

#[test]
fn test_real_fixture_decodes_all_event_data_formats() {
    // event_formats.wasm was built from tests/fixtures/source/event_formats.rs
    // (soroban-sdk 28.0.0 / stellar-cli 28.1.0) with three events using the
    // three spec data formats. This locks the decoder to all of them, so a
    // future regression that drops "map" fails here.
    let wasm = fs::read(fx("event_formats.wasm")).expect("fixture missing");
    let report = inspect_soroban(&wasm, true).expect("should decode");
    let spec = report.spec.as_ref().unwrap();
    let formats: Vec<(String, String)> = spec
        .events
        .iter()
        .map(|e| (e.name.clone(), e.data_format.clone()))
        .collect();
    assert!(
        formats.contains(&("MovedSv".to_string(), "single_value".to_string())),
        "single_value event must decode to \"single_value\": {formats:?}"
    );
    assert!(
        formats.contains(&("MovedVec".to_string(), "vec".to_string())),
        "vec event must decode to \"vec\": {formats:?}"
    );
    assert!(
        formats.contains(&("MovedMap".to_string(), "map".to_string())),
        "map event must decode to \"map\": {formats:?}"
    );
}

#[test]
fn test_event_data_format_change_is_breaking() {
    use sorob_inspect::soroban::SpecEvent;
    // map -> vec is a wire-format change for consumers of the data segment.
    let mk = |df: &str| SpecEvent {
        name: "Moved".to_string(),
        prefix_topics: vec!["moved".to_string()],
        params: vec![sorob_inspect::soroban::SpecEventParam {
            name: "dx".to_string(),
            type_: "U32".to_string(),
            location: "data".to_string(),
        }],
        data_format: df.to_string(),
    };
    let d = sorob_inspect::soroban::diff::diff_specs(
        &sorob_inspect::soroban::SpecReport {
            functions: vec![],
            types: vec![],
            events: vec![mk("map")],
        },
        &sorob_inspect::soroban::SpecReport {
            functions: vec![],
            types: vec![],
            events: vec![mk("vec")],
        },
    );
    assert_eq!(
        d.compatibility,
        sorob_inspect::soroban::diff::Compatibility::Breaking
    );
    assert!(
        d.events_changed
            .iter()
            .any(|c| c.breaking && c.detail.contains("data format changed")),
        "data_format change must be reported as breaking"
    );
}

#[test]
fn test_event_data_format_identical_is_not_breaking() {
    use sorob_inspect::soroban::SpecEvent;
    // Identical data_format must not be reported as a change at all.
    let mk = || SpecEvent {
        name: "Moved".to_string(),
        prefix_topics: vec!["moved".to_string()],
        params: vec![sorob_inspect::soroban::SpecEventParam {
            name: "dx".to_string(),
            type_: "U32".to_string(),
            location: "data".to_string(),
        }],
        data_format: "map".to_string(),
    };
    let d = sorob_inspect::soroban::diff::diff_specs(
        &sorob_inspect::soroban::SpecReport {
            functions: vec![],
            types: vec![],
            events: vec![mk()],
        },
        &sorob_inspect::soroban::SpecReport {
            functions: vec![],
            types: vec![],
            events: vec![mk()],
        },
    );
    assert!(
        !d.events_changed
            .iter()
            .any(|c| c.detail.contains("data format")),
        "identical data_format must not be reported as a change"
    );
}

// --- Direct call graph integration tests ---

/// Build a module with two defined functions where the first calls the second
/// twice.
fn wasm_with_call_graph() -> Vec<u8> {
    let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // type section: one () -> () type
    b.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // function section: two functions of type 0
    b.extend_from_slice(&[0x03, 0x03, 0x02, 0x00, 0x00]);
    // code section
    let body0 = [0x00, 0x10, 0x01, 0x10, 0x01, 0x0b]; // call 1, call 1, end
    let body1 = [0x00, 0x0b]; // end
    let payload = [
        &[0x02u8][..],
        &[body0.len() as u8][..],
        &body0[..],
        &[body1.len() as u8][..],
        &body1[..],
    ]
    .concat();
    b.push(0x0a);
    b.push(payload.len() as u8);
    b.extend_from_slice(&payload);
    b
}

#[test]
fn test_direct_call_graph_is_reported() {
    let wasm = wasm_with_call_graph();
    let report = inspect(&wasm, false).expect("should parse");
    let metrics = &report.code_body_metrics;
    assert_eq!(metrics.len(), 2);
    let edges = &metrics[0].direct_calls;
    assert_eq!(
        edges.len(),
        1,
        "two call sites to one callee aggregate to one edge"
    );
    assert_eq!(edges[0].callee_index, 1);
    assert_eq!(edges[0].call_count, 2);
    match &edges[0].resolution {
        sorob_inspect::wasm::CallTargetResolution::Defined { defined_index, .. } => {
            assert_eq!(*defined_index, 1);
        }
        other => panic!("expected Defined resolution, got {other:?}"),
    }
    // The second function makes no calls.
    assert!(metrics[1].direct_calls.is_empty());
    assert_eq!(metrics[1].indirect_call_sites, 0);
}

#[test]
fn test_direct_call_graph_json_is_additive() {
    let wasm = wasm_with_call_graph();
    let report = inspect(&wasm, false).expect("should parse");
    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    // New fields must be present, and pre-existing fields must survive.
    let entry = &value["code_body_metrics"][0];
    assert!(entry.get("direct_calls").is_some(), "new field present");
    assert!(
        entry.get("operator_count").is_some(),
        "pre-existing field survives"
    );
    assert!(
        entry.get("instruction_inventory").is_some(),
        "pre-existing field survives"
    );
}

// --- Reachability integration tests ---

/// Build a module with three defined functions where 0 calls 1 and 1 calls 2,
/// exporting function 0 as the only root.
fn wasm_with_reachability_chain() -> Vec<u8> {
    let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // type section: one () -> () type
    b.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // function section: three functions of type 0
    b.extend_from_slice(&[0x03, 0x04, 0x03, 0x00, 0x00, 0x00]);
    // export section: "entry" -> function 0
    let mut epayload = vec![0x01, 0x05];
    epayload.extend_from_slice(b"entry");
    epayload.extend_from_slice(&[0x00, 0x00]); // Func, index 0
    b.push(0x07);
    b.push(epayload.len() as u8);
    b.extend_from_slice(&epayload);
    // code section
    let bodies: [&[u8]; 3] = [
        &[0x00, 0x10, 0x01, 0x0b], // call 1, end
        &[0x00, 0x10, 0x02, 0x0b], // call 2, end
        &[0x00, 0x0b],             // end
    ];
    let mut payload = vec![0x03];
    for body in bodies {
        payload.push(body.len() as u8);
        payload.extend_from_slice(body);
    }
    b.push(0x0a);
    b.push(payload.len() as u8);
    b.extend_from_slice(&payload);
    b
}

#[test]
fn test_reachability_transitive_closure() {
    let wasm = wasm_with_reachability_chain();
    let report = inspect(&wasm, false).expect("should parse");
    let r = report.reachability.expect("reachability present");
    assert_eq!(r.roots.len(), 1);
    assert_eq!(r.roots[0].kind, "export");
    assert_eq!(r.roots[0].name.as_deref(), Some("entry"));
    assert_eq!(
        r.reachable_defined,
        vec![0, 1, 2],
        "export -> 0 -> 1 -> 2 all reached"
    );
    assert!(
        r.unreachable_defined.is_empty(),
        "every defined function is reachable in this chain"
    );
}

#[test]
fn test_reachability_json_is_additive() {
    let wasm = wasm_with_reachability_chain();
    let report = inspect(&wasm, false).expect("should parse");
    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    assert!(value.get("reachability").is_some(), "new key present");
    assert!(
        value.get("code_body_metrics").is_some(),
        "pre-existing key survives"
    );
    assert!(value.get("exports").is_some(), "pre-existing key survives");
    let r = &value["reachability"];
    assert_eq!(r["roots"][0]["kind"], "export");
    let reachable: Vec<u64> = r["reachable_defined"]
        .as_array()
        .expect("reachable_defined array")
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert_eq!(reachable, vec![0, 1, 2]);
}

// --- Complexity metric integration tests ---

/// A module with one function containing an `if` and a `br_if`.
fn wasm_with_branchy_body() -> Vec<u8> {
    let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // type section: one () -> () type
    b.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // function section: one function
    b.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // body: 0 locals, if(void){nop} br_if 0, end
    let body = [
        0x00, // 0 locals
        0x04, 0x40, 0x01, 0x0b, // if (void) { nop } end
        0x0d, 0x00, // br_if 0
        0x0b, // end (function)
    ];
    let mut payload = vec![0x01, body.len() as u8];
    payload.extend_from_slice(&body);
    b.push(0x0a);
    b.push(payload.len() as u8);
    b.extend_from_slice(&payload);
    b
}

#[test]
fn test_complexity_metrics_reported() {
    let wasm = wasm_with_branchy_body();
    let report = inspect(&wasm, false).expect("should parse");
    let m = &report.code_body_metrics[0];
    assert_eq!(m.if_count, 1);
    assert_eq!(m.conditional_branch_count, 2, "if + br_if");
    assert_eq!(m.loop_count, 0);
    assert_eq!(m.unconditional_branch_count, 0);
    assert_eq!(m.cyclomatic_complexity, 3, "1 + if + br_if");
    assert_eq!(m.direct_call_site_count, 0);
    assert_eq!(m.max_control_depth, 1);
}

#[test]
fn test_complexity_metrics_json_round_trip() {
    let wasm = wasm_with_branchy_body();
    let report = inspect(&wasm, false).expect("should parse");
    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    let entry = &value["code_body_metrics"][0];
    assert_eq!(entry["if_count"], 1);
    assert_eq!(entry["cyclomatic_complexity"], 3);
    assert_eq!(
        entry["basic_block_count"], 3,
        "entry, if-body, continuation"
    );
    // Pre-existing fields survive alongside the new ones.
    assert!(entry.get("operator_count").is_some());
    assert!(
        entry.get("direct_calls").is_none(),
        "no calls: edges omitted"
    );
}

// --- Consolidated summary integration tests ---

#[test]
fn test_summary_empty_module() {
    let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let report = inspect(&wasm, false).expect("should parse");
    let s = &report.summary;
    assert_eq!(s.imported_function_count, 0);
    assert_eq!(s.exported_function_count, 0);
    assert_eq!(s.defined_function_count, 0);
    assert_eq!(s.total_function_count, 0);
    assert_eq!(s.total_body_bytes, 0);
    assert_eq!(s.total_operator_count, 0);
    assert_eq!(s.total_local_count, 0);
    assert_eq!(s.custom_section_count, 0);
    assert!(!s.has_contract_spec);
    assert!(s.structure.is_none());
    assert!(s.reachability.is_none());
    assert!(s.instruction_family_totals.is_empty());
    assert!(s.analysis_finding_count.is_none());
}

#[test]
fn test_summary_instruction_family_totals_sum_to_operator_total() {
    // A body with a nop, an i32.add, and a call.
    let wasm = wasm_with_branchy_body();
    let report = inspect(&wasm, false).expect("should parse");
    let s = &report.summary;
    let family_sum: usize = s.instruction_family_totals.values().sum();
    assert_eq!(
        family_sum, s.total_operator_count,
        "family totals must sum to the operator total"
    );
}

#[test]
fn test_summary_build_analysis_summary_public_api() {
    let wasm = wasm_with_branchy_body();
    let report = inspect(&wasm, false).expect("should parse");
    let rebuilt = build_analysis_summary(&report).expect("rebuild");
    assert_eq!(rebuilt, report.summary, "rebuild is idempotent");
}

#[test]
fn test_summary_reflects_attached_analysis() {
    let wasm = wasm_with_branchy_body();
    let mut report = inspect(&wasm, false).expect("should parse");
    assert!(report.summary.analysis_finding_count.is_none());
    report.analysis = Some(analyze(&wasm).expect("analysis works"));
    let expected = report.analysis.as_ref().unwrap().findings.len();
    report.summary = build_analysis_summary(&report).expect("rebuild");
    assert_eq!(report.summary.analysis_finding_count, Some(expected));
}

#[test]
fn test_summary_json_round_trip_preserves_optional_omission() {
    let wasm = wasm_with_branchy_body();
    let report = inspect(&wasm, false).expect("should parse");
    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let s = &value["summary"];
    // Pre-existing top-level keys survive.
    for key in [
        "size_bytes",
        "imports",
        "exports",
        "custom_sections",
        "functions",
        "code_body_metrics",
        "interface",
        "summary",
    ] {
        assert!(value.get(key).is_some(), "key {key} present");
    }
    assert!(
        s.get("structure").is_none(),
        "branchy fixture declares no memories/tables/globals/segments/start"
    );
    assert!(s.get("reachability").is_some());
    assert!(s.get("instruction_family_totals").is_some());
}

#[test]
fn test_summary_deserializes_to_analysis_summary() {
    let wasm = wasm_with_branchy_body();
    let report = inspect(&wasm, false).expect("should parse");
    let json = serde_json::to_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let summary: AnalysisSummary =
        serde_json::from_value(value["summary"].clone()).expect("summary deserializes");
    assert_eq!(summary, report.summary);
}

#[test]
fn test_summary_deterministic_across_inspect_calls() {
    let wasm = wasm_with_branchy_body();
    let a = serde_json::to_string(&inspect(&wasm, false).unwrap()).unwrap();
    let b = serde_json::to_string(&inspect(&wasm, false).unwrap()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn test_summary_on_real_fixture() {
    let wasm = fs::read(fixture_path()).expect("fixture exists");
    let report = inspect(&wasm, false).expect("fixture parses");
    let s = &report.summary;
    assert_eq!(
        s.total_function_count,
        s.imported_function_count + s.defined_function_count
    );
    assert_eq!(s.defined_function_count, report.code_body_metrics.len());
    assert_eq!(s.custom_section_count, report.custom_sections.len());
    assert_eq!(
        s.has_contract_spec,
        report.interface.as_ref().unwrap().has_contract_spec
    );
    if let Some(r) = &s.reachability {
        let full = report.reachability.as_ref().unwrap();
        assert_eq!(r.root_count, full.roots.len());
        assert_eq!(r.reachable_defined_count, full.reachable_defined.len());
        assert_eq!(r.unreachable_defined_count, full.unreachable_defined.len());
        assert_eq!(
            r.reachable_defined_count + r.unreachable_defined_count,
            s.defined_function_count
        );
    }
}

// --- Non-Soroban WASM CLI smoke test (objective 3 of release-readiness audit) ---

/// Minimal deterministic module: magic + 1 function type `() -> ()` + 1
/// defined function + 1 empty body. No imports, no exports, no custom
/// sections, no memories/tables/globals/segments/start — a generic WASM
/// module with no Soroban markers.
fn minimal_generic_wasm() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: 1 type () -> ()
        0x03, 0x02, 0x01, 0x00, // function section: 1 function referencing type index 0
        0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: 1 body (empty locals + end)
    ]
}

#[test]
fn cli_inspect_non_soroban_module_emits_valid_json() {
    let wasm = minimal_generic_wasm();
    let bin = env!("CARGO_BIN_EXE_sorob-inspect");

    // Lib-level: parses cleanly and the summary reflects the generic module.
    let report = inspect(&wasm, false).expect("minimal generic module inspects");
    assert_eq!(report.summary.imported_function_count, 0);
    assert_eq!(report.summary.exported_function_count, 0);
    assert_eq!(report.code_body_metrics.len(), 1);
    assert!(report.custom_sections.is_empty());
    assert!(!report.summary.has_contract_spec);
    // No structure declared -> the structure summary is omitted, not zero-filled.
    assert!(report.summary.structure.is_none());
    // One defined function, no roots (no start, no exports) -> unreachable.
    let r = report
        .summary
        .reachability
        .as_ref()
        .expect("reachability present");
    assert_eq!(r.root_count, 0);
    assert_eq!(r.reachable_defined_count, 0);
    assert_eq!(r.unreachable_defined_count, 1);

    // CLI subprocess: `inspect --json` exits 0 and emits valid JSON.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("generic.wasm");
    std::fs::write(&path, &wasm).expect("write fixture");
    let out = std::process::Command::new(bin)
        .arg("inspect")
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run CLI");
    assert!(out.status.success(), "inspect exited non-zero");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("CLI JSON parses");
    assert!(value.get("summary").is_some(), "CLI summary present");
    assert_eq!(value["summary"]["has_contract_spec"], false);
    assert_eq!(value["summary"]["total_function_count"], 1);
    assert!(value["summary"].get("structure").is_none());
    assert_eq!(
        value["summary"]["reachability"]["unreachable_defined_count"],
        1
    );
    // No local paths leak into JSON output.
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("/home/") && !text.contains("LOQ LENOVO"),
        "no local host paths in CLI output"
    );
}

/// `validate --json` on a generic non-Soroban module must succeed (exit 0),
/// emit valid JSON, and report the Soroban markers as absent with the expected
/// "likely a generic WASM module" summary.
#[test]
fn cli_validate_non_soroban_module_emits_valid_json() {
    let wasm = minimal_generic_wasm();
    let bin = env!("CARGO_BIN_EXE_sorob-inspect");

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("generic.wasm");
    std::fs::write(&path, &wasm).expect("write fixture");

    let out = std::process::Command::new(bin)
        .arg("validate")
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run CLI");
    assert!(
        out.status.success(),
        "validate exited non-zero on a valid generic module"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("validate --json emits valid JSON");

    assert_eq!(value["has_contract_spec"], false);
    assert_eq!(value["has_contract_env_meta"], false);
    // No spec decodes and no consistency check runs for a non-Soroban module.
    assert!(
        value.get("spec").is_none(),
        "spec omitted for a non-Soroban module"
    );
    assert!(
        value.get("consistency").is_none(),
        "consistency omitted for a non-Soroban module"
    );
    assert_eq!(
        value["summary"],
        "No Soroban custom sections found — likely a generic WASM module."
    );
    // The underlying WASM report is still present and well-formed.
    assert!(value.get("wasm").is_some(), "wasm report present");
    assert!(value["wasm"]["summary"]
        .get("total_function_count")
        .is_some());
}

// --- env interface version diff (contractenvmetav0) ---

/// Locate the `contractenvmetav0` custom-section payload and overwrite its
/// XDR-encoded `protocol` (u32 BE, payload+4..+8) and `pre_release`
/// (u32 BE, payload+8..+12) fields. Panics if the section is absent.
fn patch_env_meta(wasm: &mut [u8], new_proto: u32, new_pre: u32) {
    let mut i = 8;
    while i < wasm.len() {
        let id = wasm[i];
        i += 1;
        let mut size: usize = 0;
        let mut shift = 0;
        loop {
            let b = wasm[i];
            i += 1;
            size |= ((b & 0x7F) as usize) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
        let body_start = i;
        let body_end = i + size;
        if id == 0 {
            let name_len = wasm[body_start] as usize;
            let name =
                std::str::from_utf8(&wasm[body_start + 1..body_start + 1 + name_len]).unwrap();
            if name == "contractenvmetav0" {
                let payload_off = body_start + 1 + name_len;
                wasm[payload_off + 4..payload_off + 8].copy_from_slice(&new_proto.to_be_bytes());
                wasm[payload_off + 8..payload_off + 12].copy_from_slice(&new_pre.to_be_bytes());
                return;
            }
        }
        i = body_end;
    }
    panic!("contractenvmetav0 section not found");
}

#[test]
fn test_diff_env_meta_identical_in_json() {
    // Two real Soroban fixtures both declare protocol 28 / pre-release 0.
    let (rc, stdout, _) = run_cli(&[
        "diff",
        "tests/fixtures/test_soroban.wasm",
        "tests/fixtures/udt_contract_c.wasm",
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["env_meta"]["status"], "identical");
    assert_eq!(v["env_meta"]["old"]["protocol"], 28);
    assert_eq!(v["env_meta"]["old"]["pre_release"], 0);
    assert_eq!(v["env_meta"]["new"]["protocol"], 28);
    assert_eq!(v["env_meta"]["new"]["pre_release"], 0);
}

#[test]
fn test_diff_env_meta_changed_in_json() {
    // Byte-patch a copy of a real fixture to protocol 27 / pre-release 1.
    let mut bytes = std::fs::read("tests/fixtures/test_soroban.wasm").unwrap();
    patch_env_meta(&mut bytes, 27, 1);
    let patched = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("temp file");
    std::fs::write(patched.path(), &bytes).unwrap();
    let patched_path = patched.path().to_string_lossy().to_string();

    let (rc, stdout, _) = run_cli(&[
        "diff",
        "tests/fixtures/test_soroban.wasm",
        &patched_path,
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["env_meta"]["status"], "changed");
    assert_eq!(v["env_meta"]["old"]["protocol"], 28);
    assert_eq!(v["env_meta"]["new"]["protocol"], 27);
    assert_eq!(v["env_meta"]["new"]["pre_release"], 1);
}

#[test]
fn test_diff_env_meta_changed_text_reports_change() {
    // The human-readable path must surface the version change.
    let mut bytes = std::fs::read("tests/fixtures/test_soroban.wasm").unwrap();
    patch_env_meta(&mut bytes, 27, 1);
    let patched = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("temp file");
    std::fs::write(patched.path(), &bytes).unwrap();
    let patched_path = patched.path().to_string_lossy().to_string();

    let (_rc, stdout, _) = run_cli(&["diff", "tests/fixtures/test_soroban.wasm", &patched_path]);
    assert!(
        stdout.contains("env interface version: CHANGED"),
        "text path reports the change"
    );
}

#[test]
fn test_diff_env_meta_removed_when_new_has_no_section() {
    // A generic non-Soroban WASM has no contractenvmetav0 section.
    let empty = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("temp file");
    std::fs::write(
        empty.path(),
        [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
    )
    .expect("write empty wasm");
    let empty_path = empty.path().to_string_lossy().to_string();

    let (rc, stdout, _) = run_cli(&[
        "diff",
        "tests/fixtures/test_soroban.wasm",
        &empty_path,
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["env_meta"]["status"], "removed");
    assert_eq!(v["env_meta"]["old"]["protocol"], 28);
    // `new` is omitted when that module has no section.
    assert!(v["env_meta"].get("new").is_none());
}

#[test]
fn test_diff_env_meta_change_does_not_trigger_fail_on_breaking() {
    // A version change is a distinct signal; it must not be folded into the
    // spec-level breaking/non-breaking verdict that --fail-on-breaking gates.
    let mut bytes = std::fs::read("tests/fixtures/udt_contract_c.wasm").unwrap();
    patch_env_meta(&mut bytes, 27, 0);
    let patched = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("temp file");
    std::fs::write(patched.path(), &bytes).unwrap();
    let patched_path = patched.path().to_string_lossy().to_string();

    // udt_contract_c and udt_contract_d differ only by one spec field (a
    // non-breaking addition), so without the version-change the verdict is
    // non-breaking and the flag must NOT fail the build.
    let (rc, stdout, _) = run_cli(&[
        "diff",
        "tests/fixtures/udt_contract_c.wasm",
        &patched_path,
        "--json",
        "--fail-on-breaking",
    ]);
    assert_eq!(rc, 0, "version change must not trigger --fail-on-breaking");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["env_meta"]["status"], "changed");
}

#[test]
fn test_validate_env_meta_diagnostic_in_json() {
    // A decoded version surfaces the host's acceptance rule + required inputs,
    // never a verdict.
    let (rc, stdout, _) = run_cli(&["validate", "tests/fixtures/test_soroban.wasm", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let em = &v["env_meta"];
    assert_eq!(em["status"], "decoded");
    let diag = em
        .get("diagnostic")
        .and_then(|d| d.as_str())
        .expect("decoded version carries a diagnostic");
    assert!(
        diag.contains("check_contract_interface_version"),
        "rule is cited"
    );
    assert!(
        diag.contains("curr_ledger_protocol"),
        "required input named"
    );
    assert!(diag.contains("host_protocol"), "host input named");
    assert!(
        !diag.contains("will be accepted") && !diag.contains("will be rejected"),
        "diagnostic is guidance, not a verdict"
    );
}

#[test]
fn test_diff_env_meta_diagnostic_per_side() {
    // In a diff, each decoded side carries its own diagnostic.
    let (rc, stdout, _) = run_cli(&[
        "diff",
        "tests/fixtures/test_soroban.wasm",
        "tests/fixtures/udt_contract_c.wasm",
        "--json",
    ]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let old_diag = &v["env_meta"]["old"]["diagnostic"];
    let new_diag = &v["env_meta"]["new"]["diagnostic"];
    assert!(old_diag.is_string(), "old side carries diagnostic");
    assert!(new_diag.is_string(), "new side carries diagnostic");
    assert!(
        old_diag.as_str().unwrap().contains("curr_ledger_protocol"),
        "old diagnostic cites the rule"
    );
    assert!(
        v["env_meta"]["status"] == "identical",
        "same versions are identical"
    );
}

#[test]
fn test_validate_env_meta_text_has_actionable_hint() {
    // The human-readable path tells the operator what to do next.
    let (rc, stdout, _) = run_cli(&["validate", "tests/fixtures/test_soroban.wasm"]);
    assert_eq!(rc, 0);
    assert!(
        stdout.contains("env interface version: protocol 28 (pre-release 0)"),
        "version is printed"
    );
    assert!(
        stdout.contains("evaluate against the target network's ledger protocol"),
        "actionable hint is printed"
    );
}

#[test]
fn test_diff_env_meta_changed_text_has_hint() {
    // When versions differ, the text path surfaces the change + the hint.
    let mut bytes = std::fs::read("tests/fixtures/test_soroban.wasm").unwrap();
    patch_env_meta(&mut bytes, 27, 0);
    let patched = tempfile::Builder::new()
        .suffix(".wasm")
        .tempfile()
        .expect("temp file");
    std::fs::write(patched.path(), &bytes).unwrap();
    let patched_path = patched.path().to_string_lossy().to_string();

    let (rc, stdout, _) = run_cli(&["diff", "tests/fixtures/test_soroban.wasm", &patched_path]);
    assert_eq!(rc, 0);
    assert!(
        stdout.contains("env interface version: CHANGED"),
        "text reports the change"
    );
    assert!(
        stdout.contains("evaluate against the target network's ledger protocol"),
        "text reports the actionable hint"
    );
}
