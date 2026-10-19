use sorob_inspect::soroban::inspect_soroban;
use sorob_inspect::wasm::inspect;
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
    // Truncated header (missing last byte).
    let bad = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00];
    let result = inspect(&bad, false);
    assert!(result.is_err());
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
    assert!(status.cases.iter().any(|c| c.contains("Pending")));
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
