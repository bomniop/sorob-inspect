use sorob_inspect::soroban::inspect_soroban;
use sorob_inspect::wasm::inspect;

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
    let wasm = wasm_with_custom_section("contractspecv0", &[0xab, 0xcd]);
    let report = inspect_soroban(&wasm, false).expect("should parse");
    assert!(report.has_contract_spec);
    assert!(!report.has_contract_env_meta);
    assert!(report.summary.contains("contractspecv0"));
}

#[test]
fn test_validate_detects_contract_env_meta_true() {
    let wasm = wasm_with_custom_section("contractenvmetav0", &[0x01]);
    let report = inspect_soroban(&wasm, false).expect("should parse");
    assert!(!report.has_contract_spec);
    assert!(report.has_contract_env_meta);
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
    let wasm = wasm_with_custom_section("contractspecv0", &[0x00]);
    let report = inspect_soroban(&wasm, false).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("has_contract_spec"));
    assert!(json.contains("true"));
}
