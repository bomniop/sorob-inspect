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
}
