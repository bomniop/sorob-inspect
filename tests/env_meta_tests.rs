//! Soroban environment metadata (`contractenvmetav0`) integration tests.
//!
//! The section carries the contract's declared env interface version. The
//! Soroban host requires it to exist and its first entry to be an
//! `SC_ENV_META_KIND_INTERFACE_VERSION` (`soroban-env-host 28.0.2`,
//! `src/vm/parsed_module.rs:472-500`).

use sorob_inspect::soroban::inspect_soroban;
use std::fs;
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_soroban.wasm")
}

/// Minimal generic WASM module: magic + version + 1 type `() -> ()` +
/// 1 function + 1 empty body. No Soroban custom sections.
fn minimal_generic_wasm() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: 1 type () -> ()
        0x03, 0x02, 0x01, 0x00, // function section: 1 function referencing type index 0
        0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: 1 body (locals=0, end)
    ]
}

/// Build a module whose only custom section is `contractenvmetav0` with the
/// given raw payload. Uses proper LEB128 section-length encoding.
fn wasm_with_env_meta_payload(payload: &[u8]) -> Vec<u8> {
    let name = b"contractenvmetav0";
    let mut buf = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    buf.push(0x00); // custom-section id
    let section_len = 1 + name.len() + payload.len();
    let mut n = section_len as u64;
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if n == 0 {
            break;
        }
    }
    buf.push(name.len() as u8);
    buf.extend_from_slice(name);
    buf.extend_from_slice(payload);
    buf
}

/// `int32 discriminant 0` + `uint32 protocol` + `uint32 pre_release`, big-endian.
fn env_meta_payload(protocol: u32, pre_release: u32) -> Vec<u8> {
    let mut v = vec![0x00, 0x00, 0x00, 0x00];
    v.extend_from_slice(&protocol.to_be_bytes());
    v.extend_from_slice(&pre_release.to_be_bytes());
    v
}

#[test]
fn validate_reports_env_interface_version_on_real_fixture() {
    // The committed Soroban fixture carries a 12-byte contractenvmetav0 payload.
    let wasm = fs::read(fixture_path()).expect("fixture exists");
    let report = inspect_soroban(&wasm, false).expect("fixture parses");
    assert!(report.has_contract_env_meta, "fixture has env meta section");
    let em = report.env_meta.expect("env meta decoded");
    assert_eq!(em.status, "decoded");
    assert!(em.protocol.is_some(), "protocol reported");
    assert!(em.pre_release.is_some(), "pre_release reported");

    // CLI JSON exposes the same decoded fields.
    let bin = env!("CARGO_BIN_EXE_sorob-inspect");
    let out = std::process::Command::new(bin)
        .arg("validate")
        .arg(fixture_path())
        .arg("--json")
        .output()
        .expect("run CLI");
    assert!(out.status.success(), "validate exited non-zero");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json parses");
    assert_eq!(value["env_meta"]["status"], "decoded");
    assert!(value["env_meta"]["protocol"].is_number());
    assert!(value["env_meta"]["pre_release"].is_number());
    // The decoded version is also surfaced in the human-readable summary.
    assert!(value["summary"]
        .as_str()
        .unwrap()
        .contains("Environment interface version"));
}

#[test]
fn env_meta_absent_for_generic_module_is_omitted() {
    // No contractenvmetav0 section: omitted, not reported as a zero version.
    let wasm = minimal_generic_wasm();
    let report = inspect_soroban(&wasm, false).expect("parses");
    assert!(!report.has_contract_env_meta);
    assert!(report.env_meta.is_none());
}

#[test]
fn env_meta_undecodable_section_is_reported_not_fatal() {
    // A present-but-garbage env meta section must not abort the report.
    let wasm = wasm_with_env_meta_payload(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let report = inspect_soroban(&wasm, false).expect("parses");
    assert!(report.has_contract_env_meta);
    let em = report.env_meta.expect("env meta reported");
    assert_eq!(em.status, "undecodable");
    assert!(em.protocol.is_none());
    assert!(em.error.is_some());
}

#[test]
fn env_meta_decodes_known_version_deterministically() {
    // Same payload must always decode to the same values.
    let wasm = wasm_with_env_meta_payload(&env_meta_payload(21, 0));
    let first = inspect_soroban(&wasm, false).expect("parses");
    let second = inspect_soroban(&wasm, false).expect("parses");
    let a = first.env_meta.expect("decoded");
    let b = second.env_meta.expect("decoded");
    assert_eq!(a, b);
    assert_eq!(a.protocol, Some(21));
    assert_eq!(a.pre_release, Some(0));
}
