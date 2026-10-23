use sorob_inspect::wasm::inspect;
use std::fs;
use std::path::PathBuf;

// --- Interface summary tests ---

/// Module with: 1 imported function, 1 imported memory, 1 imported global,
/// 1 defined function (exported), 1 defined memory (exported), 1 exported
/// global.
fn interface_fixture() -> Vec<u8> {
    vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
        // imports (3): env.fn (func type 0), env.mem (memory min 1), env.g (global i32)
        0x02, 0x1e, 0x03, 0x03, 0x65, 0x6e, 0x76, 0x02, 0x66, 0x6e, 0x00, 0x00, 0x03, 0x65, 0x6e,
        0x76, 0x03, 0x6d, 0x65, 0x6d, 0x02, 0x00, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x01, 0x67, 0x03,
        0x7f, 0x00, //
        0x03, 0x02, 0x01, 0x00, // function section: 1 defined func, type 0
        0x05, 0x03, 0x01, 0x00, 0x02, // memory section: 1 mem, min 2
        0x06, 0x06, 0x01, 0x7f, 0x00, 0x41, 0x00, 0x0b, // global: i32 immutable
        // exports (3): "do" func idx 1, "m" mem idx 1, "g" global idx 1
        0x07, 0x0e, 0x03, 0x02, 0x64, 0x6f, 0x00, 0x01, 0x01, 0x6d, 0x02, 0x01, 0x01, 0x67, 0x03,
        0x01, //
    ]
}

#[test]
fn test_interface_grouped_counts() {
    let report = inspect(&interface_fixture(), false).expect("valid wasm");
    let i = report
        .interface
        .as_ref()
        .expect("interface summary present");

    // Imports: 1 function, 1 global, 1 memory — sorted by kind name.
    let import_kinds: Vec<(&str, usize)> = i
        .imports_by_kind
        .iter()
        .map(|k| (k.kind.as_str(), k.count))
        .collect();
    assert_eq!(
        import_kinds,
        vec![("function", 1), ("global", 1), ("memory", 1)]
    );

    // Exports: 1 function, 1 global, 1 memory.
    let export_kinds: Vec<(&str, usize)> = i
        .exports_by_kind
        .iter()
        .map(|k| (k.kind.as_str(), k.count))
        .collect();
    assert_eq!(
        export_kinds,
        vec![("function", 1), ("global", 1), ("memory", 1)]
    );
}

#[test]
fn test_interface_signatures() {
    let report = inspect(&interface_fixture(), false).expect("valid wasm");
    let i = report
        .interface
        .as_ref()
        .expect("interface summary present");

    // Exported function signature, resolved through the import index space.
    assert_eq!(i.exported_functions.len(), 1);
    assert_eq!(i.exported_functions[0].name, "do");
    assert_eq!(i.exported_functions[0].index, 1);
    assert_eq!(
        i.exported_functions[0].signature.as_deref(),
        Some("() -> ()")
    );

    // Imported function signature.
    assert_eq!(i.imported_functions.len(), 1);
    assert_eq!(i.imported_functions[0].module, "env");
    assert_eq!(i.imported_functions[0].name, "fn");
    assert_eq!(
        i.imported_functions[0].signature.as_deref(),
        Some("() -> ()")
    );
}

#[test]
fn test_interface_export_names_and_kinds() {
    let report = inspect(&interface_fixture(), false).expect("valid wasm");
    let i = report
        .interface
        .as_ref()
        .expect("interface summary present");
    let pairs: Vec<(&str, &str)> = i
        .exports
        .iter()
        .map(|e| (e.name.as_str(), e.kind.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![("do", "function"), ("m", "memory"), ("g", "global")]
    );
}

#[test]
fn test_interface_deterministic_ordering() {
    let a = inspect(&interface_fixture(), false).expect("valid wasm");
    let b = inspect(&interface_fixture(), false).expect("valid wasm");
    let ia = a.interface.as_ref().expect("interface a");
    let ib = b.interface.as_ref().expect("interface b");
    assert_eq!(
        ia, ib,
        "interface summary must be identical for identical input"
    );

    // Grouped counts are sorted by kind name, not by first-seen order.
    let kinds: Vec<&str> = ia.imports_by_kind.iter().map(|k| k.kind.as_str()).collect();
    let mut sorted = kinds.clone();
    sorted.sort_unstable();
    assert_eq!(kinds, sorted, "import kinds must be sorted");
}

#[test]
fn test_interface_json_serialization() {
    let report = inspect(&interface_fixture(), false).expect("valid wasm");
    let i = report
        .interface
        .as_ref()
        .expect("interface summary present");
    let json = serde_json::to_value(i).expect("serializes");

    assert_eq!(json["imports_by_kind"][0]["kind"], "function");
    assert_eq!(json["imports_by_kind"][0]["count"], 1);
    assert_eq!(json["exports_by_kind"][0]["kind"], "function");
    assert_eq!(json["exported_functions"][0]["name"], "do");
    assert_eq!(json["exported_functions"][0]["signature"], "() -> ()");
    assert_eq!(json["imported_functions"][0]["module"], "env");
    assert_eq!(json["exports"][0]["name"], "do");
    assert_eq!(json["has_contract_spec"], false);

    // The summary is reachable from the top-level report.
    let full = serde_json::to_value(&report).expect("report serializes");
    assert!(full.get("interface").is_some());
}

#[test]
fn test_interface_empty_module_has_no_imports_or_exports() {
    let empty = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let report = inspect(&empty, false).expect("valid wasm");
    let i = report
        .interface
        .as_ref()
        .expect("interface summary present");
    assert!(i.imports_by_kind.is_empty());
    assert!(i.exports_by_kind.is_empty());
    assert!(i.exported_functions.is_empty());
    assert!(i.imported_functions.is_empty());
    assert!(i.exports.is_empty());
    assert!(!i.has_contract_spec);
}

#[test]
fn test_interface_missing_signature_is_unavailable_not_guessed() {
    // A function export whose type cannot be resolved (no type section) must
    // report `signature: null`, not a placeholder string.
    let wasm: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x07, 0x05, 0x01, 0x01, b'f', 0x00,
        0x07, // export "f" func idx 7 (unresolvable)
    ];
    let report = inspect(&wasm, false).expect("valid wasm");
    let i = report
        .interface
        .as_ref()
        .expect("interface summary present");
    assert_eq!(i.exported_functions.len(), 1);
    assert_eq!(i.exported_functions[0].name, "f");
    assert_eq!(i.exported_functions[0].index, 7);
    assert_eq!(
        i.exported_functions[0].signature, None,
        "unresolvable signature must be None, never guessed"
    );
    let json = serde_json::to_value(&i.exported_functions[0]).expect("serializes");
    assert!(
        json.get("signature").is_some() && json["signature"].is_null(),
        "unavailable signature must serialize as null"
    );
}

#[test]
fn test_interface_does_not_conflate_contract_spec_functions() {
    // The real Soroban fixture has BOTH a contractspecv0 section and raw WASM
    // exports. Contract-spec functions are a separate ABI view: they must
    // not be added to the raw-WASM export list.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/udt_contract_a.wasm");
    let bytes = fs::read(&path).expect("fixture readable");
    let report = inspect(&bytes, false).expect("valid wasm");
    let i = report
        .interface
        .as_ref()
        .expect("interface summary present");

    assert!(i.has_contract_spec, "fixture has a contractspecv0 section");

    // Raw WASM exports only.
    let raw_names: Vec<&str> = i
        .exported_functions
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(
        raw_names.contains(&"init"),
        "raw export 'init' must be listed"
    );
    assert!(
        raw_names.contains(&"process"),
        "raw export 'process' must be listed"
    );

    // Every raw export is a real WASM export, i.e. its index resolves.
    for f in &i.exported_functions {
        assert!(
            report
                .exports
                .iter()
                .any(|e| e.name == f.name && e.index == f.index),
            "every interface export must exist in the raw export list"
        );
    }
}
