// Append env-meta diff regression tests to the existing diff test module.
use sorob_inspect::soroban::diff::diff_env_meta;
use sorob_inspect::soroban::EnvMetaReport;

fn decoded(protocol: u32, pre_release: u32) -> EnvMetaReport {
    EnvMetaReport {
        status: "decoded".to_string(),
        protocol: Some(protocol),
        pre_release: Some(pre_release),
        error: None,
        diagnostic: Some(sorob_inspect::soroban::INTERFACE_VERSION_DIAGNOSTIC.to_string()),
        assessment: None,
    }
}

fn undecodable() -> EnvMetaReport {
    EnvMetaReport {
        status: "undecodable".to_string(),
        protocol: None,
        pre_release: None,
        error: Some("bad payload".to_string()),
        diagnostic: None,
        assessment: None,
    }
}

#[test]
fn env_meta_identical_versions() {
    let d = diff_env_meta(Some(&decoded(28, 0)), Some(&decoded(28, 0)));
    assert_eq!(d.status, "identical");
    assert_eq!(d.old.as_ref().unwrap().protocol, Some(28));
    assert_eq!(d.new.as_ref().unwrap().pre_release, Some(0));
}

#[test]
fn env_meta_protocol_change() {
    let d = diff_env_meta(Some(&decoded(27, 0)), Some(&decoded(28, 0)));
    assert_eq!(d.status, "changed");
    assert_eq!(d.old.as_ref().unwrap().protocol, Some(27));
    assert_eq!(d.new.as_ref().unwrap().protocol, Some(28));
}

#[test]
fn env_meta_prerelease_change() {
    // Same protocol, different pre-release: still a change.
    let d = diff_env_meta(Some(&decoded(28, 0)), Some(&decoded(28, 1)));
    assert_eq!(d.status, "changed");
}

#[test]
fn env_meta_protocol_and_prerelease_change() {
    let d = diff_env_meta(Some(&decoded(27, 1)), Some(&decoded(28, 0)));
    assert_eq!(d.status, "changed");
}

#[test]
fn env_meta_missing_from_new() {
    let d = diff_env_meta(Some(&decoded(28, 0)), None);
    assert_eq!(d.status, "removed");
    assert!(d.new.is_none());
    assert_eq!(d.old.as_ref().unwrap().protocol, Some(28));
}

#[test]
fn env_meta_missing_from_old() {
    let d = diff_env_meta(None, Some(&decoded(28, 0)));
    assert_eq!(d.status, "added");
    assert!(d.old.is_none());
    assert_eq!(d.new.as_ref().unwrap().protocol, Some(28));
}

#[test]
fn env_meta_absent_from_both() {
    let d = diff_env_meta(None, None);
    assert_eq!(d.status, "absent_both");
    assert!(d.old.is_none());
    assert!(d.new.is_none());
}

#[test]
fn env_meta_old_undecodable_new_decoded() {
    let d = diff_env_meta(Some(&undecodable()), Some(&decoded(28, 0)));
    assert_eq!(d.status, "old_undecodable");
    assert_eq!(d.new.as_ref().unwrap().protocol, Some(28));
}

#[test]
fn env_meta_new_undecodable_old_decoded() {
    let d = diff_env_meta(Some(&decoded(28, 0)), Some(&undecodable()));
    assert_eq!(d.status, "new_undecodable");
    assert_eq!(d.old.as_ref().unwrap().protocol, Some(28));
}

#[test]
fn env_meta_undecodable_on_both_sides() {
    let d = diff_env_meta(Some(&undecodable()), Some(&undecodable()));
    assert_eq!(d.status, "undecodable_both");
    assert!(d.old.as_ref().unwrap().protocol.is_none());
    assert!(d.new.as_ref().unwrap().protocol.is_none());
}

#[test]
fn env_meta_diff_is_deterministic() {
    let a = diff_env_meta(Some(&decoded(27, 0)), Some(&decoded(28, 1)));
    let b = diff_env_meta(Some(&decoded(27, 0)), Some(&decoded(28, 1)));
    assert_eq!(a.status, b.status);
    assert_eq!(a.old, b.old);
    assert_eq!(a.new, b.new);
}

#[test]
fn env_meta_diff_json_shape_is_stable() {
    // Sides are omitted from JSON when a module has no section.
    let absent = serde_json::to_value(diff_env_meta(None, None)).unwrap();
    assert!(absent.get("old").is_none(), "old omitted when absent");
    assert!(absent.get("new").is_none(), "new omitted when absent");
    assert_eq!(absent["status"], "absent_both");

    let changed =
        serde_json::to_value(diff_env_meta(Some(&decoded(27, 0)), Some(&decoded(28, 0)))).unwrap();
    assert_eq!(changed["status"], "changed");
    assert_eq!(changed["old"]["protocol"], 27);
    assert_eq!(changed["old"]["pre_release"], 0);
    assert_eq!(changed["new"]["protocol"], 28);
    assert_eq!(changed["new"]["pre_release"], 0);

    // An undecodable side keeps its error and omits the numeric fields.
    let und =
        serde_json::to_value(diff_env_meta(Some(&undecodable()), Some(&decoded(28, 0)))).unwrap();
    assert_eq!(und["status"], "old_undecodable");
    assert!(und["old"].get("protocol").is_none());
    assert_eq!(und["old"]["error"], "bad payload");
}

#[test]
fn env_meta_diagnostic_attached_to_decoded_only() {
    // A decoded side carries an actionable `diagnostic` with the host's rule.
    let r = decoded(28, 0);
    assert_eq!(r.status, "decoded");
    let d = r.diagnostic.expect("decoded carries a diagnostic");
    assert!(d.contains("check_contract_interface_version"));
    assert!(d.contains("curr_ledger_protocol"));
    assert!(d.contains("host_protocol"));
    assert!(
        !d.contains("accept") || d.contains("cannot decide"),
        "diagnostic is guidance, not a verdict"
    );

    // An undecodable side carries no diagnostic (there is no decoded version to evaluate).
    let u = undecodable();
    assert!(
        u.diagnostic.is_none(),
        "undecodable has no version to evaluate"
    );
}
