//! Table-driven unit tests for the Soroban environment interface-version
//! compatibility assessment.
//!
//! These cases encode the EXACT rule from `soroban-env-host 28.0.2`
//! `src/vm/parsed_module.rs` `check_contract_interface_version` (production /
//! non-`next` build). They are the source of truth for `assess_env_meta`'s
//! verdicts and rejection reasons.

use sorob_inspect::soroban::{assess_env_meta, EnvMetaAssessmentInputs, EnvMetaReport};

fn decoded(protocol: u32, pre_release: u32) -> EnvMetaReport {
    EnvMetaReport {
        status: "decoded".to_string(),
        protocol: Some(protocol),
        pre_release: Some(pre_release),
        error: None,
        diagnostic: None,
        assessment: None,
    }
}

fn inputs(curr: u32, host: u32, host_pre: u32) -> EnvMetaAssessmentInputs {
    EnvMetaAssessmentInputs {
        curr_ledger_protocol: curr,
        host_protocol: host,
        host_pre_release: host_pre,
    }
}

#[test]
fn env_meta_assessment_rule_table() {
    // (label, report, inputs, expected_verdict, expected_reason_substring)
    let cases: &[(&str, EnvMetaReport, EnvMetaAssessmentInputs, &str, &str)] = &[
        (
            "future_protocol_rejected",
            // got_proto(28) > want_proto(27) -> "contract protocol number is newer than host"
            decoded(28, 0),
            inputs(27, 27, 0),
            "rejected",
            "contract protocol number is newer than host",
        ),
        (
            "equal_protocol_matching_prerelease_accepted",
            // got_proto(28) == want_proto(28), got_pre(0) == host_pre(0)
            decoded(28, 0),
            inputs(28, 28, 0),
            "accepted",
            "protocol and pre-release match the host",
        ),
        (
            "equal_protocol_mismatching_prerelease_rejected",
            // got_proto(28) == want_proto(28), got_pre(1) != host_pre(0)
            decoded(28, 1),
            inputs(28, 28, 0),
            "rejected",
            "contract pre-release number for current protocol does not match host",
        ),
        (
            "older_protocol_zero_prerelease_accepted",
            // got_proto(27) < want_proto(28), got_pre(0) -> accepted
            decoded(27, 0),
            inputs(28, 28, 0),
            "accepted",
            "older finalized protocol with zero pre-release",
        ),
        (
            "older_protocol_nonzero_prerelease_rejected",
            // got_proto(27) < want_proto(28), got_pre(1) -> rejected
            decoded(27, 1),
            inputs(28, 28, 0),
            "rejected",
            "contract pre-release number for old protocol is nonzero",
        ),
        (
            "host_newer_than_network_want_uses_network_protocol",
            // curr=23, host=28 -> want=min=23; got 23 == want, pre 0 == 0 -> accepted
            decoded(23, 0),
            inputs(23, 28, 0),
            "accepted",
            "protocol and pre-release match the host",
        ),
        (
            "older_protocol_accepted_when_host_newer_than_target",
            // curr=30, host=30 -> want=30; got 28 < 30, pre 0 -> accepted
            decoded(28, 0),
            inputs(30, 30, 0),
            "accepted",
            "older finalized protocol with zero pre-release",
        ),
        (
            "host_newer_with_nonzero_host_prerelease_equal_rejects",
            // curr=28, host=28, host_pre=1 (a 'next'-pre network); got 28 pre 0 != 1 -> rejected
            decoded(28, 0),
            inputs(28, 28, 1),
            "rejected",
            "contract pre-release number for current protocol does not match host",
        ),
    ];

    for (label, report, inpts, want_verdict, want_reason_substr) in cases {
        let a = assess_env_meta(report, inpts);
        assert_eq!(a.verdict, *want_verdict, "{label}: verdict");
        assert!(
            a.reason.contains(*want_reason_substr),
            "{label}: reason `{}` contains `{}'",
            a.reason,
            want_reason_substr
        );
        // want_proto must always be min(curr, host):
        assert_eq!(
            a.want_protocol,
            inpts.curr_ledger_protocol.min(inpts.host_protocol),
            "{label}: want_proto is min(curr, host)"
        );
        // got values echo the decoded report:
        assert_eq!(
            a.got_protocol,
            report.protocol.unwrap(),
            "{label}: got_protocol"
        );
        assert_eq!(
            a.got_pre_release,
            report.pre_release.unwrap(),
            "{label}: got_pre_release"
        );
    }
}

#[test]
fn env_meta_assessment_undecodable_is_not_applicable() {
    let r = EnvMetaReport {
        status: "undecodable".to_string(),
        protocol: None,
        pre_release: None,
        error: Some("bad payload".to_string()),
        diagnostic: None,
        assessment: None,
    };
    let a = assess_env_meta(&r, &inputs(28, 28, 0));
    assert_eq!(a.verdict, "not_applicable");
    assert!(a.reason.contains("bad payload"));
    assert_eq!(a.want_protocol, 28);
}

#[test]
fn env_meta_assessment_does_not_claim_live_verification() {
    // The assessment is derived entirely from operator-supplied numbers plus
    // the decoded version. It must not claim to have queried any network.
    let a = assess_env_meta(&decoded(28, 0), &inputs(28, 28, 0));
    assert_eq!(a.verdict, "accepted");
    assert!(!a.reason.contains("queried") && !a.reason.contains("network"));
    assert_eq!(a.inputs.curr_ledger_protocol, 28);
    assert_eq!(a.inputs.host_protocol, 28);
}
