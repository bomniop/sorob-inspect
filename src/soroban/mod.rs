//! Soroban-specific inspection layered on top of the generic WASM parser.
//!
//! Contract-spec decoding uses the official `stellar-xdr` crate with the same
//! resource limits as `soroban-spec` (depth 500, len 16 MiB). We do not
//! hand-roll XDR parsing or guess the `contractspecv0` format.
//!
//! ABI compatibility is only assessed when both specs decode; otherwise the
//! verdict is `unknown`. See [`diff`].

pub mod consistency;
pub mod diff;
pub mod structural;

use crate::wasm::{inspect, InspectError, WasmReport};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use stellar_xdr::{Limited, Limits, ReadXdr, ScEnvMetaEntry, ScSpecEntry, ScSpecTypeDef};

/// Maximum size of a `contractspecv0` payload we will attempt to decode.
const MAX_SPEC_LEN: usize = 0x1000000; // 16 MiB, matches soroban-spec Limits.len
/// Maximum XDR nesting depth, matches soroban-spec Limits.depth.
const MAX_SPEC_DEPTH: u32 = 500;

/// Outcome of a Soroban-specific validation pass.
#[derive(Debug, Serialize, Deserialize)]
pub struct SorobanReport {
    /// Underlying generic WASM report.
    pub wasm: WasmReport,
    /// `true` if a `contractspecv0` custom section was found.
    pub has_contract_spec: bool,
    /// `true` if a `contractenvmetav0` custom section was found.
    pub has_contract_env_meta: bool,
    /// Decoded contract spec, if present and parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<SpecReport>,
    /// Contract-spec vs raw WASM export consistency. Present when a spec was
    /// available (or attempted) so consumers can see what was compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency: Option<crate::soroban::consistency::ConsistencyReport>,
    /// Decoded Soroban environment metadata (`contractenvmetav0`): the contract's
    /// declared interface version. Present only when that section exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_meta: Option<EnvMetaReport>,
    /// Human-readable summary of Soroban-relevant observations.
    pub summary: String,
}

/// Decoded Soroban environment metadata (`contractenvmetav0`).
///
/// The section carries an XDR stream of `ScEnvMetaEntry` unions. The Soroban
/// host requires the section to exist and its first entry to be an
/// `SC_ENV_META_KIND_INTERFACE_VERSION`; otherwise instantiation fails
/// (`soroban-env-host 28.0.2`, `src/vm/parsed_module.rs:472-500`,
/// `check_meta_section`). The host then checks the version against the ledger
/// protocol (`:322-395`, `check_contract_interface_version`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvMetaReport {
    /// `decoded` when the first entry was an interface version, or
    /// `undecodable` when the section existed but could not be read.
    pub status: String,
    /// Declared protocol number. Present only when `status` is `decoded`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
    /// Declared pre-release number (0 for finalized protocols). Present only
    /// when `status` is `decoded`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_release: Option<u32>,
    /// Why decoding failed. Present only when `status` is `undecodable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Actionable guidance for evaluating `protocol` / `pre_release` against a
    /// target network. Present only when `status` is `decoded`.
    ///
    /// This is documentation, **not** a verdict: see
    /// [`INTERFACE_VERSION_DIAGNOSTIC`] for why no verdict can be rendered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    /// Compatibility assessment against an explicitly supplied target protocol.
    /// Present only when the operator supplied `--target-protocol`; otherwise
    /// the version is decoded but deliberately left unassessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment: Option<EnvMetaAssessment>,
}

/// Actionable guidance attached to every decoded interface version.
///
/// This describes the host's acceptance rule verbatim; it is *not* a
/// compatibility verdict. SorobInspect cannot decide acceptance because the
/// rule needs two inputs it has no access to: the target network's current
/// ledger protocol and the running host's compiled interface version. Rather
/// than guess (or perform an unverified network lookup), the decoded value is
/// reported together with this guidance so the operator can evaluate it.
///
/// Rule source: `soroban-env-host 28.0.2`, `src/vm/parsed_module.rs`,
/// `check_contract_interface_version` (lines 322-400).
pub const INTERFACE_VERSION_DIAGNOSTIC: &str = "\
The Soroban host accepts a module only in the context of a target ledger \
protocol. Its check (soroban-env-host 28.0.2, src/vm/parsed_module.rs, \
check_contract_interface_version) compares got_proto (this module's declared \
protocol) against want_proto = min(curr_ledger_protocol, host_protocol): \
(1) got_proto > want_proto is rejected as \"contract protocol number is newer \
than host\"; (2) got_proto == want_proto is accepted only when pre_release \
equals the host's compiled pre_release; (3) got_proto < want_proto is accepted \
only when pre_release is 0 (older protocols are finalized). This tool has no \
access to the target ledger protocol or to the running host's interface \
version, so it cannot decide acceptance. Evaluate this value against the target \
network's current ledger protocol.";

/// Operator-supplied inputs for assessing a decoded interface version against
/// the Soroban host's acceptance rule.
///
/// These mirror the arguments `soroban-env-host` receives at runtime. SorobInspect
/// has no way to obtain them automatically, so they must be supplied explicitly
/// via the CLI. See [`assess_env_meta`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvMetaAssessmentInputs {
    /// Target network's current ledger protocol (`curr_ledger_protocol`).
    pub curr_ledger_protocol: u32,
    /// Host's compiled protocol (`host_protocol`; `meta::INTERFACE_VERSION.protocol`).
    pub host_protocol: u32,
    /// Host's compiled pre-release (`meta::INTERFACE_VERSION.pre_release`).
    pub host_pre_release: u32,
}

/// Outcome of applying the host's interface-version acceptance rule
/// (line 322-400 of `soroban-env-host 28.0.2`, production / non-`next` build)
/// to a decoded interface version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvMetaAssessment {
    /// `accepted`, `rejected`, or `not_applicable` (when the version could not
    /// be decoded).
    pub verdict: String,
    /// The host's exact rejection reason, or a human explanation of acceptance.
    pub reason: String,
    /// The inputs the assessment was run with.
    pub inputs: EnvMetaAssessmentInputs,
    /// `got_proto`: the module's declared protocol.
    pub got_protocol: u32,
    /// The module's declared pre-release.
    pub got_pre_release: u32,
    /// `want_proto = min(curr_ledger_protocol, host_protocol)`.
    pub want_protocol: u32,
}

/// Apply the Soroban host's `check_contract_interface_version` rule
/// (production / non-`next` semantics) to a decoded environment interface
/// version.
///
/// Returns `verdict: "not_applicable"` when `report` is not `decoded`. The
/// host itself rejects `curr_ledger_protocol > host_protocol` as an internal
/// error ("ledger protocol number is ahead of supported env protocol number");
/// callers should treat such inputs as contradictory rather than passing them
/// here — the verdict strings below otherwise mirror the host's error messages
/// verbatim.
///
/// `pre_release` checks are modeled for stable (`non-next`) builds, which is the
/// only mode SorobInspect can represent (it does not depend on the `next`
/// feature of `soroban-env-host`).
pub fn assess_env_meta(
    report: &EnvMetaReport,
    inputs: &EnvMetaAssessmentInputs,
) -> EnvMetaAssessment {
    let got_protocol = report.protocol.unwrap_or(0);
    let got_pre_release = report.pre_release.unwrap_or(0);
    let want_protocol = inputs.curr_ledger_protocol.min(inputs.host_protocol);
    let (verdict, reason) = match report.status.as_str() {
        "decoded" => {
            let want_pre = inputs.host_pre_release;
            if got_protocol > want_protocol {
                (
                    "rejected",
                    "contract protocol number is newer than host".to_string(),
                )
            } else if got_protocol == want_protocol {
                if got_pre_release == want_pre {
                    (
                        "accepted",
                        format!(
                            "protocol and pre-release match the host (want_proto={}, host_pre_release={})",
                            want_protocol, want_pre
                        ),
                    )
                } else {
                    (
                        "rejected",
                        "contract pre-release number for current protocol does not match host"
                            .to_string(),
                    )
                }
            } else {
                if got_pre_release == 0 {
                    (
                        "accepted",
                        format!(
                            "older finalized protocol with zero pre-release (want_proto={})",
                            want_protocol
                        ),
                    )
                } else {
                    (
                        "rejected",
                        "contract pre-release number for old protocol is nonzero".to_string(),
                    )
                }
            }
        }
        "undecodable" => (
            "not_applicable",
            report
                .error
                .clone()
                .unwrap_or_else(|| "env meta undecodable".to_string()),
        ),
        other => (
            "not_applicable",
            format!("unknown env_meta status: {other}"),
        ),
    };
    EnvMetaAssessment {
        verdict: verdict.to_string(),
        reason,
        inputs: inputs.clone(),
        got_protocol,
        got_pre_release,
        want_protocol,
    }
}

/// Decoded contract-spec contents.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpecReport {
    /// Exported contract functions from the spec.
    pub functions: Vec<SpecFunction>,
    /// User-defined type declarations (structs, unions, enums, error enums).
    pub types: Vec<SpecType>,
    /// Contract events (separate from UDTs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<SpecEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecFunction {
    pub name: String,
    /// Input parameter names and types.
    pub inputs: Vec<SpecInput>,
    /// Return types as human-readable strings.
    pub outputs: Vec<String>,
    /// Documentation string from the spec (trimmed).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub doc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecInput {
    pub name: String,
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecType {
    /// Kind of UDT: "struct", "union", "enum", "error_enum", or "event".
    pub kind: String,
    pub name: String,
    /// Fields for structs (name + type), empty for other kinds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<SpecField>,
    /// Cases for unions/enums/error enums, with payload types and discriminants
    /// preserved as read from the XDR spec.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cases: Vec<SpecCase>,
}

/// A single union/enum case.
///
/// Payload types (union tuple cases) and discriminant values (enum and error
/// enum cases) are preserved so that compatibility diffing can see changes to
/// them. Dropping either field makes a real ABI change invisible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecCase {
    pub name: String,
    /// "void" (no payload), "tuple" (payload present), or "enum" (unit variant).
    pub kind: String,
    /// Payload types for tuple cases, empty otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<String>,
    /// Discriminant value for enum/error-enum cases. `None` when the spec form
    /// carries no discriminant (union cases), which is not a zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,
}

impl SpecCase {
    /// Compact label used by the human-readable output.
    pub fn label(&self) -> String {
        match self.kind.as_str() {
            "void" => format!("Void({})", self.name),
            "tuple" => format!("Tuple({})", self.name),
            _ => self.name.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecField {
    pub name: String,
    pub type_: String,
}

/// A decoded contract event, separate from UDTs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecEvent {
    pub name: String,
    /// Topic prefix names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prefix_topics: Vec<String>,
    /// Event parameters with their location ("topic" or "data").
    pub params: Vec<SpecEventParam>,
    /// Data format of the event's data segment, matching the
    /// `data_format` field of the spec XDR (`ScSpecEventDataFormat`).
    /// One of `"single_value"`, `"vec"`, or `"map"`.
    pub data_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecEventParam {
    pub name: String,
    pub type_: String,
    pub location: String,
}

/// Errors from Soroban inspection.
#[derive(Debug)]
pub enum SorobanError {
    /// Generic WASM parsing failed.
    Wasm(InspectError),
    /// `contractspecv0` section exists but its XDR payload is invalid.
    SpecDecode(String),
    /// Spec payload exceeds the resource limit.
    SpecTooLarge(usize),
}

impl std::fmt::Display for SorobanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SorobanError::Wasm(e) => write!(f, "{e}"),
            SorobanError::SpecDecode(msg) => write!(f, "contract spec decode failed: {msg}"),
            SorobanError::SpecTooLarge(n) => {
                write!(
                    f,
                    "contract spec too large: {n} bytes (limit {MAX_SPEC_LEN})"
                )
            }
        }
    }
}

impl std::error::Error for SorobanError {}

impl From<InspectError> for SorobanError {
    fn from(e: InspectError) -> Self {
        SorobanError::Wasm(e)
    }
}

/// Detect Soroban markers and, when possible, decode the contract spec.
///
/// # Errors
/// Propagates generic WASM parse errors and contract-spec decode errors.
pub fn inspect_soroban(bytes: &[u8], validate: bool) -> Result<SorobanReport, SorobanError> {
    let wasm = inspect(bytes, validate)?;
    let has_contract_spec = wasm
        .custom_sections
        .iter()
        .any(|s| s.name == "contractspecv0");
    let has_contract_env_meta = wasm
        .custom_sections
        .iter()
        .any(|s| s.name == "contractenvmetav0");

    let spec = if has_contract_spec {
        Some(decode_spec_from_wasm(bytes)?)
    } else {
        None
    };

    // Consistency: reuse the spec we just decoded (no second decode) and the
    // already-parsed wasm report (no reparse).
    let consistency = if has_contract_spec {
        Some(consistency::check_spec_export_consistency(
            &wasm,
            spec.as_ref(),
        ))
    } else {
        None
    };

    // Environment metadata: the Soroban host requires this section and reads the
    // contract's declared interface version from its first entry.
    let env_meta = decode_env_meta_from_wasm(bytes)?;

    let mut summary = match (&spec, has_contract_spec, has_contract_env_meta) {
        (Some(s), true, true) => format!(
            "Soroban contract artifact: {} function(s), {} type(s), {} event(s) decoded from contractspecv0.",
            s.functions.len(),
            s.types.len(),
            s.events.len()
        ),
        (_, true, true) => {
            "Soroban contract artifact detected (contractspecv0 + contractenvmetav0 present)."
                .to_string()
        }
        (_, true, false) | (_, false, true) => {
            "Partial Soroban markers — one of contractspecv0/contractenvmetav0 missing.".to_string()
        }
        (_, false, false) => {
            "No Soroban custom sections found — likely a generic WASM module.".to_string()
        }
    };

    if let Some(em) = &env_meta {
        if em.status == "decoded" {
            summary.push_str(&format!(
                " Environment interface version: protocol {} (pre-release {}).",
                em.protocol.unwrap_or(0),
                em.pre_release.unwrap_or(0)
            ));
        } else {
            summary.push_str(" Environment metadata section present but not decodable.");
        }
    }

    Ok(SorobanReport {
        wasm,
        has_contract_spec,
        has_contract_env_meta,
        spec,
        consistency,
        env_meta,
        summary,
    })
}

/// Extract and decode the `contractspecv0` payload from a WASM binary.
///
/// # Errors
/// `SpecTooLarge` when the section exceeds the limit, `SpecDecode` when the
/// section is missing or its XDR is invalid.
pub fn decode_spec_from_wasm(bytes: &[u8]) -> Result<SpecReport, SorobanError> {
    let raw = extract_spec_bytes(bytes)?;
    decode_spec_raw(&raw)
}

/// Extract the `contractenvmetav0` custom-section payload, if present.
///
/// Returns `Ok(None)` when the section is absent. A present section is never
/// serialized; only its decoded version is reported.
fn extract_env_meta_bytes(bytes: &[u8]) -> Result<Option<Vec<u8>>, SorobanError> {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload =
            payload.map_err(|e| SorobanError::Wasm(InspectError::Malformed(e.to_string())))?;
        if let wasmparser::Payload::CustomSection(section) = payload {
            if section.name() == "contractenvmetav0" {
                return Ok(Some(section.data().to_vec()));
            }
        }
    }
    Ok(None)
}

/// Decode the Soroban environment interface version from a module.
///
/// Returns `Ok(None)` when the module has no `contractenvmetav0` section. When
/// the section exists, its first `ScEnvMetaEntry` must be an
/// `ScEnvMetaKindInterfaceVersion` — the same rule the Soroban host enforces
/// (`soroban-env-host 28.0.2`, `src/vm/parsed_module.rs:472-500`). A section
/// that cannot be read is reported as `undecodable` rather than treated as an
/// error, so a malformed section is visible without aborting the whole report.
pub fn decode_env_meta_from_wasm(bytes: &[u8]) -> Result<Option<EnvMetaReport>, SorobanError> {
    let Some(raw) = extract_env_meta_bytes(bytes)? else {
        return Ok(None);
    };
    Ok(Some(decode_env_meta_raw(&raw)))
}

/// Decode raw `contractenvmetav0` bytes into an [`EnvMetaReport`].
pub fn decode_env_meta_raw(raw: &[u8]) -> EnvMetaReport {
    let mut limited = Limited::new(
        Cursor::new(raw),
        Limits {
            depth: MAX_SPEC_DEPTH,
            len: raw.len(),
        },
    );
    match ScEnvMetaEntry::read_xdr_iter(&mut limited).next() {
        // `ScEnvMetaEntry` has exactly one variant, so a successfully decoded
        // entry is always an interface version. A wrong discriminant fails
        // decoding and surfaces through the `Some(Err(_))` arm below.
        Some(Ok(ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(v))) => EnvMetaReport {
            status: "decoded".to_string(),
            protocol: Some(v.protocol),
            pre_release: Some(v.pre_release),
            error: None,
            diagnostic: Some(INTERFACE_VERSION_DIAGNOSTIC.to_string()),
            assessment: None,
        },
        Some(Err(e)) => EnvMetaReport {
            status: "undecodable".to_string(),
            protocol: None,
            pre_release: None,
            error: Some(format!("contractenvmetav0 decode failed: {e}")),
            diagnostic: None,
            assessment: None,
        },
        None => EnvMetaReport {
            status: "undecodable".to_string(),
            protocol: None,
            pre_release: None,
            error: Some("contractenvmetav0 is empty".to_string()),
            diagnostic: None,
            assessment: None,
        },
    }
}

/// Extract the `contractspecv0` custom-section payload.
fn extract_spec_bytes(bytes: &[u8]) -> Result<Vec<u8>, SorobanError> {
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload =
            payload.map_err(|e| SorobanError::Wasm(InspectError::Malformed(e.to_string())))?;
        if let wasmparser::Payload::CustomSection(section) = payload {
            if section.name() == "contractspecv0" {
                let data = section.data();
                if data.len() > MAX_SPEC_LEN {
                    return Err(SorobanError::SpecTooLarge(data.len()));
                }
                return Ok(data.to_vec());
            }
        }
    }
    Err(SorobanError::SpecDecode(
        "contractspecv0 section not found".to_string(),
    ))
}

/// Decode raw XDR spec bytes into structured entries.
///
/// # Errors
/// `SpecDecode` for malformed or truncated XDR, or when the entry count or
/// depth exceeds the configured limits.
pub fn decode_spec_raw(raw: &[u8]) -> Result<SpecReport, SorobanError> {
    let cursor = Cursor::new(raw);
    let mut limited = Limited::new(
        cursor,
        Limits {
            depth: MAX_SPEC_DEPTH,
            len: MAX_SPEC_LEN,
        },
    );
    let mut reader = ScSpecEntry::read_xdr_iter(&mut limited);

    let mut functions = Vec::new();
    let mut types = Vec::new();
    let mut events = Vec::new();
    loop {
        match reader.next() {
            Some(Ok(entry)) => match entry {
                ScSpecEntry::FunctionV0(f) => functions.push(SpecFunction {
                    name: f.name.to_string(),
                    inputs: f
                        .inputs
                        .to_vec()
                        .into_iter()
                        .map(|i| SpecInput {
                            name: i.name.to_string(),
                            type_: format_type_def(&i.type_),
                        })
                        .collect(),
                    outputs: f
                        .outputs
                        .to_vec()
                        .into_iter()
                        .map(|o| format_type_def(&o))
                        .collect(),
                    doc: f.doc.to_string().trim().to_string(),
                }),
                ScSpecEntry::UdtStructV0(s) => types.push(SpecType {
                    kind: "struct".to_string(),
                    name: s.name.to_string(),
                    fields: s
                        .fields
                        .to_vec()
                        .into_iter()
                        .map(|fld| SpecField {
                            name: fld.name.to_string(),
                            type_: format_type_def(&fld.type_),
                        })
                        .collect(),
                    cases: Vec::new(),
                }),
                ScSpecEntry::UdtUnionV0(u) => types.push(SpecType {
                    kind: "union".to_string(),
                    name: u.name.to_string(),
                    fields: Vec::new(),
                    cases: u
                        .cases
                        .to_vec()
                        .into_iter()
                        .map(|c| match c {
                            stellar_xdr::ScSpecUdtUnionCaseV0::TupleV0(t) => SpecCase {
                                name: t.name.to_string(),
                                kind: "tuple".to_string(),
                                payload: t
                                    .type_
                                    .to_vec()
                                    .into_iter()
                                    .map(|x| format_type_def(&x))
                                    .collect(),
                                value: None,
                            },
                            stellar_xdr::ScSpecUdtUnionCaseV0::VoidV0(v) => SpecCase {
                                name: v.name.to_string(),
                                kind: "void".to_string(),
                                payload: Vec::new(),
                                value: None,
                            },
                        })
                        .collect(),
                }),
                ScSpecEntry::UdtEnumV0(e) => types.push(SpecType {
                    kind: "enum".to_string(),
                    name: e.name.to_string(),
                    fields: Vec::new(),
                    cases: e
                        .cases
                        .to_vec()
                        .into_iter()
                        .map(|c| SpecCase {
                            name: c.name.to_string(),
                            kind: "enum".to_string(),
                            payload: Vec::new(),
                            value: Some(c.value),
                        })
                        .collect(),
                }),
                ScSpecEntry::UdtErrorEnumV0(e) => types.push(SpecType {
                    kind: "error_enum".to_string(),
                    name: e.name.to_string(),
                    fields: Vec::new(),
                    cases: e
                        .cases
                        .to_vec()
                        .into_iter()
                        .map(|c| SpecCase {
                            name: c.name.to_string(),
                            kind: "error_enum".to_string(),
                            payload: Vec::new(),
                            value: Some(c.value),
                        })
                        .collect(),
                }),
                ScSpecEntry::EventV0(ev) => events.push(SpecEvent {
                    name: ev.name.to_string(),
                    prefix_topics: ev
                        .prefix_topics
                        .to_vec()
                        .into_iter()
                        .map(|t| t.to_string())
                        .collect(),
                    params: ev
                        .params
                        .to_vec()
                        .into_iter()
                        .map(|p| SpecEventParam {
                            name: p.name.to_string(),
                            type_: format_type_def(&p.type_),
                            location: match p.location {
                                stellar_xdr::ScSpecEventParamLocationV0::Data => "data".to_string(),
                                stellar_xdr::ScSpecEventParamLocationV0::TopicList => {
                                    "topic".to_string()
                                }
                            },
                        })
                        .collect(),
                    data_format: match ev.data_format {
                        stellar_xdr::ScSpecEventDataFormat::SingleValue => {
                            "single_value".to_string()
                        }
                        stellar_xdr::ScSpecEventDataFormat::Vec => "vec".to_string(),
                        stellar_xdr::ScSpecEventDataFormat::Map => "map".to_string(),
                    },
                }),
            },
            Some(Err(e)) => return Err(SorobanError::SpecDecode(e.to_string())),
            None => break,
        }
    }

    Ok(SpecReport {
        functions,
        types,
        events,
    })
}

/// Render an `ScSpecTypeDef` as a compact human-readable type string.
fn format_type_def(t: &ScSpecTypeDef) -> String {
    match t {
        ScSpecTypeDef::Val => "Val".into(),
        ScSpecTypeDef::Bool => "Bool".into(),
        ScSpecTypeDef::Void => "Void".into(),
        ScSpecTypeDef::Error => "Error".into(),
        ScSpecTypeDef::U32 => "U32".into(),
        ScSpecTypeDef::I32 => "I32".into(),
        ScSpecTypeDef::U64 => "U64".into(),
        ScSpecTypeDef::I64 => "I64".into(),
        ScSpecTypeDef::Timepoint => "Timepoint".into(),
        ScSpecTypeDef::Duration => "Duration".into(),
        ScSpecTypeDef::U128 => "U128".into(),
        ScSpecTypeDef::I128 => "I128".into(),
        ScSpecTypeDef::U256 => "U256".into(),
        ScSpecTypeDef::I256 => "I256".into(),
        ScSpecTypeDef::Bytes => "Bytes".into(),
        ScSpecTypeDef::String => "String".into(),
        ScSpecTypeDef::Symbol => "Symbol".into(),
        ScSpecTypeDef::Address => "Address".into(),
        ScSpecTypeDef::MuxedAddress => "MuxedAddress".into(),
        ScSpecTypeDef::BytesN(n) => format!("BytesN<{}>", n.n),
        ScSpecTypeDef::Option(o) => format!("Option<{}>", format_type_def(&o.value_type)),
        ScSpecTypeDef::Result(r) => format!(
            "Result<{}, {}>",
            format_type_def(&r.ok_type),
            format_type_def(&r.error_type)
        ),
        ScSpecTypeDef::Vec(v) => format!("Vec<{}>", format_type_def(&v.element_type)),
        ScSpecTypeDef::Map(m) => format!(
            "Map<{}, {}>",
            format_type_def(&m.key_type),
            format_type_def(&m.value_type)
        ),
        ScSpecTypeDef::Tuple(t) => {
            let elems: Vec<String> = t.value_types.to_vec().iter().map(format_type_def).collect();
            format!("Tuple<{}>", elems.join(", "))
        }
        ScSpecTypeDef::Udt(u) => u.name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn empty_module_is_not_soroban() {
        let report = inspect_soroban(EMPTY_WASM, false).unwrap();
        assert!(!report.has_contract_spec);
        assert!(!report.has_contract_env_meta);
        assert!(report.spec.is_none());
        assert!(report.summary.contains("No Soroban"));
    }

    #[test]
    fn malformed_input_errors() {
        let result = inspect_soroban(&[0xff, 0xff, 0xff], false);
        assert!(result.is_err());
    }

    /// Build a minimal valid WASM module with a `contractspecv0` custom section
    /// of the given data size, using proper LEB128 section-length encoding
    /// (the integration-test helper only supports small sections).
    fn wasm_with_spec_section_size(data_len: usize) -> Vec<u8> {
        let name = b"contractspecv0";
        let payload_len = 1 + name.len() + data_len;
        let mut buf = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        buf.push(0x00); // custom-section id
                        // LEB128-encode payload_len.
        let mut n = payload_len as u64;
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
        buf.resize(buf.len() + data_len, 0x00);
        buf
    }

    #[test]
    fn spec_over_limit_is_rejected() {
        // data_len = MAX_SPEC_LEN + 1 → must return SpecTooLarge, not panic
        // or proceed to XDR decode.
        let wasm = wasm_with_spec_section_size(MAX_SPEC_LEN + 1);
        let result = inspect_soroban(&wasm, false);
        assert!(
            matches!(result, Err(SorobanError::SpecTooLarge(n)) if n == MAX_SPEC_LEN + 1),
            "expected SpecTooLarge({}), got {:?}",
            MAX_SPEC_LEN + 1,
            result
        );
    }

    #[test]
    fn spec_at_limit_passes_size_check() {
        // data_len = MAX_SPEC_LEN exactly → must NOT return SpecTooLarge.
        // The data is zero-filled (invalid XDR), so decode fails with
        // SpecDecode; the only thing this test guards is the size boundary.
        let wasm = wasm_with_spec_section_size(MAX_SPEC_LEN);
        let result = inspect_soroban(&wasm, false);
        assert!(
            !matches!(result, Err(SorobanError::SpecTooLarge(_))),
            "size-at-limit must not trigger SpecTooLarge"
        );
    }

    #[test]
    fn decode_empty_spec_is_valid() {
        // Zero entries is valid under XDR framing.
        let report = decode_spec_raw(&[]).unwrap();
        assert!(report.functions.is_empty());
        assert!(report.types.is_empty());
    }

    #[test]
    fn decode_malformed_xdr_errors_cleanly() {
        let result = decode_spec_raw(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(result, Err(SorobanError::SpecDecode(_))));
    }

    #[test]
    fn decode_truncated_xdr_errors_cleanly() {
        // Valid discriminant, truncated body.
        let result = decode_spec_raw(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(result, Err(SorobanError::SpecDecode(_))));
    }

    // --- contractenvmetav0 (environment interface version) tests ---

    /// Build a `contractenvmetav0` payload: the interface-version union as
    /// `int32 discriminant 0` + `uint32 protocol` + `uint32 pre_release`, all
    /// big-endian, matching `soroban-env-host`'s framing.
    fn env_meta_payload(protocol: u32, pre_release: u32) -> Vec<u8> {
        let mut v = vec![0x00, 0x00, 0x00, 0x00];
        v.extend_from_slice(&protocol.to_be_bytes());
        v.extend_from_slice(&pre_release.to_be_bytes());
        v
    }

    #[test]
    fn env_meta_decodes_interface_version() {
        let em = decode_env_meta_raw(&env_meta_payload(21, 0));
        assert_eq!(em.status, "decoded");
        assert_eq!(em.protocol, Some(21));
        assert_eq!(em.pre_release, Some(0));
        assert!(em.error.is_none());
    }

    #[test]
    fn env_meta_decodes_nonzero_prerelease() {
        // Pre-release numbers are meaningful for not-yet-finalized protocols.
        let em = decode_env_meta_raw(&env_meta_payload(22, 1));
        assert_eq!(em.status, "decoded");
        assert_eq!(em.protocol, Some(22));
        assert_eq!(em.pre_release, Some(1));
    }

    #[test]
    fn env_meta_empty_section_is_undecodable_not_panic() {
        // The host rejects an empty section ("contract missing environment
        // interface version"); the report must surface it, not crash.
        let em = decode_env_meta_raw(&[]);
        assert_eq!(em.status, "undecodable");
        assert!(em.protocol.is_none());
        assert!(em.pre_release.is_none());
        assert!(em.error.is_some());
    }

    #[test]
    fn env_meta_truncated_section_is_undecodable_not_panic() {
        let em = decode_env_meta_raw(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(em.status, "undecodable");
        assert!(em.error.is_some());
    }

    #[test]
    fn env_meta_wrong_discriminant_is_undecodable_not_panic() {
        // A discriminant other than 0 is not an interface version.
        let mut payload = vec![0x00, 0x00, 0x00, 0x01];
        payload.extend_from_slice(&21u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        let em = decode_env_meta_raw(&payload);
        assert_eq!(em.status, "undecodable");
        assert!(em.error.is_some());
    }

    #[test]
    fn env_meta_from_wasm_absent_section_is_none() {
        // Generic module without the section: absent, not an error.
        let wasm = wasm_with_spec_section_size(0);
        let em = decode_env_meta_from_wasm(&wasm).expect("no error when section absent");
        assert!(em.is_none());
    }

    #[test]
    fn env_meta_from_wasm_decodes_present_section() {
        // A module whose only custom section is contractenvmetav0.
        let name = b"contractenvmetav0";
        let payload = env_meta_payload(21, 0);
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
        buf.extend_from_slice(&payload);

        let em = decode_env_meta_from_wasm(&buf).expect("decodes");
        let em = em.expect("section present");
        assert_eq!(em.status, "decoded");
        assert_eq!(em.protocol, Some(21));
        assert_eq!(em.pre_release, Some(0));
    }

    #[test]
    fn env_meta_is_reported_on_inspect_soroban() {
        // End-to-end: the decoded version reaches the report and the summary.
        let name = b"contractenvmetav0";
        let payload = env_meta_payload(21, 0);
        let mut buf = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        buf.push(0x00);
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
        buf.extend_from_slice(&payload);

        let report = inspect_soroban(&buf, false).expect("parses");
        assert!(report.has_contract_env_meta);
        let em = report.env_meta.expect("env meta present");
        assert_eq!(em.status, "decoded");
        assert_eq!(em.protocol, Some(21));
        assert!(
            report.summary.contains("protocol 21"),
            "summary must mention the decoded version: {}",
            report.summary
        );
    }
}
