//! Contract-spec compatibility diff.
//!
//! Compares two decoded contract specs and classifies each difference as
//! breaking, non-breaking, or uncertain. Rules are documented below.
//!
//! Compatibility is only ever assessed when BOTH specs decode successfully.
//! If either side fails to decode, the verdict is `unknown` — never a guess.
//!
//! # Compatibility rules
//!
//! | Change | Verdict | Rationale |
//! |--------|---------|-----------|
//! | Function added | non-breaking | New entry point, existing callers unaffected |
//! | Function removed | breaking | Existing callers lose access |
//! | Param count changed | breaking | Positional callers break |
//! | Param type changed | breaking | Type mismatch at call site |
//! | Param renamed | non-breaking | Positional callers unaffected |
//! | Return type changed | breaking | Callers expecting old type break |
//! | Struct field added | breaking | Existing constructors/initializers may not set it |
//! | Struct field removed | breaking | Existing code referencing it breaks |
//! | Struct field type changed | breaking | Type mismatch |
//! | Struct field renamed | breaking | The field name is part of the encoded struct form |
//! | Enum variant added | non-breaking | Exhaustive matches may need update but existing code works |
//! | Enum variant removed | breaking | Existing matches on that variant break |
//! | Enum discriminant changed | breaking | Wire value changes; stored/encoded data becomes unreadable |
//! | Union variant added | non-breaking | Same as enum variant added |
//! | Union variant removed | breaking | Same as enum variant removed |
//! | Union tuple-case payload changed | breaking | Callers must supply/receive a different type |
//! | Union case kind changed (void ↔ tuple) | breaking | Shape of the case changes on the wire |
//! | Discriminant present on only one side | unknown | The decoded specs are not comparable on this field |
//!
//! | Event added | non-breaking | New event, existing subscribers unaffected |
//! | Event removed | breaking | Subscribers lose the event |
//! | Event param added | breaking | Subscribers expecting old shape break |
//! | Event param removed | breaking | Subscribers referencing it break |
//! | Event param type changed | breaking | Type mismatch for subscribers |
//! | Event param renamed | breaking | Conservative: a subscriber may match on the param name |
//! | Event topic list changed | breaking | Topic filter changes affect subscribers |
//! | Event data format changed | breaking | Subscribers parsing payload break |

use crate::soroban::{SpecEvent, SpecFunction, SpecReport, SpecType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Result of comparing two decoded contract specs.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpecDiff {
    /// Functions present in new but not old.
    pub functions_added: Vec<String>,
    /// Functions present in old but not new.
    pub functions_removed: Vec<String>,
    /// Functions present in both but with changed signatures.
    pub functions_changed: Vec<FunctionChange>,
    /// Types present in new but not old.
    pub types_added: Vec<String>,
    /// Types present in old but not new.
    pub types_removed: Vec<String>,
    /// Types present in both but with changed fields/cases.
    pub types_changed: Vec<TypeChange>,
    /// Events present in new but not old.
    pub events_added: Vec<String>,
    /// Events present in old but not new.
    pub events_removed: Vec<String>,
    /// Events present in both but with changed params/topics/format.
    pub events_changed: Vec<EventChange>,
    /// Overall verdict derived from the changes above.
    pub compatibility: Compatibility,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionChange {
    pub name: String,
    /// What changed, e.g. "param type changed: to String -> Symbol".
    pub detail: String,
    /// Whether this specific change is breaking.
    pub breaking: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TypeChange {
    pub name: String,
    pub kind: String,
    pub detail: String,
    pub breaking: bool,
    /// True when the decoded specs do not carry enough information to decide
    /// the verdict for this change (e.g. one side lacks a discriminant). Such
    /// cases force an overall `unknown` verdict instead of a guessed one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub uncertain: bool,
}

impl TypeChange {
    fn new(name: &str, kind: &str, detail: impl Into<String>, breaking: bool) -> Self {
        TypeChange {
            name: name.to_string(),
            kind: kind.to_string(),
            detail: detail.into(),
            breaking,
            uncertain: false,
        }
    }
}

/// Build a change that cannot be classified from the spec alone → overall verdict becomes `unknown`.
fn uncertain_change(name: &str, kind: &str, detail: impl Into<String>) -> TypeChange {
    TypeChange {
        name: name.to_string(),
        kind: kind.to_string(),
        detail: detail.into(),
        breaking: false,
        uncertain: true,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventChange {
    pub name: String,
    pub detail: String,
    pub breaking: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Compatibility {
    /// No changes at all.
    Identical,
    /// Only additions — existing callers keep working.
    NonBreaking,
    /// At least one removal or breaking signature change.
    Breaking,
    /// One or both specs could not be decoded — no verdict.
    Unknown,
}

/// Compare two decoded specs and produce a compatibility verdict.
///
/// Semantic equivalence is NOT inferred from names — the comparison is
/// structural on the decoded XDR spec only.
pub fn diff_specs(old: &SpecReport, new: &SpecReport) -> SpecDiff {
    let old_fns: BTreeMap<&str, &SpecFunction> =
        old.functions.iter().map(|f| (f.name.as_str(), f)).collect();
    let new_fns: BTreeMap<&str, &SpecFunction> =
        new.functions.iter().map(|f| (f.name.as_str(), f)).collect();

    let mut functions_added = Vec::new();
    let mut functions_removed = Vec::new();
    let mut functions_changed = Vec::new();

    for name in new_fns.keys() {
        if !old_fns.contains_key(name) {
            functions_added.push((*name).to_string());
        }
    }
    for (name, old_f) in &old_fns {
        match new_fns.get(name) {
            None => functions_removed.push((*name).to_string()),
            Some(new_f) => {
                functions_changed.extend(compare_functions(old_f, new_f));
            }
        }
    }

    let old_types: BTreeMap<&str, &SpecType> =
        old.types.iter().map(|t| (t.name.as_str(), t)).collect();
    let new_types: BTreeMap<&str, &SpecType> =
        new.types.iter().map(|t| (t.name.as_str(), t)).collect();

    let mut types_added = Vec::new();
    let mut types_removed = Vec::new();
    let mut types_changed = Vec::new();

    for name in new_types.keys() {
        if !old_types.contains_key(name) {
            types_added.push((*name).to_string());
        }
    }
    for (name, old_t) in &old_types {
        match new_types.get(name) {
            None => types_removed.push((*name).to_string()),
            Some(new_t) => {
                types_changed.extend(compare_types(old_t, new_t));
            }
        }
    }

    let old_events: BTreeMap<&str, &SpecEvent> =
        old.events.iter().map(|e| (e.name.as_str(), e)).collect();
    let new_events: BTreeMap<&str, &SpecEvent> =
        new.events.iter().map(|e| (e.name.as_str(), e)).collect();

    let mut events_added = Vec::new();
    let mut events_removed = Vec::new();
    let mut events_changed = Vec::new();

    for name in new_events.keys() {
        if !old_events.contains_key(name) {
            events_added.push((*name).to_string());
        }
    }
    for (name, old_e) in &old_events {
        match new_events.get(name) {
            None => events_removed.push((*name).to_string()),
            Some(new_e) => {
                events_changed.extend(compare_events(old_e, new_e));
            }
        }
    }

    let compatibility = classify(
        &functions_added,
        &functions_removed,
        &functions_changed,
        &types_added,
        &types_removed,
        &types_changed,
        &events_added,
        &events_removed,
        &events_changed,
    );

    functions_added.sort();
    functions_removed.sort();
    types_added.sort();
    types_removed.sort();
    events_added.sort();
    events_removed.sort();

    SpecDiff {
        functions_added,
        functions_removed,
        functions_changed,
        types_added,
        types_removed,
        types_changed,
        events_added,
        events_removed,
        events_changed,
        compatibility,
    }
}

fn compare_functions(old: &SpecFunction, new: &SpecFunction) -> Vec<FunctionChange> {
    let mut changes = Vec::new();

    if old.inputs.len() != new.inputs.len() {
        changes.push(FunctionChange {
            name: old.name.clone(),
            detail: format!(
                "param count changed: {} -> {}",
                old.inputs.len(),
                new.inputs.len()
            ),
            breaking: true,
        });
        // If count changed, don't compare individual params — the shift makes
        // per-position comparison misleading.
        if old.outputs != new.outputs {
            changes.push(FunctionChange {
                name: old.name.clone(),
                detail: format!(
                    "return type changed: {:?} -> {:?}",
                    old.outputs, new.outputs
                ),
                breaking: true,
            });
        }
        return changes;
    }

    for (oi, ni) in old.inputs.iter().zip(new.inputs.iter()) {
        if oi.type_ != ni.type_ {
            // Report every changed parameter, not just the first: a caller
            // fixing one type mismatch must also see the others.
            changes.push(FunctionChange {
                name: old.name.clone(),
                detail: format!(
                    "param type changed: {} {} -> {} {}",
                    oi.name, oi.type_, ni.name, ni.type_
                ),
                breaking: true,
            });
        } else if oi.name != ni.name {
            changes.push(FunctionChange {
                name: old.name.clone(),
                detail: format!("param renamed: {} -> {}", oi.name, ni.name),
                breaking: false,
            });
        }
    }

    if old.outputs != new.outputs {
        changes.push(FunctionChange {
            name: old.name.clone(),
            detail: format!(
                "return type changed: {:?} -> {:?}",
                old.outputs, new.outputs
            ),
            breaking: true,
        });
    }

    changes
}

fn compare_types(old: &SpecType, new: &SpecType) -> Vec<TypeChange> {
    let mut changes = Vec::new();

    // Struct field comparison.
    if old.kind == "struct" && new.kind == "struct" {
        let old_fields: BTreeMap<&str, &str> = old
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.type_.as_str()))
            .collect();
        let new_fields: BTreeMap<&str, &str> = new
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.type_.as_str()))
            .collect();

        for (name, old_ty) in &old_fields {
            match new_fields.get(name) {
                None => changes.push(TypeChange::new(
                    &old.name,
                    &old.kind,
                    format!("field '{}' removed", name),
                    true,
                )),
                Some(new_ty) => {
                    if old_ty != new_ty {
                        changes.push(TypeChange::new(
                            &old.name,
                            &old.kind,
                            format!("field '{}' type changed: {} -> {}", name, old_ty, new_ty),
                            true,
                        ));
                    }
                }
            }
        }
        for name in new_fields.keys() {
            if !old_fields.contains_key(name) {
                changes.push(TypeChange::new(
                    &old.name,
                    &old.kind,
                    format!("field '{}' added", name),
                    true,
                ));
            }
        }
    }

    // Enum/union/error_enum case comparison.
    if matches!(old.kind.as_str(), "enum" | "union" | "error_enum") && old.kind == new.kind {
        let old_cases: BTreeMap<&str, &crate::soroban::SpecCase> =
            old.cases.iter().map(|c| (c.name.as_str(), c)).collect();
        let new_cases: BTreeMap<&str, &crate::soroban::SpecCase> =
            new.cases.iter().map(|c| (c.name.as_str(), c)).collect();

        for (name, old_c) in &old_cases {
            match new_cases.get(name) {
                None => changes.push(TypeChange::new(
                    &old.name,
                    &old.kind,
                    format!("variant '{}' removed", old_c.label()),
                    true,
                )),
                Some(new_c) => {
                    // A case that survives by name can still change shape:
                    // payload types on tuple cases, discriminant on enum cases,
                    // or void <-> tuple kind.
                    if old_c.kind != new_c.kind {
                        changes.push(TypeChange::new(
                            &old.name,
                            &old.kind,
                            format!(
                                "variant '{}' kind changed: {} -> {}",
                                name, old_c.kind, new_c.kind
                            ),
                            true,
                        ));
                    }
                    if old_c.payload != new_c.payload {
                        changes.push(TypeChange::new(
                            &old.name,
                            &old.kind,
                            format!(
                                "variant '{}' payload changed: {:?} -> {:?}",
                                name, old_c.payload, new_c.payload
                            ),
                            true,
                        ));
                    }
                    // Discriminants are only comparable when BOTH sides carry
                    // one. If exactly one side has a value, the spec does not
                    // tell us enough to decide — that must be `unknown`, never
                    // a guessed `identical`.
                    match (old_c.value, new_c.value) {
                        (Some(o), Some(n)) if o != n => changes.push(TypeChange::new(
                            &old.name,
                            &old.kind,
                            format!("variant '{}' discriminant changed: {} -> {}", name, o, n),
                            true,
                        )),
                        (None, Some(_)) | (Some(_), None) => changes.push(uncertain_change(
                            &old.name,
                            &old.kind,
                            format!(
                                "variant '{}' discriminant present on only one side: {:?} -> {:?}",
                                name, old_c.value, new_c.value
                            ),
                        )),
                        _ => {}
                    }
                }
            }
        }
        for (name, new_c) in &new_cases {
            if !old_cases.contains_key(name) {
                changes.push(TypeChange::new(
                    &old.name,
                    &old.kind,
                    format!("variant '{}' added", new_c.label()),
                    false,
                ));
            }
        }
    }

    // Kind changed (e.g. struct → enum) — treat as breaking.
    if old.kind != new.kind {
        changes.push(TypeChange::new(
            &old.name,
            &old.kind,
            format!("type kind changed: {} -> {}", old.kind, new.kind),
            true,
        ));
    }

    changes
}

fn compare_events(old: &SpecEvent, new: &SpecEvent) -> Vec<EventChange> {
    let mut changes = Vec::new();

    if old.prefix_topics != new.prefix_topics {
        changes.push(EventChange {
            name: old.name.clone(),
            detail: format!(
                "topic list changed: {:?} -> {:?}",
                old.prefix_topics, new.prefix_topics
            ),
            breaking: true,
        });
    }

    if old.data_format != new.data_format {
        changes.push(EventChange {
            name: old.name.clone(),
            detail: format!(
                "data format changed: {} -> {}",
                old.data_format, new.data_format
            ),
            breaking: true,
        });
    }

    // Param comparison: match by name; count change → breaking.
    if old.params.len() != new.params.len() {
        changes.push(EventChange {
            name: old.name.clone(),
            detail: format!(
                "param count changed: {} -> {}",
                old.params.len(),
                new.params.len()
            ),
            breaking: true,
        });
        return changes;
    }

    let old_params: BTreeMap<&str, (&str, &str)> = old
        .params
        .iter()
        .map(|p| (p.name.as_str(), (p.type_.as_str(), p.location.as_str())))
        .collect();
    let new_params: BTreeMap<&str, (&str, &str)> = new
        .params
        .iter()
        .map(|p| (p.name.as_str(), (p.type_.as_str(), p.location.as_str())))
        .collect();

    for (name, (old_ty, old_loc)) in &old_params {
        match new_params.get(name) {
            None => changes.push(EventChange {
                name: old.name.clone(),
                detail: format!("param '{}' removed", name),
                breaking: true,
            }),
            Some((new_ty, new_loc)) => {
                if old_ty != new_ty {
                    changes.push(EventChange {
                        name: old.name.clone(),
                        detail: format!("param '{}' type changed: {} -> {}", name, old_ty, new_ty),
                        breaking: true,
                    });
                }
                if old_loc != new_loc {
                    changes.push(EventChange {
                        name: old.name.clone(),
                        detail: format!(
                            "param '{}' location changed: {} -> {}",
                            name, old_loc, new_loc
                        ),
                        breaking: true,
                    });
                }
            }
        }
    }
    for name in new_params.keys() {
        if !old_params.contains_key(name) {
            changes.push(EventChange {
                name: old.name.clone(),
                detail: format!("param '{}' added", name),
                breaking: true,
            });
        }
    }

    changes
}

#[allow(clippy::too_many_arguments)]
fn classify(
    fns_added: &[String],
    fns_removed: &[String],
    fns_changed: &[FunctionChange],
    types_added: &[String],
    types_removed: &[String],
    types_changed: &[TypeChange],
    events_added: &[String],
    events_removed: &[String],
    events_changed: &[EventChange],
) -> Compatibility {
    let has_breaking = !fns_removed.is_empty()
        || !types_removed.is_empty()
        || !events_removed.is_empty()
        || fns_changed.iter().any(|c| c.breaking)
        || types_changed.iter().any(|c| c.breaking)
        || events_changed.iter().any(|c| c.breaking);

    if has_breaking {
        return Compatibility::Breaking;
    }

    // Any uncertain change forces an `unknown` verdict — never guess.
    if types_changed.iter().any(|c| c.uncertain) {
        return Compatibility::Unknown;
    }

    let has_any_change = !fns_added.is_empty()
        || !types_added.is_empty()
        || !events_added.is_empty()
        || !fns_changed.is_empty()
        || !types_changed.is_empty()
        || !events_changed.is_empty();

    if has_any_change {
        Compatibility::NonBreaking
    } else {
        Compatibility::Identical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soroban::{SpecField, SpecInput};

    fn fn_spec(name: &str, params: Vec<(&str, &str)>, outputs: Vec<&str>) -> SpecFunction {
        SpecFunction {
            name: name.to_string(),
            inputs: params
                .into_iter()
                .map(|(n, t)| SpecInput {
                    name: n.to_string(),
                    type_: t.to_string(),
                })
                .collect(),
            outputs: outputs.into_iter().map(String::from).collect(),
            doc: String::new(),
        }
    }

    fn spec(fns: Vec<SpecFunction>, types: Vec<SpecType>, events: Vec<SpecEvent>) -> SpecReport {
        SpecReport {
            functions: fns,
            types,
            events,
        }
    }

    fn udt(name: &str, kind: &str) -> SpecType {
        SpecType {
            kind: kind.to_string(),
            name: name.to_string(),
            fields: Vec::new(),
            cases: Vec::new(),
        }
    }

    fn struct_with_fields(name: &str, fields: Vec<(&str, &str)>) -> SpecType {
        SpecType {
            kind: "struct".to_string(),
            name: name.to_string(),
            fields: fields
                .into_iter()
                .map(|(n, t)| SpecField {
                    name: n.to_string(),
                    type_: t.to_string(),
                })
                .collect(),
            cases: Vec::new(),
        }
    }

    fn enum_with_cases(name: &str, cases: Vec<&str>) -> SpecType {
        SpecType {
            kind: "enum".to_string(),
            name: name.to_string(),
            fields: Vec::new(),
            cases: cases
                .into_iter()
                .enumerate()
                .map(|(i, n)| crate::soroban::SpecCase {
                    name: n.to_string(),
                    kind: "enum".to_string(),
                    payload: Vec::new(),
                    value: Some(i as u32),
                })
                .collect(),
        }
    }

    fn event(name: &str, topics: Vec<&str>, params: Vec<(&str, &str, &str)>) -> SpecEvent {
        SpecEvent {
            name: name.to_string(),
            prefix_topics: topics.into_iter().map(String::from).collect(),
            params: params
                .into_iter()
                .map(|(n, t, loc)| crate::soroban::SpecEventParam {
                    name: n.to_string(),
                    type_: t.to_string(),
                    location: loc.to_string(),
                })
                .collect(),
            data_format: "single_value".to_string(),
        }
    }

    #[test]
    fn identical_specs_are_identical() {
        let a = spec(
            vec![fn_spec(
                "hello",
                vec![("to", "String")],
                vec!["Vec<String>"],
            )],
            vec![],
            vec![],
        );
        let b = spec(
            vec![fn_spec(
                "hello",
                vec![("to", "String")],
                vec!["Vec<String>"],
            )],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Identical);
        assert!(d.functions_changed.is_empty());
    }

    #[test]
    fn added_function_is_non_breaking() {
        let a = spec(vec![fn_spec("hello", vec![], vec![])], vec![], vec![]);
        let b = spec(
            vec![
                fn_spec("hello", vec![], vec![]),
                fn_spec("goodbye", vec![], vec![]),
            ],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.functions_added, vec!["goodbye"]);
    }

    #[test]
    fn removed_function_is_breaking() {
        let a = spec(
            vec![
                fn_spec("hello", vec![], vec![]),
                fn_spec("goodbye", vec![], vec![]),
            ],
            vec![],
            vec![],
        );
        let b = spec(vec![fn_spec("hello", vec![], vec![])], vec![], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.functions_removed, vec!["goodbye"]);
    }

    #[test]
    fn param_type_change_is_breaking() {
        let a = spec(
            vec![fn_spec("hello", vec![("to", "String")], vec![])],
            vec![],
            vec![],
        );
        let b = spec(
            vec![fn_spec("hello", vec![("to", "Symbol")], vec![])],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.functions_changed.len(), 1);
        assert!(d.functions_changed[0].breaking);
    }

    #[test]
    fn multiple_param_type_changes_are_all_reported() {
        // Previously the loop `break`ed after the first type change, so a second
        // broken parameter was invisible to the caller.
        let a = spec(
            vec![fn_spec(
                "transfer",
                vec![("from", "Address"), ("to", "Address"), ("amount", "I128")],
                vec![],
            )],
            vec![],
            vec![],
        );
        let b = spec(
            vec![fn_spec(
                "transfer",
                vec![("from", "Address"), ("to", "U64"), ("amount", "U64")],
                vec![],
            )],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        let type_changes: Vec<&FunctionChange> = d
            .functions_changed
            .iter()
            .filter(|c| c.detail.starts_with("param type changed"))
            .collect();
        assert_eq!(
            type_changes.len(),
            2,
            "both parameter type changes must be reported: {:?}",
            d.functions_changed
        );
        assert!(type_changes.iter().all(|c| c.breaking));
        assert!(
            type_changes
                .iter()
                .any(|c| c.detail.contains("to Address -> to U64")),
            "second parameter change must be present: {:?}",
            d.functions_changed
        );
        assert!(
            type_changes
                .iter()
                .any(|c| c.detail.contains("amount I128 -> amount U64")),
            "third parameter change must be present: {:?}",
            d.functions_changed
        );
    }

    #[test]
    fn param_with_type_and_name_change_reports_once() {
        // When a param changes both name and type it must surface as a single
        // breaking type-change entry (the `else if` prevents a redundant
        // non-breaking rename entry for the same parameter).
        let a = spec(
            vec![fn_spec("f", vec![("a", "U32")], vec![])],
            vec![],
            vec![],
        );
        let b = spec(
            vec![fn_spec("f", vec![("b", "U64")], vec![])],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(
            d.functions_changed.len(),
            1,
            "a single param changing name+type must produce exactly one change"
        );
        assert_eq!(
            d.functions_changed[0].detail,
            "param type changed: a U32 -> b U64"
        );
        assert!(d.functions_changed[0].breaking);
    }

    #[test]
    fn param_count_change_is_breaking() {
        let a = spec(
            vec![fn_spec("f", vec![("a", "U32")], vec![])],
            vec![],
            vec![],
        );
        let b = spec(
            vec![fn_spec("f", vec![("a", "U32"), ("b", "U32")], vec![])],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn return_type_change_is_breaking() {
        let a = spec(vec![fn_spec("f", vec![], vec!["U32"])], vec![], vec![]);
        let b = spec(vec![fn_spec("f", vec![], vec!["U64"])], vec![], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn param_rename_is_non_breaking() {
        let a = spec(
            vec![fn_spec("f", vec![("a", "U32")], vec![])],
            vec![],
            vec![],
        );
        let b = spec(
            vec![fn_spec("f", vec![("b", "U32")], vec![])],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.functions_changed.len(), 1);
        assert!(!d.functions_changed[0].breaking);
    }

    #[test]
    fn removed_type_is_breaking() {
        let a = spec(vec![], vec![udt("MyStruct", "struct")], vec![]);
        let b = spec(vec![], vec![], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.types_removed, vec!["MyStruct"]);
    }

    #[test]
    fn added_type_is_non_breaking() {
        let a = spec(vec![], vec![], vec![]);
        let b = spec(vec![], vec![udt("NewStruct", "struct")], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.types_added, vec!["NewStruct"]);
    }

    // --- UDT field changes ---

    #[test]
    fn multiple_struct_field_type_changes_are_all_reported() {
        // Every changed struct field must be reported, not just the first.
        let a = spec(
            vec![],
            vec![struct_with_fields(
                "Config",
                vec![("owner", "Address"), ("fee", "U32"), ("active", "Bool")],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![struct_with_fields(
                "Config",
                vec![("owner", "Address"), ("fee", "U64"), ("active", "I32")],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        let field_changes: Vec<&TypeChange> = d
            .types_changed
            .iter()
            .filter(|c| c.detail.contains("type changed"))
            .collect();
        assert_eq!(
            field_changes.len(),
            2,
            "both struct field type changes must be reported: {:?}",
            d.types_changed
        );
        assert!(field_changes.iter().all(|c| c.breaking));
        assert!(
            field_changes
                .iter()
                .any(|c| c.detail.contains("field 'fee' type changed: U32 -> U64")),
            "second field change missing: {:?}",
            d.types_changed
        );
        assert!(
            field_changes.iter().any(|c| c
                .detail
                .contains("field 'active' type changed: Bool -> I32")),
            "third field change missing: {:?}",
            d.types_changed
        );
    }

    #[test]
    fn unchanged_struct_fields_produce_no_changes() {
        // Identical structs must not produce any type change entries.
        let mk = || struct_with_fields("Config", vec![("owner", "Address"), ("fee", "U32")]);
        let d = diff_specs(
            &spec(vec![], vec![mk()], vec![]),
            &spec(vec![], vec![mk()], vec![]),
        );
        assert!(
            d.types_changed.is_empty(),
            "identical struct fields must not report changes: {:?}",
            d.types_changed
        );
    }

    #[test]
    fn struct_field_added_is_breaking() {
        let a = spec(
            vec![],
            vec![struct_with_fields("Config", vec![("owner", "Address")])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![struct_with_fields(
                "Config",
                vec![("owner", "Address"), ("fee", "U32")],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.types_changed.len(), 1);
        assert!(d.types_changed[0].breaking);
        assert!(d.types_changed[0].detail.contains("added"));
    }

    #[test]
    fn struct_field_removed_is_breaking() {
        let a = spec(
            vec![],
            vec![struct_with_fields(
                "Config",
                vec![("owner", "Address"), ("fee", "U32")],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![struct_with_fields("Config", vec![("owner", "Address")])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.types_changed.len(), 1);
        assert!(d.types_changed[0].detail.contains("removed"));
    }

    #[test]
    fn struct_field_type_changed_is_breaking() {
        let a = spec(
            vec![],
            vec![struct_with_fields("Config", vec![("fee", "U32")])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![struct_with_fields("Config", vec![("fee", "U64")])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.types_changed.len(), 1);
        assert!(d.types_changed[0].detail.contains("type changed"));
    }

    // --- Enum variant changes ---

    #[test]
    fn enum_variant_added_is_non_breaking() {
        let a = spec(
            vec![],
            vec![enum_with_cases("Status", vec!["Pending", "Active"])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![enum_with_cases(
                "Status",
                vec!["Pending", "Active", "Suspended"],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.types_changed.len(), 1);
        assert!(!d.types_changed[0].breaking);
    }

    #[test]
    fn enum_variant_removed_is_breaking() {
        let a = spec(
            vec![],
            vec![enum_with_cases(
                "Status",
                vec!["Pending", "Active", "Suspended"],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![enum_with_cases("Status", vec!["Pending", "Active"])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.types_changed.len(), 1);
        assert!(d.types_changed[0].breaking);
    }

    // --- Event changes ---

    #[test]
    fn event_added_is_non_breaking() {
        let a = spec(vec![], vec![], vec![]);
        let b = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("from", "Address", "data")])],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.events_added, vec!["Transfer"]);
    }

    #[test]
    fn event_removed_is_breaking() {
        let a = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("from", "Address", "data")])],
        );
        let b = spec(vec![], vec![], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.events_removed, vec!["Transfer"]);
    }

    #[test]
    fn event_param_type_changed_is_breaking() {
        let a = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("amount", "U32", "data")])],
        );
        let b = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("amount", "U64", "data")])],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.events_changed.len(), 1);
        assert!(d.events_changed[0].breaking);
    }

    #[test]
    fn multiple_event_param_type_changes_are_all_reported() {
        // Each mismatched event param must surface as its own breaking change,
        // with param count and data_format held constant.
        let a = spec(
            vec![],
            vec![],
            vec![event(
                "Transfer",
                vec![],
                vec![
                    ("from", "Address", "data"),
                    ("to", "Address", "data"),
                    ("amount", "I128", "data"),
                ],
            )],
        );
        let b = spec(
            vec![],
            vec![],
            vec![event(
                "Transfer",
                vec![],
                vec![
                    ("from", "Address", "data"),
                    ("to", "U64", "data"),
                    ("amount", "U64", "data"),
                ],
            )],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        let type_changes: Vec<&EventChange> = d
            .events_changed
            .iter()
            .filter(|c| c.detail.contains("type changed"))
            .collect();
        assert_eq!(
            type_changes.len(),
            2,
            "both event param type changes must be reported: {:?}",
            d.events_changed
        );
        assert!(type_changes.iter().all(|c| c.breaking));
        assert!(
            type_changes
                .iter()
                .any(|c| c.detail.contains("param 'to' type changed: Address -> U64")),
            "second param change missing: {:?}",
            d.events_changed
        );
        assert!(
            type_changes.iter().any(|c| c
                .detail
                .contains("param 'amount' type changed: I128 -> U64")),
            "third param change missing: {:?}",
            d.events_changed
        );
    }

    #[test]
    fn unchanged_event_params_produce_no_changes() {
        // Identical event params (same names, types, locations, count) must not
        // produce any event change entries.
        let mk = || {
            event(
                "Transfer",
                vec!["transfer"],
                vec![("from", "Address", "topic"), ("to", "Address", "data")],
            )
        };
        let d = diff_specs(
            &spec(vec![], vec![], vec![mk()]),
            &spec(vec![], vec![], vec![mk()]),
        );
        assert!(
            d.events_changed.is_empty(),
            "identical event params must not report changes: {:?}",
            d.events_changed
        );
    }

    #[test]
    fn event_param_added_is_breaking() {
        let a = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("from", "Address", "data")])],
        );
        let b = spec(
            vec![],
            vec![],
            vec![event(
                "Transfer",
                vec![],
                vec![("from", "Address", "data"), ("to", "Address", "data")],
            )],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn event_param_removed_is_breaking() {
        let a = spec(
            vec![],
            vec![],
            vec![event(
                "Transfer",
                vec![],
                vec![("from", "Address", "data"), ("to", "Address", "data")],
            )],
        );
        let b = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("from", "Address", "data")])],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn event_topic_list_changed_is_breaking() {
        let a = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("amount", "U64", "data")])],
        );
        let b = spec(
            vec![],
            vec![],
            vec![event(
                "Transfer",
                vec!["from"],
                vec![("amount", "U64", "data")],
            )],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn event_identical_is_identical() {
        let e = event("Transfer", vec![], vec![("amount", "U64", "data")]);
        let a = spec(vec![], vec![], vec![e.clone()]);
        let b = spec(vec![], vec![], vec![e]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Identical);
    }

    // --- Regressions: prior docs contradicted the implementation ---

    #[test]
    fn struct_field_rename_is_breaking() {
        let a = spec(
            vec![],
            vec![struct_with_fields("Config", vec![("owner", "Address")])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![struct_with_fields("Config", vec![("admin", "Address")])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        let details: Vec<&str> = d.types_changed.iter().map(|c| c.detail.as_str()).collect();
        assert!(details.iter().any(|s| s.contains("'owner' removed")));
        assert!(details.iter().any(|s| s.contains("'admin' added")));
        assert!(d.types_changed.iter().all(|c| c.breaking));
    }

    #[test]
    fn event_param_rename_is_breaking() {
        let a = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("from", "Address", "data")])],
        );
        let b = spec(
            vec![],
            vec![],
            vec![event(
                "Transfer",
                vec![],
                vec![("sender", "Address", "data")],
            )],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        // A rename must never surface as a non-breaking "param renamed" entry.
        assert!(d
            .events_changed
            .iter()
            .all(|c| !c.detail.contains("param renamed")));
        assert!(d.events_changed.iter().any(|c| c.breaking));
    }

    #[test]
    fn event_param_location_change_is_breaking() {
        let a = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("amount", "U64", "data")])],
        );
        let b = spec(
            vec![],
            vec![],
            vec![event("Transfer", vec![], vec![("amount", "U64", "topic")])],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d
            .events_changed
            .iter()
            .any(|c| c.detail.contains("location changed")));
    }

    #[test]
    fn udt_kind_change_is_breaking() {
        let a = spec(vec![], vec![udt("Thing", "struct")], vec![]);
        let b = spec(vec![], vec![udt("Thing", "enum")], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d
            .types_changed
            .iter()
            .any(|c| c.detail.contains("type kind changed")));
    }

    #[test]
    fn unaffected_by_order_of_declaration() {
        let a = spec(
            vec![fn_spec("a", vec![], vec![]), fn_spec("b", vec![], vec![])],
            vec![],
            vec![],
        );
        let b = spec(
            vec![fn_spec("b", vec![], vec![]), fn_spec("a", vec![], vec![])],
            vec![],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Identical);
    }

    // --- ABI blind-spot regressions: case payload + discriminant ---

    fn union_with_cases(name: &str, cases: Vec<(&str, &str, Vec<&str>)>) -> SpecType {
        SpecType {
            kind: "union".to_string(),
            name: name.to_string(),
            fields: Vec::new(),
            cases: cases
                .into_iter()
                .map(|(n, kind, payload)| crate::soroban::SpecCase {
                    name: n.to_string(),
                    kind: kind.to_string(),
                    payload: payload.into_iter().map(String::from).collect(),
                    value: None,
                })
                .collect(),
        }
    }

    #[test]
    fn multiple_variant_payload_changes_are_all_reported() {
        // Two surviving variants both changing payload type must each produce
        // their own breaking change entry.
        let a = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![
                    ("Circle", "tuple", vec!["U32"]),
                    ("Rect", "tuple", vec!["U32", "U32"]),
                ],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![
                    ("Circle", "tuple", vec!["U64"]),
                    ("Rect", "tuple", vec!["U64", "U64"]),
                ],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        let payload_changes: Vec<&TypeChange> = d
            .types_changed
            .iter()
            .filter(|c| c.detail.contains("payload changed"))
            .collect();
        assert_eq!(
            payload_changes.len(),
            2,
            "both variant payload changes must be reported: {:?}",
            d.types_changed
        );
        assert!(payload_changes.iter().all(|c| c.breaking));
        assert!(
            payload_changes
                .iter()
                .any(|c| c.detail.contains("variant 'Circle' payload changed")),
            "first variant payload change missing: {:?}",
            d.types_changed
        );
        assert!(
            payload_changes
                .iter()
                .any(|c| c.detail.contains("variant 'Rect' payload changed")),
            "second variant payload change missing: {:?}",
            d.types_changed
        );
    }

    #[test]
    fn union_case_void_to_tuple_kind_change_is_breaking() {
        // A surviving case whose shape changes void -> tuple must be reported
        // as breaking.
        let a = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Unit", "void", vec![]), ("Circle", "tuple", vec!["U32"])],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![
                    ("Unit", "tuple", vec!["U32"]),
                    ("Circle", "tuple", vec!["U32"]),
                ],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(
            d.types_changed.iter().any(|c| c
                .detail
                .contains("variant 'Unit' kind changed: void -> tuple")),
            "void -> tuple kind change must be reported: {:?}",
            d.types_changed
        );
    }

    #[test]
    fn union_variant_added_is_non_breaking() {
        // Adding a union variant is non-breaking under the documented policy:
        // existing code matching the old variants keeps working.
        let a = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Circle", "tuple", vec!["U32"])],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![
                    ("Circle", "tuple", vec!["U32"]),
                    ("Rect", "tuple", vec!["U32", "U32"]),
                ],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.types_changed.len(), 1);
        assert!(!d.types_changed[0].breaking);
    }

    #[test]
    fn tuple_case_payload_type_change_is_breaking() {
        let a = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Circle", "tuple", vec!["U32"])],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Circle", "tuple", vec!["U64"])],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        // The blind spot: identical case names, different payload types.
        assert_ne!(d.compatibility, Compatibility::Identical);
        assert_ne!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d
            .types_changed
            .iter()
            .any(|c| c.detail.contains("payload changed")));
    }

    #[test]
    fn tuple_case_payload_arity_change_is_breaking() {
        let a = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Pair", "tuple", vec!["U32"])],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Pair", "tuple", vec!["U32", "U64"])],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d
            .types_changed
            .iter()
            .any(|c| c.detail.contains("payload changed")));
    }

    #[test]
    fn void_to_tuple_case_kind_change_is_breaking() {
        let a = spec(
            vec![],
            vec![union_with_cases("Shape", vec![("Unit", "void", vec![])])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Unit", "tuple", vec!["U32"])],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d
            .types_changed
            .iter()
            .any(|c| c.detail.contains("kind changed")));
    }

    fn enum_with_values(name: &str, cases: Vec<(&str, u32)>) -> SpecType {
        SpecType {
            kind: "enum".to_string(),
            name: name.to_string(),
            fields: Vec::new(),
            cases: cases
                .into_iter()
                .map(|(n, v)| crate::soroban::SpecCase {
                    name: n.to_string(),
                    kind: "enum".to_string(),
                    payload: Vec::new(),
                    value: Some(v),
                })
                .collect(),
        }
    }

    #[test]
    fn enum_discriminant_change_is_breaking() {
        let a = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 0), ("B", 1)])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 5), ("B", 1)])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        // Blind spot: same names, different discriminants.
        assert_ne!(d.compatibility, Compatibility::Identical);
        assert_ne!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d
            .types_changed
            .iter()
            .any(|c| c.detail.contains("discriminant changed")));
    }

    #[test]
    fn enum_discriminant_reorder_is_breaking() {
        let a = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 0), ("B", 1)])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 1), ("B", 0)])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(
            d.types_changed
                .iter()
                .filter(|c| c.detail.contains("discriminant changed"))
                .count(),
            2
        );
    }

    #[test]
    fn identical_case_payload_and_discriminant_is_identical() {
        let a = spec(
            vec![],
            vec![
                union_with_cases("Shape", vec![("Circle", "tuple", vec!["U32"])]),
                enum_with_values("Kind", vec![("A", 0), ("B", 1)]),
            ],
            vec![],
        );
        let b = a_spec_clone();
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Identical);
    }

    fn a_spec_clone() -> SpecReport {
        spec(
            vec![],
            vec![
                union_with_cases("Shape", vec![("Circle", "tuple", vec!["U32"])]),
                enum_with_values("Kind", vec![("A", 0), ("B", 1)]),
            ],
            vec![],
        )
    }

    #[test]
    fn union_case_removed_reports_label_without_payload_noise() {
        let a = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Circle", "tuple", vec!["U32"]), ("Unit", "void", vec![])],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Circle", "tuple", vec!["U32"])],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d
            .types_changed
            .iter()
            .any(|c| c.detail.contains("variant 'Void(Unit)' removed")));
    }

    #[test]
    fn enum_case_added_applies_discriminant_without_breaking() {
        let a = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 0)])],
            vec![],
        );
        let b = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 0), ("B", 1)])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert!(d
            .types_changed
            .iter()
            .filter(|c| c.detail.contains("added"))
            .all(|c| !c.breaking));
    }

    #[test]
    fn discriminant_present_on_only_one_side_is_unknown() {
        // Old side carries a discriminant, new side does not (or vice versa):
        // the specs are not comparable on this field, so the verdict must be
        // `unknown` rather than a guessed `identical`/`non-breaking`.
        let a = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 0)])],
            vec![],
        );
        let mut b_ty = enum_with_values("Kind", vec![("A", 0)]);
        b_ty.cases[0].value = None;
        let b = spec(vec![], vec![b_ty], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Unknown);
        assert!(d.types_changed.iter().any(|c| c.uncertain));
        assert!(d.types_changed.iter().all(|c| !c.breaking));
    }

    #[test]
    fn uncertain_outranks_non_breaking_addition() {
        // A mixed spec — an uncertain discriminant change plus a non-breaking
        // addition — must yield `unknown`, never `non-breaking`. Precedence:
        // Breaking > Unknown > NonBreaking > Identical.
        let a = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 0)])],
            vec![],
        );
        let mut b_ty = enum_with_values("Kind", vec![("A", 0)]);
        b_ty.cases[0].value = None;
        let b = spec(vec![], vec![b_ty, udt("Extra", "struct")], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Unknown);
        assert!(d.types_changed.iter().any(|c| c.uncertain));
        assert_eq!(d.types_added, vec!["Extra"]);
    }

    #[test]
    fn breaking_outranks_uncertain() {
        // A definite breaking change is reported even when an uncertain change
        // is present alongside it.
        let a = spec(
            vec![],
            vec![enum_with_values("Kind", vec![("A", 0), ("B", 1)])],
            vec![],
        );
        let mut b_ty = enum_with_values("Kind", vec![("A", 9), ("B", 1)]);
        b_ty.cases[1].value = None;
        let b = spec(vec![], vec![b_ty], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert!(d.types_changed.iter().any(|c| c.uncertain));
    }

    #[test]
    fn unknown_is_not_reported_as_compatible() {
        let a = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Circle", "tuple", vec!["U32"])],
            )],
            vec![],
        );
        let b = spec(
            vec![],
            vec![union_with_cases(
                "Shape",
                vec![("Circle", "tuple", vec!["U64"])],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_ne!(d.compatibility, Compatibility::Unknown);
        assert_ne!(d.compatibility, Compatibility::NonBreaking);
        assert_ne!(d.compatibility, Compatibility::Identical);
    }
}
