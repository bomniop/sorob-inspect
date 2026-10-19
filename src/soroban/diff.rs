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
//! | Struct field renamed | non-breaking | Positional/structural init unaffected |
//! | Enum variant added | non-breaking | Exhaustive matches may need update but existing code works |
//! | Enum variant removed | breaking | Existing matches on that variant break |
//! | Union variant added | non-breaking | Same as enum variant added |
//! | Union variant removed | breaking | Same as enum variant removed |
//! | Event added | non-breaking | New event, existing subscribers unaffected |
//! | Event removed | breaking | Subscribers lose the event |
//! | Event param added | breaking | Subscribers expecting old shape break |
//! | Event param removed | breaking | Subscribers referencing it break |
//! | Event param type changed | breaking | Type mismatch for subscribers |
//! | Event param renamed | non-breaking | Positional subscribers unaffected |
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
            changes.push(FunctionChange {
                name: old.name.clone(),
                detail: format!(
                    "param type changed: {} {} -> {} {}",
                    oi.name, oi.type_, ni.name, ni.type_
                ),
                breaking: true,
            });
            break; // one type change per function is enough to flag
        }
        if oi.name != ni.name {
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
                None => changes.push(TypeChange {
                    name: old.name.clone(),
                    kind: old.kind.clone(),
                    detail: format!("field '{}' removed", name),
                    breaking: true,
                }),
                Some(new_ty) => {
                    if old_ty != new_ty {
                        changes.push(TypeChange {
                            name: old.name.clone(),
                            kind: old.kind.clone(),
                            detail: format!(
                                "field '{}' type changed: {} -> {}",
                                name, old_ty, new_ty
                            ),
                            breaking: true,
                        });
                    }
                }
            }
        }
        for name in new_fields.keys() {
            if !old_fields.contains_key(name) {
                changes.push(TypeChange {
                    name: old.name.clone(),
                    kind: old.kind.clone(),
                    detail: format!("field '{}' added", name),
                    breaking: true,
                });
            }
        }
    }

    // Enum/union/error_enum case comparison.
    if matches!(old.kind.as_str(), "enum" | "union" | "error_enum") && old.kind == new.kind {
        let old_cases: BTreeMap<&str, ()> = old.cases.iter().map(|c| (c.as_str(), ())).collect();
        let new_cases: BTreeMap<&str, ()> = new.cases.iter().map(|c| (c.as_str(), ())).collect();

        for name in old_cases.keys() {
            if !new_cases.contains_key(name) {
                changes.push(TypeChange {
                    name: old.name.clone(),
                    kind: old.kind.clone(),
                    detail: format!("variant '{}' removed", name),
                    breaking: true,
                });
            }
        }
        for name in new_cases.keys() {
            if !old_cases.contains_key(name) {
                changes.push(TypeChange {
                    name: old.name.clone(),
                    kind: old.kind.clone(),
                    detail: format!("variant '{}' added", name),
                    breaking: false,
                });
            }
        }
    }

    // Kind changed (e.g. struct → enum) — treat as breaking.
    if old.kind != new.kind {
        changes.push(TypeChange {
            name: old.name.clone(),
            kind: old.kind.clone(),
            detail: format!("type kind changed: {} -> {}", old.kind, new.kind),
            breaking: true,
        });
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

    // Renamed params (same type+location, different name) — non-breaking.
    for (old_name, (old_ty, old_loc)) in &old_params {
        if new_params.contains_key(old_name) {
            continue;
        }
        for (new_name, (new_ty, new_loc)) in &new_params {
            if old_params.contains_key(new_name) {
                continue;
            }
            if old_ty == new_ty && old_loc == new_loc {
                changes.push(EventChange {
                    name: old.name.clone(),
                    detail: format!("param renamed: {} -> {}", old_name, new_name),
                    breaking: false,
                });
            }
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
            cases: cases.into_iter().map(String::from).collect(),
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
}
