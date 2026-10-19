//! Contract-spec compatibility diff.
//!
//! Compares two decoded contract specs and classifies each difference as
//! breaking, non-breaking, or uncertain. Rules are documented below.
//!
//! Compatibility is only ever assessed when BOTH specs decode successfully.
//! If either side fails to decode, the verdict is `unknown` — never a guess.

use crate::soroban::{SpecFunction, SpecReport, SpecType};
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
/// Rules:
/// - Function removed → breaking.
/// - Function added → non-breaking.
/// - Param count changed → breaking.
/// - Param type changed → breaking.
/// - Param name changed → non-breaking (positional).
/// - Return type changed → breaking.
/// - Type (UDT) removed → breaking (may be referenced by a function).
/// - Type added → non-breaking.
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
                if let Some(change) = compare_functions(old_f, new_f) {
                    functions_changed.push(change);
                }
            }
        }
    }

    let old_types: BTreeMap<&str, &SpecType> =
        old.types.iter().map(|t| (t.name.as_str(), t)).collect();
    let new_types: BTreeMap<&str, &SpecType> =
        new.types.iter().map(|t| (t.name.as_str(), t)).collect();

    let mut types_added = Vec::new();
    let mut types_removed = Vec::new();
    for name in new_types.keys() {
        if !old_types.contains_key(name) {
            types_added.push((*name).to_string());
        }
    }
    for name in old_types.keys() {
        if !new_types.contains_key(name) {
            types_removed.push((*name).to_string());
        }
    }

    let compatibility = classify(
        &functions_added,
        &functions_removed,
        &functions_changed,
        &types_added,
        &types_removed,
    );

    functions_added.sort();
    functions_removed.sort();
    types_added.sort();
    types_removed.sort();

    SpecDiff {
        functions_added,
        functions_removed,
        functions_changed,
        types_added,
        types_removed,
        compatibility,
    }
}

fn compare_functions(old: &SpecFunction, new: &SpecFunction) -> Option<FunctionChange> {
    // Param count change → breaking.
    if old.inputs.len() != new.inputs.len() {
        return Some(FunctionChange {
            name: old.name.clone(),
            detail: format!(
                "param count changed: {} -> {}",
                old.inputs.len(),
                new.inputs.len()
            ),
            breaking: true,
        });
    }

    // Per-param type change → breaking. Name change alone → non-breaking.
    for (oi, ni) in old.inputs.iter().zip(new.inputs.iter()) {
        if oi.type_ != ni.type_ {
            return Some(FunctionChange {
                name: old.name.clone(),
                detail: format!(
                    "param type changed: {} {} -> {} {}",
                    oi.name, oi.type_, ni.name, ni.type_
                ),
                breaking: true,
            });
        }
        if oi.name != ni.name {
            return Some(FunctionChange {
                name: old.name.clone(),
                detail: format!("param renamed: {} -> {}", oi.name, ni.name),
                breaking: false,
            });
        }
    }

    // Return type change → breaking.
    if old.outputs != new.outputs {
        return Some(FunctionChange {
            name: old.name.clone(),
            detail: format!(
                "return type changed: {:?} -> {:?}",
                old.outputs, new.outputs
            ),
            breaking: true,
        });
    }

    None
}

fn classify(
    fns_added: &[String],
    fns_removed: &[String],
    fns_changed: &[FunctionChange],
    types_added: &[String],
    types_removed: &[String],
) -> Compatibility {
    let has_breaking = !fns_removed.is_empty()
        || !types_removed.is_empty()
        || fns_changed.iter().any(|c| c.breaking);

    if has_breaking {
        return Compatibility::Breaking;
    }

    let has_any_change =
        !fns_added.is_empty() || !types_added.is_empty() || !fns_changed.is_empty();

    if has_any_change {
        Compatibility::NonBreaking
    } else {
        Compatibility::Identical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soroban::{SpecInput, SpecType};

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

    fn spec(fns: Vec<SpecFunction>, types: Vec<SpecType>) -> SpecReport {
        SpecReport {
            functions: fns,
            types,
        }
    }

    fn udt(name: &str, kind: &str) -> SpecType {
        SpecType {
            kind: kind.to_string(),
            name: name.to_string(),
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
        );
        let b = spec(
            vec![fn_spec(
                "hello",
                vec![("to", "String")],
                vec!["Vec<String>"],
            )],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Identical);
        assert!(d.functions_changed.is_empty());
    }

    #[test]
    fn added_function_is_non_breaking() {
        let a = spec(vec![fn_spec("hello", vec![], vec![])], vec![]);
        let b = spec(
            vec![
                fn_spec("hello", vec![], vec![]),
                fn_spec("goodbye", vec![], vec![]),
            ],
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
        );
        let b = spec(vec![fn_spec("hello", vec![], vec![])], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.functions_removed, vec!["goodbye"]);
    }

    #[test]
    fn param_type_change_is_breaking() {
        let a = spec(
            vec![fn_spec("hello", vec![("to", "String")], vec![])],
            vec![],
        );
        let b = spec(
            vec![fn_spec("hello", vec![("to", "Symbol")], vec![])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.functions_changed.len(), 1);
        assert!(d.functions_changed[0].breaking);
    }

    #[test]
    fn param_count_change_is_breaking() {
        let a = spec(vec![fn_spec("f", vec![("a", "U32")], vec![])], vec![]);
        let b = spec(
            vec![fn_spec("f", vec![("a", "U32"), ("b", "U32")], vec![])],
            vec![],
        );
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn return_type_change_is_breaking() {
        let a = spec(vec![fn_spec("f", vec![], vec!["U32"])], vec![]);
        let b = spec(vec![fn_spec("f", vec![], vec!["U64"])], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn param_rename_is_non_breaking() {
        let a = spec(vec![fn_spec("f", vec![("a", "U32")], vec![])], vec![]);
        let b = spec(vec![fn_spec("f", vec![("b", "U32")], vec![])], vec![]);
        let d = diff_specs(&a, &b);
        // Positional callers unaffected.
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.functions_changed.len(), 1);
        assert!(!d.functions_changed[0].breaking);
    }

    #[test]
    fn removed_type_is_breaking() {
        let a = spec(vec![], vec![udt("MyStruct", "struct")]);
        let b = spec(vec![], vec![]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::Breaking);
        assert_eq!(d.types_removed, vec!["MyStruct"]);
    }

    #[test]
    fn added_type_is_non_breaking() {
        let a = spec(vec![], vec![]);
        let b = spec(vec![], vec![udt("NewStruct", "struct")]);
        let d = diff_specs(&a, &b);
        assert_eq!(d.compatibility, Compatibility::NonBreaking);
        assert_eq!(d.types_added, vec!["NewStruct"]);
    }
}
