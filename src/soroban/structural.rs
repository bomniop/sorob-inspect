//! Structural WASM export comparison, independent of contract specs.
//!
//! The spec-level diff in [`crate::soroban::diff`] compares decoded
//! `contractspecv0` contents. That is the richest view of a Soroban contract's
//! ABI, but it is only available when BOTH modules carry a decodable spec
//! section. This module covers the complementary case: the raw exported
//! symbols of the WASM module itself, which every module has.
//!
//! # Single-module observations
//!
//! [`export_findings`] derives findings from ONE module. A single module
//! establishes no baseline, so it never reports `export_added`,
//! `export_removed`, or `export_signature_changed`: those require a comparison
//! reference. What it does report is what the module itself proves — chiefly
//! an export whose description cannot be resolved. Use [`diff_exports`] when a
//! baseline exists.
//!
//! # What is compared
//!
//! Exports are keyed by **name + external kind** (`name [kind]`). A symbol
//! present on only one side is reported as added/removed. A symbol present on
//! both sides is compared by its *resolved* description:
//!
//! - **functions**: the resolved signature string (`(params) -> (results)`),
//!   already computed by `crate::wasm` from the module's type section through
//!   the full function index space. When the signature could not be resolved
//!   the export is reported as `unresolved` rather than being given an invented
//!   signature.
//! - **memories / tables / globals**: the bounds/type detail already collected
//!   by `crate::wasm`.
//!
//! Type *indices* are deliberately not compared. An index is a position in the
//! declaring module's type section, so it is not a stable semantic identifier
//! across independently compiled modules: two modules can declare the same
//! signature at different indices, or different signatures at the same index.
//! Only the resolved signature is semantically meaningful.
//!
//! # Classification
//!
//! Every change is classified with one rule, applied uniformly:
//!
//! | Change | Classification | Rationale |
//! |--------|----------------|-----------|
//! | Export added | non-breaking | New symbol; existing callers unaffected |
//! | Export removed | breaking | Existing callers lose access |
//! | Export signature/bounds changed | breaking | Callers compiled against the old shape break |
//! | Signature unresolvable | unknown | Cannot be classified without inventing a signature |
//!
//! `unknown` never silently becomes `breaking`: an unresolvable signature is a
//! limitation of the input, not evidence of a change.
//!
//! This classification is **structural only**. It is reported separately from
//! the spec-level compatibility verdict and from the environment protocol
//! assessment, and it does not feed `--fail-on-breaking`.

use crate::wasm::ExportEntry;
use serde::{Deserialize, Serialize};

/// Classification of a structural export change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuralChangeKind {
    /// New export on the new side.
    Added,
    /// Export present on the old side is gone.
    Removed,
    /// Export exists on both sides but its resolved description differs.
    Changed,
    /// Export exists on both sides but at least one signature could not be
    /// resolved, so no comparison was possible.
    Unresolved,
}

/// Compatibility classification for a structural export change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuralCompatibility {
    NonBreaking,
    Breaking,
    Unknown,
}

/// One structural export difference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralExportChange {
    /// Export name.
    pub name: String,
    /// External kind (`function`, `memory`, `table`, `global`).
    pub kind: String,
    /// What kind of change this is.
    pub change: StructuralChangeKind,
    /// Compatibility classification for this change.
    pub compatibility: StructuralCompatibility,
    /// Resolved description on the old side, when the export existed there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    /// Resolved description on the new side, when the export exists there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

/// Result of structurally comparing two modules' exports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuralExportDiff {
    /// Every difference, sorted by (name, kind) for deterministic output.
    pub changes: Vec<StructuralExportChange>,
    /// Aggregate classification across all changes.
    ///
    /// - `breaking` when any change is breaking,
    /// - `unknown` when there are no breaking changes but at least one is
    ///   unknown,
    /// - `non-breaking` when every change is an addition,
    /// - `identical` when there are no changes at all.
    pub compatibility: String,
}

/// Resolved, semantically meaningful description of an export.
///
/// Returns `None` when the export is a function whose signature could not be
/// resolved — the caller reports `unknown` rather than inventing one.
///
/// Shared by the diff comparison and by the single-module `inspect` findings,
/// so both paths resolve an export identically.
pub fn describe_export(export: &ExportEntry) -> Option<String> {
    match export.kind.as_str() {
        "function" => export.type_sig.clone(),
        "memory" => export.memory.as_ref().map(|m| {
            format!(
                "memory min={} max={} is64={} shared={}",
                m.min_pages,
                m.max_pages
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                m.is64,
                m.shared
            )
        }),
        "table" => export.table.as_ref().map(|t| {
            format!(
                "table {} min={} max={}",
                t.element_type,
                t.min_size,
                t.max_size
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            )
        }),
        "global" => export.global.as_ref().map(|g| {
            format!(
                "global {} mutable={}",
                g.value_type,
                if g.mutable { "yes" } else { "no" }
            )
        }),
        other => Some(format!("{other} (no detail collected)")),
    }
}

/// A single-module observation about the module's exported public surface.
///
/// These are facts the inspected module establishes on its own. They are NOT
/// change findings: a single module has no baseline, so nothing here asserts
/// that an export was added, removed, or modified relative to anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportObservation {
    /// Stable machine-readable code. Currently only `export_unresolvable`.
    pub code: String,
    /// Export name.
    pub name: String,
    /// External kind (`function`, `memory`, `table`, `global`).
    pub kind: String,
    /// Why the observation was raised.
    pub message: String,
}

/// Derive single-module observations from a module's exports.
///
/// The only code emitted today is `export_unresolvable`: an export whose
/// resolved description is unavailable. For a function export that means the
/// signature could not be resolved from the module's type section; for a
/// memory/table/global export it means the corresponding detail was not
/// collected.
///
/// Deliberately NOT emitted (they need a baseline that one module cannot
/// provide): `export_added`, `export_removed`, `export_signature_changed`.
/// Use [`diff_exports`] against a reference module for those.
///
/// Output is sorted by `(name, kind)` for deterministic ordering.
pub fn export_findings(exports: &[ExportEntry]) -> Vec<ExportObservation> {
    let mut out: Vec<ExportObservation> = exports
        .iter()
        .filter(|e| describe_export(e).is_none())
        .map(|e| ExportObservation {
            code: "export_unresolvable".to_string(),
            name: e.name.clone(),
            kind: e.kind.clone(),
            message: format!(
                "export '{}' [{}] has no resolvable description; \
                 signature/bounds could not be determined from this module",
                e.name, e.kind
            ),
        })
        .collect();
    out.sort_by(|a, b| (&a.name, &a.kind).cmp(&(&b.name, &b.kind)));
    out
}

/// Compare two modules' exports structurally.
///
/// Both sides are keyed by `name [kind]`, so a name reused for a different
/// external kind (e.g. `foo` as a function and later as a global) is treated as
/// two distinct symbols rather than one changed symbol.
pub fn diff_exports(old: &[ExportEntry], new: &[ExportEntry]) -> StructuralExportDiff {
    use std::collections::BTreeMap;

    let key = |e: &ExportEntry| format!("{} [{}]", e.name, e.kind);
    let index = |exports: &[ExportEntry]| -> BTreeMap<String, ExportEntry> {
        exports.iter().cloned().map(|e| (key(&e), e)).collect()
    };

    let old_map = index(old);
    let new_map = index(new);

    let mut changes = Vec::new();

    for (k, old_export) in old_map.iter() {
        let Some(new_export) = new_map.get(k) else {
            changes.push(StructuralExportChange {
                name: old_export.name.clone(),
                kind: old_export.kind.clone(),
                change: StructuralChangeKind::Removed,
                compatibility: StructuralCompatibility::Breaking,
                old: describe_export(old_export),
                new: None,
            });
            continue;
        };

        let old_desc = describe_export(old_export);
        let new_desc = describe_export(new_export);
        let (change, compatibility) = match (&old_desc, &new_desc) {
            (Some(o), Some(n)) if o == n => continue,
            (Some(o), Some(n)) => {
                let _ = (o, n);
                (
                    StructuralChangeKind::Changed,
                    StructuralCompatibility::Breaking,
                )
            }
            _ => (
                StructuralChangeKind::Unresolved,
                StructuralCompatibility::Unknown,
            ),
        };
        changes.push(StructuralExportChange {
            name: old_export.name.clone(),
            kind: old_export.kind.clone(),
            change,
            compatibility,
            old: old_desc,
            new: new_desc,
        });
    }

    for (k, new_export) in new_map.iter() {
        if old_map.contains_key(k) {
            continue;
        }
        changes.push(StructuralExportChange {
            name: new_export.name.clone(),
            kind: new_export.kind.clone(),
            change: StructuralChangeKind::Added,
            compatibility: StructuralCompatibility::NonBreaking,
            old: None,
            new: describe_export(new_export),
        });
    }

    changes.sort_by(|a, b| (&a.name, &a.kind).cmp(&(&b.name, &b.kind)));

    let compatibility = if changes.is_empty() {
        "identical"
    } else if changes
        .iter()
        .any(|c| c.compatibility == StructuralCompatibility::Breaking)
    {
        "breaking"
    } else if changes
        .iter()
        .any(|c| c.compatibility == StructuralCompatibility::Unknown)
    {
        "unknown"
    } else {
        "non-breaking"
    }
    .to_string();

    StructuralExportDiff {
        changes,
        compatibility,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::{ExportEntry, GlobalEntry, MemoryBounds, TableBounds};

    fn func(name: &str, sig: Option<&str>, type_index: Option<u32>) -> ExportEntry {
        ExportEntry {
            name: name.to_string(),
            kind: "function".to_string(),
            index: 0,
            type_sig: sig.map(|s| s.to_string()),
            type_index,
            memory: None,
            table: None,
            global: None,
        }
    }

    fn mem(name: &str, min: u64, max: Option<u64>) -> ExportEntry {
        ExportEntry {
            name: name.to_string(),
            kind: "memory".to_string(),
            index: 0,
            type_sig: None,
            type_index: None,
            memory: Some(MemoryBounds {
                min_pages: min,
                max_pages: max,
                is64: false,
                shared: false,
            }),
            table: None,
            global: None,
        }
    }

    fn glob(name: &str, value_type: &str, mutable: bool) -> ExportEntry {
        ExportEntry {
            name: name.to_string(),
            kind: "global".to_string(),
            index: 0,
            type_sig: None,
            type_index: None,
            memory: None,
            table: None,
            global: Some(GlobalEntry {
                mutable,
                value_type: value_type.to_string(),
            }),
        }
    }

    #[test]
    fn identical_exports_produce_no_changes() {
        let a = vec![func("hello", Some("(i32) -> ()"), Some(0))];
        let b = vec![func("hello", Some("(i32) -> ()"), Some(0))];
        let d = diff_exports(&a, &b);
        assert!(d.changes.is_empty());
        assert_eq!(d.compatibility, "identical");
    }

    #[test]
    fn identical_signature_with_different_type_index_is_not_a_change() {
        // Type indices are positions in each module's own type section, so they
        // are not stable identifiers. Only the resolved signature matters.
        let a = vec![func("hello", Some("(i32) -> ()"), Some(0))];
        let b = vec![func("hello", Some("(i32) -> ()"), Some(7))];
        let d = diff_exports(&a, &b);
        assert!(
            d.changes.is_empty(),
            "same resolved signature must not be reported as a change: {:?}",
            d.changes
        );
        assert_eq!(d.compatibility, "identical");
    }

    #[test]
    fn added_function_is_non_breaking() {
        let a = vec![func("hello", Some("() -> ()"), Some(0))];
        let b = vec![
            func("hello", Some("() -> ()"), Some(0)),
            func("extra", Some("(i64) -> (i64)"), Some(1)),
        ];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].change, StructuralChangeKind::Added);
        assert_eq!(
            d.changes[0].compatibility,
            StructuralCompatibility::NonBreaking
        );
        assert_eq!(d.compatibility, "non-breaking");
    }

    #[test]
    fn removed_function_is_breaking() {
        let a = vec![
            func("hello", Some("() -> ()"), Some(0)),
            func("gone", Some("() -> ()"), Some(1)),
        ];
        let b = vec![func("hello", Some("() -> ()"), Some(0))];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].change, StructuralChangeKind::Removed);
        assert_eq!(
            d.changes[0].compatibility,
            StructuralCompatibility::Breaking
        );
        assert_eq!(d.compatibility, "breaking");
    }

    #[test]
    fn changed_function_signature_is_breaking() {
        let a = vec![func("hello", Some("(i32) -> ()"), Some(0))];
        let b = vec![func("hello", Some("(i64) -> ()"), Some(0))];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].change, StructuralChangeKind::Changed);
        assert_eq!(
            d.changes[0].compatibility,
            StructuralCompatibility::Breaking
        );
        assert_eq!(d.changes[0].old.as_deref(), Some("(i32) -> ()"));
        assert_eq!(d.changes[0].new.as_deref(), Some("(i64) -> ()"));
        assert_eq!(d.compatibility, "breaking");
    }

    #[test]
    fn added_and_removed_non_function_symbols_are_reported() {
        let a = vec![mem("memory", 1, Some(4)), glob("g", "i32", false)];
        let b = vec![mem("memory", 1, Some(4))];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].kind, "global");
        assert_eq!(d.changes[0].change, StructuralChangeKind::Removed);

        let d2 = diff_exports(&b, &a);
        assert_eq!(d2.changes.len(), 1);
        assert_eq!(d2.changes[0].kind, "global");
        assert_eq!(d2.changes[0].change, StructuralChangeKind::Added);
    }

    #[test]
    fn changed_memory_bounds_are_breaking() {
        let a = vec![mem("memory", 1, Some(4))];
        let b = vec![mem("memory", 2, Some(8))];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].change, StructuralChangeKind::Changed);
        assert_eq!(
            d.changes[0].compatibility,
            StructuralCompatibility::Breaking
        );
    }

    #[test]
    fn changed_table_bounds_are_breaking() {
        let mk = |min: u64| ExportEntry {
            name: "t".to_string(),
            kind: "table".to_string(),
            index: 0,
            type_sig: None,
            type_index: None,
            memory: None,
            table: Some(TableBounds {
                element_type: "funcref".to_string(),
                min_size: min,
                max_size: None,
            }),
            global: None,
        };
        let d = diff_exports(&[mk(1)], &[mk(2)]);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].change, StructuralChangeKind::Changed);
    }

    #[test]
    fn unresolvable_signature_is_unknown_not_breaking() {
        let a = vec![func("hello", None, Some(0))];
        let b = vec![func("hello", Some("(i32) -> ()"), Some(0))];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].change, StructuralChangeKind::Unresolved);
        assert_eq!(d.changes[0].compatibility, StructuralCompatibility::Unknown);
        assert_eq!(d.compatibility, "unknown");
    }

    #[test]
    fn both_sides_unresolvable_is_unknown() {
        let a = vec![func("hello", None, Some(0))];
        let b = vec![func("hello", None, Some(3))];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].change, StructuralChangeKind::Unresolved);
        assert_eq!(d.compatibility, "unknown");
    }

    #[test]
    fn same_name_different_kind_is_two_symbols() {
        let a = vec![func("x", Some("() -> ()"), Some(0))];
        let b = vec![func("x", Some("() -> ()"), Some(0)), glob("x", "i32", true)];
        let d = diff_exports(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].kind, "global");
        assert_eq!(d.changes[0].change, StructuralChangeKind::Added);
    }

    #[test]
    fn changes_are_sorted_deterministically() {
        let a = vec![
            func("zeta", Some("() -> ()"), Some(0)),
            func("alpha", Some("() -> ()"), Some(1)),
        ];
        let b = vec![
            func("alpha", Some("() -> ()"), Some(1)),
            func("zeta", Some("(i32) -> ()"), Some(0)),
            func("mid", Some("() -> ()"), Some(2)),
        ];
        let d = diff_exports(&a, &b);
        let names: Vec<&str> = d.changes.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["mid", "zeta"]);
    }

    #[test]
    fn breaking_dominates_unknown_and_non_breaking() {
        let a = vec![
            func("kept", Some("() -> ()"), Some(0)),
            func("gone", Some("() -> ()"), Some(1)),
            func("unresolved", None, Some(2)),
        ];
        let b = vec![
            func("kept", Some("() -> ()"), Some(0)),
            func("unresolved", Some("() -> ()"), Some(2)),
            func("fresh", Some("() -> ()"), Some(3)),
        ];
        let d = diff_exports(&a, &b);
        assert_eq!(d.compatibility, "breaking");
    }

    #[test]
    fn export_findings_empty_when_all_exports_resolve() {
        let exports = vec![
            func("hello", Some("() -> ()"), Some(0)),
            mem("memory", 1, Some(4)),
            glob("g", "i32", false),
        ];
        assert!(export_findings(&exports).is_empty());
    }

    #[test]
    fn export_findings_reports_unresolvable_function_signature() {
        let exports = vec![
            func("resolved", Some("() -> ()"), Some(0)),
            func("unresolved", None, Some(1)),
        ];
        let findings = export_findings(&exports);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "export_unresolvable");
        assert_eq!(findings[0].name, "unresolved");
        assert_eq!(findings[0].kind, "function");
        assert!(findings[0].message.contains("unresolved"));
    }

    #[test]
    fn export_findings_reports_unresolvable_non_function_export() {
        // A memory export with no collected bounds detail is unresolvable.
        let exports = vec![ExportEntry {
            name: "mem".to_string(),
            kind: "memory".to_string(),
            index: 0,
            type_sig: None,
            type_index: None,
            memory: None,
            table: None,
            global: None,
        }];
        let findings = export_findings(&exports);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "export_unresolvable");
        assert_eq!(findings[0].kind, "memory");
    }

    #[test]
    fn export_findings_never_reports_added_or_removed() {
        // A single module has no baseline: no change codes may ever appear.
        let exports = vec![
            func("a", Some("() -> ()"), Some(0)),
            func("b", None, Some(1)),
        ];
        for f in export_findings(&exports) {
            assert_eq!(f.code, "export_unresolvable");
            assert_ne!(f.code, "export_added");
            assert_ne!(f.code, "export_removed");
            assert_ne!(f.code, "export_signature_changed");
        }
    }

    #[test]
    fn export_findings_are_deterministically_ordered() {
        let exports = vec![
            func("zeta", None, Some(0)),
            func("alpha", None, Some(1)),
            func("mid", None, Some(2)),
        ];
        let findings = export_findings(&exports);
        let names: Vec<&str> = findings.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);
    }

    #[test]
    fn export_findings_empty_for_no_exports() {
        assert!(export_findings(&[]).is_empty());
    }
}
