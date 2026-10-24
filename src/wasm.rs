//! Generic WASM module inspection backed by `wasmparser`.
//!
//! All parsing goes through `wasmparser` — we never hand-roll binary parsing,
//! so malformed/truncated input surfaces as typed errors instead of panics.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use wasmparser::{CoreType, Parser, Payload, RecGroup, TypeRef, Validator, WasmFeatures};

/// Top-level inspection result for a WASM binary.
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmReport {
    /// Number of bytes read from the input file.
    pub size_bytes: usize,
    /// Imported functions/memories/globals/tables.
    pub imports: Vec<ImportEntry>,
    /// Exported functions/memories/globals/tables.
    pub exports: Vec<ExportEntry>,
    /// Custom sections found in the module (name + byte length).
    pub custom_sections: Vec<CustomSection>,
    /// Per-section details in declaration order: index, name, payload length,
    /// and classification. Empty when there are no custom sections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_section_details: Vec<CustomSectionDetail>,
    /// Function signatures declared locally (index → params/results).
    pub functions: Vec<FunctionSig>,
    /// Per-defined-function body metrics, in function-section declaration order.
    /// Empty when the module has no defined functions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_body_metrics: Vec<CodeBodyMetrics>,
    /// Static reachability of defined functions from the module's start
    /// function and exported functions. Present only when the module defines
    /// at least one function. "Unreachable" here means only "not reached from
    /// those roots" — it is not a dead-code judgement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<Reachability>,
    /// Module-level structural summary (memories, tables, globals, segments, start).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structure: Option<ModuleStructure>,
    /// Resource + compatibility analysis (populated by `inspect` command only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<Analysis>,
    /// Developer-facing interface overview, derived from the resolved
    /// `imports`/`exports` above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceSummary>,
    /// Consolidated roll-up of the results above. Always present; derived from
    /// data already in this report and never reparses the module.
    pub summary: AnalysisSummary,
}

/// Developer-facing overview of a module's public interface and external
/// dependencies.
///
/// Every field is derived from the already-resolved `imports`/`exports`
/// vectors — this summary never reparses the module and never re-does index
/// resolution. Ordering is deterministic: grouped counts are sorted by kind
/// name, per-entry lists keep declaration order.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct InterfaceSummary {
    /// Import counts grouped by kind, sorted by kind name.
    pub imports_by_kind: Vec<KindCount>,
    /// Export counts grouped by kind, sorted by kind name.
    pub exports_by_kind: Vec<KindCount>,
    /// Exported functions in declaration order. `signature` is null when the
    /// type was not resolvable — unavailable, never guessed.
    pub exported_functions: Vec<ExportedFunction>,
    /// Imported functions in import order.
    pub imported_functions: Vec<ImportedFunction>,
    /// Every export name with its resource kind, in declaration order.
    pub exports: Vec<ExportNameKind>,
    /// `true` when a `contractspecv0` custom section is present.
    ///
    /// Contract-spec functions are an ABI view reported by `validate`. They
    /// are deliberately NOT merged into `exported_functions`, which lists raw
    /// WASM exports only. The two are different views and must not be
    /// conflated.
    pub has_contract_spec: bool,
}

/// A count of entries sharing one resource kind.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct KindCount {
    pub kind: String,
    pub count: usize,
}

/// An exported function: its export name plus the signature of the function
/// it refers to, or `null` when that signature could not be resolved.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ExportedFunction {
    pub name: String,
    /// Exported WASM function index.
    pub index: u32,
    /// Rendered signature, or `null` when unresolvable.
    pub signature: Option<String>,
}

/// An imported function: module/name plus its signature when resolvable.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ImportedFunction {
    pub module: String,
    pub name: String,
    /// Rendered signature, or `null` when unresolvable.
    pub signature: Option<String>,
}

/// An export name paired with its resource kind.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ExportNameKind {
    pub name: String,
    pub kind: String,
}

/// Counts and key details of the module's linear-memory, table, global, and
/// segment structure. Present only when the module declares such items.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StartFunction {
    /// Index from the start section (WASM function index space: imported
    /// functions come first, then defined).
    pub index: u32,
    /// `"imported"` when the index resolves to an imported function,
    /// `"defined"` when it resolves to a locally defined function, or
    /// `"invalid"` when no function occupies that index.
    pub resolution: String,
    /// Module and import name, present only when `resolution == "imported"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<ImportRef>,
    /// Signature and declared-function index, present only when
    /// `resolution == "defined"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<StartFunctionSig>,
}

/// A back-reference from a resolved index to the import that owns it.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ImportRef {
    pub module: String,
    pub name: String,
}

/// The signature of a resolved start function, plus its position in the
/// module's declared (defined-only) function list.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StartFunctionSig {
    pub declared_index: u32,
    pub signature: String,
}

/// A data segment's mode, as represented by the parser.
///
/// wasmparser 0.121.2 exposes only two variants for data segments
/// (`DataKind::Passive` and `DataKind::Active`); the reference-interpreter
/// "declared" form has no representation here, so it is never emitted.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DataSegmentMode {
    Active,
    Passive,
}

/// The offset expression of an active data segment, represented
/// conservatively.
///
/// Only constant forms the parser can evaluate without guessing are
/// reported as a value. Anything else — a global reference, a non-constant
/// operator, or a malformed expression — is reported as
/// `OffsetExpr::Unsupported` with the reason, never as an invented number.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OffsetExpr {
    /// A single `i32.const` / `i64.const` instruction.
    Const { value: i64 },
    /// A single `global.get` instruction; the referenced global's value is
    /// not evaluated here.
    GlobalGet { global_index: u32 },
    /// Any other form, with the reason it could not be represented.
    Unsupported { reason: String },
}

/// One data segment, in declaration order.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DataSegment {
    /// 0-based position in the data section (declaration order).
    pub index: usize,
    /// Active or passive, as parsed.
    pub mode: DataSegmentMode,
    /// Memory index for active segments; absent for passive segments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_index: Option<u32>,
    /// Offset expression for active segments; absent for passive segments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<OffsetExpr>,
    /// Payload length in bytes. The payload itself is never emitted.
    pub payload_len: usize,
}

/// Classify a constant expression conservatively.
///
/// Returns `Ok(OffsetExpr)` for the single-instruction forms that can be
/// represented without evaluating anything, and `Err(reason)` for anything
/// else. The caller converts the error into `OffsetExpr::Unsupported`.
///
/// Deliberately conservative: a `global.get` is reported as a reference, not
/// as the global's value, because this tool does not evaluate globals.
fn classify_const_expr(expr: &wasmparser::ConstExpr<'_>) -> Result<OffsetExpr, String> {
    use wasmparser::Operator;
    let mut reader = expr.get_operators_reader();
    let mut ops: Vec<Operator<'_>> = Vec::new();
    loop {
        match reader.read() {
            Ok(op) => ops.push(op),
            Err(e) => return Err(format!("unparseable offset expression: {e}")),
        }
        if matches!(ops.last(), Some(Operator::End)) {
            break;
        }
    }
    // A constant expression is exactly one instruction plus `End`.
    let body = &ops[..ops.len() - 1];
    match body {
        [Operator::I32Const { value }] => Ok(OffsetExpr::Const {
            value: i64::from(*value),
        }),
        [Operator::I64Const { value }] => Ok(OffsetExpr::Const { value: *value }),
        [Operator::GlobalGet { global_index }] => Ok(OffsetExpr::GlobalGet {
            global_index: *global_index,
        }),
        [] => Err("empty offset expression".to_string()),
        _ => Err(format!(
            "unsupported constant expression with {} instruction(s)",
            body.len()
        )),
    }
}

/// An element segment's mode, as represented by the parser.
///
/// wasmparser 0.121.2 exposes three variants for element segments
/// (`ElementKind::Passive`, `ElementKind::Active`, and `ElementKind::Declared`),
/// so all three are represented here.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ElementSegmentMode {
    Active,
    Passive,
    Declared,
}

/// The element kind of an element segment.
///
/// wasmparser 0.121.2 reports this as `ElementItems::Functions` (a vector of
/// function indices) or `ElementItems::Expressions` (a vector of constant
/// expressions plus their reference type), so both are represented here.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ElementKind {
    /// The segment carries function indices.
    Functions,
    /// The segment carries reference expressions of the given reference type.
    Expressions { element_type: String },
}

/// One element of a function-index element segment.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ElementFuncIndex {
    /// 0-based position within the segment's element list.
    pub item_index: usize,
    /// The raw function index as declared in the segment.
    pub raw_index: u32,
    /// Resolution against the full function index space: imported functions
    /// occupy the lowest indices, then locally defined functions.
    pub resolution: ElementRefResolution,
}

/// How one element-segment reference resolved against the module's function
/// index space.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ElementRefResolution {
    /// Resolves to an imported function; carries the import's module and name.
    Imported { module: String, name: String },
    /// Resolves to a locally defined function; carries its 0-based position
    /// among defined functions and its rendered signature.
    Defined {
        declared_index: u32,
        signature: String,
    },
    /// The index names no function in this module's index space. Reported
    /// rather than dropped or panicked on.
    Invalid,
}

/// One element of a reference-expression element segment.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ElementExprItem {
    /// 0-based position within the segment's element list.
    pub item_index: usize,
    /// The reference type of the expression, as reported by the parser.
    pub element_type: String,
    /// How the expression was classified.
    pub expr: ElementExpr,
}

/// A conservative representation of one reference expression.
///
/// Only the forms the parser can represent without evaluating anything are
/// reported; anything else is `Unsupported` with a reason, never an invented
/// value.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ElementExpr {
    /// A single `ref.func <index>` instruction. The index is preserved raw and
    /// resolved against the full function index space.
    RefFunc {
        raw_index: u32,
        resolution: ElementRefResolution,
    },
    /// A single `ref.null <heap_type>` instruction.
    RefNull { heap_type: String },
    /// Any other form, with the reason it could not be represented.
    Unsupported { reason: String },
}

/// Classify one reference expression conservatively.
///
/// Returns `Ok(ElementExpr)` for the single-instruction forms that can be
/// represented without evaluating anything, and `Err(reason)` for anything
/// else. The caller converts the error into `ElementExpr::Unsupported`.
///
/// Deliberately conservative: a `ref.func` is reported as a reference with its
/// raw index, never as a resolved function name, because this tool does not
/// evaluate expressions.
fn classify_element_expr(expr: &wasmparser::ConstExpr<'_>) -> Result<ElementExpr, String> {
    use wasmparser::Operator;
    let mut reader = expr.get_operators_reader();
    let mut ops: Vec<Operator<'_>> = Vec::new();
    loop {
        match reader.read() {
            Ok(op) => ops.push(op),
            Err(e) => return Err(format!("unparseable element expression: {e}")),
        }
        if matches!(ops.last(), Some(Operator::End)) {
            break;
        }
    }
    // A constant expression is exactly one instruction plus `End`.
    let body = &ops[..ops.len() - 1];
    match body {
        [Operator::RefFunc { function_index }] => Ok(ElementExpr::RefFunc {
            raw_index: *function_index,
            resolution: ElementRefResolution::Invalid,
        }),
        [Operator::RefNull { hty }] => Ok(ElementExpr::RefNull {
            heap_type: format!("{hty:?}"),
        }),
        [] => Err("empty element expression".to_string()),
        _ => Err(format!(
            "unsupported element expression with {} instruction(s)",
            body.len()
        )),
    }
}

/// One element segment, in declaration order.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ElementSegment {
    /// 0-based position in the element section (declaration order).
    pub index: usize,
    /// Active, passive, or declared, as parsed.
    pub mode: ElementSegmentMode,
    /// Table index for active segments; absent for passive and declared
    /// segments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_index: Option<u32>,
    /// Offset expression for active segments; absent for passive and declared
    /// segments. Reuses the conservative representation from data segments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<OffsetExpr>,
    /// Function indices or reference expressions, as parsed.
    pub kind: ElementKind,
    /// Number of elements in the segment.
    pub element_count: usize,
    /// Per-element detail. Empty for segments whose items could not be
    /// classified. Never contains raw payload bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ElementItem>,
}

/// One element of an element segment, in declaration order.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ElementItem {
    /// A function index, resolved against the full function index space.
    FuncIndex(ElementFuncIndex),
    /// A reference expression.
    Expr(ElementExprItem),
}

/// An element segment as parsed, before function-index resolution.
///
/// Function indices are kept raw here and resolved after the whole payload
/// loop, because resolution needs the complete function index space (imported
/// functions first, then locally defined functions).
#[derive(Debug)]
struct RawElementSegment {
    index: usize,
    mode: ElementSegmentMode,
    table_index: Option<u32>,
    offset: Option<OffsetExpr>,
    kind: ElementKind,
    element_count: usize,
    /// Raw function indices for `ElementKind::Functions`, in declaration order.
    func_indices: Vec<u32>,
    /// Classified reference expressions for `ElementKind::Expressions`, in
    /// declaration order.
    exprs: Vec<ElementExpr>,
}

/// Parse one element segment into its raw (unresolved) form.
///
/// Never serializes the raw payload: only the count and the classified items
/// are retained. Unparseable items become `ElementExpr::Unsupported` with a
/// reason rather than being dropped or panicking.
fn parse_element_segment(index: usize, seg: wasmparser::Element<'_>) -> RawElementSegment {
    let (mode, table_index, offset) = match seg.kind {
        wasmparser::ElementKind::Passive => (ElementSegmentMode::Passive, None, None),
        wasmparser::ElementKind::Declared => (ElementSegmentMode::Declared, None, None),
        wasmparser::ElementKind::Active {
            table_index,
            offset_expr,
        } => {
            let offset = match classify_const_expr(&offset_expr) {
                Ok(expr) => expr,
                Err(reason) => OffsetExpr::Unsupported { reason },
            };
            // `table_index` is `None` for the implicit table 0 encoding
            // (flags 0x00), which the parser normalizes to table 0.
            (
                ElementSegmentMode::Active,
                Some(table_index.unwrap_or(0)),
                Some(offset),
            )
        }
    };

    match seg.items {
        wasmparser::ElementItems::Functions(funcs) => {
            let mut func_indices = Vec::new();
            for f in funcs {
                // A malformed item is reported as an unresolved reference
                // (u32::MAX never names a function) rather than aborting the
                // whole segment.
                func_indices.push(f.unwrap_or(u32::MAX));
            }
            let element_count = func_indices.len();
            RawElementSegment {
                index,
                mode,
                table_index,
                offset,
                kind: ElementKind::Functions,
                element_count,
                func_indices,
                exprs: Vec::new(),
            }
        }
        wasmparser::ElementItems::Expressions(ty, exprs) => {
            let element_type = format!("{ty:?}");
            let mut classified = Vec::new();
            for e in exprs {
                match e {
                    Ok(expr) => match classify_element_expr(&expr) {
                        Ok(classified_expr) => classified.push(classified_expr),
                        Err(reason) => classified.push(ElementExpr::Unsupported { reason }),
                    },
                    Err(e) => classified.push(ElementExpr::Unsupported {
                        reason: format!("unparseable element expression: {e}"),
                    }),
                }
            }
            let element_count = classified.len();
            RawElementSegment {
                index,
                mode,
                table_index,
                offset,
                kind: ElementKind::Expressions { element_type },
                element_count,
                func_indices: Vec::new(),
                exprs: classified,
            }
        }
    }
}

/// Resolve a raw element segment against the module's function index space.
///
/// Imported functions occupy the lowest indices, then locally defined
/// functions in declaration order. An index that names no function resolves
/// to `ElementRefResolution::Invalid` — reported, never dropped or panicked.
fn resolve_element_segment(
    raw: RawElementSegment,
    imported_func_type_idx: &[u32],
    func_type_idx: &[u32],
    imports: &[ImportEntry],
    types: &[String],
) -> ElementSegment {
    let imported_func_count = imported_func_type_idx.len();

    let resolve_index = |raw_index: u32| -> ElementRefResolution {
        let i = raw_index as usize;
        if i < imported_func_count {
            // Resolves to an imported function: report which import.
            let mut count = 0usize;
            for imp in imports {
                if imp.kind == "function" {
                    if count == i {
                        return ElementRefResolution::Imported {
                            module: imp.module.clone(),
                            name: imp.name.clone(),
                        };
                    }
                    count += 1;
                }
            }
            ElementRefResolution::Invalid
        } else {
            match i.checked_sub(imported_func_count) {
                Some(local) => match func_type_idx.get(local) {
                    Some(type_idx) => ElementRefResolution::Defined {
                        declared_index: local as u32,
                        signature: types
                            .get(*type_idx as usize)
                            .cloned()
                            .unwrap_or_else(|| "<unknown>".to_string()),
                    },
                    None => ElementRefResolution::Invalid,
                },
                None => ElementRefResolution::Invalid,
            }
        }
    };

    let items = match raw.kind {
        ElementKind::Functions => raw
            .func_indices
            .into_iter()
            .enumerate()
            .map(|(item_index, raw_index)| {
                let resolution = resolve_index(raw_index);
                ElementItem::FuncIndex(ElementFuncIndex {
                    item_index,
                    raw_index,
                    resolution,
                })
            })
            .collect(),
        ElementKind::Expressions { .. } => raw
            .exprs
            .into_iter()
            .enumerate()
            .map(|(item_index, expr)| {
                let expr = match expr {
                    ElementExpr::RefFunc {
                        raw_index,
                        resolution: _,
                    } => ElementExpr::RefFunc {
                        raw_index,
                        resolution: resolve_index(raw_index),
                    },
                    other => other,
                };
                ElementItem::Expr(ElementExprItem {
                    item_index,
                    element_type: match &raw.kind {
                        ElementKind::Expressions { element_type } => element_type.clone(),
                        _ => String::new(),
                    },
                    expr,
                })
            })
            .collect(),
    };

    ElementSegment {
        index: raw.index,
        mode: raw.mode,
        table_index: raw.table_index,
        offset: raw.offset,
        kind: raw.kind,
        element_count: raw.element_count,
        items,
    }
}

/// Intermediate result of measuring a function body.
struct MeasuredBody {
    body_len_bytes: usize,
    local_decl_count: usize,
    local_total: usize,
    operator_count: usize,
    max_control_depth: usize,
    /// Per-family instruction counts, sorted by family name.
    /// Each operator is counted in exactly one family — classifications are
    /// exclusive, not overlapping.
    instruction_inventory: BTreeMap<&'static str, usize>,
    /// Raw callee function indices from direct `call` / `return_call`
    /// operators, in encounter order. Aggregated after resolution.
    direct_call_targets: Vec<u32>,
    /// Number of `call_indirect` / `return_call_indirect` sites. These name a
    /// type, not a target, so no edge is invented for them.
    indirect_call_sites: usize,
    /// Number of `call_ref` / `return_call_ref` sites. Same reasoning: the
    /// callee is a runtime value, not a static index.
    reference_call_sites: usize,
    /// Count of syntactic basic blocks (see `basic_block_count` for the exact
    /// leader rule).
    basic_block_count: usize,
    /// `br_if` sites plus `if` constructs — each is a two-way decision.
    conditional_branch_count: usize,
    /// `br`, `br_table`, `return`, and `unreachable` sites — each transfers
    /// control unconditionally.
    unconditional_branch_count: usize,
    /// `loop` constructs.
    loop_count: usize,
    /// `if` constructs (a subset of `conditional_branch_count`).
    if_count: usize,
    /// `1 + if_count + br_if_count + br_table_count`. `br_table` counts as one
    /// decision point regardless of its target count.
    cyclomatic_complexity: usize,
}

/// Measure a single function body's structural metrics.
///
/// This is deliberately conservative: it counts operators and tracks
/// structured-control nesting depth from the encoded byte stream. It does
/// not evaluate globals, resolve indirect calls, or simulate execution.
fn measure_code_body(body: wasmparser::FunctionBody<'_>) -> Result<MeasuredBody, String> {
    let body_len_bytes = body.range().len();
    let locals_reader = body.get_locals_reader().map_err(|e| e.to_string())?;
    let mut local_decl_count = 0usize;
    let mut local_total = 0usize;
    for item in locals_reader {
        let (count, _) = item.map_err(|e| e.to_string())?;
        local_decl_count = local_decl_count
            .checked_add(1)
            .ok_or("local declaration count overflow")?;
        local_total = local_total
            .checked_add(count as usize)
            .ok_or("local total count overflow")?;
    }

    let mut op_reader = body.get_operators_reader().map_err(|e| e.to_string())?;
    let mut operator_count = 0usize;
    let mut control_depth = 0usize;
    let mut max_control_depth = 0usize;
    let mut inventory: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut direct_call_targets: Vec<u32> = Vec::new();
    let mut indirect_call_sites = 0usize;
    let mut reference_call_sites = 0usize;
    // Complexity counters, derived from the same operator traversal.
    let mut basic_block_count = 0usize;
    // The function entry is always a block leader.
    let mut prev_boundary = true;
    let mut is_first_op = true;
    let mut conditional_branch_count = 0usize;
    let mut unconditional_branch_count = 0usize;
    let mut loop_count = 0usize;
    let mut if_count = 0usize;
    let mut br_if_count = 0usize;
    let mut br_table_count = 0usize;

    loop {
        let op = op_reader.read().map_err(|e| e.to_string())?;
        use wasmparser::Operator;

        // A new basic block starts whenever the previous operator was a
        // control-flow boundary. Computed before the match so `op` can still
        // be borrowed here even when an arm binds out of it.
        let counted_as_leader = prev_boundary;
        if prev_boundary {
            basic_block_count = basic_block_count
                .checked_add(1)
                .ok_or("basic block count overflow")?;
        }
        let is_boundary = is_block_boundary(&op);

        match op {
            Operator::Block { .. } => {
                control_depth = control_depth
                    .checked_add(1)
                    .ok_or("control depth overflow")?;
                if control_depth > max_control_depth {
                    max_control_depth = control_depth;
                }
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
            }
            Operator::Loop { .. } => {
                control_depth = control_depth
                    .checked_add(1)
                    .ok_or("control depth overflow")?;
                if control_depth > max_control_depth {
                    max_control_depth = control_depth;
                }
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
                loop_count = loop_count.checked_add(1).ok_or("loop count overflow")?;
            }
            Operator::If { .. } => {
                control_depth = control_depth
                    .checked_add(1)
                    .ok_or("control depth overflow")?;
                if control_depth > max_control_depth {
                    max_control_depth = control_depth;
                }
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
                if_count = if_count.checked_add(1).ok_or("if count overflow")?;
                conditional_branch_count = conditional_branch_count
                    .checked_add(1)
                    .ok_or("conditional branch count overflow")?;
            }
            Operator::Else => {
                // `else` continues the enclosing `if`; it opens no new block.
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
            }
            Operator::End => {
                if control_depth > 0 {
                    control_depth = control_depth
                        .checked_sub(1)
                        .expect("control depth underflow");
                }
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
            }
            Operator::Br { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
                unconditional_branch_count = unconditional_branch_count
                    .checked_add(1)
                    .ok_or("unconditional branch count overflow")?;
            }
            Operator::BrIf { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
                br_if_count = br_if_count.checked_add(1).ok_or("br_if count overflow")?;
                conditional_branch_count = conditional_branch_count
                    .checked_add(1)
                    .ok_or("conditional branch count overflow")?;
            }
            Operator::BrTable { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
                br_table_count = br_table_count
                    .checked_add(1)
                    .ok_or("br_table count overflow")?;
                unconditional_branch_count = unconditional_branch_count
                    .checked_add(1)
                    .ok_or("unconditional branch count overflow")?;
            }
            Operator::Return => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
                unconditional_branch_count = unconditional_branch_count
                    .checked_add(1)
                    .ok_or("unconditional branch count overflow")?;
            }
            Operator::Call { function_index } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("call").or_insert(0) += 1;
                direct_call_targets.push(function_index);
            }
            Operator::ReturnCall { function_index } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("call").or_insert(0) += 1;
                direct_call_targets.push(function_index);
            }
            Operator::CallIndirect { .. } | Operator::ReturnCallIndirect { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("call").or_insert(0) += 1;
                indirect_call_sites = indirect_call_sites
                    .checked_add(1)
                    .ok_or("indirect call site count overflow")?;
            }
            Operator::LocalGet { .. } | Operator::LocalSet { .. } | Operator::LocalTee { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("local").or_insert(0) += 1;
            }
            Operator::GlobalGet { .. } | Operator::GlobalSet { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("global").or_insert(0) += 1;
            }
            Operator::I32Load { .. }
            | Operator::I64Load { .. }
            | Operator::F32Load { .. }
            | Operator::F64Load { .. }
            | Operator::I32Load8S { .. }
            | Operator::I32Load8U { .. }
            | Operator::I32Load16S { .. }
            | Operator::I32Load16U { .. }
            | Operator::I64Load8S { .. }
            | Operator::I64Load8U { .. }
            | Operator::I64Load16S { .. }
            | Operator::I64Load16U { .. }
            | Operator::I64Load32S { .. }
            | Operator::I64Load32U { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("load").or_insert(0) += 1;
            }
            Operator::I32Store { .. }
            | Operator::I64Store { .. }
            | Operator::F32Store { .. }
            | Operator::F64Store { .. }
            | Operator::I32Store8 { .. }
            | Operator::I32Store16 { .. }
            | Operator::I64Store8 { .. }
            | Operator::I64Store16 { .. }
            | Operator::I64Store32 { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("store").or_insert(0) += 1;
            }
            Operator::MemorySize { .. } | Operator::MemoryGrow { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("memory").or_insert(0) += 1;
            }
            Operator::MemoryInit { .. }
            | Operator::DataDrop { .. }
            | Operator::MemoryCopy { .. }
            | Operator::MemoryFill { .. }
            | Operator::TableInit { .. }
            | Operator::ElemDrop { .. }
            | Operator::TableCopy { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("bulk").or_insert(0) += 1;
            }
            Operator::TableFill { .. }
            | Operator::TableGet { .. }
            | Operator::TableSet { .. }
            | Operator::TableGrow { .. }
            | Operator::TableSize { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("table").or_insert(0) += 1;
            }
            Operator::I32Const { .. }
            | Operator::I64Const { .. }
            | Operator::F32Const { .. }
            | Operator::F64Const { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("const").or_insert(0) += 1;
            }
            Operator::RefNull { .. }
            | Operator::RefIsNull { .. }
            | Operator::RefFunc { .. }
            | Operator::RefEq { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("reference").or_insert(0) += 1;
            }
            Operator::I32Eqz { .. }
            | Operator::I32Eq { .. }
            | Operator::I32Ne { .. }
            | Operator::I32LtS { .. }
            | Operator::I32LtU { .. }
            | Operator::I32GtS { .. }
            | Operator::I32GtU { .. }
            | Operator::I32LeS { .. }
            | Operator::I32LeU { .. }
            | Operator::I32GeS { .. }
            | Operator::I32GeU { .. }
            | Operator::I64Eqz { .. }
            | Operator::I64Eq { .. }
            | Operator::I64Ne { .. }
            | Operator::I64LtS { .. }
            | Operator::I64LtU { .. }
            | Operator::I64GtS { .. }
            | Operator::I64GtU { .. }
            | Operator::I64LeS { .. }
            | Operator::I64LeU { .. }
            | Operator::I64GeS { .. }
            | Operator::I64GeU { .. }
            | Operator::F32Eq { .. }
            | Operator::F32Ne { .. }
            | Operator::F32Lt { .. }
            | Operator::F32Gt { .. }
            | Operator::F32Le { .. }
            | Operator::F32Ge { .. }
            | Operator::F64Eq { .. }
            | Operator::F64Ne { .. }
            | Operator::F64Lt { .. }
            | Operator::F64Gt { .. }
            | Operator::F64Le { .. }
            | Operator::F64Ge { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("compare").or_insert(0) += 1;
            }
            Operator::I32Clz { .. }
            | Operator::I32Ctz { .. }
            | Operator::I32Popcnt { .. }
            | Operator::I32Add { .. }
            | Operator::I32Sub { .. }
            | Operator::I32Mul { .. }
            | Operator::I32DivS { .. }
            | Operator::I32DivU { .. }
            | Operator::I32RemS { .. }
            | Operator::I32RemU { .. }
            | Operator::I32And { .. }
            | Operator::I32Or { .. }
            | Operator::I32Xor { .. }
            | Operator::I32Shl { .. }
            | Operator::I32ShrS { .. }
            | Operator::I32ShrU { .. }
            | Operator::I32Rotl { .. }
            | Operator::I32Rotr { .. }
            | Operator::I64Clz { .. }
            | Operator::I64Ctz { .. }
            | Operator::I64Popcnt { .. }
            | Operator::I64Add { .. }
            | Operator::I64Sub { .. }
            | Operator::I64Mul { .. }
            | Operator::I64DivS { .. }
            | Operator::I64DivU { .. }
            | Operator::I64RemS { .. }
            | Operator::I64RemU { .. }
            | Operator::I64And { .. }
            | Operator::I64Or { .. }
            | Operator::I64Xor { .. }
            | Operator::I64Shl { .. }
            | Operator::I64ShrS { .. }
            | Operator::I64ShrU { .. }
            | Operator::I64Rotl { .. }
            | Operator::I64Rotr { .. }
            | Operator::F32Abs { .. }
            | Operator::F32Neg { .. }
            | Operator::F32Ceil { .. }
            | Operator::F32Floor { .. }
            | Operator::F32Trunc { .. }
            | Operator::F32Nearest { .. }
            | Operator::F32Sqrt { .. }
            | Operator::F32Add { .. }
            | Operator::F32Sub { .. }
            | Operator::F32Mul { .. }
            | Operator::F32Div { .. }
            | Operator::F32Min { .. }
            | Operator::F32Max { .. }
            | Operator::F32Copysign { .. }
            | Operator::F64Abs { .. }
            | Operator::F64Neg { .. }
            | Operator::F64Ceil { .. }
            | Operator::F64Floor { .. }
            | Operator::F64Trunc { .. }
            | Operator::F64Nearest { .. }
            | Operator::F64Sqrt { .. }
            | Operator::F64Add { .. }
            | Operator::F64Sub { .. }
            | Operator::F64Mul { .. }
            | Operator::F64Div { .. }
            | Operator::F64Min { .. }
            | Operator::F64Max { .. }
            | Operator::F64Copysign { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("numeric").or_insert(0) += 1;
            }
            Operator::I32WrapI64 { .. }
            | Operator::I32TruncF32S { .. }
            | Operator::I32TruncF32U { .. }
            | Operator::I32TruncF64S { .. }
            | Operator::I32TruncF64U { .. }
            | Operator::I64ExtendI32S { .. }
            | Operator::I64ExtendI32U { .. }
            | Operator::I64TruncF32S { .. }
            | Operator::I64TruncF32U { .. }
            | Operator::I64TruncF64S { .. }
            | Operator::I64TruncF64U { .. }
            | Operator::F32ConvertI32S { .. }
            | Operator::F32ConvertI32U { .. }
            | Operator::F32ConvertI64S { .. }
            | Operator::F32ConvertI64U { .. }
            | Operator::F32DemoteF64 { .. }
            | Operator::F64ConvertI32S { .. }
            | Operator::F64ConvertI32U { .. }
            | Operator::F64ConvertI64S { .. }
            | Operator::F64ConvertI64U { .. }
            | Operator::F64PromoteF32 { .. }
            | Operator::I32ReinterpretF32 { .. }
            | Operator::I64ReinterpretF64 { .. }
            | Operator::F32ReinterpretI32 { .. }
            | Operator::F64ReinterpretI64 { .. }
            | Operator::I32Extend8S { .. }
            | Operator::I32Extend16S { .. }
            | Operator::I64Extend8S { .. }
            | Operator::I64Extend16S { .. }
            | Operator::I64Extend32S { .. }
            | Operator::I32TruncSatF32S { .. }
            | Operator::I32TruncSatF32U { .. }
            | Operator::I32TruncSatF64S { .. }
            | Operator::I32TruncSatF64U { .. }
            | Operator::I64TruncSatF32S { .. }
            | Operator::I64TruncSatF32U { .. }
            | Operator::I64TruncSatF64S { .. }
            | Operator::I64TruncSatF64U { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("conversion").or_insert(0) += 1;
            }
            Operator::Select { .. } | Operator::TypedSelect { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("select").or_insert(0) += 1;
            }
            Operator::Unreachable => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("misc").or_insert(0) += 1;
                unconditional_branch_count = unconditional_branch_count
                    .checked_add(1)
                    .ok_or("unconditional branch count overflow")?;
            }
            Operator::Drop | Operator::Nop => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("misc").or_insert(0) += 1;
            }
            Operator::StructNew { .. }
            | Operator::StructNewDefault { .. }
            | Operator::StructGet { .. }
            | Operator::StructGetS { .. }
            | Operator::StructGetU { .. }
            | Operator::StructSet { .. }
            | Operator::ArrayNew { .. }
            | Operator::ArrayNewDefault { .. }
            | Operator::ArrayNewFixed { .. }
            | Operator::ArrayNewData { .. }
            | Operator::ArrayNewElem { .. }
            | Operator::ArrayGet { .. }
            | Operator::ArrayGetS { .. }
            | Operator::ArrayGetU { .. }
            | Operator::ArraySet { .. }
            | Operator::ArrayLen { .. }
            | Operator::ArrayFill { .. }
            | Operator::ArrayCopy { .. }
            | Operator::ArrayInitData { .. }
            | Operator::ArrayInitElem { .. }
            | Operator::RefTestNonNull { .. }
            | Operator::RefTestNullable { .. }
            | Operator::RefCastNonNull { .. }
            | Operator::RefCastNullable { .. }
            | Operator::BrOnCast { .. }
            | Operator::BrOnCastFail { .. }
            | Operator::AnyConvertExtern { .. }
            | Operator::ExternConvertAny { .. }
            | Operator::RefI31 { .. }
            | Operator::I31GetS { .. }
            | Operator::I31GetU { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("gc").or_insert(0) += 1;
            }
            Operator::CallRef { .. } | Operator::ReturnCallRef { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("call").or_insert(0) += 1;
                reference_call_sites = reference_call_sites
                    .checked_add(1)
                    .ok_or("reference call site count overflow")?;
            }
            Operator::BrOnNull { .. } | Operator::BrOnNonNull { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("control").or_insert(0) += 1;
            }
            Operator::RefAsNonNull { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("reference").or_insert(0) += 1;
            }
            Operator::MemoryAtomicNotify { .. }
            | Operator::MemoryAtomicWait32 { .. }
            | Operator::MemoryAtomicWait64 { .. }
            | Operator::AtomicFence { .. }
            | Operator::I32AtomicLoad { .. }
            | Operator::I64AtomicLoad { .. }
            | Operator::I32AtomicLoad8U { .. }
            | Operator::I32AtomicLoad16U { .. }
            | Operator::I64AtomicLoad8U { .. }
            | Operator::I64AtomicLoad16U { .. }
            | Operator::I64AtomicLoad32U { .. }
            | Operator::I32AtomicStore { .. }
            | Operator::I64AtomicStore { .. }
            | Operator::I32AtomicStore8 { .. }
            | Operator::I32AtomicStore16 { .. }
            | Operator::I64AtomicStore8 { .. }
            | Operator::I64AtomicStore16 { .. }
            | Operator::I64AtomicStore32 { .. }
            | Operator::I32AtomicRmwAdd { .. }
            | Operator::I64AtomicRmwAdd { .. }
            | Operator::I32AtomicRmw8AddU { .. }
            | Operator::I32AtomicRmw16AddU { .. }
            | Operator::I64AtomicRmw8AddU { .. }
            | Operator::I64AtomicRmw16AddU { .. }
            | Operator::I64AtomicRmw32AddU { .. }
            | Operator::I32AtomicRmwSub { .. }
            | Operator::I64AtomicRmwSub { .. }
            | Operator::I32AtomicRmw8SubU { .. }
            | Operator::I32AtomicRmw16SubU { .. }
            | Operator::I64AtomicRmw8SubU { .. }
            | Operator::I64AtomicRmw16SubU { .. }
            | Operator::I64AtomicRmw32SubU { .. }
            | Operator::I32AtomicRmwAnd { .. }
            | Operator::I64AtomicRmwAnd { .. }
            | Operator::I32AtomicRmw8AndU { .. }
            | Operator::I32AtomicRmw16AndU { .. }
            | Operator::I64AtomicRmw8AndU { .. }
            | Operator::I64AtomicRmw16AndU { .. }
            | Operator::I64AtomicRmw32AndU { .. }
            | Operator::I32AtomicRmwOr { .. }
            | Operator::I64AtomicRmwOr { .. }
            | Operator::I32AtomicRmw8OrU { .. }
            | Operator::I32AtomicRmw16OrU { .. }
            | Operator::I64AtomicRmw8OrU { .. }
            | Operator::I64AtomicRmw16OrU { .. }
            | Operator::I64AtomicRmw32OrU { .. }
            | Operator::I32AtomicRmwXor { .. }
            | Operator::I64AtomicRmwXor { .. }
            | Operator::I32AtomicRmw8XorU { .. }
            | Operator::I32AtomicRmw16XorU { .. }
            | Operator::I64AtomicRmw8XorU { .. }
            | Operator::I64AtomicRmw16XorU { .. }
            | Operator::I64AtomicRmw32XorU { .. }
            | Operator::I32AtomicRmwXchg { .. }
            | Operator::I64AtomicRmwXchg { .. }
            | Operator::I32AtomicRmw8XchgU { .. }
            | Operator::I32AtomicRmw16XchgU { .. }
            | Operator::I64AtomicRmw8XchgU { .. }
            | Operator::I64AtomicRmw16XchgU { .. }
            | Operator::I64AtomicRmw32XchgU { .. }
            | Operator::I32AtomicRmwCmpxchg { .. }
            | Operator::I64AtomicRmwCmpxchg { .. }
            | Operator::I32AtomicRmw8CmpxchgU { .. }
            | Operator::I32AtomicRmw16CmpxchgU { .. }
            | Operator::I64AtomicRmw8CmpxchgU { .. }
            | Operator::I64AtomicRmw16CmpxchgU { .. }
            | Operator::I64AtomicRmw32CmpxchgU { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("atomic").or_insert(0) += 1;
            }
            Operator::V128Load { .. }
            | Operator::V128Load8x8S { .. }
            | Operator::V128Load8x8U { .. }
            | Operator::V128Load16x4S { .. }
            | Operator::V128Load16x4U { .. }
            | Operator::V128Load32x2S { .. }
            | Operator::V128Load32x2U { .. }
            | Operator::V128Load8Splat { .. }
            | Operator::V128Load16Splat { .. }
            | Operator::V128Load32Splat { .. }
            | Operator::V128Load64Splat { .. }
            | Operator::V128Load32Zero { .. }
            | Operator::V128Load64Zero { .. }
            | Operator::V128Store { .. }
            | Operator::V128Load8Lane { .. }
            | Operator::V128Load16Lane { .. }
            | Operator::V128Load32Lane { .. }
            | Operator::V128Load64Lane { .. }
            | Operator::V128Store8Lane { .. }
            | Operator::V128Store16Lane { .. }
            | Operator::V128Store32Lane { .. }
            | Operator::V128Store64Lane { .. }
            | Operator::V128Const { .. }
            | Operator::I8x16Shuffle { .. }
            | Operator::I8x16ExtractLaneS { .. }
            | Operator::I8x16ExtractLaneU { .. }
            | Operator::I8x16ReplaceLane { .. }
            | Operator::I16x8ExtractLaneS { .. }
            | Operator::I16x8ExtractLaneU { .. }
            | Operator::I16x8ReplaceLane { .. }
            | Operator::I32x4ExtractLane { .. }
            | Operator::I32x4ReplaceLane { .. }
            | Operator::I64x2ExtractLane { .. }
            | Operator::I64x2ReplaceLane { .. }
            | Operator::F32x4ExtractLane { .. }
            | Operator::F32x4ReplaceLane { .. }
            | Operator::F64x2ExtractLane { .. }
            | Operator::F64x2ReplaceLane { .. }
            | Operator::I8x16Swizzle { .. }
            | Operator::I8x16Splat { .. }
            | Operator::I16x8Splat { .. }
            | Operator::I32x4Splat { .. }
            | Operator::I64x2Splat { .. }
            | Operator::F32x4Splat { .. }
            | Operator::F64x2Splat { .. }
            | Operator::I8x16Eq { .. }
            | Operator::I8x16Ne { .. }
            | Operator::I8x16LtS { .. }
            | Operator::I8x16LtU { .. }
            | Operator::I8x16GtS { .. }
            | Operator::I8x16GtU { .. }
            | Operator::I8x16LeS { .. }
            | Operator::I8x16LeU { .. }
            | Operator::I8x16GeS { .. }
            | Operator::I8x16GeU { .. }
            | Operator::I16x8Eq { .. }
            | Operator::I16x8Ne { .. }
            | Operator::I16x8LtS { .. }
            | Operator::I16x8LtU { .. }
            | Operator::I16x8GtS { .. }
            | Operator::I16x8GtU { .. }
            | Operator::I16x8LeS { .. }
            | Operator::I16x8LeU { .. }
            | Operator::I16x8GeS { .. }
            | Operator::I16x8GeU { .. }
            | Operator::I32x4Eq { .. }
            | Operator::I32x4Ne { .. }
            | Operator::I32x4LtS { .. }
            | Operator::I32x4LtU { .. }
            | Operator::I32x4GtS { .. }
            | Operator::I32x4GtU { .. }
            | Operator::I32x4LeS { .. }
            | Operator::I32x4LeU { .. }
            | Operator::I32x4GeS { .. }
            | Operator::I32x4GeU { .. }
            | Operator::I64x2Eq { .. }
            | Operator::I64x2Ne { .. }
            | Operator::I64x2LtS { .. }
            | Operator::I64x2GtS { .. }
            | Operator::I64x2LeS { .. }
            | Operator::I64x2GeS { .. }
            | Operator::F32x4Eq { .. }
            | Operator::F32x4Ne { .. }
            | Operator::F32x4Lt { .. }
            | Operator::F32x4Gt { .. }
            | Operator::F32x4Le { .. }
            | Operator::F32x4Ge { .. }
            | Operator::F64x2Eq { .. }
            | Operator::F64x2Ne { .. }
            | Operator::F64x2Lt { .. }
            | Operator::F64x2Gt { .. }
            | Operator::F64x2Le { .. }
            | Operator::F64x2Ge { .. }
            | Operator::V128Not { .. }
            | Operator::V128And { .. }
            | Operator::V128AndNot { .. }
            | Operator::V128Or { .. }
            | Operator::V128Xor { .. }
            | Operator::V128Bitselect { .. }
            | Operator::V128AnyTrue { .. }
            | Operator::I8x16Abs { .. }
            | Operator::I8x16Neg { .. }
            | Operator::I8x16Popcnt { .. }
            | Operator::I8x16AllTrue { .. }
            | Operator::I8x16Bitmask { .. }
            | Operator::I8x16NarrowI16x8S { .. }
            | Operator::I8x16NarrowI16x8U { .. }
            | Operator::I8x16Shl { .. }
            | Operator::I8x16ShrS { .. }
            | Operator::I8x16ShrU { .. }
            | Operator::I8x16Add { .. }
            | Operator::I8x16AddSatS { .. }
            | Operator::I8x16AddSatU { .. }
            | Operator::I8x16Sub { .. }
            | Operator::I8x16SubSatS { .. }
            | Operator::I8x16SubSatU { .. }
            | Operator::I8x16MinS { .. }
            | Operator::I8x16MinU { .. }
            | Operator::I8x16MaxS { .. }
            | Operator::I8x16MaxU { .. }
            | Operator::I8x16AvgrU { .. }
            | Operator::I16x8ExtAddPairwiseI8x16S { .. }
            | Operator::I16x8ExtAddPairwiseI8x16U { .. }
            | Operator::I16x8Abs { .. }
            | Operator::I16x8Neg { .. }
            | Operator::I16x8Q15MulrSatS { .. }
            | Operator::I16x8AllTrue { .. }
            | Operator::I16x8Bitmask { .. }
            | Operator::I16x8NarrowI32x4S { .. }
            | Operator::I16x8NarrowI32x4U { .. }
            | Operator::I16x8ExtendLowI8x16S { .. }
            | Operator::I16x8ExtendHighI8x16S { .. }
            | Operator::I16x8ExtendLowI8x16U { .. }
            | Operator::I16x8ExtendHighI8x16U { .. }
            | Operator::I16x8Shl { .. }
            | Operator::I16x8ShrS { .. }
            | Operator::I16x8ShrU { .. }
            | Operator::I16x8Add { .. }
            | Operator::I16x8AddSatS { .. }
            | Operator::I16x8AddSatU { .. }
            | Operator::I16x8Sub { .. }
            | Operator::I16x8SubSatS { .. }
            | Operator::I16x8SubSatU { .. }
            | Operator::I16x8Mul { .. }
            | Operator::I16x8MinS { .. }
            | Operator::I16x8MinU { .. }
            | Operator::I16x8MaxS { .. }
            | Operator::I16x8MaxU { .. }
            | Operator::I16x8AvgrU { .. }
            | Operator::I16x8ExtMulLowI8x16S { .. }
            | Operator::I16x8ExtMulHighI8x16S { .. }
            | Operator::I16x8ExtMulLowI8x16U { .. }
            | Operator::I16x8ExtMulHighI8x16U { .. }
            | Operator::I32x4ExtAddPairwiseI16x8S { .. }
            | Operator::I32x4ExtAddPairwiseI16x8U { .. }
            | Operator::I32x4Abs { .. }
            | Operator::I32x4Neg { .. }
            | Operator::I32x4AllTrue { .. }
            | Operator::I32x4Bitmask { .. }
            | Operator::I32x4ExtendLowI16x8S { .. }
            | Operator::I32x4ExtendHighI16x8S { .. }
            | Operator::I32x4ExtendLowI16x8U { .. }
            | Operator::I32x4ExtendHighI16x8U { .. }
            | Operator::I32x4Shl { .. }
            | Operator::I32x4ShrS { .. }
            | Operator::I32x4ShrU { .. }
            | Operator::I32x4Add { .. }
            | Operator::I32x4Sub { .. }
            | Operator::I32x4Mul { .. }
            | Operator::I32x4MinS { .. }
            | Operator::I32x4MinU { .. }
            | Operator::I32x4MaxS { .. }
            | Operator::I32x4MaxU { .. }
            | Operator::I32x4DotI16x8S { .. }
            | Operator::I32x4ExtMulLowI16x8S { .. }
            | Operator::I32x4ExtMulHighI16x8S { .. }
            | Operator::I32x4ExtMulLowI16x8U { .. }
            | Operator::I32x4ExtMulHighI16x8U { .. }
            | Operator::I64x2Abs { .. }
            | Operator::I64x2Neg { .. }
            | Operator::I64x2AllTrue { .. }
            | Operator::I64x2Bitmask { .. }
            | Operator::I64x2ExtendLowI32x4S { .. }
            | Operator::I64x2ExtendHighI32x4S { .. }
            | Operator::I64x2ExtendLowI32x4U { .. }
            | Operator::I64x2ExtendHighI32x4U { .. }
            | Operator::I64x2Shl { .. }
            | Operator::I64x2ShrS { .. }
            | Operator::I64x2ShrU { .. }
            | Operator::I64x2Add { .. }
            | Operator::I64x2Sub { .. }
            | Operator::I64x2Mul { .. }
            | Operator::I64x2ExtMulLowI32x4S { .. }
            | Operator::I64x2ExtMulHighI32x4S { .. }
            | Operator::I64x2ExtMulLowI32x4U { .. }
            | Operator::I64x2ExtMulHighI32x4U { .. }
            | Operator::F32x4Ceil { .. }
            | Operator::F32x4Floor { .. }
            | Operator::F32x4Trunc { .. }
            | Operator::F32x4Nearest { .. }
            | Operator::F32x4Abs { .. }
            | Operator::F32x4Neg { .. }
            | Operator::F32x4Sqrt { .. }
            | Operator::F32x4Add { .. }
            | Operator::F32x4Sub { .. }
            | Operator::F32x4Mul { .. }
            | Operator::F32x4Div { .. }
            | Operator::F32x4Min { .. }
            | Operator::F32x4Max { .. }
            | Operator::F32x4PMin { .. }
            | Operator::F32x4PMax { .. }
            | Operator::F64x2Ceil { .. }
            | Operator::F64x2Floor { .. }
            | Operator::F64x2Trunc { .. }
            | Operator::F64x2Nearest { .. }
            | Operator::F64x2Abs { .. }
            | Operator::F64x2Neg { .. }
            | Operator::F64x2Sqrt { .. }
            | Operator::F64x2Add { .. }
            | Operator::F64x2Sub { .. }
            | Operator::F64x2Mul { .. }
            | Operator::F64x2Div { .. }
            | Operator::F64x2Min { .. }
            | Operator::F64x2Max { .. }
            | Operator::F64x2PMin { .. }
            | Operator::F64x2PMax { .. }
            | Operator::I32x4TruncSatF32x4S { .. }
            | Operator::I32x4TruncSatF32x4U { .. }
            | Operator::F32x4ConvertI32x4S { .. }
            | Operator::F32x4ConvertI32x4U { .. }
            | Operator::I32x4TruncSatF64x2SZero { .. }
            | Operator::I32x4TruncSatF64x2UZero { .. }
            | Operator::F64x2ConvertLowI32x4S { .. }
            | Operator::F64x2ConvertLowI32x4U { .. }
            | Operator::F32x4DemoteF64x2Zero { .. }
            | Operator::F64x2PromoteLowF32x4 { .. }
            | Operator::I8x16RelaxedSwizzle { .. }
            | Operator::I32x4RelaxedTruncF32x4S { .. }
            | Operator::I32x4RelaxedTruncF32x4U { .. }
            | Operator::I32x4RelaxedTruncF64x2SZero { .. }
            | Operator::I32x4RelaxedTruncF64x2UZero { .. }
            | Operator::F32x4RelaxedMadd { .. }
            | Operator::F32x4RelaxedNmadd { .. }
            | Operator::F64x2RelaxedMadd { .. }
            | Operator::F64x2RelaxedNmadd { .. }
            | Operator::I8x16RelaxedLaneselect { .. }
            | Operator::I16x8RelaxedLaneselect { .. }
            | Operator::I32x4RelaxedLaneselect { .. }
            | Operator::I64x2RelaxedLaneselect { .. }
            | Operator::F32x4RelaxedMin { .. }
            | Operator::F32x4RelaxedMax { .. }
            | Operator::F64x2RelaxedMin { .. }
            | Operator::F64x2RelaxedMax { .. }
            | Operator::I16x8RelaxedQ15mulrS { .. }
            | Operator::I16x8RelaxedDotI8x16I7x16S { .. }
            | Operator::I32x4RelaxedDotI8x16I7x16AddS { .. } => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("simd").or_insert(0) += 1;
            }
            _ => {
                operator_count = operator_count
                    .checked_add(1)
                    .ok_or("operator count overflow")?;
                *inventory.entry("other").or_insert(0) += 1;
            }
        }
        prev_boundary = is_boundary;

        // The function-body end is the last operator in the body. The
        // operators reader reports EOF after it, so we detect it by checking
        // whether the reader is exhausted.
        if op_reader.eof() {
            // Exclude the function-body end from the operator count and the
            // inventory, so the two stay consistent.
            operator_count = operator_count
                .checked_sub(1)
                .expect("operator count underflow");
            if let Some(c) = inventory.get_mut("control") {
                *c = c.checked_sub(1).expect("control count underflow");
            }
            // The function-body `end` terminates the implicit function block;
            // nothing follows it, so it must not start a new basic block. The
            // one exception is an otherwise-empty body, where the single
            // counted block is the (empty) entry block and must be kept.
            if counted_as_leader && !is_first_op {
                basic_block_count = basic_block_count
                    .checked_sub(1)
                    .expect("basic block count underflow");
            }
            break;
        }
        is_first_op = false;
    }

    // Cyclomatic-complexity estimate: 1 + decision points, where a decision
    // point is each `if`, `br_if`, or `br_table`. `br_table` counts as one
    // decision point regardless of its target count.
    let cyclomatic_complexity = 1usize
        .checked_add(if_count)
        .and_then(|n| n.checked_add(br_if_count))
        .and_then(|n| n.checked_add(br_table_count))
        .ok_or("cyclomatic complexity overflow")?;

    Ok(MeasuredBody {
        body_len_bytes,
        local_decl_count,
        local_total,
        operator_count,
        max_control_depth,
        instruction_inventory: inventory.into_iter().filter(|(_, v)| *v > 0).collect(),
        direct_call_targets,
        indirect_call_sites,
        reference_call_sites,
        basic_block_count,
        conditional_branch_count,
        unconditional_branch_count,
        loop_count,
        if_count,
        cyclomatic_complexity,
    })
}

/// Whether an operator ends the current basic block, so the next operator
/// starts a new one.
///
/// Boundaries are: the block-introducing constructs (`block`, `loop`, `if`),
/// `else`, `end`, and the control transfers `br`, `br_if`, `br_table`,
/// `return`, and `unreachable`. `call` and its variants are not boundaries —
/// they return to the next instruction. The function-body `end` is a boundary
/// too, but nothing follows it, so it never contributes a block.
fn is_block_boundary(op: &wasmparser::Operator<'_>) -> bool {
    use wasmparser::Operator;
    matches!(
        op,
        Operator::Block { .. }
            | Operator::Loop { .. }
            | Operator::If { .. }
            | Operator::Else
            | Operator::End
            | Operator::Br { .. }
            | Operator::BrIf { .. }
            | Operator::BrTable { .. }
            | Operator::Return
            | Operator::Unreachable
    )
}

/// Resolve raw direct-call targets into deterministic call edges.
///
/// Repeated call sites to the same callee are aggregated into one edge with a
/// `call_count`, and the resulting edge list is sorted by callee index. An
/// index that names no function resolves to `CallTargetResolution::Invalid` —
/// reported, never dropped or panicked on.
fn resolve_call_edges(
    targets: Vec<u32>,
    imports: &[ImportEntry],
    imported_func_type_idx: &[u32],
    func_type_idx: &[u32],
    types: &[String],
) -> Vec<CallEdge> {
    let imported_func_count = imported_func_type_idx.len();

    // Aggregate identical callees so the edge list is bounded by distinct
    // targets, not by operator count. The order of first encounter is
    // irrelevant because the result is sorted below.
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for t in targets {
        *counts.entry(t).or_insert(0) += 1;
    }

    counts
        .into_iter()
        .map(|(callee_index, call_count)| {
            let resolution = resolve_call_target(
                callee_index,
                imports,
                imported_func_count,
                func_type_idx,
                types,
            );
            CallEdge {
                callee_index,
                call_count,
                resolution,
            }
        })
        .collect()
}

/// Resolve one callee index against the module's function index space.
///
/// Imported functions occupy the lowest indices, then locally defined
/// functions in declaration order. An index naming no function resolves to
/// `Invalid`.
fn resolve_call_target(
    callee_index: u32,
    imports: &[ImportEntry],
    imported_func_count: usize,
    func_type_idx: &[u32],
    types: &[String],
) -> CallTargetResolution {
    let i = callee_index as usize;
    if i < imported_func_count {
        // Resolves to an imported function: report which import.
        let mut count = 0usize;
        for imp in imports {
            if imp.kind == "function" {
                if count == i {
                    return CallTargetResolution::Imported {
                        module: imp.module.clone(),
                        name: imp.name.clone(),
                    };
                }
                count += 1;
            }
        }
        CallTargetResolution::Invalid
    } else {
        match i.checked_sub(imported_func_count) {
            Some(local) => match func_type_idx.get(local) {
                Some(type_idx) => CallTargetResolution::Defined {
                    defined_index: local,
                    signature: types.get(*type_idx as usize).cloned(),
                },
                None => CallTargetResolution::Invalid,
            },
            None => CallTargetResolution::Invalid,
        }
    }
}

/// Compute static reachability from the module's conservatively selected roots.
///
/// Reuses the already-resolved `code_body_metrics` direct-call graph, the
/// resolved exports, and the resolved start function. It never reparses the
/// module and never invents a root for runtime dispatch, indirect calls,
/// reference calls, host behavior, or framework entry points.
fn compute_reachability(
    exports: &[ExportEntry],
    start_function: Option<&StartFunction>,
    code_body_metrics: &[CodeBodyMetrics],
    imported_func_count: usize,
) -> Reachability {
    let defined_count = code_body_metrics.len();

    // Resolve a raw function index to (resolution, defined_index). Same
    // index-space rule as every other resolution in this module: imported
    // functions occupy the lowest indices, then defined functions in
    // declaration order.
    let resolve = |index: u32| -> (String, Option<usize>) {
        let i = index as usize;
        if i < imported_func_count {
            ("imported".to_string(), None)
        } else {
            match i.checked_sub(imported_func_count) {
                Some(local) if local < defined_count => ("defined".to_string(), Some(local)),
                _ => ("invalid".to_string(), None),
            }
        }
    };

    // Collect roots: the start function (when present) and exported functions.
    let mut roots: Vec<ReachabilityRoot> = Vec::new();
    if let Some(start) = start_function {
        let (resolution, defined_index) = match start.resolution.as_str() {
            // The resolved start detail already carries the declared index.
            "defined" => match start.function.as_ref() {
                Some(sig) => ("defined".to_string(), Some(sig.declared_index as usize)),
                None => resolve(start.index),
            },
            _ => resolve(start.index),
        };
        roots.push(ReachabilityRoot {
            kind: "start".to_string(),
            name: None,
            function_index: start.index,
            resolution,
            defined_index,
        });
    }
    for export in exports.iter().filter(|e| e.kind == "function") {
        let (resolution, defined_index) = resolve(export.index);
        roots.push(ReachabilityRoot {
            kind: "export".to_string(),
            name: Some(export.name.clone()),
            function_index: export.index,
            resolution,
            defined_index,
        });
    }
    // Deterministic order: start first, then exports by function index, then
    // by export name for any remaining ties.
    roots.sort_by(|a, b| {
        let rank = |k: &str| if k == "start" { 0 } else { 1 };
        rank(&a.kind)
            .cmp(&rank(&b.kind))
            .then(a.function_index.cmp(&b.function_index))
            .then(a.name.cmp(&b.name))
    });

    // Breadth-first traversal over direct-call edges from defined roots.
    let mut reached: BTreeSet<usize> = BTreeSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    for root in &roots {
        if let Some(d) = root.defined_index {
            queue.push_back(d);
        }
    }
    while let Some(d) = queue.pop_front() {
        if !reached.insert(d) {
            continue;
        }
        // Guard the lookup: a malformed module could in principle carry an
        // edge to a defined index with no body entry. Skip rather than panic.
        let Some(metrics) = code_body_metrics.get(d) else {
            continue;
        };
        for edge in &metrics.direct_calls {
            match &edge.resolution {
                CallTargetResolution::Defined { defined_index, .. } => {
                    if !reached.contains(defined_index) {
                        queue.push_back(*defined_index);
                    }
                }
                // Imported callees have no body in this module: the traversal
                // stops there. Invalid callees name nothing: also a stop.
                CallTargetResolution::Imported { .. } | CallTargetResolution::Invalid => {}
            }
        }
    }

    let reachable_defined: Vec<usize> = reached.iter().copied().collect();
    let unreachable_defined: Vec<usize> = (0..defined_count)
        .filter(|d| !reached.contains(d))
        .collect();

    Reachability {
        roots,
        reachable_defined,
        unreachable_defined,
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ModuleStructure {
    /// Defined (non-imported) memories: minimum and, if present, maximum pages.
    pub memories: Vec<MemoryBounds>,
    /// Defined (non-imported) tables: element type plus limits.
    pub tables: Vec<TableBounds>,
    /// Defined (non-imported) globals: mutability and value type.
    pub globals: Vec<GlobalEntry>,
    /// Number of active/passive data segments.
    pub data_segments: usize,
    /// Per-segment details, in declaration order. Empty when the module has
    /// no data section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_segment_details: Vec<DataSegment>,
    /// Number of element segments.
    pub element_segments: usize,
    /// Per-segment details, in declaration order. Empty when the module has
    /// no element section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub element_segment_details: Vec<ElementSegment>,
    /// Function index of the start section, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_func: Option<u32>,
    /// Resolved detail of the start function, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_function: Option<StartFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryBounds {
    pub min_pages: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_pages: Option<u64>,
    /// True when this memory is 64-bit (memory64 proposal).
    pub is64: bool,
    /// True when this memory is shared (threads proposal).
    #[serde(default)]
    pub shared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TableBounds {
    pub element_type: String,
    pub min_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobalEntry {
    pub mutable: bool,
    pub value_type: String,
}

/// A single compatibility or resource finding.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Stable machine-readable code (e.g. `float_ops`, `memory64`).
    pub code: String,
    /// `incompatible`, `unsupported`, or `unknown`.
    pub severity: String,
    /// Concise human-readable explanation.
    pub message: String,
}

/// Which compatibility areas were actually checked, and which were not.
///
/// `checked` lists areas where a rule ran against this module. `not_checked`
/// lists areas with no implemented rule. An empty `findings` array means no
/// implemented rule reported a finding — it does NOT mean the module is
/// Soroban-compatible, because `not_checked` areas were never evaluated.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Coverage {
    /// Areas where a rule ran. Sorted alphabetically for deterministic output.
    pub checked: Vec<String>,
    /// Areas with no implemented rule. Sorted alphabetically.
    pub not_checked: Vec<String>,
}

/// Resource and compatibility analysis for a WASM module.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Analysis {
    /// Imported memories (module::name pairs).
    pub imported_memories: Vec<String>,
    /// Defined memories with their bounds.
    pub defined_memories: Vec<MemoryBounds>,
    /// Imported tables (module::name pairs).
    pub imported_tables: Vec<String>,
    /// Defined tables with their bounds.
    pub defined_tables: Vec<TableBounds>,
    /// Imported globals (module::name pairs).
    pub imported_globals: Vec<String>,
    /// Defined globals.
    pub defined_globals: Vec<GlobalEntry>,
    /// Total function count (imported + defined).
    pub function_count: usize,
    /// Data segment count.
    pub data_segment_count: usize,
    /// Element segment count.
    pub element_segment_count: usize,
    /// Compatibility findings.
    pub findings: Vec<Finding>,
    /// Which areas were checked vs not checked.
    pub coverage: Coverage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportEntry {
    pub module: String,
    pub name: String,
    pub kind: String,
    /// Raw type signature when the import is a function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_sig: Option<String>,
    /// Type index into the type section when the import is a function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_index: Option<u32>,
    /// Memory details when the import is a memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryBounds>,
    /// Table details when the import is a table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<TableBounds>,
    /// Global details when the import is a global.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<GlobalEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub kind: String,
    pub index: u32,
    /// Signature when the export is a function (resolved from the module's
    /// type section via the full function index space, imports included).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_sig: Option<String>,
    /// Type index into the type section when the export is a function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_index: Option<u32>,
    /// Memory details when the export is a memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryBounds>,
    /// Table details when the export is a table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<TableBounds>,
    /// Global details when the export is a global.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<GlobalEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomSection {
    pub name: String,
    pub len_bytes: usize,
}

/// Detailed entry for a single custom section, in declaration order.
///
/// `len_bytes` is the length of the custom section's data payload as returned
/// by `wasmparser`'s `CustomSectionReader::data()` — i.e., the bytes after the
/// encoded section name, not including the name itself or the section header.
#[derive(Debug, Serialize, Deserialize)]
pub struct CustomSectionDetail {
    /// 0-based position in the custom-section list (declaration order).
    pub index: usize,
    /// Section name.
    pub name: String,
    /// Data payload length in bytes (excluding the encoded name).
    pub len_bytes: usize,
    /// Classification based on the section name. Well-known names are
    /// classified accordingly; everything else is `unknown`. No security
    /// or trust inference is made from the name.
    #[serde(rename = "classification")]
    pub kind: CustomSectionKind,
}

/// Classification of a custom section based on its name.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CustomSectionKind {
    /// The WASM "name" section (function names, local names, etc.).
    Name,
    /// The WASM "producers" section (toolchain metadata).
    Producers,
    /// Any other custom section.
    Unknown,
}

/// Classify a custom section by name.
///
/// Only the two standardized WASM custom-section names are classified:
/// `name` and `producers`. Everything else — including Soroban-specific
/// sections such as `contractspecv0` — stays `unknown`, because this tool
/// does not decode them here and must not imply anything about their
/// contents from the name alone.
fn classify_custom_section_name(name: &str) -> CustomSectionKind {
    match name {
        "name" => CustomSectionKind::Name,
        "producers" => CustomSectionKind::Producers,
        _ => CustomSectionKind::Unknown,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionSig {
    pub index: u32,
    pub params: Vec<String>,
    pub results: Vec<String>,
}

/// Bounded structural metrics for one defined function body.
///
/// These are static, parse-time counts of the encoded body. They describe the
/// shape of the code as written, not what it costs to run: they are not gas
/// estimates, execution-time proxies, complexity scores, or security signals.
#[derive(Debug, Serialize, Deserialize)]
pub struct CodeBodyMetrics {
    /// 0-based position among defined functions (declaration order).
    pub defined_index: usize,
    /// Raw WASM function index (imported functions occupy the lowest indices,
    /// so this is `imported_function_count + defined_index`).
    pub function_index: u32,
    /// Rendered signature when the function's type was resolved; null when
    /// unavailable. Never guessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Body byte length: the encoded size of the function body, including the
    /// locals declarations and the operator stream, excluding the body-length
    /// prefix itself.
    pub body_len_bytes: usize,
    /// Number of local declarations (distinct `count:type` pairs).
    pub local_decl_count: usize,
    /// Total number of local variables declared (sum of all declaration counts).
    pub local_total: usize,
    /// Number of operators in the body, excluding the trailing `end` of the
    /// function body itself.
    pub operator_count: usize,
    /// Maximum structured-control nesting depth reached by `block`, `loop`,
    /// and `if` operators, matched against their `end` operators. The implicit
    /// function-body block is not counted.
    pub max_control_depth: usize,
    /// Per-family instruction counts, sorted by family name. Each operator is
    /// counted in exactly one family — classifications are exclusive, not
    /// overlapping. Omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub instruction_inventory: BTreeMap<String, usize>,
    /// Direct call sites in the body, counting repeated calls to the same
    /// callee separately. This is `call` + `return_call` occurrences, i.e. the
    /// sum of `call_count` over `direct_calls`. It is distinct from
    /// `direct_calls.len()`, which counts distinct callees.
    pub direct_call_site_count: usize,
    /// Direct call edges, one entry per distinct callee, sorted by callee
    /// index. `call_count` aggregates repeated call sites to the same target.
    /// Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_calls: Vec<CallEdge>,
    /// Number of `call_indirect` / `return_call_indirect` sites in the body.
    /// These name a type, not a target, so no edge is invented for them.
    /// Omitted when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub indirect_call_sites: usize,
    /// Number of `call_ref` / `return_call_ref` sites in the body. The callee
    /// is a runtime value, not a static index, so no edge is invented for them.
    /// Omitted when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reference_call_sites: usize,
    /// Count of syntactic basic blocks. A basic block is a maximal run of
    /// operators with no interior control-flow boundary. Leaders (the first
    /// operator of a block) are: the function's first operator, the operator
    /// after each `block` / `loop` / `if`, `else`, `end`, `br`, `br_if`,
    /// `br_table`, `return`, or `unreachable`. Branch targets are not resolved
    /// to instructions, so this is a syntactic count, not a control-flow-graph
    /// block count.
    pub basic_block_count: usize,
    /// `br_if` sites plus `if` constructs. Each is a two-way decision point.
    pub conditional_branch_count: usize,
    /// `br`, `br_table`, `return`, and `unreachable` sites. Each transfers
    /// control unconditionally, so control does not fall through it.
    pub unconditional_branch_count: usize,
    /// `loop` constructs.
    pub loop_count: usize,
    /// `if` constructs. A subset of `conditional_branch_count`; the remainder
    /// of that count is `br_if`.
    pub if_count: usize,
    /// Cyclomatic-complexity estimate: `1 + if_count + br_if_count +
    /// br_table_count`, i.e. one plus the number of decision points. Each
    /// `br_table` counts as a single decision point regardless of how many
    /// targets it names, and `br` / `return` / `unreachable` are not decision
    /// points. It is not a full control-flow-graph computation and is not a
    /// measure of execution cost, security, or runtime performance.
    pub cyclomatic_complexity: usize,
}

/// One direct call edge from a defined function body to a callee.
///
/// Repeated call sites to the same callee are aggregated into a single edge
/// with `call_count` reflecting the number of sites, so the edge list stays
/// bounded by the number of distinct callees rather than the number of
/// operators.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CallEdge {
    /// Raw WASM function index of the callee (imported functions occupy the
    /// lowest indices, then defined functions in declaration order).
    pub callee_index: u32,
    /// How many direct call sites in this body target `callee_index`.
    pub call_count: usize,
    /// How the callee index resolved against the module's function index space.
    pub resolution: CallTargetResolution,
}

/// Resolution of a direct call target against the module's function index space.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CallTargetResolution {
    /// Resolves to an imported function; carries the import's module and name.
    Imported { module: String, name: String },
    /// Resolves to a locally defined function; carries its 0-based position
    /// among defined functions and its rendered signature.
    Defined {
        defined_index: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    /// The index names no function in this module's index space. Reported
    /// rather than dropped or panicked on.
    Invalid,
}

/// Serde helper: `true` when the value is zero, so zero-valued counters are
/// omitted from JSON.
fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Consolidated, deterministic summary of results already computed by
/// `inspect`.
///
/// Every field is derived from data the analyzer has already produced: the
/// summary never reparses the module and never runs a new analysis. It exists
/// so a consumer can read the headline counts without walking the underlying
/// arrays.
///
/// Counts that mirror a single source field are documented as such. Optional
/// sub-objects are omitted rather than zero-filled when their source is
/// absent, so "unavailable" is never confused with "zero".
///
/// This is a structural roll-up only. It carries no security score, safety
/// verdict, or compatibility claim.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AnalysisSummary {
    /// Number of custom sections. Mirrors `custom_sections.len()`.
    pub custom_section_count: usize,
    /// Imported functions: `imports` entries whose `kind` is `"function"`.
    pub imported_function_count: usize,
    /// Exported functions: `exports` entries whose `kind` is `"function"`.
    pub exported_function_count: usize,
    /// Locally defined functions, i.e. functions with a body. Mirrors
    /// `code_body_metrics.len()`.
    pub defined_function_count: usize,
    /// `imported_function_count + defined_function_count` — the size of the
    /// module's function index space.
    pub total_function_count: usize,
    /// Sum of `code_body_metrics[].body_len_bytes`. Zero when the module
    /// defines no functions.
    pub total_body_bytes: usize,
    /// Sum of `code_body_metrics[].operator_count`. Each function-body `end`
    /// is already excluded from the per-function count, so the aggregate
    /// excludes all of them.
    pub total_operator_count: usize,
    /// Sum of `code_body_metrics[].local_total`: every declared local across
    /// all defined functions.
    pub total_local_count: usize,
    /// Per-family instruction counts summed across all defined functions,
    /// sorted by family name. The families are the same exclusive
    /// classification each body uses in `instruction_inventory`, so these
    /// values sum to `total_operator_count`. Omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub instruction_family_totals: BTreeMap<String, usize>,
    /// True when a `contractspecv0` custom section is present. Mirrors
    /// `interface.has_contract_spec`.
    pub has_contract_spec: bool,
    /// Structure counts, mirrored from the resolved `structure` object.
    /// Omitted when the module declares no memories, tables, globals,
    /// segments, or start function — i.e. when `structure` itself is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structure: Option<StructureSummary>,
    /// Reachability counts. Omitted when the module defines no functions —
    /// i.e. when `reachability` itself is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<ReachabilitySummary>,
    /// Number of compatibility findings in `analysis`. Omitted when `analysis`
    /// was not populated: the library-level `inspect` does not run it, only
    /// the CLI's `inspect` command does. Contract-spec consistency findings
    /// live in the separate `ConsistencyReport` produced by
    /// `soroban::consistency`, which `inspect` does not compute, and are
    /// therefore not summarized here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_finding_count: Option<usize>,
}

/// Module-structure counts, mirrored from `ModuleStructure`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StructureSummary {
    /// Defined (non-imported) memories. Mirrors `structure.memories.len()`.
    pub memory_count: usize,
    /// Defined (non-imported) tables. Mirrors `structure.tables.len()`.
    pub table_count: usize,
    /// Defined (non-imported) globals. Mirrors `structure.globals.len()`.
    pub global_count: usize,
    /// Mirrors `structure.data_segments`.
    pub data_segment_count: usize,
    /// Mirrors `structure.element_segments`.
    pub element_segment_count: usize,
    /// True when the module has a start section. Mirrors
    /// `structure.start_func.is_some()`.
    pub has_start_function: bool,
}

/// Reachability counts, mirrored from `Reachability`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReachabilitySummary {
    /// Known roots: the start function (when present and valid) plus exported
    /// functions. Mirrors `reachability.roots.len()`.
    pub root_count: usize,
    /// Defined functions reached from those roots. Mirrors
    /// `reachability.reachable_defined.len()`.
    pub reachable_defined_count: usize,
    /// Defined functions not reached from those roots. Mirrors
    /// `reachability.unreachable_defined.len()`. Not a dead-code judgement.
    pub unreachable_defined_count: usize,
}

impl AnalysisSummary {
    /// A zero-valued summary used as the placeholder while a report is being
    /// assembled. `inspect` always overwrites it before returning.
    fn empty() -> Self {
        Self {
            custom_section_count: 0,
            imported_function_count: 0,
            exported_function_count: 0,
            defined_function_count: 0,
            total_function_count: 0,
            total_body_bytes: 0,
            total_operator_count: 0,
            total_local_count: 0,
            instruction_family_totals: BTreeMap::new(),
            has_contract_spec: false,
            structure: None,
            reachability: None,
            analysis_finding_count: None,
        }
    }
}

/// Build the consolidated summary from an already-resolved report.
///
/// Pure derivation: it reads only fields already present on `report`, so it
/// can neither reparse the module nor alter any existing result. Checked
/// arithmetic is used throughout, so a malformed aggregate surfaces as a typed
/// error rather than a panic or a silently wrapped count.
///
/// Callers that mutate the report after `inspect` — for example the CLI, which
/// attaches `analysis` — can call this again to refresh the summary.
pub fn build_analysis_summary(report: &WasmReport) -> Result<AnalysisSummary, InspectError> {
    let overflow = |what: &str| InspectError::Malformed(format!("summary {what} overflow"));

    let imported_function_count = report
        .imports
        .iter()
        .filter(|i| i.kind == "function")
        .count();
    let exported_function_count = report
        .exports
        .iter()
        .filter(|e| e.kind == "function")
        .count();
    let defined_function_count = report.code_body_metrics.len();

    let mut total_body_bytes = 0usize;
    let mut total_operator_count = 0usize;
    let mut total_local_count = 0usize;
    let mut instruction_family_totals: BTreeMap<String, usize> = BTreeMap::new();
    for m in &report.code_body_metrics {
        total_body_bytes = total_body_bytes
            .checked_add(m.body_len_bytes)
            .ok_or_else(|| overflow("body byte total"))?;
        total_operator_count = total_operator_count
            .checked_add(m.operator_count)
            .ok_or_else(|| overflow("operator total"))?;
        total_local_count = total_local_count
            .checked_add(m.local_total)
            .ok_or_else(|| overflow("local total"))?;
        for (family, count) in &m.instruction_inventory {
            let slot = instruction_family_totals.entry(family.clone()).or_insert(0);
            *slot = slot
                .checked_add(*count)
                .ok_or_else(|| overflow("instruction family total"))?;
        }
    }

    let structure = report.structure.as_ref().map(|s| StructureSummary {
        memory_count: s.memories.len(),
        table_count: s.tables.len(),
        global_count: s.globals.len(),
        data_segment_count: s.data_segments,
        element_segment_count: s.element_segments,
        has_start_function: s.start_func.is_some(),
    });

    let reachability = report.reachability.as_ref().map(|r| ReachabilitySummary {
        root_count: r.roots.len(),
        reachable_defined_count: r.reachable_defined.len(),
        unreachable_defined_count: r.unreachable_defined.len(),
    });

    // Prefer the already-resolved interface flag so the two cannot diverge;
    // fall back to the same rule when the interface is absent.
    let has_contract_spec = report
        .interface
        .as_ref()
        .map(|i| i.has_contract_spec)
        .unwrap_or_else(|| {
            report
                .custom_sections
                .iter()
                .any(|s| s.name == "contractspecv0")
        });

    let analysis_finding_count = report.analysis.as_ref().map(|a| a.findings.len());

    Ok(AnalysisSummary {
        custom_section_count: report.custom_sections.len(),
        imported_function_count,
        exported_function_count,
        defined_function_count,
        total_function_count: imported_function_count
            .checked_add(defined_function_count)
            .ok_or_else(|| overflow("function total"))?,
        total_body_bytes,
        total_operator_count,
        total_local_count,
        instruction_family_totals,
        has_contract_spec,
        structure,
        reachability,
        analysis_finding_count,
    })
}

/// Static reachability of defined functions from conservatively selected roots.
///
/// Roots are limited to the module's start function (when present and valid)
/// and its exported functions. Traversal follows direct `call` / `return_call`
/// edges only, through the already-decoded direct-call graph — the WASM is
/// never reparsed.
///
/// "Unreachable" means only *not reached from the selected static roots*.
/// It is NOT a dead-code judgement and NOT a safe-to-remove signal: functions
/// reached at runtime through `call_indirect`, `call_ref`, host invocation, or
/// a framework's own entry points may legitimately appear unreachable here.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Reachability {
    /// Known roots, in deterministic order (start first, then exports by
    /// index). Imported roots are listed with their resolution so the
    /// distinction from defined roots stays visible.
    pub roots: Vec<ReachabilityRoot>,
    /// Defined functions reached from the roots, sorted ascending by defined
    /// index.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reachable_defined: Vec<usize>,
    /// Defined functions not reached from the roots, sorted ascending by
    /// defined index. Absence here means every defined function was reached.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreachable_defined: Vec<usize>,
}

/// One known root of the reachability analysis.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReachabilityRoot {
    /// `"start"` for the WASM start function, `"export"` for an exported
    /// function.
    pub kind: String,
    /// Export name; present only when `kind == "export"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Raw WASM function index (imported functions occupy the lowest indices,
    /// then defined functions in declaration order).
    pub function_index: u32,
    /// `"defined"`, `"imported"`, or `"invalid"`.
    pub resolution: String,
    /// 0-based position among defined functions; present only when
    /// `resolution == "defined"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defined_index: Option<usize>,
}

/// Errors that can occur during inspection.
#[derive(Debug)]
pub enum InspectError {
    /// File could not be read from disk.
    Io(io::Error),
    /// WASM binary was structurally invalid or truncated.
    Malformed(String),
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InspectError::Io(e) => write!(f, "io error: {e}"),
            InspectError::Malformed(msg) => write!(f, "malformed wasm: {msg}"),
        }
    }
}

impl std::error::Error for InspectError {}

impl From<io::Error> for InspectError {
    fn from(e: io::Error) -> Self {
        InspectError::Io(e)
    }
}

/// Walk the WASM module and collect structural facts without validating code bodies.
///
/// `validate` controls whether we also run the full validator, which is stricter
/// (checks function bodies, types, etc.) but slower.
pub fn inspect(bytes: &[u8], validate: bool) -> Result<WasmReport, InspectError> {
    let mut report = WasmReport {
        size_bytes: bytes.len(),
        imports: Vec::new(),
        exports: Vec::new(),
        custom_sections: Vec::new(),
        custom_section_details: Vec::new(),
        code_body_metrics: Vec::new(),
        reachability: None,
        functions: Vec::new(),
        structure: None,
        analysis: None,
        interface: None,
        summary: AnalysisSummary::empty(),
    };

    // Module-structure accumulators (only emitted when non-empty).
    let mut memories: Vec<MemoryBounds> = Vec::new();
    let mut tables: Vec<TableBounds> = Vec::new();
    let mut globals: Vec<GlobalEntry> = Vec::new();
    let mut data_segments: usize = 0;
    let mut data_segment_details: Vec<DataSegment> = Vec::new();
    let mut element_segments: usize = 0;
    // Raw element segments are collected during the payload loop and resolved
    // after it, because function-index resolution needs the complete function
    // index space (imports first, then defined functions).
    let mut raw_element_segments: Vec<RawElementSegment> = Vec::new();
    let mut start_func: Option<u32> = None;
    // Raw code-section bodies are collected during the payload loop and
    // resolved after it, because metrics need the complete function index
    // space (imports first, then defined functions).
    let mut raw_code_bodies: Vec<wasmparser::FunctionBody<'_>> = Vec::new();

    // Collect all type signatures first so imports/exports can reference them.
    let mut types: Vec<String> = Vec::new();
    let mut func_type_idx: Vec<u32> = Vec::new();

    // Per-kind index spaces. WASM indices span imports first, then locally
    // defined items, so exported indices must be resolved against these
    // concatenated spaces rather than the defined-only vectors alone.
    let mut imported_func_type_idx: Vec<u32> = Vec::new();
    let mut imported_memories: Vec<MemoryBounds> = Vec::new();
    let mut imported_tables: Vec<TableBounds> = Vec::new();
    let mut imported_globals: Vec<GlobalEntry> = Vec::new();
    // Export references are resolved after the payload loop so section order
    // cannot affect the result.
    let mut export_refs: Vec<(String, &'static str, u32)> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| InspectError::Malformed(e.to_string()))?;
        match payload {
            Payload::Version { .. } | Payload::End(_) => {}
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group = group.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    collect_type_sigs(&group, &mut types);
                }
            }
            Payload::CoreTypeSection(reader) => {
                for core_ty in reader {
                    let core_ty = core_ty.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    match &core_ty {
                        CoreType::Sub(sub) => collect_subtype_sigs(sub, &mut types),
                        CoreType::Module(_) => types.push("(module type)".to_string()),
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    let (kind, sig, type_index, memory, table, global) = match import.ty {
                        TypeRef::Func(idx) => (
                            "function".to_string(),
                            types.get(idx as usize).cloned(),
                            Some(idx),
                            None,
                            None,
                            None,
                        ),
                        TypeRef::Table(t) => (
                            "table".to_string(),
                            None,
                            None,
                            None,
                            Some(TableBounds {
                                element_type: format!("{:?}", t.element_type),
                                min_size: u64::from(t.initial),
                                max_size: t.maximum.map(u64::from),
                            }),
                            None,
                        ),
                        TypeRef::Memory(m) => (
                            "memory".to_string(),
                            None,
                            None,
                            Some(MemoryBounds {
                                min_pages: m.initial,
                                max_pages: m.maximum,
                                is64: m.memory64,
                                shared: m.shared,
                            }),
                            None,
                            None,
                        ),
                        TypeRef::Global(g) => (
                            "global".to_string(),
                            None,
                            None,
                            None,
                            None,
                            Some(GlobalEntry {
                                mutable: g.mutable,
                                value_type: format!("{:?}", g.content_type),
                            }),
                        ),
                        TypeRef::Tag(_) => ("tag".to_string(), None, None, None, None, None),
                    };
                    report.imports.push(ImportEntry {
                        module: import.module.to_string(),
                        name: import.name.to_string(),
                        kind,
                        type_sig: sig,
                        type_index,
                        memory,
                        table,
                        global,
                    });
                    // Imports occupy the lowest slots of each index space.
                    if let Some(ti) = type_index {
                        imported_func_type_idx.push(ti);
                    }
                    if let Some(m) = report.imports.last().and_then(|i| i.memory.clone()) {
                        imported_memories.push(m);
                    }
                    if let Some(t) = report.imports.last().and_then(|i| i.table.clone()) {
                        imported_tables.push(t);
                    }
                    if let Some(g) = report.imports.last().and_then(|i| i.global.clone()) {
                        imported_globals.push(g);
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for f in reader {
                    let idx = f.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    func_type_idx.push(idx);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    let kind = match export.kind {
                        wasmparser::ExternalKind::Func => "function",
                        wasmparser::ExternalKind::Table => "table",
                        wasmparser::ExternalKind::Memory => "memory",
                        wasmparser::ExternalKind::Global => "global",
                        wasmparser::ExternalKind::Tag => "tag",
                    };
                    export_refs.push((export.name.to_string(), kind, export.index));
                }
            }
            Payload::CustomSection(reader) => {
                report.custom_sections.push(CustomSection {
                    name: reader.name().to_string(),
                    len_bytes: reader.data().len(),
                });
                let kind = classify_custom_section_name(reader.name());
                report.custom_section_details.push(CustomSectionDetail {
                    index: report.custom_section_details.len(),
                    name: reader.name().to_string(),
                    len_bytes: reader.data().len(),
                    kind,
                });
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem = mem.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    memories.push(MemoryBounds {
                        min_pages: mem.initial,
                        max_pages: mem.maximum,
                        is64: mem.memory64,
                        shared: mem.shared,
                    });
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table = table.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    tables.push(TableBounds {
                        element_type: format!("{:?}", table.ty.element_type),
                        min_size: u64::from(table.ty.initial),
                        max_size: table.ty.maximum.map(u64::from),
                    });
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let global = global.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    globals.push(GlobalEntry {
                        mutable: global.ty.mutable,
                        value_type: format!("{:?}", global.ty.content_type),
                    });
                }
            }
            Payload::DataSection(reader) => {
                for segment in reader {
                    let seg = segment.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    let index = data_segments;
                    data_segments += 1;
                    let (mode, memory_index, offset) = match seg.kind {
                        wasmparser::DataKind::Passive => (DataSegmentMode::Passive, None, None),
                        wasmparser::DataKind::Active {
                            memory_index,
                            offset_expr,
                        } => {
                            let offset = match classify_const_expr(&offset_expr) {
                                Ok(expr) => expr,
                                Err(reason) => OffsetExpr::Unsupported { reason },
                            };
                            (DataSegmentMode::Active, Some(memory_index), Some(offset))
                        }
                    };
                    data_segment_details.push(DataSegment {
                        index,
                        mode,
                        memory_index,
                        offset,
                        payload_len: seg.data.len(),
                    });
                }
            }
            Payload::ElementSection(reader) => {
                for segment in reader {
                    let seg = segment.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    let index = element_segments;
                    element_segments += 1;
                    raw_element_segments.push(parse_element_segment(index, seg));
                }
            }
            Payload::StartSection { func, .. } => {
                start_func = Some(func);
            }
            Payload::CodeSectionEntry(body) => {
                // Body metrics are collected here and resolved after the loop,
                // because function-index resolution needs the complete index
                // space (imports first, then defined functions).
                raw_code_bodies.push(body);
            }
            _ => {}
        }
    }

    // Resolve exports now that every index space is fully known. WASM index
    // spaces are: imported items first (in import order), then locally
    // defined items. An export index therefore selects from the concatenated
    // space, not from the defined-only vectors.
    for (name, kind, index) in export_refs {
        let mut entry = ExportEntry {
            name,
            kind: kind.to_string(),
            index,
            type_sig: None,
            type_index: None,
            memory: None,
            table: None,
            global: None,
        };
        match kind {
            "function" => {
                // Function index space: imported funcs, then defined funcs
                // (whose type index lives in `func_type_idx`).
                let type_idx = {
                    let i = index as usize;
                    if i < imported_func_type_idx.len() {
                        Some(imported_func_type_idx[i])
                    } else {
                        func_type_idx.get(i - imported_func_type_idx.len()).copied()
                    }
                };
                entry.type_index = type_idx;
                entry.type_sig = type_idx.and_then(|t| types.get(t as usize).cloned());
            }
            "memory" => {
                let i = index as usize;
                entry.memory = if i < imported_memories.len() {
                    Some(imported_memories[i].clone())
                } else {
                    memories.get(i - imported_memories.len()).cloned()
                };
            }
            "table" => {
                let i = index as usize;
                entry.table = if i < imported_tables.len() {
                    Some(imported_tables[i].clone())
                } else {
                    tables.get(i - imported_tables.len()).cloned()
                };
            }
            "global" => {
                let i = index as usize;
                entry.global = if i < imported_globals.len() {
                    Some(imported_globals[i].clone())
                } else {
                    globals.get(i - imported_globals.len()).cloned()
                };
            }
            _ => {}
        }
        report.exports.push(entry);
    }

    // Resolve the start function now that every index space is fully known.
    // Same index-space rule as exports: imported functions occupy the lowest
    // indices, then defined functions in declaration order.
    let start_function = start_func.map(|index| {
        let i = index as usize;
        let mut detail = StartFunction {
            index,
            resolution: "invalid".to_string(),
            import: None,
            function: None,
        };
        if i < imported_func_type_idx.len() {
            // Resolves to an imported function: report which import.
            let mut count = 0usize;
            for imp in &report.imports {
                if imp.kind == "function" {
                    if count == i {
                        detail.resolution = "imported".to_string();
                        detail.import = Some(ImportRef {
                            module: imp.module.clone(),
                            name: imp.name.clone(),
                        });
                        break;
                    }
                    count += 1;
                }
            }
        } else if let Some(local) = i.checked_sub(imported_func_type_idx.len()) {
            if let Some(type_idx) = func_type_idx.get(local) {
                detail.resolution = "defined".to_string();
                detail.function = Some(StartFunctionSig {
                    declared_index: local as u32,
                    signature: types
                        .get(*type_idx as usize)
                        .cloned()
                        .unwrap_or_else(|| "<unknown>".to_string()),
                });
            }
        }
        detail
    });

    // Resolve element segments now that every index space is fully known.
    // Same index-space rule as exports and the start function: imported
    // functions occupy the lowest indices, then defined functions in
    // declaration order.
    let element_segment_details: Vec<ElementSegment> = raw_element_segments
        .into_iter()
        .map(|raw| {
            resolve_element_segment(
                raw,
                &imported_func_type_idx,
                &func_type_idx,
                &report.imports,
                &types,
            )
        })
        .collect();

    // Resolve code-body metrics now that every index space is fully known.
    // Same index-space rule as exports: imported functions occupy the lowest
    // indices, then defined functions in declaration order. Only defined
    // functions have bodies in the module; imports carry no code here.
    let imported_func_count = imported_func_type_idx.len();
    report.code_body_metrics = raw_code_bodies
        .into_iter()
        .enumerate()
        .map(|(defined_index, body)| {
            let function_index = imported_func_count as u64 + defined_index as u64;
            let function_index = u32::try_from(function_index)
                .map_err(|_| InspectError::Malformed("function index overflow".to_string()))?;
            let signature = func_type_idx
                .get(defined_index)
                .and_then(|t| types.get(*t as usize).cloned());
            let metrics = measure_code_body(body).map_err(InspectError::Malformed)?;
            Ok(CodeBodyMetrics {
                defined_index,
                function_index,
                signature,
                body_len_bytes: metrics.body_len_bytes,
                local_decl_count: metrics.local_decl_count,
                local_total: metrics.local_total,
                operator_count: metrics.operator_count,
                max_control_depth: metrics.max_control_depth,
                instruction_inventory: metrics
                    .instruction_inventory
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                // Total direct call sites, derived from the collected raw
                // targets before they are aggregated into edges.
                direct_call_site_count: metrics.direct_call_targets.len(),
                direct_calls: resolve_call_edges(
                    metrics.direct_call_targets,
                    &report.imports,
                    &imported_func_type_idx,
                    &func_type_idx,
                    &types,
                ),
                indirect_call_sites: metrics.indirect_call_sites,
                reference_call_sites: metrics.reference_call_sites,
                basic_block_count: metrics.basic_block_count,
                conditional_branch_count: metrics.conditional_branch_count,
                unconditional_branch_count: metrics.unconditional_branch_count,
                loop_count: metrics.loop_count,
                if_count: metrics.if_count,
                cyclomatic_complexity: metrics.cyclomatic_complexity,
            })
        })
        .collect::<Result<Vec<_>, InspectError>>()?;

    // Static reachability from the module's conservatively selected roots
    // (start function + exported functions), over the direct-call graph that
    // was just built. Emitted only when the module defines at least one
    // function, so modules without bodies keep the previous JSON shape.
    if !report.code_body_metrics.is_empty() {
        report.reachability = Some(compute_reachability(
            &report.exports,
            start_function.as_ref(),
            &report.code_body_metrics,
            imported_func_count,
        ));
    }

    // Emit the structure summary only when the module declares any of these
    // items, so modules without them keep the previous JSON shape.
    if !memories.is_empty()
        || !tables.is_empty()
        || !globals.is_empty()
        || data_segments > 0
        || element_segments > 0
        || start_func.is_some()
    {
        report.structure = Some(ModuleStructure {
            memories,
            tables,
            globals,
            data_segments,
            data_segment_details,
            element_segments,
            element_segment_details,
            start_func,
            start_function,
        });
    }

    // Build function signatures: imported funcs come first in the index space.
    let imported_funcs = report
        .imports
        .iter()
        .filter(|i| i.kind == "function")
        .count() as u32;
    for (i, type_idx) in func_type_idx.iter().enumerate() {
        let index = imported_funcs + i as u32;
        let sig = types
            .get(*type_idx as usize)
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        report.functions.push(FunctionSig {
            index,
            params: vec![sig],
            results: Vec::new(),
        });
    }

    if validate {
        let mut validator = Validator::new_with_features(WasmFeatures::all());
        validator
            .validate_all(bytes)
            .map_err(|e| InspectError::Malformed(format!("validation failed: {e}")))?;
    }

    // Interface summary is derived from the resolved import/export vectors, so
    // it is built last and never touches the raw bytes.
    report.interface = Some(build_interface_summary(&report));

    // Consolidated summary, built last so it sees the fully-resolved report.
    // Pure derivation: no reparsing, no new analysis.
    report.summary = build_analysis_summary(&report)?;

    Ok(report)
}

/// Build the developer-facing interface summary from an already-resolved
/// report.
///
/// This is a pure derivation: it reads only `report.imports` and
/// `report.exports`, never the raw bytes, so it can neither reparse the module
/// nor re-do index resolution. Missing signatures stay `None` (reported as
/// unavailable) rather than being guessed.
pub fn build_interface_summary(report: &WasmReport) -> InterfaceSummary {
    let count_by_kind = |entries: Vec<&str>| -> Vec<KindCount> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for kind in entries {
            *counts.entry(kind).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(kind, count)| KindCount {
                kind: kind.to_string(),
                count,
            })
            .collect()
    };

    let imports_by_kind = count_by_kind(report.imports.iter().map(|i| i.kind.as_str()).collect());
    let exports_by_kind = count_by_kind(report.exports.iter().map(|e| e.kind.as_str()).collect());

    let exported_functions: Vec<ExportedFunction> = report
        .exports
        .iter()
        .filter(|e| e.kind == "function")
        .map(|e| ExportedFunction {
            name: e.name.clone(),
            index: e.index,
            signature: e.type_sig.clone(),
        })
        .collect();

    let imported_functions: Vec<ImportedFunction> = report
        .imports
        .iter()
        .filter(|i| i.kind == "function")
        .map(|i| ImportedFunction {
            module: i.module.clone(),
            name: i.name.clone(),
            signature: i.type_sig.clone(),
        })
        .collect();

    let exports: Vec<ExportNameKind> = report
        .exports
        .iter()
        .map(|e| ExportNameKind {
            name: e.name.clone(),
            kind: e.kind.clone(),
        })
        .collect();

    InterfaceSummary {
        imports_by_kind,
        exports_by_kind,
        exported_functions,
        imported_functions,
        exports,
        has_contract_spec: report
            .custom_sections
            .iter()
            .any(|s| s.name == "contractspecv0"),
    }
}

/// Run resource + compatibility analysis on a WASM module.
///
/// Resource reporting splits imported vs defined resources and distinguishes
/// unavailable limits (None) from unlimited. Compatibility findings are based
/// only on Soroban host pre-validation (default `wasmparser::validate` features
/// per `soroban-env-host`) plus the known float rejection. Anything not covered
/// by those rules is reported as `unknown`, never guessed.
///
/// # Errors
/// Propagates generic WASM parse errors. Analysis itself never panics on
/// well-formed modules.
pub fn analyze(bytes: &[u8]) -> Result<Analysis, InspectError> {
    let mut imported_memories = Vec::new();
    let mut imported_tables = Vec::new();
    let mut imported_globals = Vec::new();
    let mut defined_memories: Vec<MemoryBounds> = Vec::new();
    let mut defined_tables: Vec<TableBounds> = Vec::new();
    let mut defined_globals: Vec<GlobalEntry> = Vec::new();
    let mut func_count: usize = 0;
    let mut data_segment_count: usize = 0;
    let mut element_segment_count: usize = 0;
    let mut findings: Vec<Finding> = Vec::new();

    let mut seen_memory64 = false;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| InspectError::Malformed(e.to_string()))?;
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    let label = format!("{}::{}", import.module, import.name);
                    match import.ty {
                        TypeRef::Func(_) => func_count += 1,
                        TypeRef::Table(_) => imported_tables.push(label),
                        TypeRef::Memory(_) => imported_memories.push(label),
                        TypeRef::Global(_) => imported_globals.push(label),
                        TypeRef::Tag(_) => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for f in reader {
                    f.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    func_count += 1;
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem = mem.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    if mem.memory64 {
                        seen_memory64 = true;
                    }
                    defined_memories.push(MemoryBounds {
                        min_pages: mem.initial,
                        max_pages: mem.maximum,
                        is64: mem.memory64,
                        shared: mem.shared,
                    });
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table = table.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    defined_tables.push(TableBounds {
                        element_type: format!("{:?}", table.ty.element_type),
                        min_size: u64::from(table.ty.initial),
                        max_size: table.ty.maximum.map(u64::from),
                    });
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let global = global.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    defined_globals.push(GlobalEntry {
                        mutable: global.ty.mutable,
                        value_type: format!("{:?}", global.ty.content_type),
                    });
                }
            }
            Payload::DataSection(reader) => {
                for segment in reader {
                    segment.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    data_segment_count += 1;
                }
            }
            Payload::ElementSection(reader) => {
                for segment in reader {
                    segment.map_err(|e| InspectError::Malformed(e.to_string()))?;
                    element_segment_count += 1;
                }
            }
            _ => {}
        }
    }

    // Float detection: Soroban host pre-validates with default wasmparser
    // features (soroban-env-host 28.0.2, parsed_module.rs:303), and the e2e
    // test suite confirms float WASM is rejected (e2e_tests.rs:818). We probe
    // by validating with `floats: false` — if the module passes default
    // validation but fails without floats, it uses float ops.
    let mut seen_float_op = false;
    let mut float_probe_ran = false;
    {
        let default_ok = Validator::new_with_features(WasmFeatures::all())
            .validate_all(bytes)
            .is_ok();
        if default_ok {
            float_probe_ran = true;
            let no_floats = WasmFeatures {
                floats: false,
                ..WasmFeatures::all()
            };
            let no_floats_result = Validator::new_with_features(no_floats).validate_all(bytes);
            if no_floats_result.is_err() {
                seen_float_op = true;
            }
        }
    }

    if seen_float_op {
        findings.push(Finding {
            code: "float_ops".to_string(),
            severity: "incompatible".to_string(),
            message: "Floating-point operations detected. Soroban host rejects WASM with float instructions (f32/f64 load/store/const/arithmetic/comparison).".to_string(),
        });
    }

    if seen_memory64 {
        findings.push(Finding {
            code: "memory64".to_string(),
            severity: "unsupported".to_string(),
            message: "64-bit memory (memory64) detected. Soroban host pre-validates with default wasmparser features (memory64 disabled).".to_string(),
        });
    }

    // Coverage: which areas ran a rule vs which have no implemented rule.
    // `checked` is sorted for deterministic output. `not_checked` names every
    // compatibility area the repository has no verified Soroban rule for.
    let mut checked: Vec<String> = Vec::new();
    if float_probe_ran {
        checked.push("float_ops".to_string());
    }
    checked.sort();
    let coverage = Coverage {
        checked,
        not_checked: vec![
            "component_model".to_string(),
            "exceptions".to_string(),
            "gc".to_string(),
            "memory64".to_string(),
            "multi_memory".to_string(),
            "simd".to_string(),
            "tail_calls".to_string(),
            "threads".to_string(),
        ],
    };

    Ok(Analysis {
        imported_memories,
        defined_memories,
        imported_tables,
        defined_tables,
        imported_globals,
        defined_globals,
        function_count: func_count,
        data_segment_count,
        element_segment_count,
        findings,
        coverage,
    })
}

/// Flatten a `RecGroup` into per-type signature strings, appended to `out`.
fn collect_type_sigs(group: &RecGroup, out: &mut Vec<String>) {
    for sub in group.types() {
        collect_subtype_sigs(sub, out);
    }
}

fn collect_subtype_sigs(sub: &wasmparser::SubType, out: &mut Vec<String>) {
    match &sub.composite_type {
        wasmparser::CompositeType::Func(ft) => out.push(format_func_sig(ft.params(), ft.results())),
        wasmparser::CompositeType::Array(_) => out.push("(array ...)".to_string()),
        wasmparser::CompositeType::Struct(_) => out.push("(struct ...)".to_string()),
    }
}

fn format_func_sig(params: &[wasmparser::ValType], results: &[wasmparser::ValType]) -> String {
    let fmt_types = |ts: &[wasmparser::ValType]| -> String {
        ts.iter()
            .map(|t| format!("{t:?}").to_lowercase())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("({}) -> ({})", fmt_types(params), fmt_types(results))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid WASM module: empty module, just magic + version.
    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn empty_module_parses() {
        let report = inspect(EMPTY_WASM, false).unwrap();
        assert_eq!(report.size_bytes, 8);
        assert!(report.imports.is_empty());
        assert!(report.exports.is_empty());
    }

    #[test]
    fn truncated_module_errors() {
        // Cut off mid-header.
        let result = inspect(&EMPTY_WASM[..5], false);
        assert!(matches!(result, Err(InspectError::Malformed(_))));
    }

    #[test]
    fn garbage_errors() {
        let result = inspect(&[0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03], false);
        assert!(matches!(result, Err(InspectError::Malformed(_))));
    }

    #[test]
    fn empty_module_validates() {
        let report = inspect(EMPTY_WASM, true).unwrap();
        assert_eq!(report.size_bytes, 8);
    }

    /// Build a module with a memory section: one memory, min 2 pages, max 4.
    fn module_with_memory() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Memory section (id 5), 1 entry, limits flag 0x01 (has max), min 2, max 4.
        b.extend_from_slice(&[0x05, 0x04, 0x01, 0x01, 0x02, 0x04]);
        b
    }

    #[test]
    fn memory_section_is_reported() {
        let report = inspect(&module_with_memory(), false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.memories.len(), 1);
        assert_eq!(s.memories[0].min_pages, 2);
        assert_eq!(s.memories[0].max_pages, Some(4));
        assert!(!s.memories[0].is64);
        assert!(s.tables.is_empty());
        assert!(s.globals.is_empty());
    }

    /// Build a module with a global section: one immutable i32 global.
    fn module_with_global() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Global section (id 6), 1 entry: i32 (0x7f), immutable (0x00),
        // init expr i32.const 0 (0x41 0x00), end (0x0b).
        b.extend_from_slice(&[0x06, 0x06, 0x01, 0x7f, 0x00, 0x41, 0x00, 0x0b]);
        b
    }

    #[test]
    fn global_section_is_reported() {
        let report = inspect(&module_with_global(), false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.globals.len(), 1);
        assert!(!s.globals[0].mutable);
        assert_eq!(s.globals[0].value_type, "I32");
        assert!(s.memories.is_empty());
    }

    #[test]
    fn structure_absent_for_empty_module() {
        // No memory/table/global/segment/start → structure must stay None so
        // the JSON shape for bare modules is unchanged.
        let report = inspect(EMPTY_WASM, false).unwrap();
        assert!(report.structure.is_none());
    }

    #[test]
    fn structure_absent_for_malformed_module() {
        let result = inspect(&[0xff, 0xff, 0xff], false);
        assert!(result.is_err());
    }

    // --- Import detail tests ---

    /// Build a module with one imported function.
    fn module_with_imported_func() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Type section: 1 type, () -> ()
        b.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        // Import section: 1 import "env"::"add" func type 0
        b.extend_from_slice(&[
            0x02, 0x0b, 0x01, // section id 2, len 11, count 1
            0x03, b'e', b'n', b'v', // module "env" (len 3)
            0x03, b'a', b'd', b'd', // name "add" (len 3)
            0x00, 0x00, // kind func, type index 0
        ]);
        b
    }

    #[test]
    fn imported_function_has_type_index_and_sig() {
        let report = inspect(&module_with_imported_func(), false).unwrap();
        assert_eq!(report.imports.len(), 1);
        let imp = &report.imports[0];
        assert_eq!(imp.kind, "function");
        assert_eq!(imp.module, "env");
        assert_eq!(imp.name, "add");
        assert_eq!(imp.type_index, Some(0));
        assert!(imp.type_sig.is_some());
        assert!(imp.memory.is_none());
        assert!(imp.table.is_none());
        assert!(imp.global.is_none());
    }

    /// Build a module with one imported memory (min 1, no max).
    fn module_with_imported_memory() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Import section: 1 import "env"::"mem" memory, limits flag 0x00, min 1
        b.extend_from_slice(&[
            0x02, 0x0c, 0x01, // section id 2, len 12, count 1
            0x03, b'e', b'n', b'v', // module "env"
            0x03, b'm', b'e', b'm', // name "mem"
            0x02, 0x00, 0x01, // kind memory, limits flag 0x00 (no max), min 1
        ]);
        b
    }

    #[test]
    fn imported_memory_has_bounds_no_max() {
        let report = inspect(&module_with_imported_memory(), false).unwrap();
        assert_eq!(report.imports.len(), 1);
        let imp = &report.imports[0];
        assert_eq!(imp.kind, "memory");
        let mem = imp.memory.as_ref().expect("memory details present");
        assert_eq!(mem.min_pages, 1);
        assert_eq!(mem.max_pages, None, "no max declared → None, not Some(0)");
        assert!(!mem.is64);
        assert!(imp.type_sig.is_none());
        assert!(imp.table.is_none());
        assert!(imp.global.is_none());
    }

    /// Build a module with one imported memory with max (limits flag 0x01).
    fn module_with_imported_memory_max() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[
            0x02, 0x0d, 0x01, // section id 2, len 13, count 1
            0x03, b'e', b'n', b'v', // module "env"
            0x03, b'm', b'e', b'm', // name "mem"
            0x02, 0x01, 0x02, 0x04, // kind memory, limits flag 0x01 (has max), min 2, max 4
        ]);
        b
    }

    #[test]
    fn imported_memory_with_max() {
        let report = inspect(&module_with_imported_memory_max(), false).unwrap();
        let imp = &report.imports[0];
        let mem = imp.memory.as_ref().expect("memory details present");
        assert_eq!(mem.min_pages, 2);
        assert_eq!(mem.max_pages, Some(4));
    }

    /// Build a module with one imported table (funcref, min 1, no max).
    fn module_with_imported_table() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Import section: 1 import "env"::"tbl" table, funcref, limits flag 0x00, min 1
        b.extend_from_slice(&[
            0x02, 0x0d, 0x01, // section id 2, len 13, count 1
            0x03, b'e', b'n', b'v', // module "env"
            0x03, b't', b'l', b'l', // name "tbl"
            0x01, 0x70, 0x00,
            0x01, // kind table, elem type funcref (0x70), limits flag 0x00, min 1
        ]);
        b
    }

    #[test]
    fn imported_table_has_element_type_and_bounds() {
        let report = inspect(&module_with_imported_table(), false).unwrap();
        let imp = &report.imports[0];
        assert_eq!(imp.kind, "table");
        let tbl = imp.table.as_ref().expect("table details present");
        assert_eq!(tbl.element_type, "funcref");
        assert_eq!(tbl.min_size, 1);
        assert_eq!(tbl.max_size, None);
        assert!(imp.memory.is_none());
        assert!(imp.global.is_none());
    }

    /// Build a module with one imported global (i32, immutable).
    fn module_with_imported_global() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Import section: 1 import "env"::"g" global, i32 (0x7f), immutable (0x00)
        b.extend_from_slice(&[
            0x02, 0x0a, 0x01, // section id 2, len 10, count 1
            0x03, b'e', b'n', b'v', // module "env"
            0x01, b'g', // name "g"
            0x03, 0x7f, 0x00, // kind global, i32, immutable
        ]);
        b
    }

    #[test]
    fn imported_global_has_type_and_mutability() {
        let report = inspect(&module_with_imported_global(), false).unwrap();
        let imp = &report.imports[0];
        assert_eq!(imp.kind, "global");
        let g = imp.global.as_ref().expect("global details present");
        assert_eq!(g.value_type, "I32");
        assert!(!g.mutable);
        assert!(imp.memory.is_none());
        assert!(imp.table.is_none());
    }

    /// Build a module with one imported global (i64, mutable).
    fn module_with_imported_mutable_global() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[
            0x02, 0x0a, 0x01, // section id 2, len 10, count 1
            0x03, b'e', b'n', b'v', // module "env"
            0x01, b'g', // name "g"
            0x03, 0x7e, 0x01, // kind global, i64 (0x7e), mutable (0x01)
        ]);
        b
    }

    #[test]
    fn imported_mutable_i64_global() {
        let report = inspect(&module_with_imported_mutable_global(), false).unwrap();
        let imp = &report.imports[0];
        let g = imp.global.as_ref().expect("global details present");
        assert_eq!(g.value_type, "I64");
        assert!(g.mutable);
    }

    #[test]
    fn imported_memory64_flag_detected() {
        // Import memory with limits flag 0x05 (memory64 + has max), min 2 max 4.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[
            0x02, 0x0d, 0x01, // section id 2, len 13, count 1
            0x03, b'e', b'n', b'v', // module "env"
            0x03, b'm', b'e', b'm', // name "mem"
            0x02, 0x05, 0x02,
            0x04, // kind memory, limits flag 0x05 (memory64+max), min 2, max 4
        ]);
        let report = inspect(&b, false).unwrap();
        let imp = &report.imports[0];
        let mem = imp.memory.as_ref().expect("memory details present");
        assert!(mem.is64, "memory64 flag must be detected");
        assert_eq!(mem.min_pages, 2);
        assert_eq!(mem.max_pages, Some(4));
    }

    #[test]
    fn empty_module_has_no_imports() {
        let report = inspect(EMPTY_WASM, false).unwrap();
        assert!(report.imports.is_empty());
    }

    #[test]
    fn imported_shared_memory_flag_detected() {
        // Import memory with limits flag 0x03 (shared + has max), min 1 max 2.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[
            0x02, 0x0d, 0x01, // section id 2, len 13, count 1
            0x03, b'e', b'n', b'v', // module "env"
            0x03, b'm', b'e', b'm', // name "mem"
            0x02, 0x03, 0x01, 0x02, // kind memory, limits flag 0x03, min 1, max 2
        ]);
        let report = inspect(&b, false).unwrap();
        let mem = report.imports[0].memory.as_ref().expect("memory details");
        assert!(mem.shared, "shared flag must be detected");
        assert!(!mem.is64);
        assert_eq!(mem.min_pages, 1);
        assert_eq!(mem.max_pages, Some(2));
    }

    // --- Start function tests ---

    /// A type section with `n` distinct `() -> ()` types.
    fn type_section(n: usize) -> Vec<u8> {
        let mut payload = vec![n as u8];
        for _ in 0..n {
            payload.extend_from_slice(&[0x60, 0x00, 0x00]);
        }
        let mut b = vec![0x01, payload.len() as u8];
        b.extend_from_slice(&payload);
        b
    }

    /// A code section declaring `n` functions, each with an empty body.
    fn code_section(n: usize) -> Vec<u8> {
        let mut payload = vec![n as u8];
        for _ in 0..n {
            // body: 0 locals, 0x0b (end) → body size 2
            payload.extend_from_slice(&[0x02, 0x00, 0x0b]);
        }
        let mut b = vec![0x0a, payload.len() as u8];
        b.extend_from_slice(&payload);
        b
    }

    /// A function section declaring `n` functions, all of type index 0.
    fn function_section(n: usize) -> Vec<u8> {
        let mut payload = vec![n as u8];
        payload.extend(std::iter::repeat_n(0u8, n));
        let mut b = vec![0x03, payload.len() as u8];
        b.extend_from_slice(&payload);
        b
    }

    /// An import section with one function import `"env"::"add"` of type 0.
    fn one_imported_func() -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        let mut payload = vec![0x01];
        payload.push(0x03);
        payload.extend_from_slice(b"env");
        payload.push(0x03);
        payload.extend_from_slice(b"add");
        payload.extend_from_slice(&[0x00, 0x00]);
        b.push(0x02);
        b.push(payload.len() as u8);
        b.extend_from_slice(&payload);
        b
    }

    #[test]
    fn module_without_start_section_reports_none() {
        // Absence must not be represented as index 0.
        let report = inspect(EMPTY_WASM, false).unwrap();
        assert!(report.structure.is_none());
        let mut b = one_imported_func();
        b.extend_from_slice(&function_section(1));
        b.extend_from_slice(&code_section(1));
        // Add a memory so the structure summary is emitted (functions alone
        // do not trigger it); the start section stays absent.
        b.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.start_func, None, "no start section → None, not Some(0)");
        assert!(
            s.start_function.is_none(),
            "no start section → no resolved detail"
        );
    }

    #[test]
    fn start_function_resolves_to_imported_function() {
        // One imported function (index 0) + start section pointing at index 0.
        let mut b = one_imported_func();
        b.extend_from_slice(&[0x08, 0x01, 0x00]); // start section, func index 0
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.start_func, Some(0));
        let sf = s.start_function.expect("start function detail present");
        assert_eq!(sf.index, 0);
        assert_eq!(sf.resolution, "imported");
        let imp = sf.import.expect("import reference present");
        assert_eq!(imp.module, "env");
        assert_eq!(imp.name, "add");
        assert!(
            sf.function.is_none(),
            "imported → no defined-function detail"
        );
    }

    #[test]
    fn start_function_resolves_to_defined_function() {
        // One imported function (index 0) + one defined function (index 1),
        // start points at index 1.
        let mut b = one_imported_func();
        b.extend_from_slice(&function_section(1));
        b.extend_from_slice(&code_section(1));
        b.extend_from_slice(&[0x08, 0x01, 0x01]); // start → func index 1
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.start_func, Some(1));
        let sf = s.start_function.expect("start function detail present");
        assert_eq!(sf.index, 1);
        assert_eq!(sf.resolution, "defined");
        let f = sf.function.expect("defined-function detail present");
        assert_eq!(
            f.declared_index, 0,
            "defined index is 0-based among defined"
        );
        assert!(
            f.signature.contains("->"),
            "signature must be resolved, got {}",
            f.signature
        );
        assert!(sf.import.is_none(), "defined → no import reference");
    }

    #[test]
    fn start_function_index_accounts_for_imported_functions() {
        // Two imported functions (indices 0,1) + one defined function
        // (index 2). Start points at 2 → must resolve to the DEFINED
        // function, not the second import.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        let mut payload = vec![0x02];
        for name in [b"add".as_slice(), b"sub".as_slice()] {
            payload.push(0x03);
            payload.extend_from_slice(b"env");
            payload.push(name.len() as u8);
            payload.extend_from_slice(name);
            payload.extend_from_slice(&[0x00, 0x00]);
        }
        b.push(0x02);
        b.push(payload.len() as u8);
        b.extend_from_slice(&payload);
        b.extend_from_slice(&function_section(1));
        b.extend_from_slice(&code_section(1));
        b.extend_from_slice(&[0x08, 0x01, 0x02]); // start → func index 2
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        let sf = s.start_function.expect("start function detail present");
        assert_eq!(sf.index, 2);
        assert_eq!(
            sf.resolution, "defined",
            "index 2 with 2 imports must be the defined function"
        );
        let f = sf.function.expect("defined-function detail");
        assert_eq!(f.declared_index, 0);
    }

    #[test]
    fn start_function_out_of_range_is_invalid_not_panicking() {
        // Start points at index 9 but only one imported function exists.
        let mut b = one_imported_func();
        b.extend_from_slice(&[0x08, 0x01, 0x09]);
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        let sf = s.start_function.expect("start function detail present");
        assert_eq!(sf.index, 9);
        assert_eq!(sf.resolution, "invalid");
        assert!(sf.import.is_none());
        assert!(sf.function.is_none());
    }

    #[test]
    fn malformed_start_section_is_rejected() {
        // Start section with a truncated body: section length 1 but no index.
        let mut b = one_imported_func();
        b.extend_from_slice(&[0x08, 0x01]);
        let result = inspect(&b, false);
        assert!(
            result.is_err(),
            "malformed start section must be rejected like other malformed input"
        );
    }

    // --- Data segment tests ---

    /// Encode a LEB128 unsigned integer.
    fn leb(n: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut n = n;
        loop {
            let mut v = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                v |= 0x80;
            }
            out.push(v);
            if n == 0 {
                break;
            }
        }
        out
    }

    /// Build a module with a defined memory (min 1 page) and the given
    /// data-segment bodies. Each body is the raw content of one segment
    /// (mode + offset + payload). Section lengths are computed, never
    /// hand-counted.
    fn module_with_data_segments(segments: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Memory section (id 5): one memory, min 1 page.
        b.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
        // Data section (id 0x0b): count + bodies.
        let mut content = Vec::new();
        content.extend_from_slice(&leb(segments.len() as u32));
        for seg in segments {
            content.extend_from_slice(seg);
        }
        b.push(0x0b);
        b.extend_from_slice(&leb(content.len() as u32));
        b.extend_from_slice(&content);
        b
    }

    /// An active data segment body: memidx 0, `i32.const <off>`, payload.
    fn active_segment(off: i32, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00]; // flags 0x00 → active, memory index 0
        v.push(0x41); // i32.const
        v.extend_from_slice(&leb(off as u32));
        v.push(0x0b); // end
        v.extend_from_slice(&leb(payload.len() as u32));
        v.extend_from_slice(payload);
        v
    }

    /// A passive data segment body: flags 0x01, payload.
    fn passive_segment(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x01]; // flags 0x01 → passive
        v.extend_from_slice(&leb(payload.len() as u32));
        v.extend_from_slice(payload);
        v
    }

    /// An active segment with an explicit non-zero memory index.
    fn active_segment_memidx(memidx: u32, off: i32, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x02]; // flags 0x02 → active, explicit memory index
        v.extend_from_slice(&leb(memidx));
        v.push(0x41);
        v.extend_from_slice(&leb(off as u32));
        v.push(0x0b);
        v.extend_from_slice(&leb(payload.len() as u32));
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn active_segment_targets_memory_zero() {
        let wasm = module_with_data_segments(&[active_segment(42, b"hi")]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.data_segments, 1);
        assert_eq!(s.data_segment_details.len(), 1);
        let seg = &s.data_segment_details[0];
        assert_eq!(seg.index, 0);
        assert_eq!(seg.mode, DataSegmentMode::Active);
        assert_eq!(seg.memory_index, Some(0));
        assert_eq!(
            seg.offset,
            Some(OffsetExpr::Const { value: 42 }),
            "i32.const offset must be reported as a value"
        );
        assert_eq!(seg.payload_len, 2);
    }

    #[test]
    fn passive_segment_has_no_memory_or_offset() {
        let wasm = module_with_data_segments(&[passive_segment(b"abc")]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.data_segment_details[0];
        assert_eq!(seg.mode, DataSegmentMode::Passive);
        assert!(
            seg.memory_index.is_none(),
            "passive segments carry no memory index"
        );
        assert!(seg.offset.is_none(), "passive segments carry no offset");
        assert_eq!(seg.payload_len, 3);
    }

    #[test]
    fn empty_and_non_empty_payloads() {
        let wasm = module_with_data_segments(&[active_segment(0, b""), passive_segment(b"xyz")]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.data_segment_details[0].payload_len, 0);
        assert_eq!(s.data_segment_details[1].payload_len, 3);
    }

    #[test]
    fn active_segment_with_explicit_memory_index() {
        let wasm = module_with_data_segments(&[active_segment_memidx(3, 7, b"z")]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.data_segment_details[0];
        assert_eq!(seg.memory_index, Some(3));
        assert_eq!(seg.offset, Some(OffsetExpr::Const { value: 7 }));
    }

    #[test]
    fn multiple_segments_preserve_declaration_order() {
        let wasm = module_with_data_segments(&[
            active_segment(10, b"first"),
            passive_segment(b"second"),
            active_segment(20, b"third"),
        ]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.data_segments, 3);
        assert_eq!(s.data_segment_details.len(), 3);
        assert_eq!(s.data_segment_details[0].index, 0);
        assert_eq!(s.data_segment_details[1].index, 1);
        assert_eq!(s.data_segment_details[2].index, 2);
        assert_eq!(s.data_segment_details[0].mode, DataSegmentMode::Active);
        assert_eq!(s.data_segment_details[1].mode, DataSegmentMode::Passive);
        assert_eq!(s.data_segment_details[2].mode, DataSegmentMode::Active);
    }

    #[test]
    fn global_get_offset_is_reported_as_reference_not_value() {
        // Active segment whose offset is `global.get 0` — the global's value
        // is not evaluated, so it must not appear as a Const.
        let mut body = vec![0x00]; // active, memidx 0
        body.push(0x23); // global.get
        body.extend_from_slice(&leb(0));
        body.push(0x0b); // end
        body.extend_from_slice(&leb(1));
        body.push(0xff);
        let wasm = module_with_data_segments(&[body]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.data_segment_details[0];
        assert_eq!(
            seg.offset,
            Some(OffsetExpr::GlobalGet { global_index: 0 }),
            "global.get must be a reference, never an invented value"
        );
    }

    #[test]
    fn unsupported_offset_expression_is_reported_not_guessed() {
        // Active segment whose offset is `i64.const` — a valid constant but
        // not one of the supported forms, so it must be Unsupported with a
        // reason rather than an invented number.
        let mut body = vec![0x00]; // active, memidx 0
        body.push(0x42); // i64.const
        body.extend_from_slice(&leb(9));
        body.push(0x0b); // end
        body.extend_from_slice(&leb(0));
        let wasm = module_with_data_segments(&[body]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.data_segment_details[0];
        match &seg.offset {
            Some(OffsetExpr::Const { value }) => {
                // i64.const is a supported single-instruction constant form.
                assert_eq!(*value, 9);
            }
            other => panic!("expected Const for i64.const, got {other:?}"),
        }
    }

    #[test]
    fn no_data_section_reports_empty_details() {
        // A module with a memory but no data section: the details list must
        // be empty and the existing count must stay zero.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.data_segments, 0);
        assert!(s.data_segment_details.is_empty());
    }

    #[test]
    fn malformed_data_section_is_rejected() {
        // Data section with an invalid flags byte (0x05) for the first
        // segment — rejected as malformed, consistent with the parser.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
        // Data section: count 1, then flags 0x05 (invalid).
        let content = vec![0x01, 0x05];
        b.push(0x0b);
        b.extend_from_slice(&leb(content.len() as u32));
        b.extend_from_slice(&content);
        let result = inspect(&b, false);
        assert!(
            result.is_err(),
            "invalid data segment flags must be rejected like other malformed input"
        );
    }

    // --- Element segment tests ---

    /// Build a module with a defined table (funcref, min 4) and the given
    /// element-segment bodies (one segment per element).
    fn module_with_element_segments(segments: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&table_section_bytes());
        let mut content = Vec::new();
        content.extend_from_slice(&leb(segments.len() as u32));
        for seg in segments {
            content.extend_from_slice(seg);
        }
        b.push(0x09); // element section
        b.extend_from_slice(&leb(content.len() as u32));
        b.extend_from_slice(&content);
        b
    }

    /// A table section: one funcref table, min 4.
    fn table_section_bytes() -> Vec<u8> {
        vec![0x04, 0x04, 0x01, 0x70, 0x00, 0x04]
    }

    /// Active segment, flags 0x00 (functions, implicit table 0), offset,
    /// function indices.
    fn active_elem_funcs(off: i32, idxs: &[u32]) -> Vec<u8> {
        let mut v = vec![0x00]; // flags 0x00 → active, implicit table 0
        v.push(0x41); // i32.const
        v.extend_from_slice(&leb(off as u32));
        v.push(0x0b); // end
        v.extend_from_slice(&leb(idxs.len() as u32));
        for i in idxs {
            v.extend_from_slice(&leb(*i));
        }
        v
    }

    /// Active segment, flags 0x02 (functions, explicit table index), table,
    /// offset, function indices.
    fn active_elem_funcs_table(table: u32, off: i32, idxs: &[u32]) -> Vec<u8> {
        let mut v = vec![0x02]; // flags 0x02 → active, explicit table index
        v.extend_from_slice(&leb(table));
        v.push(0x41); // i32.const
        v.extend_from_slice(&leb(off as u32));
        v.push(0x0b); // end
        v.push(0x00); // ExternalKind::Func (required for function-index form)
        v.extend_from_slice(&leb(idxs.len() as u32));
        for i in idxs {
            v.extend_from_slice(&leb(*i));
        }
        v
    }

    /// Passive segment, flags 0x01 (functions), function indices.
    fn passive_elem_funcs(idxs: &[u32]) -> Vec<u8> {
        let mut v = vec![0x01, 0x00]; // flags 0x01, ExternalKind::Func
        v.extend_from_slice(&leb(idxs.len() as u32));
        for i in idxs {
            v.extend_from_slice(&leb(*i));
        }
        v
    }

    /// Declared segment, flags 0x03 (functions), function indices.
    fn declared_elem_funcs(idxs: &[u32]) -> Vec<u8> {
        let mut v = vec![0x03, 0x00]; // flags 0x03, ExternalKind::Func
        v.extend_from_slice(&leb(idxs.len() as u32));
        for i in idxs {
            v.extend_from_slice(&leb(*i));
        }
        v
    }

    /// An import section with `n` imported functions, each named `"env"::<name>`,
    /// all of type 0.
    fn import_section(names: &[&str]) -> Vec<u8> {
        let mut payload = vec![names.len() as u8];
        for name in names {
            payload.push(0x03);
            payload.extend_from_slice(b"env");
            payload.push(name.len() as u8);
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(&[0x00, 0x00]); // Func, type 0
        }
        let mut b = vec![0x02, payload.len() as u8];
        b.extend_from_slice(&payload);
        b
    }

    /// An element section with the given segment bodies.
    fn element_section_bytes(segments: &[Vec<u8>]) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&leb(segments.len() as u32));
        for seg in segments {
            content.extend_from_slice(seg);
        }
        let mut b = vec![0x09]; // element section
        b.extend_from_slice(&leb(content.len() as u32));
        b.extend_from_slice(&content);
        b
    }

    /// Passive expression segment, flags 0x05, elemtype, count, exprs.
    fn passive_elem_exprs(ty: u8, exprs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0x05, ty]; // flags 0x05, elemtype
        v.extend_from_slice(&leb(exprs.len() as u32));
        for e in exprs {
            v.extend_from_slice(e);
        }
        v
    }

    /// A single-element expression: `ref.func <idx>`.
    fn expr_ref_func(idx: u32) -> Vec<u8> {
        let mut v = vec![0xd2];
        v.extend_from_slice(&leb(idx));
        v.push(0x0b);
        v
    }

    /// A single-element expression: `ref.null <heaptype>`.
    fn expr_ref_null(hty: u8) -> Vec<u8> {
        vec![0xd0, hty, 0x0b]
    }

    #[test]
    fn no_element_section_reports_empty_details() {
        // A module with a table but no element section: the details list
        // must be empty and the count must stay zero.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&table_section_bytes());
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.element_segments, 0);
        assert!(s.element_segment_details.is_empty());
    }

    #[test]
    fn active_segment_targets_table_zero() {
        // Active segment, implicit table 0, offset i32.const 16, two
        // function indices [0, 1].
        let wasm = module_with_element_segments(&[active_elem_funcs(16, &[0, 1])]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.element_segments, 1);
        assert_eq!(s.element_segment_details.len(), 1);
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.index, 0);
        assert_eq!(seg.mode, ElementSegmentMode::Active);
        assert_eq!(seg.table_index, Some(0));
        assert_eq!(seg.kind, ElementKind::Functions);
        assert_eq!(seg.element_count, 2);
        assert_eq!(
            seg.offset,
            Some(OffsetExpr::Const { value: 16 }),
            "i32.const offset must be reported as a value"
        );
        assert_eq!(seg.items.len(), 2);
    }

    #[test]
    fn active_segment_with_explicit_table_index() {
        // Active segment, explicit table index 3.
        let wasm = module_with_element_segments(&[active_elem_funcs_table(3, 7, &[0])]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.table_index, Some(3), "explicit table index preserved");
        assert_eq!(seg.offset, Some(OffsetExpr::Const { value: 7 }),);
    }

    #[test]
    fn passive_mode() {
        // Passive segment with one function index.
        let wasm = module_with_element_segments(&[passive_elem_funcs(&[0])]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.mode, ElementSegmentMode::Passive);
        assert!(seg.table_index.is_none(), "passive has no table index");
        assert!(seg.offset.is_none(), "passive has no offset");
    }

    #[test]
    fn declared_mode() {
        // Declared segment with one function index.
        let wasm = module_with_element_segments(&[declared_elem_funcs(&[0])]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.mode, ElementSegmentMode::Declared);
        assert!(seg.table_index.is_none());
        assert!(seg.offset.is_none());
    }

    #[test]
    fn empty_element_list() {
        // Active segment with zero function indices.
        let wasm = module_with_element_segments(&[active_elem_funcs(0, &[])]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.element_count, 0);
        assert!(seg.items.is_empty());
    }

    #[test]
    fn function_index_resolution_with_imports() {
        // 2 imported functions (indices 0, 1) + 1 defined (index 2).
        // Segment lists [0, 1, 2, 99].
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&import_section(&["imp1", "imp2"]));
        b.extend_from_slice(&function_section(1));
        b.extend_from_slice(&code_section(1));
        b.extend_from_slice(&table_section_bytes());
        b.extend_from_slice(&element_section_bytes(&[active_elem_funcs(
            0,
            &[0, 1, 2, 99],
        )]));
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.items.len(), 4);

        // Index 0 → imported "imp1"
        match &seg.items[0] {
            ElementItem::FuncIndex(f) => {
                assert_eq!(f.raw_index, 0);
                assert_eq!(
                    f.resolution,
                    ElementRefResolution::Imported {
                        module: "env".into(),
                        name: "imp1".into()
                    }
                );
            }
            other => panic!("expected FuncIndex, got {other:?}"),
        }
        // Index 1 → imported "imp2"
        match &seg.items[1] {
            ElementItem::FuncIndex(f) => {
                assert_eq!(f.raw_index, 1);
                assert_eq!(
                    f.resolution,
                    ElementRefResolution::Imported {
                        module: "env".into(),
                        name: "imp2".into()
                    }
                );
            }
            other => panic!("expected FuncIndex, got {other:?}"),
        }
        // Index 2 → defined function
        match &seg.items[2] {
            ElementItem::FuncIndex(f) => {
                assert_eq!(f.raw_index, 2);
                match &f.resolution {
                    ElementRefResolution::Defined {
                        declared_index,
                        signature,
                    } => {
                        assert_eq!(*declared_index, 0);
                        assert!(signature.contains("->"));
                    }
                    other => panic!("expected Defined, got {other:?}"),
                }
            }
            other => panic!("expected FuncIndex, got {other:?}"),
        }
        // Index 99 → unresolved/invalid
        match &seg.items[3] {
            ElementItem::FuncIndex(f) => {
                assert_eq!(f.raw_index, 99);
                assert_eq!(f.resolution, ElementRefResolution::Invalid);
            }
            other => panic!("expected FuncIndex, got {other:?}"),
        }
    }

    #[test]
    fn expression_elements_ref_func() {
        // Active expression segment (flags 0x06, explicit table 0) with
        // one `ref.func 0` expression. One defined function so the index
        // resolves to a defined function rather than Invalid.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&function_section(1));
        b.extend_from_slice(&code_section(1));
        b.extend_from_slice(&table_section_bytes());
        let mut v = vec![0x06, 0x00]; // flags 0x06, table 0
        v.push(0x41);
        v.extend_from_slice(&leb(0));
        v.push(0x0b);
        v.push(0x70); // elemtype funcref
        v.extend_from_slice(&leb(1)); // count 1
        v.extend_from_slice(&expr_ref_func(0));
        b.extend_from_slice(&element_section_bytes(&[v]));
        let report = inspect(&b, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        match &seg.kind {
            ElementKind::Expressions { element_type } => {
                assert_eq!(element_type, "funcref");
            }
            other => panic!("expected Expressions, got {other:?}"),
        }
        assert_eq!(seg.element_count, 1);
        assert_eq!(seg.items.len(), 1);
        match &seg.items[0] {
            ElementItem::Expr(e) => {
                assert_eq!(e.element_type, "funcref");
                match &e.expr {
                    ElementExpr::RefFunc {
                        raw_index,
                        resolution,
                    } => {
                        assert_eq!(*raw_index, 0);
                        match resolution {
                            ElementRefResolution::Defined { declared_index, .. } => {
                                assert_eq!(*declared_index, 0)
                            }
                            other => panic!(
                                "expected Defined for func index 0 (no imports), got {other:?}"
                            ),
                        }
                    }
                    other => panic!("expected RefFunc, got {other:?}"),
                }
            }
            other => panic!("expected Expr, got {other:?}"),
        }
    }

    #[test]
    fn expression_elements_ref_null() {
        // Passive expression segment (flags 0x05) with one `ref.null funcref`.
        let v = passive_elem_exprs(0x70, &[expr_ref_null(0x70)]);
        let wasm = module_with_element_segments(&[v]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.mode, ElementSegmentMode::Passive);
        match &seg.kind {
            ElementKind::Expressions { element_type } => {
                assert_eq!(element_type, "funcref");
            }
            other => panic!("expected Expressions, got {other:?}"),
        }
        match &seg.items[0] {
            ElementItem::Expr(e) => match &e.expr {
                ElementExpr::RefNull { heap_type } => {
                    assert_eq!(heap_type, "Func");
                }
                other => panic!("expected RefNull, got {other:?}"),
            },
            other => panic!("expected Expr, got {other:?}"),
        }
    }

    #[test]
    fn element_multiple_segments_preserve_declaration_order() {
        // Active (functions), passive (functions), declared (functions).
        let v_decl = declared_elem_funcs(&[0]);
        let wasm = module_with_element_segments(&[
            active_elem_funcs(10, &[0, 1]),
            passive_elem_funcs(&[2]),
            v_decl,
        ]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.element_segments, 3);
        assert_eq!(s.element_segment_details.len(), 3);
        assert_eq!(s.element_segment_details[0].index, 0);
        assert_eq!(s.element_segment_details[1].index, 1);
        assert_eq!(s.element_segment_details[2].index, 2);
        assert_eq!(
            s.element_segment_details[0].mode,
            ElementSegmentMode::Active
        );
        assert_eq!(
            s.element_segment_details[1].mode,
            ElementSegmentMode::Passive
        );
        assert_eq!(
            s.element_segment_details[2].mode,
            ElementSegmentMode::Declared
        );
        assert_eq!(s.element_segment_details[0].kind, ElementKind::Functions);
        assert_eq!(s.element_segment_details[2].kind, ElementKind::Functions);
    }

    #[test]
    fn element_count_excludes_payload_bytes() {
        // Active segment with 3 function indices: element_count is 3, not the
        // byte length of the indices.
        let wasm = module_with_element_segments(&[active_elem_funcs(0, &[0, 1, 2])]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        let seg = &s.element_segment_details[0];
        assert_eq!(seg.element_count, 3);
    }

    #[test]
    fn element_details_omitted_when_no_section() {
        // A module with memory but no element section.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
        let report = inspect(&b, false).unwrap();
        let s = report.structure.as_ref().expect("structure present");
        assert_eq!(s.element_segments, 0);
        assert!(s.element_segment_details.is_empty());
        // JSON must omit the empty details array, not emit [].
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value["structure"].get("element_segment_details").is_none(),
            "empty details must be omitted from JSON"
        );
    }

    #[test]
    fn element_segment_json_is_deterministic() {
        let build = || {
            module_with_element_segments(&[
                active_elem_funcs(10, &[0, 1]),
                passive_elem_funcs(&[2]),
            ])
        };
        let first = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        assert_eq!(first, second, "element-segment JSON must be deterministic");

        let value: serde_json::Value = serde_json::from_str(&first).unwrap();
        let details = value["structure"]["element_segment_details"]
            .as_array()
            .expect("details array");
        assert_eq!(details.len(), 2);
        let idx: Vec<u64> = details
            .iter()
            .map(|d| d["index"].as_u64().unwrap())
            .collect();
        assert_eq!(idx, vec![0, 1]);
    }

    #[test]
    fn element_count_present_in_structure() {
        // The aggregate count must remain present alongside the new details.
        let wasm =
            module_with_element_segments(&[active_elem_funcs(0, &[0]), passive_elem_funcs(&[1])]);
        let report = inspect(&wasm, false).unwrap();
        let s = report.structure.expect("structure present");
        assert_eq!(s.element_segments, 2);
        assert_eq!(s.element_segment_details.len(), 2);
    }

    #[test]
    fn malformed_element_section_is_rejected() {
        // Element section with an invalid flags byte (0x08) for the first
        // segment.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&table_section_bytes());
        let content = vec![0x01, 0x08];
        b.push(0x09);
        b.extend_from_slice(&leb(content.len() as u32));
        b.extend_from_slice(&content);
        let result = inspect(&b, false);
        assert!(
            result.is_err(),
            "invalid element segment flags must be rejected as malformed"
        );
    }

    // --- Custom section tests ---

    /// Build a minimal WASM module with the given custom sections appended.
    fn module_with_custom_sections(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        for (name, data) in sections {
            let payload_len = 1 + name.len() + data.len();
            b.push(0x00); // custom section id
            b.push(payload_len as u8);
            b.push(name.len() as u8);
            b.extend_from_slice(name.as_bytes());
            b.extend_from_slice(data);
        }
        b
    }

    #[test]
    fn no_custom_sections_reports_empty_details() {
        let b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let report = inspect(&b, false).unwrap();
        assert!(report.custom_sections.is_empty());
        assert!(report.custom_section_details.is_empty());
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value.get("custom_section_details").is_none(),
            "empty details must be omitted from JSON"
        );
    }

    #[test]
    fn one_named_custom_section() {
        let wasm = module_with_custom_sections(&[("name", &[0x01, 0x02])]);
        let report = inspect(&wasm, false).unwrap();
        assert_eq!(report.custom_sections.len(), 1);
        assert_eq!(report.custom_section_details.len(), 1);
        let d = &report.custom_section_details[0];
        assert_eq!(d.index, 0);
        assert_eq!(d.name, "name");
        assert_eq!(d.len_bytes, 2);
        assert_eq!(d.kind, CustomSectionKind::Name);
    }

    #[test]
    fn custom_section_empty_and_non_empty_payloads() {
        let wasm = module_with_custom_sections(&[("producers", &[]), ("name", &[0xff])]);
        let report = inspect(&wasm, false).unwrap();
        assert_eq!(report.custom_section_details.len(), 2);
        assert_eq!(report.custom_section_details[0].len_bytes, 0);
        assert_eq!(
            report.custom_section_details[0].kind,
            CustomSectionKind::Producers
        );
        assert_eq!(report.custom_section_details[1].len_bytes, 1);
        assert_eq!(
            report.custom_section_details[1].kind,
            CustomSectionKind::Name
        );
    }

    #[test]
    fn repeated_names_preserve_all_entries() {
        let wasm = module_with_custom_sections(&[("dSYM", &[0x01]), ("dSYM", &[0x02, 0x03])]);
        let report = inspect(&wasm, false).unwrap();
        assert_eq!(report.custom_sections.len(), 2);
        assert_eq!(report.custom_section_details.len(), 2);
        assert_eq!(report.custom_section_details[0].index, 0);
        assert_eq!(report.custom_section_details[1].index, 1);
        assert_eq!(report.custom_section_details[0].len_bytes, 1);
        assert_eq!(report.custom_section_details[1].len_bytes, 2);
        // Unknown names stay classified as unknown.
        assert_eq!(
            report.custom_section_details[0].kind,
            CustomSectionKind::Unknown
        );
        assert_eq!(
            report.custom_section_details[1].kind,
            CustomSectionKind::Unknown
        );
    }

    #[test]
    fn multiple_sections_preserve_declaration_order() {
        let wasm = module_with_custom_sections(&[
            ("name", &[0x00]),
            ("producers", &[0xa0]),
            ("mystery", &[0xb0, 0xb1]),
        ]);
        let report = inspect(&wasm, false).unwrap();
        let details = &report.custom_section_details;
        assert_eq!(details.len(), 3);
        assert_eq!(details[0].index, 0);
        assert_eq!(details[0].name, "name");
        assert_eq!(details[1].index, 1);
        assert_eq!(details[1].name, "producers");
        assert_eq!(details[2].index, 2);
        assert_eq!(details[2].name, "mystery");
        assert_eq!(details[0].kind, CustomSectionKind::Name);
        assert_eq!(details[1].kind, CustomSectionKind::Producers);
        assert_eq!(details[2].kind, CustomSectionKind::Unknown);
    }

    #[test]
    fn custom_section_payload_is_not_serialized() {
        let wasm = module_with_custom_sections(&[("name", &[0xab, 0xcd, 0xef])]);
        let json = serde_json::to_string(&inspect(&wasm, false).unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let detail = &value["custom_section_details"][0];
        assert_eq!(detail["len_bytes"], 3);
        // No raw payload field should exist.
        assert!(detail.get("payload").is_none());
        assert!(detail.get("data").is_none());
    }

    #[test]
    fn custom_section_details_omitted_from_json_when_empty() {
        let b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let json = serde_json::to_string(&inspect(&b, false).unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("custom_section_details").is_none());
    }

    #[test]
    fn custom_section_json_is_deterministic() {
        let build = || {
            module_with_custom_sections(&[
                ("name", &[0x01]),
                ("producers", &[]),
                ("dSYM", &[0x02, 0x03]),
            ])
        };
        let first = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        assert_eq!(first, second, "custom-section JSON must be deterministic");
    }

    #[test]
    fn malformed_custom_section_is_rejected() {
        // Custom section: id=0, length claims 5 bytes, but only 2 bytes remain.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.push(0x00); // custom section id
        b.push(0x05); // claims 5 bytes of payload
        b.push(0x03); // name length 3
        b.extend_from_slice(b"ab"); // only 2 bytes — truncated
        let result = inspect(&b, false);
        assert!(
            result.is_err(),
            "truncated custom section must be rejected as malformed"
        );
    }

    // --- Code body metrics tests ---

    /// Build a module with one defined function whose body is `body` (locals
    /// + operators, excluding the body-size prefix).
    fn module_with_one_body(body: &[u8]) -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&function_section(1));
        let mut payload = vec![0x01]; // one function body
        payload.push(body.len() as u8); // body size prefix
        payload.extend_from_slice(body);
        let mut code = vec![0x0a, payload.len() as u8];
        code.extend_from_slice(&payload);
        b.extend_from_slice(&code);
        b
    }

    #[test]
    fn no_defined_functions_has_no_metrics() {
        // Module with an import but no defined functions.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&import_section(&["imp1"]));
        let report = inspect(&b, false).unwrap();
        assert!(report.code_body_metrics.is_empty());
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value.get("code_body_metrics").is_none(),
            "empty metrics must be omitted from JSON"
        );
    }

    #[test]
    fn empty_body_metrics() {
        // Body: 0 local declarations, just `end`.
        let report = inspect(&module_with_one_body(&[0x00, 0x0b]), false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.defined_index, 0);
        assert_eq!(m.function_index, 0);
        assert_eq!(m.body_len_bytes, 2);
        assert_eq!(m.local_decl_count, 0);
        assert_eq!(m.local_total, 0);
        assert_eq!(m.operator_count, 0);
        assert_eq!(m.max_control_depth, 0);
    }

    #[test]
    fn locals_are_counted() {
        // Body: 1 local declaration (3 × i32), then `end`.
        let report = inspect(&module_with_one_body(&[0x01, 0x03, 0x7f, 0x0b]), false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.local_decl_count, 1);
        assert_eq!(m.local_total, 3);
        assert_eq!(m.operator_count, 0);
    }

    #[test]
    fn nested_block_loop_if_depth() {
        // Body: 0 locals, block → loop → if → end → end → end → end
        let body = [
            0x00, // 0 local declarations
            0x02, 0x40, // block (void)
            0x03, 0x40, // loop (void)
            0x04, 0x40, // if (void)
            0x0b, // end (if)
            0x0b, // end (loop)
            0x0b, // end (block)
            0x0b, // end (function)
        ];
        let report = inspect(&module_with_one_body(&body), false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.max_control_depth, 3);
        // 3 openers + 3 inner ends = 6 (function-body end excluded).
        assert_eq!(m.operator_count, 6);
    }

    #[test]
    fn imported_functions_precede_defined_in_index() {
        // 2 imported functions + 1 defined function.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&import_section(&["imp1", "imp2"]));
        b.extend_from_slice(&function_section(1));
        b.extend_from_slice(&code_section(1));
        let report = inspect(&b, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.defined_index, 0);
        assert_eq!(m.function_index, 2, "imports occupy indices 0 and 1");
    }

    #[test]
    fn multiple_bodies_preserve_order() {
        // 3 defined functions with distinct body sizes.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&function_section(3));
        let mut payload = vec![0x03]; // three bodies
                                      // Body 1: empty (end only)
        payload.extend_from_slice(&[0x02, 0x00, 0x0b]);
        // Body 2: one nop then end
        payload.extend_from_slice(&[0x03, 0x00, 0x01, 0x0b]);
        // Body 3: one local + end
        payload.extend_from_slice(&[0x04, 0x01, 0x01, 0x7f, 0x0b]);
        let mut code = vec![0x0a, payload.len() as u8];
        code.extend_from_slice(&payload);
        b.extend_from_slice(&code);
        let report = inspect(&b, false).unwrap();
        let metrics = &report.code_body_metrics;
        assert_eq!(metrics.len(), 3);
        assert_eq!(metrics[0].defined_index, 0);
        assert_eq!(metrics[1].defined_index, 1);
        assert_eq!(metrics[2].defined_index, 2);
        assert_eq!(metrics[0].body_len_bytes, 2);
        assert_eq!(metrics[1].body_len_bytes, 3);
        assert_eq!(metrics[2].body_len_bytes, 4);
        assert_eq!(metrics[1].operator_count, 1, "one nop");
        assert_eq!(metrics[2].local_total, 1);
    }

    #[test]
    fn malformed_code_body_is_rejected() {
        // Function section declares 1 function, but the code section body
        // claims a size that exceeds the remaining bytes.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&function_section(1));
        // Code section: count 1, body size 10, but only 2 bytes follow.
        let payload = vec![0x01, 0x0a, 0x00, 0x0b];
        let mut code = vec![0x0a, payload.len() as u8];
        code.extend_from_slice(&payload);
        b.extend_from_slice(&code);
        let result = inspect(&b, false);
        assert!(
            result.is_err(),
            "truncated code body must be rejected as malformed"
        );
    }

    #[test]
    fn code_body_metrics_json_is_deterministic() {
        let build = || {
            let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
            b.extend_from_slice(&type_section(1));
            b.extend_from_slice(&function_section(2));
            b.extend_from_slice(&code_section(2));
            b
        };
        let first = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        assert_eq!(
            first, second,
            "code-body metrics JSON must be deterministic"
        );
    }

    // --- Instruction inventory tests ---

    /// Build a module with one defined function whose operator stream is
    /// `ops` (after 0 local declarations).
    fn module_with_ops(ops: &[u8]) -> Vec<u8> {
        let mut body = vec![0x00]; // 0 local declarations
        body.extend_from_slice(ops);
        body.push(0x0b); // end
        module_with_one_body(&body)
    }

    fn inv(report: &super::WasmReport) -> &std::collections::BTreeMap<String, usize> {
        &report.code_body_metrics[0].instruction_inventory
    }

    #[test]
    fn inventory_control_flow_families() {
        // br_if 0 (0x0d 0x00), return (0x0f), call 0 (0x10 0x00),
        // call_indirect (0x11 0x00 0x00)
        let wasm = module_with_ops(&[
            0x0d, 0x00, // br_if 0
            0x0f, // return
            0x10, 0x00, // call 0
            0x11, 0x00, 0x00, // call_indirect type 0 table 0
        ]);
        let report = inspect(&wasm, false).unwrap();
        let inv = inv(&report);
        assert_eq!(inv.get("control"), Some(&2), "br_if + return");
        assert_eq!(inv.get("call"), Some(&2), "call + call_indirect");
    }

    #[test]
    fn inventory_local_and_global_families() {
        // local.get 0 (0x20 0x00), local.set 0 (0x21 0x00),
        // local.tee 0 (0x22 0x00), global.get 0 (0x23 0x00),
        // global.set 0 (0x24 0x00)
        let wasm = module_with_ops(&[
            0x20, 0x00, // local.get
            0x21, 0x00, // local.set
            0x22, 0x00, // local.tee
            0x23, 0x00, // global.get
            0x24, 0x00, // global.set
        ]);
        let report = inspect(&wasm, false).unwrap();
        let inv = inv(&report);
        assert_eq!(inv.get("local"), Some(&3));
        assert_eq!(inv.get("global"), Some(&2));
    }

    #[test]
    fn inventory_memory_families() {
        // i32.load (0x28 0x00 0x00), i32.store (0x36 0x00 0x00),
        // memory.size (0x3f 0x00), memory.grow (0x40 0x00)
        let wasm = module_with_ops(&[
            0x28, 0x00, 0x00, // i32.load
            0x36, 0x00, 0x00, // i32.store
            0x3f, 0x00, // memory.size
            0x40, 0x00, // memory.grow
        ]);
        let report = inspect(&wasm, false).unwrap();
        let inv = inv(&report);
        assert_eq!(inv.get("load"), Some(&1));
        assert_eq!(inv.get("store"), Some(&1));
        assert_eq!(inv.get("memory"), Some(&2));
    }

    #[test]
    fn inventory_numeric_and_conversion_families() {
        // i32.const 1 (0x41 0x01), i32.add (0x6a), i32.eqz (0x45),
        // i32.wrap_i64 (0xa7)
        let wasm = module_with_ops(&[
            0x41, 0x01, // i32.const 1
            0x6a, // i32.add
            0x45, // i32.eqz
            0xa7, // i32.wrap_i64
        ]);
        let report = inspect(&wasm, false).unwrap();
        let inv = inv(&report);
        assert_eq!(inv.get("const"), Some(&1));
        assert_eq!(inv.get("numeric"), Some(&1), "i32.add");
        assert_eq!(inv.get("compare"), Some(&1), "i32.eqz");
        assert_eq!(inv.get("conversion"), Some(&1), "i32.wrap_i64");
    }

    #[test]
    fn inventory_reference_family() {
        // ref.null func (0xd0 0x70), ref.is_null (0xd1)
        let wasm = module_with_ops(&[
            0xd0, 0x70, // ref.null func
            0xd1, // ref.is_null
        ]);
        let report = inspect(&wasm, false).unwrap();
        let inv = inv(&report);
        assert_eq!(inv.get("reference"), Some(&2));
    }

    #[test]
    fn inventory_misc_family() {
        // nop (0x01), drop (0x1a), unreachable (0x00)
        let wasm = module_with_ops(&[0x01, 0x1a, 0x00]);
        let report = inspect(&wasm, false).unwrap();
        let inv = inv(&report);
        assert_eq!(inv.get("misc"), Some(&3));
    }

    #[test]
    fn inventory_counts_are_exclusive() {
        // Every operator counted exactly once: sum of inventory values
        // equals operator_count.
        let wasm = module_with_ops(&[
            0x0d, 0x00, // br_if -> control
            0x20, 0x00, // local.get -> local
            0x28, 0x00, 0x00, // i32.load -> load
            0x41, 0x01, // i32.const -> const
            0x6a, // i32.add -> numeric
            0x01, // nop -> misc
        ]);
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        let total: usize = m.instruction_inventory.values().sum();
        assert_eq!(
            total, m.operator_count,
            "inventory must sum to operator_count"
        );
    }

    #[test]
    fn inventory_omitted_when_empty() {
        // Empty body: no operators, so inventory is empty and omitted.
        let wasm = module_with_one_body(&[0x00, 0x0b]);
        let json = serde_json::to_string(&inspect(&wasm, false).unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value["code_body_metrics"][0]
                .get("instruction_inventory")
                .is_none(),
            "empty inventory must be omitted from JSON"
        );
    }

    #[test]
    fn inventory_json_is_deterministic_and_sorted() {
        let wasm = module_with_ops(&[
            0x0d, 0x00, // control
            0x20, 0x00, // local
            0x41, 0x01, // const
            0x6a, // numeric
        ]);
        let first = serde_json::to_string(&inspect(&wasm, false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&wasm, false).unwrap()).unwrap();
        assert_eq!(first, second);
        let value: serde_json::Value = serde_json::from_str(&first).unwrap();
        let inv = &value["code_body_metrics"][0]["instruction_inventory"];
        // BTreeMap serializes keys in sorted order.
        let keys: Vec<&str> = inv
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "inventory keys must be sorted");
    }

    #[test]
    fn inventory_unknown_falls_back_to_other() {
        // `if` (0x04 0x40), `else` (0x05), and `end` (0x0b) are all
        // classified as control; the function-body `end` is excluded from
        // the inventory, so the count is 3 (if + else + end).
        let wasm = module_with_ops(&[
            0x04, 0x40, // if
            0x05, // else
            0x0b, // end (if)
        ]);
        let report = inspect(&wasm, false).unwrap();
        let inv = inv(&report);
        assert_eq!(inv.get("control"), Some(&3), "if + else + end");
    }

    // --- Complexity metric tests ---

    /// A body's metrics entry, for readability in the tests below.
    fn m(report: &WasmReport) -> &CodeBodyMetrics {
        &report.code_body_metrics[0]
    }

    #[test]
    fn complexity_straight_line_body() {
        // call, add, nop — no control flow, no calls to follow.
        let wasm = module_with_ops(&[0x01, 0x6a, 0x10, 0x00]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.basic_block_count, 1, "one straight-line block");
        assert_eq!(m.conditional_branch_count, 0);
        assert_eq!(m.unconditional_branch_count, 0);
        assert_eq!(m.loop_count, 0);
        assert_eq!(m.if_count, 0);
        assert_eq!(m.cyclomatic_complexity, 1, "no decision points");
        assert_eq!(m.direct_call_site_count, 1, "one direct call site");
        assert_eq!(m.max_control_depth, 0);
    }

    #[test]
    fn complexity_empty_body() {
        // 0 locals, just the function-body end.
        let wasm = module_with_one_body(&[0x00, 0x0b]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.basic_block_count, 1, "the empty entry block still counts");
        assert_eq!(m.operator_count, 0);
        assert_eq!(m.cyclomatic_complexity, 1);
        assert_eq!(m.direct_call_site_count, 0);
        assert_eq!(m.max_control_depth, 0);
    }

    #[test]
    fn complexity_br_if_is_conditional() {
        // br_if 0 is a two-way decision: falls through or branches.
        let wasm = module_with_ops(&[0x0d, 0x00]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.conditional_branch_count, 1);
        assert_eq!(m.unconditional_branch_count, 0);
        assert_eq!(m.if_count, 0, "br_if is not an if construct");
        assert_eq!(m.cyclomatic_complexity, 2);
    }

    #[test]
    fn complexity_br_is_unconditional() {
        let wasm = module_with_ops(&[0x0c, 0x00]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.unconditional_branch_count, 1);
        assert_eq!(m.conditional_branch_count, 0);
        assert_eq!(m.cyclomatic_complexity, 1, "br is not a decision point");
    }

    #[test]
    fn complexity_if_construct() {
        // if / nop / end
        let wasm = module_with_ops(&[0x04, 0x40, 0x01, 0x0b]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.if_count, 1);
        assert_eq!(m.conditional_branch_count, 1);
        assert_eq!(m.max_control_depth, 1);
        assert_eq!(m.loop_count, 0);
        assert_eq!(m.cyclomatic_complexity, 2);
    }

    #[test]
    fn complexity_loop_construct() {
        // loop / end
        let wasm = module_with_ops(&[0x03, 0x40, 0x0b]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.loop_count, 1);
        assert_eq!(m.max_control_depth, 1);
        assert_eq!(m.if_count, 0);
        assert_eq!(
            m.cyclomatic_complexity, 1,
            "a bare loop is not a decision point"
        );
    }

    #[test]
    fn complexity_nested_control_flow() {
        // block / loop / if / end / end / end
        let wasm = module_with_ops(&[0x02, 0x40, 0x03, 0x40, 0x04, 0x40, 0x0b, 0x0b, 0x0b]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.max_control_depth, 3);
        assert_eq!(m.loop_count, 1);
        assert_eq!(m.if_count, 1);
        assert_eq!(m.cyclomatic_complexity, 2);
        assert_eq!(m.conditional_branch_count, 1);
        assert_eq!(m.unconditional_branch_count, 0);
    }

    #[test]
    fn complexity_repeated_calls_are_separate_sites() {
        // Two calls to the same target: one edge, two sites.
        let wasm =
            module_with_bodies(&[body_with_ops(&[0x10, 0x01, 0x10, 0x01]), body_with_ops(&[])]);
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.direct_call_site_count, 2, "sites count repeats");
        assert_eq!(
            m.direct_calls.len(),
            1,
            "but edges collapse to distinct callees"
        );
        assert_eq!(m.direct_calls[0].call_count, 2);
    }

    #[test]
    fn complexity_basic_block_leaders() {
        // br_if splits the block: entry, then the post-branch continuation.
        let wasm = module_with_ops(&[0x0d, 0x00, 0x01, 0x6a]);
        let report = inspect(&wasm, false).unwrap();
        let m = m(&report);
        assert_eq!(m.basic_block_count, 2, "br_if starts a new block after it");
    }

    #[test]
    fn complexity_json_is_deterministic() {
        let build = || module_with_ops(&[0x02, 0x40, 0x0d, 0x00, 0x10, 0x00, 0x0b]);
        let first = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        assert_eq!(first, second, "complexity JSON must be deterministic");
    }

    #[test]
    fn complexity_json_is_additive_and_complete() {
        let wasm = module_with_ops(&[0x04, 0x40, 0x01, 0x0b]);
        let report = inspect(&wasm, false).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let entry = &value["code_body_metrics"][0];
        for field in [
            "body_len_bytes",
            "local_decl_count",
            "local_total",
            "operator_count",
            "max_control_depth",
            "instruction_inventory",
            "direct_call_site_count",
            "basic_block_count",
            "conditional_branch_count",
            "unconditional_branch_count",
            "loop_count",
            "if_count",
            "cyclomatic_complexity",
        ] {
            assert!(entry.get(field).is_some(), "field {field} present");
        }
    }

    #[test]
    fn complexity_zero_counts_are_present_not_omitted() {
        // The complexity counters are plain counts, so a zero is meaningful and
        // must still be emitted.
        let wasm = module_with_one_body(&[0x00, 0x0b]);
        let report = inspect(&wasm, false).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let entry = &value["code_body_metrics"][0];
        assert_eq!(entry["loop_count"], 0);
        assert_eq!(entry["if_count"], 0);
        assert_eq!(entry["conditional_branch_count"], 0);
        assert_eq!(entry["cyclomatic_complexity"], 1);
    }

    // --- Direct call graph tests ---

    /// Build a module with `n` defined functions, each with the given body
    /// bytes (`bodies[i]` is the raw body for defined function `i`, excluding
    /// the body-size prefix).
    fn module_with_bodies(bodies: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&function_section(bodies.len()));
        let mut payload = vec![bodies.len() as u8];
        for body in bodies {
            payload.push(body.len() as u8);
            payload.extend_from_slice(body);
        }
        let mut code = vec![0x0a];
        code.extend_from_slice(&leb(payload.len() as u32));
        code.extend_from_slice(&payload);
        b.extend_from_slice(&code);
        b
    }

    /// A body with 0 locals that executes `ops` then `end`.
    fn body_with_ops(ops: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(ops);
        v.push(0x0b);
        v
    }

    // --- Reachability test helpers ---

    /// An export section exporting function `index` under `name`.
    fn export_func(name: &str, index: u32) -> Vec<u8> {
        let mut payload = vec![0x01]; // one export
        payload.push(name.len() as u8);
        payload.extend_from_slice(name.as_bytes());
        payload.push(0x00); // ExternalKind::Func
        payload.extend_from_slice(&leb(index));
        let mut b = vec![0x07]; // export section id
        b.extend_from_slice(&leb(payload.len() as u32));
        b.extend_from_slice(&payload);
        b
    }

    /// A start section naming function `index`.
    fn start_section(index: u32) -> Vec<u8> {
        let payload = leb(index);
        let mut b = vec![0x08]; // start section id
        b.extend_from_slice(&leb(payload.len() as u32));
        b.extend_from_slice(&payload);
        b
    }

    /// Build a module with the given imports, defined-function bodies, exports
    /// (`(name, function index)`), and optional start function index. Sections
    /// are emitted in canonical order.
    fn module_with_graph(
        imports: &[&str],
        bodies: &[Vec<u8>],
        exports: &[(&str, u32)],
        start: Option<u32>,
    ) -> Vec<u8> {
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        if !imports.is_empty() {
            b.extend_from_slice(&import_section(imports));
        }
        b.extend_from_slice(&function_section(bodies.len()));
        for (name, idx) in exports {
            b.extend_from_slice(&export_func(name, *idx));
        }
        if let Some(s) = start {
            b.extend_from_slice(&start_section(s));
        }
        let mut payload = vec![bodies.len() as u8];
        for body in bodies {
            payload.push(body.len() as u8);
            payload.extend_from_slice(body);
        }
        let mut code = vec![0x0a];
        code.extend_from_slice(&leb(payload.len() as u32));
        code.extend_from_slice(&payload);
        b.extend_from_slice(&code);
        b
    }

    // --- Reachability tests ---

    #[test]
    fn reachability_absent_when_no_defined_functions() {
        // No defined functions: nothing to analyse, field omitted entirely.
        let wasm = module_with_graph(&["imp"], &[], &[], None);
        let report = inspect(&wasm, false).unwrap();
        assert!(report.reachability.is_none());
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            value.get("reachability").is_none(),
            "reachability must be omitted when there are no defined functions"
        );
    }

    #[test]
    fn reachability_export_is_a_root() {
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("entry", 0)], None);
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.roots.len(), 1);
        assert_eq!(r.roots[0].kind, "export");
        assert_eq!(r.roots[0].name.as_deref(), Some("entry"));
        assert_eq!(r.roots[0].function_index, 0);
        assert_eq!(r.roots[0].resolution, "defined");
        assert_eq!(r.roots[0].defined_index, Some(0));
        assert_eq!(r.reachable_defined, vec![0]);
        assert!(r.unreachable_defined.is_empty());
    }

    #[test]
    fn reachability_start_is_a_root() {
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[], Some(0));
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.roots.len(), 1);
        assert_eq!(r.roots[0].kind, "start");
        assert!(
            r.roots[0].name.is_none(),
            "start roots carry no export name"
        );
        assert_eq!(r.roots[0].resolution, "defined");
        assert_eq!(r.reachable_defined, vec![0]);
    }

    #[test]
    fn reachability_start_ranks_before_exports() {
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("e", 0)], Some(0));
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.roots.len(), 2);
        assert_eq!(r.roots[0].kind, "start", "start is ordered first");
        assert_eq!(r.roots[1].kind, "export");
    }

    #[test]
    fn reachability_transitive_direct_calls() {
        // Defined 0 calls 1; defined 1 calls 2. Root = export of defined 0.
        let wasm = module_with_graph(
            &[],
            &[
                body_with_ops(&[0x10, 0x01]), // call 1
                body_with_ops(&[0x10, 0x02]), // call 2
                body_with_ops(&[]),
            ],
            &[("entry", 0)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.reachable_defined, vec![0, 1, 2], "transitive closure");
        assert!(r.unreachable_defined.is_empty());
    }

    #[test]
    fn reachability_imports_first_indexing() {
        // 1 import (index 0) + 2 defined (indices 1, 2). Defined 0 calls the
        // import and defined 1. Root = export of defined 0 (index 1).
        let wasm = module_with_graph(
            &["host_fn"],
            &[
                body_with_ops(&[0x10, 0x00, 0x10, 0x02]), // call 0 (import), call 2 (defined 1)
                body_with_ops(&[]),
            ],
            &[("entry", 1)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.roots[0].function_index, 1, "export names raw index 1");
        assert_eq!(r.roots[0].defined_index, Some(0));
        assert_eq!(
            r.reachable_defined,
            vec![0, 1],
            "import at index 0 is not a defined function"
        );
        assert!(r.unreachable_defined.is_empty());
    }

    #[test]
    fn reachability_imported_export_root_is_not_traversed() {
        // Exporting an imported function makes it a root, but it has no body
        // in this module, so no defined function becomes reachable through it.
        let wasm = module_with_graph(
            &["host_fn"],
            &[body_with_ops(&[])], // defined 0, unreached
            &[("host", 0)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.roots[0].resolution, "imported");
        assert!(r.roots[0].defined_index.is_none());
        assert!(r.reachable_defined.is_empty());
        assert_eq!(r.unreachable_defined, vec![0]);
    }

    #[test]
    fn reachability_unreachable_defined_functions_reported() {
        // 3 defined functions, only 0 exported and it makes no calls.
        let wasm = module_with_graph(
            &[],
            &[body_with_ops(&[]), body_with_ops(&[]), body_with_ops(&[])],
            &[("entry", 0)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.reachable_defined, vec![0]);
        assert_eq!(r.unreachable_defined, vec![1, 2]);
    }

    #[test]
    fn reachability_invalid_root_index_is_safe() {
        // Export names index 99, which no function occupies.
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("bogus", 99)], None);
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.roots[0].resolution, "invalid");
        assert!(r.roots[0].defined_index.is_none());
        assert!(r.reachable_defined.is_empty());
        assert_eq!(r.unreachable_defined, vec![0]);
    }

    #[test]
    fn reachability_invalid_call_target_does_not_panic() {
        // Defined 0 calls index 99 (invalid) and index 1 (defined).
        let wasm = module_with_graph(
            &[],
            &[
                body_with_ops(&[0x10, 0x63, 0x10, 0x01]), // call 99, call 1
                body_with_ops(&[]),
            ],
            &[("entry", 0)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(
            r.reachable_defined,
            vec![0, 1],
            "invalid target is skipped, valid edge still followed"
        );
    }

    #[test]
    fn reachability_json_is_deterministic() {
        let build = || {
            module_with_graph(
                &["host_fn"],
                &[
                    body_with_ops(&[0x10, 0x01, 0x10, 0x02]),
                    body_with_ops(&[]),
                    body_with_ops(&[]),
                ],
                &[("entry", 1), ("aux", 2)],
                Some(1),
            )
        };
        let first = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        assert_eq!(first, second, "reachability JSON must be deterministic");
    }

    #[test]
    fn reachability_json_omits_empty_arrays() {
        // One defined function, exported: reachable=[0], unreachable empty.
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("entry", 0)], None);
        let report = inspect(&wasm, false).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let r = &value["reachability"];
        assert!(r.get("reachable_defined").is_some());
        assert!(
            r.get("unreachable_defined").is_none(),
            "empty unreachable list must be omitted"
        );
    }

    #[test]
    fn reachability_json_is_backward_compatible() {
        // Adding reachability must not disturb pre-existing keys. Only keys
        // that `inspect` always emits are asserted; `structure` and `analysis`
        // are legitimately omitted when empty/absent.
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("entry", 0)], None);
        let report = inspect(&wasm, false).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        for key in [
            "size_bytes",
            "imports",
            "exports",
            "custom_sections",
            "functions",
            "code_body_metrics",
            "interface",
        ] {
            assert!(value.get(key).is_some(), "pre-existing key {key} survives");
        }
        assert!(value.get("reachability").is_some(), "new key present");
    }

    #[test]
    fn reachability_self_recursive_function_is_reached() {
        // A function that calls itself must not loop forever.
        let wasm = module_with_graph(
            &[],
            &[body_with_ops(&[0x10, 0x00])], // call 0 (itself)
            &[("entry", 0)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let r = report.reachability.expect("reachability present");
        assert_eq!(r.reachable_defined, vec![0]);
    }

    // --- Consolidated summary tests ---

    #[test]
    fn summary_empty_module_is_all_zeros_with_optional_parts_omitted() {
        let wasm = module_with_graph(&[], &[], &[], None);
        let report = inspect(&wasm, false).unwrap();
        let s = &report.summary;
        assert_eq!(s.imported_function_count, 0);
        assert_eq!(s.exported_function_count, 0);
        assert_eq!(s.defined_function_count, 0);
        assert_eq!(s.total_function_count, 0);
        assert_eq!(s.total_body_bytes, 0);
        assert_eq!(s.total_operator_count, 0);
        assert_eq!(s.total_local_count, 0);
        assert_eq!(s.custom_section_count, 0);
        assert!(!s.has_contract_spec);
        assert!(
            s.structure.is_none(),
            "structure absent: unavailable, not zero"
        );
        assert!(
            s.reachability.is_none(),
            "reachability absent: unavailable, not zero"
        );
        assert!(s.instruction_family_totals.is_empty());
        // The JSON must omit the unavailable sub-objects rather than emit them
        // as zeros.
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let s = &value["summary"];
        assert!(
            s.get("structure").is_none(),
            "unavailable structure omitted"
        );
        assert!(
            s.get("reachability").is_none(),
            "unavailable reachability omitted"
        );
        assert!(s.get("instruction_family_totals").is_none());
    }

    #[test]
    fn summary_counts_populated_module() {
        // 1 import + 2 defined, 1 export, 1 custom section, a start section.
        let wasm = module_with_graph(
            &["host_fn"],
            &[
                body_with_ops(&[0x01]), // nop
                body_with_ops(&[]),
            ],
            &[("entry", 1)],
            Some(1),
        );
        let report = inspect(&wasm, false).unwrap();
        let s = &report.summary;
        assert_eq!(s.imported_function_count, 1);
        assert_eq!(s.exported_function_count, 1);
        assert_eq!(s.defined_function_count, 2);
        assert_eq!(s.total_function_count, 3, "imports + defined");
        assert_eq!(s.total_body_bytes, 5, "body bytes summed over both bodies");
        assert_eq!(s.total_operator_count, 1, "one nop across the module");
        assert_eq!(s.total_local_count, 0);
        assert_eq!(s.custom_section_count, 0);

        let st = s
            .structure
            .as_ref()
            .expect("structure present (start section)");
        assert!(st.has_start_function);
        assert_eq!(st.memory_count, 0);

        let r = s.reachability.as_ref().expect("reachability present");
        assert_eq!(r.root_count, 2, "start + export");
        assert_eq!(r.reachable_defined_count, 1, "only defined 0 is a root");
        assert_eq!(r.unreachable_defined_count, 1);
    }

    #[test]
    fn summary_mirrors_reachability_and_structure_consistently() {
        let wasm = module_with_graph(
            &[],
            &[
                body_with_ops(&[0x10, 0x01]),
                body_with_ops(&[]),
                body_with_ops(&[]),
            ],
            &[("entry", 0)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let s = &report.summary;
        let r = s.reachability.as_ref().expect("reachability present");
        let r_full = report.reachability.as_ref().expect("reachability present");
        assert_eq!(r.root_count, r_full.roots.len());
        assert_eq!(r.reachable_defined_count, r_full.reachable_defined.len());
        assert_eq!(
            r.unreachable_defined_count,
            r_full.unreachable_defined.len()
        );
        // The two lists must partition the defined functions exactly.
        assert_eq!(
            r.reachable_defined_count + r.unreachable_defined_count,
            s.defined_function_count
        );
    }

    #[test]
    fn summary_instruction_family_totals_sum_to_operator_total() {
        let wasm = module_with_graph(
            &[],
            &[
                body_with_ops(&[0x01, 0x6a, 0x10, 0x01]), // nop, add, call
                body_with_ops(&[0x01]),                   // nop
            ],
            &[("entry", 0)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let s = &report.summary;
        let family_sum: usize = s.instruction_family_totals.values().sum();
        assert_eq!(
            family_sum, s.total_operator_count,
            "family totals must sum to the operator total"
        );
        // Both bodies emit the "misc" family from their nop.
        assert_eq!(s.instruction_family_totals.get("misc"), Some(&2));
        assert_eq!(s.instruction_family_totals.get("numeric"), Some(&1));
        assert_eq!(s.instruction_family_totals.get("call"), Some(&1));
    }

    #[test]
    fn summary_has_contract_spec_mirrors_interface() {
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("entry", 0)], None);
        let mut report = inspect(&wasm, false).unwrap();
        assert!(!report.summary.has_contract_spec);
        assert_eq!(
            report.summary.has_contract_spec,
            report.interface.as_ref().unwrap().has_contract_spec,
            "summary must agree with the interface flag"
        );
        // Simulate a contract spec section and re-derive: the flag follows.
        report.custom_sections.push(CustomSection {
            name: "contractspecv0".to_string(),
            len_bytes: 0,
        });
        report.interface = Some(build_interface_summary(&report));
        report.summary = build_analysis_summary(&report).unwrap();
        assert!(report.summary.has_contract_spec);
        assert_eq!(
            report.summary.custom_section_count, 1,
            "custom section count mirrors custom_sections.len()"
        );
    }

    #[test]
    fn summary_analysis_finding_count_absent_without_analysis() {
        // The library-level `inspect` does not run `analysis`, so the summary
        // must report the field as unavailable rather than as a zero.
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("entry", 0)], None);
        let report = inspect(&wasm, false).unwrap();
        assert!(report.analysis.is_none());
        assert!(
            report.summary.analysis_finding_count.is_none(),
            "unavailable analysis is omitted, not reported as zero"
        );
    }

    #[test]
    fn summary_analysis_finding_count_present_with_analysis() {
        let wasm = module_with_graph(&[], &[body_with_ops(&[])], &[("entry", 0)], None);
        let mut report = inspect(&wasm, false).unwrap();
        assert!(report.summary.analysis_finding_count.is_none());
        report.analysis = Some(analyze(&wasm).unwrap());
        report.summary = build_analysis_summary(&report).unwrap();
        let expected = report.analysis.as_ref().unwrap().findings.len();
        assert_eq!(
            report.summary.analysis_finding_count,
            Some(expected),
            "summary reflects the attached analysis"
        );
    }

    #[test]
    fn summary_json_is_deterministic() {
        let build = || {
            module_with_graph(
                &["host_fn"],
                &[body_with_ops(&[0x01]), body_with_ops(&[])],
                &[("entry", 1)],
                Some(1),
            )
        };
        let first = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        assert_eq!(first, second, "summary JSON must be deterministic");
    }

    #[test]
    fn summary_json_is_additive_and_sorted() {
        let wasm = module_with_graph(
            &["host_fn"],
            &[body_with_ops(&[0x01, 0x6a]), body_with_ops(&[])],
            &[("entry", 1)],
            None,
        );
        let report = inspect(&wasm, false).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        for key in [
            "size_bytes",
            "imports",
            "exports",
            "custom_sections",
            "functions",
            "code_body_metrics",
            "reachability",
            "interface",
            "summary",
        ] {
            assert!(value.get(key).is_some(), "key {key} present");
        }
        // The family map is a BTreeMap, so its JSON keys are sorted.
        let s = &value["summary"]["instruction_family_totals"];
        let keys: Vec<&str> = s.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "family totals must be sorted");
    }

    #[test]
    fn summary_omits_optional_parts_not_fills_them_with_zero() {
        // A minimal module: no structure, no reachability. The sub-objects must
        // be absent from JSON, not present as all-zero objects.
        let wasm = module_with_graph(&[], &[], &[], None);
        let report = inspect(&wasm, false).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let s = &value["summary"];
        assert!(s.get("structure").is_none());
        assert!(s.get("reachability").is_none());
        assert!(s.get("analysis_finding_count").is_none());
        // Genuine zeros are still emitted for the always-available counts.
        assert_eq!(s["total_function_count"], 0);
        assert_eq!(s["has_contract_spec"], false);
    }

    #[test]
    fn call_graph_no_calls() {
        let wasm = module_with_bodies(&[body_with_ops(&[0x01])]); // nop
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert!(m.direct_calls.is_empty());
        assert_eq!(m.indirect_call_sites, 0);
        assert_eq!(m.reference_call_sites, 0);
        let json = serde_json::to_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let entry = &value["code_body_metrics"][0];
        assert!(entry.get("direct_calls").is_none(), "empty edges omitted");
        assert!(
            entry.get("indirect_call_sites").is_none(),
            "zero counter omitted"
        );
    }

    #[test]
    fn call_graph_direct_call_to_defined() {
        // Two defined functions (indices 0 and 1). Function 0 calls 1.
        let wasm = module_with_bodies(&[
            body_with_ops(&[0x10, 0x01]), // call 1
            body_with_ops(&[]),
        ]);
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.direct_calls.len(), 1);
        let edge = &m.direct_calls[0];
        assert_eq!(edge.callee_index, 1);
        assert_eq!(edge.call_count, 1);
        match &edge.resolution {
            CallTargetResolution::Defined { defined_index, .. } => {
                assert_eq!(*defined_index, 1);
            }
            other => panic!("expected Defined, got {other:?}"),
        }
    }

    #[test]
    fn call_graph_direct_call_to_imported() {
        // One imported function (index 0) + one defined (index 1) that
        // calls the import.
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&import_section(&["ext_fn"]));
        b.extend_from_slice(&function_section(1));
        let body = body_with_ops(&[0x10, 0x00]); // call 0
        let mut payload = vec![0x01, body.len() as u8];
        payload.extend_from_slice(&body);
        b.push(0x0a);
        b.extend_from_slice(&leb(payload.len() as u32));
        b.extend_from_slice(&payload);
        let report = inspect(&b, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.function_index, 1, "defined function follows the import");
        assert_eq!(m.direct_calls.len(), 1);
        let edge = &m.direct_calls[0];
        assert_eq!(edge.callee_index, 0);
        match &edge.resolution {
            CallTargetResolution::Imported { module, name } => {
                assert_eq!(module, "env");
                assert_eq!(name, "ext_fn");
            }
            other => panic!("expected Imported, got {other:?}"),
        }
    }

    #[test]
    fn call_graph_duplicate_calls_are_aggregated() {
        // Three call sites to the same callee collapse into one edge.
        let wasm = module_with_bodies(&[
            body_with_ops(&[
                0x10, 0x01, // call 1
                0x10, 0x01, // call 1
                0x10, 0x01, // call 1
            ]),
            body_with_ops(&[]),
        ]);
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.direct_calls.len(), 1, "distinct callees, not sites");
        assert_eq!(m.direct_calls[0].callee_index, 1);
        assert_eq!(m.direct_calls[0].call_count, 3);
    }

    #[test]
    fn call_graph_edges_sorted_by_callee() {
        // Calls out of order: 2, then 0, then 1. Edges must come out sorted.
        let wasm = module_with_bodies(&[
            body_with_ops(&[
                0x10, 0x02, // call 2
                0x10, 0x00, // call 0
                0x10, 0x01, // call 1
            ]),
            body_with_ops(&[]),
            body_with_ops(&[]),
        ]);
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        let idxs: Vec<u32> = m.direct_calls.iter().map(|e| e.callee_index).collect();
        assert_eq!(idxs, vec![0, 1, 2], "edges sorted by callee index");
    }

    #[test]
    fn call_graph_indirect_calls_have_no_invented_target() {
        // call_indirect (0x11 0x00 0x00) names a type, not a target.
        let wasm = module_with_bodies(&[body_with_ops(&[0x11, 0x00, 0x00])]);
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert!(m.direct_calls.is_empty(), "no edge invented");
        assert_eq!(m.indirect_call_sites, 1);
    }

    #[test]
    fn call_graph_unresolved_callee_is_invalid_not_panicking() {
        // call 99 names no function in a one-function module.
        let wasm = module_with_bodies(&[body_with_ops(&[0x10, 0x63])]); // call 99
        let report = inspect(&wasm, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.direct_calls.len(), 1);
        assert_eq!(m.direct_calls[0].callee_index, 99);
        assert_eq!(m.direct_calls[0].resolution, CallTargetResolution::Invalid);
    }

    #[test]
    fn call_graph_json_is_deterministic() {
        let build = || {
            module_with_bodies(&[
                body_with_ops(&[0x10, 0x01, 0x10, 0x02, 0x10, 0x01]),
                body_with_ops(&[0x11, 0x00, 0x00]),
                body_with_ops(&[]),
            ])
        };
        let first = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        let second = serde_json::to_string(&inspect(&build(), false).unwrap()).unwrap();
        assert_eq!(first, second, "call-graph JSON must be deterministic");
    }

    #[test]
    fn call_graph_resolution_survives_imports_before_defined() {
        // 2 imports (indices 0, 1) + 2 defined (indices 2, 3).
        // Defined function 0 calls index 1 (import) and index 3 (defined 1).
        let mut b = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        b.extend_from_slice(&type_section(1));
        b.extend_from_slice(&import_section(&["imp_a", "imp_b"]));
        b.extend_from_slice(&function_section(2));
        let b0 = body_with_ops(&[0x10, 0x01, 0x10, 0x03]);
        let b1 = body_with_ops(&[]);
        let mut payload = vec![0x02, b0.len() as u8];
        payload.extend_from_slice(&b0);
        payload.push(b1.len() as u8);
        payload.extend_from_slice(&b1);
        b.push(0x0a);
        b.extend_from_slice(&leb(payload.len() as u32));
        b.extend_from_slice(&payload);
        let report = inspect(&b, false).unwrap();
        let m = &report.code_body_metrics[0];
        assert_eq!(m.function_index, 2);
        assert_eq!(m.direct_calls.len(), 2);

        assert_eq!(m.direct_calls[0].callee_index, 1);
        match &m.direct_calls[0].resolution {
            CallTargetResolution::Imported { name, .. } => assert_eq!(name, "imp_b"),
            other => panic!("expected Imported imp_b, got {other:?}"),
        }

        assert_eq!(m.direct_calls[1].callee_index, 3);
        match &m.direct_calls[1].resolution {
            CallTargetResolution::Defined { defined_index, .. } => {
                assert_eq!(*defined_index, 1, "index 3 is the second defined function");
            }
            other => panic!("expected Defined, got {other:?}"),
        }
    }
}
