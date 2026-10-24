//! `sorob-inspect` CLI — inspect, validate, and diff Soroban WASM artifacts.

use clap::{Parser, Subcommand};
use serde::Serialize;
use sorob_inspect::soroban::inspect_soroban;
use sorob_inspect::soroban::{assess_env_meta, EnvMetaAssessmentInputs};
use sorob_inspect::wasm::{
    analyze, inspect, DataSegmentMode, ElementExpr, ElementItem, ElementKind, ElementRefResolution,
    ElementSegmentMode, OffsetExpr, WasmReport,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

// Re-export for integration tests.
pub use sorob_inspect::soroban::decode_spec_from_wasm;

#[derive(Parser)]
#[command(
    name = "sorob-inspect",
    version,
    about = "Inspect, validate, and diff Soroban WASM artifacts",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Structural inspection: imports, exports, custom sections, functions.
    Inspect {
        /// Path to a .wasm file
        file: PathBuf,
        /// Emit JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Validate the WASM module (generic WASM validation + Soroban marker check).
    Validate {
        /// Path to a .wasm file
        file: PathBuf,
        /// Emit JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Target network's current ledger protocol. When supplied together
        /// with an environment interface version, attaches a compatibility
        /// assessment under `env_meta.assessment` using the Soroban host's
        /// exact acceptance rule. The assessment is informational only and
        /// never changes the exit code.
        #[arg(long, value_name = "PROTOCOL")]
        target_protocol: Option<u32>,
        /// Host's compiled protocol (host_protocol). Required only when
        /// `--target-protocol` is given; defaults to the target protocol
        /// (i.e. a host that supports the network's protocol).
        #[arg(long, value_name = "PROTOCOL")]
        host_protocol: Option<u32>,
        /// Host's compiled pre-release. Defaults to 0 (a stable host). Only
        /// meaningful when `--target-protocol` is given.
        #[arg(long, value_name = "PRE_RELEASE")]
        host_pre_release: Option<u32>,
        /// Exit non-zero when the protocol assessment is `rejected`. Requires
        /// `--target-protocol`. Does NOT fire on `not_assessable` (missing or
        /// undecodable metadata), and is independent of `--fail-on-breaking`.
        #[arg(long)]
        fail_if_rejected: bool,
    },
    /// Structural diff between two WASM artifacts.
    ///
    /// Reports added/removed imports, exports, and custom sections, plus a
    /// spec-level compatibility verdict when both contract specs decode. Also
    /// reports the Soroban environment interface-version change as a distinct
    /// signal (not folded into the breaking/non-breaking verdict).
    Diff {
        /// Old/baseline .wasm file
        old: PathBuf,
        /// New/candidate .wasm file
        new: PathBuf,
        /// Emit JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Exit with code 1 when the spec-level compatibility verdict is
        /// `breaking` or `unknown`. Without this flag the exit code is 0
        /// whenever the diff itself ran successfully. Intended for CI gating.
        ///
        /// An environment interface-version change does NOT trigger this flag:
        /// it is reported separately because whether it is acceptable depends
        /// on the target network's ledger protocol, which this tool does not
        /// know.
        #[arg(long)]
        fail_on_breaking: bool,
        /// Target network's current ledger protocol. When supplied, both the old
        /// and new modules are assessed against the Soroban host's exact
        /// acceptance rule and the result (each side's verdict plus a
        /// transition summary) is added to `env_meta`. Assessment is
        /// informational only; it never changes the `--fail-on-breaking`
        /// verdict or the exit code. Shares the same validation as `validate`.
        #[arg(long, value_name = "PROTOCOL")]
        target_protocol: Option<u32>,
        /// Host's compiled protocol for the assessment. Defaults to
        /// `--target-protocol`. Requires `--target-protocol`.
        #[arg(long, value_name = "PROTOCOL")]
        host_protocol: Option<u32>,
        /// Host's compiled pre-release for the assessment. Defaults to 0.
        /// Requires `--target-protocol`.
        #[arg(long, value_name = "PRE_RELEASE")]
        host_pre_release: Option<u32>,
        /// Exit non-zero when either assessed side is `rejected`. Requires
        /// `--target-protocol`. Does NOT fire on `not_assessable`; independent
        /// of `--fail-on-breaking`.
        #[arg(long)]
        fail_if_rejected: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn read_wasm(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Validate and assemble explicit protocol inputs for an env-interface-version
/// assessment. Shared by `validate` and `diff` so both enforce identical rules.
///
/// Returns `Ok(None)` when no `--target-protocol` was supplied (no assessment).
/// Performs *no* network lookup and infers nothing: the host protocol defaults
/// to the target protocol, and the host pre-release defaults to 0, both
/// documented choices rather than network-derived values.
fn build_assessment_inputs(
    target_protocol: Option<u32>,
    host_protocol: Option<u32>,
    host_pre_release: Option<u32>,
) -> Result<Option<EnvMetaAssessmentInputs>, String> {
    match target_protocol {
        None => {
            if host_protocol.is_some() || host_pre_release.is_some() {
                return Err(
                    "--host-protocol and --host-pre-release require --target-protocol".to_string(),
                );
            }
            Ok(None)
        }
        Some(target) => {
            if target == 0 {
                return Err("--target-protocol must be >= 1".to_string());
            }
            let host = host_protocol.unwrap_or(target);
            if host == 0 {
                return Err("--host-protocol must be >= 1".to_string());
            }
            if target > host {
                return Err(format!(
                    "--target-protocol ({target}) exceeds --host-protocol ({host}): \
                     the host cannot validate a network running a newer protocol \
                     than the host supports"
                ));
            }
            Ok(Some(EnvMetaAssessmentInputs {
                curr_ledger_protocol: target,
                host_protocol: host,
                host_pre_release: host_pre_release.unwrap_or(0),
            }))
        }
    }
}

/// Whether a report carries an actual `rejected` assessment verdict.
///
/// `not_applicable` (missing or undecodable metadata) is deliberately NOT
/// treated as rejected, so `--fail-if-rejected` never fires on unavailable
/// assessment.
fn is_rejected(report: Option<&sorob_inspect::soroban::EnvMetaReport>) -> bool {
    report
        .and_then(|r| r.assessment.as_ref())
        .map(|a| a.verdict == "rejected")
        .unwrap_or(false)
}

/// `--fail-if-rejected` is only meaningful alongside `--target-protocol`.
fn require_target_for_gate(fail_if_rejected: bool, has_inputs: bool) -> Result<(), String> {
    if fail_if_rejected && !has_inputs {
        return Err("--fail-if-rejected requires --target-protocol to assess against".to_string());
    }
    Ok(())
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Inspect { file, json } => {
            let bytes = read_wasm(&file)?;
            let mut report = inspect(&bytes, false).map_err(|e| e.to_string())?;
            report.analysis = Some(analyze(&bytes).map_err(|e| e.to_string())?);
            // Refresh the consolidated summary so `analysis_finding_count`
            // reflects the analysis that was just attached.
            report.summary =
                sorob_inspect::wasm::build_analysis_summary(&report).map_err(|e| e.to_string())?;
            if json {
                print_json(&report)?;
            } else {
                print_wasm_report(&file, &report);
            }
        }
        Command::Validate {
            file,
            json,
            target_protocol,
            host_protocol,
            host_pre_release,
            fail_if_rejected,
        } => {
            let bytes = read_wasm(&file)?;
            let mut report = inspect_soroban(&bytes, true).map_err(|e| e.to_string())?;

            // Explicit protocol inputs. Nothing is assumed: an assessment is
            // produced only when the operator supplies the target protocol.
            // Shared with `diff` so both commands enforce identical validation.
            let assessment_inputs =
                build_assessment_inputs(target_protocol, host_protocol, host_pre_release)?;
            require_target_for_gate(fail_if_rejected, assessment_inputs.is_some())?;

            if let Some(inputs) = assessment_inputs.as_ref() {
                if let Some(em) = report.env_meta.as_mut() {
                    let assessment = assess_env_meta(em, inputs);
                    em.assessment = Some(assessment);
                }
            }

            if json {
                print_json(&report)?;
            } else {
                println!("file: {}", file.display());
                println!("generic wasm validation: PASS");
                println!("soroban spec section: {}", report.has_contract_spec);
                println!("soroban env meta section: {}", report.has_contract_env_meta);
                if let Some(spec) = &report.spec {
                    println!("spec functions: {}", spec.functions.len());
                    println!("spec types: {}", spec.types.len());
                    println!("spec events: {}", spec.events.len());
                }
                if let Some(em) = &report.env_meta {
                    if em.status == "decoded" {
                        println!(
                            "env interface version: protocol {} (pre-release {})",
                            em.protocol.unwrap_or(0),
                            em.pre_release.unwrap_or(0)
                        );
                        println!(
                            "  -> evaluate against the target network's ledger protocol \
                             (see env_meta.diagnostic in --json for the host's rule)"
                        );
                    } else {
                        println!(
                            "env metadata: {} ({})",
                            em.status,
                            em.error.clone().unwrap_or_default()
                        );
                    }
                    if let Some(a) = &em.assessment {
                        println!(
                            "env interface version assessment: {} — {}",
                            a.verdict.to_uppercase(),
                            a.reason
                        );
                        println!(
                            "  (got protocol {}/pre-release {} vs want_proto {}; \
                             target {} / host {} / host pre-release {})",
                            a.got_protocol,
                            a.got_pre_release,
                            a.want_protocol,
                            a.inputs.curr_ledger_protocol,
                            a.inputs.host_protocol,
                            a.inputs.host_pre_release
                        );
                    }
                } else if target_protocol.is_some() {
                    println!(
                        "env interface version assessment: NOT ASSESSED — \
                         module has no contractenvmetav0 section"
                    );
                }
                if let Some(c) = &report.consistency {
                    println!("--- spec/export consistency ---");
                    println!("  status: {}", c.status);
                    if let Some(r) = &c.reason {
                        println!("  reason: {r}");
                    }
                    println!(
                        "  spec functions: {}, wasm function exports: {}",
                        c.spec_function_count, c.wasm_function_export_count
                    );
                    for f in &c.findings {
                        println!(
                            "  [{}] {}: {} (evidence: {})",
                            f.severity, f.code, f.message, f.evidence
                        );
                    }
                    if !c.unmatched_exports.is_empty() {
                        println!(
                            "  exports not named by spec (informational): {}",
                            c.unmatched_exports.join(", ")
                        );
                    }
                    if !c.not_checked.is_empty() {
                        println!("  not checked: {}", c.not_checked.join(", "));
                    }
                }
                println!("summary: {}", report.summary);
                println!();
                println!(
                    "note: contract-spec decoding implemented; full ABI compatibility not assessed."
                );
            }
            // Gate: after the report is emitted, fail on a `rejected` verdict.
            // `not_applicable` (missing/undecodable) is intentionally excluded.
            if fail_if_rejected && is_rejected(report.env_meta.as_ref()) {
                let reason = report
                    .env_meta
                    .as_ref()
                    .and_then(|em| em.assessment.as_ref())
                    .map(|a| a.reason.as_str())
                    .unwrap_or("environment interface-version rejected");
                return Err(format!(
                    "environment interface-version assessment rejected: {reason}"
                ));
            }
        }
        Command::Diff {
            old,
            new,
            json,
            fail_on_breaking,
            target_protocol,
            host_protocol,
            host_pre_release,
            fail_if_rejected,
        } => {
            let old_bytes = read_wasm(&old)?;
            let new_bytes = read_wasm(&new)?;
            let old_report = inspect(&old_bytes, false).map_err(|e| e.to_string())?;
            let new_report = inspect(&new_bytes, false).map_err(|e| e.to_string())?;
            let diff = build_diff(&old_report, &new_report);

            // Spec-level diff: only when both specs decode successfully.
            let spec_diff = match (
                sorob_inspect::soroban::decode_spec_from_wasm(&old_bytes),
                sorob_inspect::soroban::decode_spec_from_wasm(&new_bytes),
            ) {
                (Ok(o), Ok(n)) => Some(sorob_inspect::soroban::diff::diff_specs(&o, &n)),
                _ => None,
            };

            // Environment interface version diff: reuse the decoder from the
            // `validate` path. `None` means the module has no env-meta section.
            let mut old_env_meta = sorob_inspect::soroban::decode_env_meta_from_wasm(&old_bytes)
                .map_err(|e| e.to_string())?;
            let mut new_env_meta = sorob_inspect::soroban::decode_env_meta_from_wasm(&new_bytes)
                .map_err(|e| e.to_string())?;

            // Same validation/rules as `validate`: no inference, no network
            // lookup. When supplied, attach the exact host-rule verdict to each
            // side *before* diffing so `transition` reflects both assessments.
            let assessment_inputs =
                build_assessment_inputs(target_protocol, host_protocol, host_pre_release)?;
            require_target_for_gate(fail_if_rejected, assessment_inputs.is_some())?;
            let assessed = assessment_inputs.is_some();
            if let Some(inputs) = assessment_inputs.as_ref() {
                if let Some(em) = old_env_meta.as_mut() {
                    em.assessment = Some(assess_env_meta(em, inputs));
                }
                if let Some(em) = new_env_meta.as_mut() {
                    em.assessment = Some(assess_env_meta(em, inputs));
                }
            }

            let env_meta_diff = sorob_inspect::soroban::diff::diff_env_meta(
                old_env_meta.as_ref(),
                new_env_meta.as_ref(),
            );

            if json {
                print_json(&serde_json::json!({
                    "schema_version": 1,
                    "structural": diff,
                    "spec": spec_diff,
                    "env_meta": env_meta_diff,
                }))?;
            } else {
                print_diff(&old, &new, &diff);
                if let Some(sd) = &spec_diff {
                    println!();
                    println!("spec-level compatibility: {:?}", sd.compatibility);
                    for a in &sd.functions_added {
                        println!("  + function {a}");
                    }
                    for r in &sd.functions_removed {
                        println!("  - function {r}");
                    }
                    for c in &sd.functions_changed {
                        let marker = if c.breaking {
                            "BREAKING"
                        } else {
                            "non-breaking"
                        };
                        println!("  ~ function {}: {} ({marker})", c.name, c.detail);
                    }
                    for t in &sd.types_added {
                        println!("  + type {t}");
                    }
                    for t in &sd.types_removed {
                        println!("  - type {t}");
                    }
                    for tc in &sd.types_changed {
                        let marker = if tc.breaking {
                            "BREAKING"
                        } else {
                            "non-breaking"
                        };
                        println!("  ~ type {}: {} ({marker})", tc.name, tc.detail);
                    }
                    for e in &sd.events_added {
                        println!("  + event {e}");
                    }
                    for e in &sd.events_removed {
                        println!("  - event {e}");
                    }
                    for ec in &sd.events_changed {
                        let marker = if ec.breaking {
                            "BREAKING"
                        } else {
                            "non-breaking"
                        };
                        println!("  ~ event {}: {} ({marker})", ec.name, ec.detail);
                    }
                } else {
                    println!();
                    println!("spec-level compatibility: unknown (one or both specs could not be decoded)");
                }
                // Environment interface version: a distinct signal, deliberately
                // not folded into the spec-level breaking/non-breaking verdict.
                println!();
                println!(
                    "env interface version: {}",
                    describe_env_meta_diff(&env_meta_diff)
                );
                if matches!(
                    env_meta_diff.status.as_str(),
                    "changed" | "added" | "removed"
                ) {
                    println!(
                        "  -> evaluate against the target network's ledger protocol \
                         (see env_meta.diagnostic in --json for the host's rule)"
                    );
                }
                // Optional protocol assessment (when --target-protocol was given).
                // Informational only; never affects the spec-level verdict.
                if assessed {
                    println!();
                    println!("env interface version assessment:");
                    print_env_meta_side("old", env_meta_diff.old.as_ref());
                    print_env_meta_side("new", env_meta_diff.new.as_ref());
                    println!(
                        "  transition: {}",
                        format_transition(&env_meta_diff.transition)
                    );
                }
            }
            // CI gating: emit the report above, then map the verdict to an exit
            // code. `breaking` and `unknown` both fail; the diff ran fine, so we
            // exit 1 rather than returning an Err (which would print an error and
            // skip the normal report). No diagnostics contaminate stdout.
            if fail_on_breaking {
                let verdict = spec_diff.as_ref().map(|sd| &sd.compatibility);
                let fail = match verdict {
                    None => true, // undecodable spec -> unknown -> fail
                    Some(c) => {
                        matches!(
                            c,
                            sorob_inspect::soroban::diff::Compatibility::Breaking
                                | sorob_inspect::soroban::diff::Compatibility::Unknown
                        )
                    }
                };
                if fail {
                    return Err("spec-level compatibility is breaking or unknown".to_string());
                }
            }
            // Independent gate: fail only on an actual `rejected` verdict.
            // `not_applicable` (missing/undecodable) and `not_assessable` sides do
            // not trigger this.
            if fail_if_rejected
                && (is_rejected(env_meta_diff.old.as_ref())
                    || is_rejected(env_meta_diff.new.as_ref()))
            {
                return Err(
                    "environment interface-version assessment rejected on one or more sides"
                        .to_string(),
                );
            }
        }
    }
    Ok(())
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let s = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    println!("{s}");
    Ok(())
}

fn print_wasm_report(path: &Path, report: &WasmReport) {
    println!("file: {}", path.display());
    println!("size: {} bytes", report.size_bytes);
    println!("imports: {}", report.imports.len());
    for i in &report.imports {
        let detail = match (&i.type_sig, &i.memory, &i.table, &i.global) {
            (Some(sig), ..) => Some(format!("type {} {sig}", i.type_index.unwrap_or(0))),
            (None, Some(m), ..) => Some(match m.max_pages {
                Some(max) => format!(
                    "min {} pages (max {max}){}",
                    m.min_pages,
                    if m.is64 { " 64-bit" } else { "" }
                ),
                None => format!(
                    "min {} pages{}",
                    m.min_pages,
                    if m.is64 { " 64-bit" } else { "" }
                ),
            }),
            (None, None, Some(t), _) => Some(match t.max_size {
                Some(max) => format!("{} min {} max {}", t.element_type, t.min_size, max),
                None => format!("{} min {}", t.element_type, t.min_size),
            }),
            (None, None, None, Some(g)) => Some(format!(
                "{} {}",
                g.value_type,
                if g.mutable {
                    "(mutable)"
                } else {
                    "(immutable)"
                }
            )),
            _ => None,
        };
        match detail {
            Some(d) => println!("  {}::{} [{}] {d}", i.module, i.name, i.kind),
            None => println!("  {}::{} [{}]", i.module, i.name, i.kind),
        }
    }
    println!("exports: {}", report.exports.len());
    for e in &report.exports {
        let detail = match (&e.type_sig, &e.memory, &e.table, &e.global) {
            (Some(sig), ..) => format!("type {} {sig}", e.type_index.unwrap_or(0)),
            (None, Some(m), ..) => match m.max_pages {
                Some(max) => format!(
                    "min {} pages (max {max}){}",
                    m.min_pages,
                    if m.is64 { " 64-bit" } else { "" }
                ),
                None => format!(
                    "min {} pages{}",
                    m.min_pages,
                    if m.is64 { " 64-bit" } else { "" }
                ),
            },
            (None, None, Some(t), _) => match t.max_size {
                Some(max) => format!("{} min {} max {}", t.element_type, t.min_size, max),
                None => format!("{} min {}", t.element_type, t.min_size),
            },
            (None, None, None, Some(g)) => format!(
                "{} {}",
                g.value_type,
                if g.mutable {
                    "(mutable)"
                } else {
                    "(immutable)"
                }
            ),
            _ => String::new(),
        };
        if detail.is_empty() {
            println!("  {} [{}] idx={}", e.name, e.kind, e.index);
        } else {
            println!("  {} [{}] idx={} {detail}", e.name, e.kind, e.index);
        }
    }
    println!("custom sections: {}", report.custom_sections.len());
    for s in &report.custom_sections {
        println!("  {} ({} bytes)", s.name, s.len_bytes);
    }
    println!("defined functions: {}", report.functions.len());
    if let Some(s) = &report.structure {
        println!("--- module structure ---");
        if !s.memories.is_empty() {
            for (i, m) in s.memories.iter().enumerate() {
                match m.max_pages {
                    Some(max) => println!(
                        "  memory[{i}]: {}{} pages (max {max})",
                        m.min_pages,
                        if m.is64 { " (64-bit)" } else { "" }
                    ),
                    None => println!(
                        "  memory[{i}]: min {} pages{}",
                        m.min_pages,
                        if m.is64 { " (64-bit)" } else { "" }
                    ),
                }
            }
        }
        if !s.tables.is_empty() {
            for (i, t) in s.tables.iter().enumerate() {
                match t.max_size {
                    Some(max) => println!(
                        "  table[{i}]: {} min {} max {}",
                        t.element_type, t.min_size, max
                    ),
                    None => println!("  table[{i}]: {} min {}", t.element_type, t.min_size),
                }
            }
        }
        if !s.globals.is_empty() {
            for (i, g) in s.globals.iter().enumerate() {
                println!(
                    "  global[{i}]: {} {}",
                    g.value_type,
                    if g.mutable {
                        "(mutable)"
                    } else {
                        "(immutable)"
                    }
                );
            }
        }
        if s.data_segments > 0 {
            println!("  data segments: {}", s.data_segments);
            for seg in &s.data_segment_details {
                match seg.mode {
                    DataSegmentMode::Active => {
                        let mem = seg.memory_index.unwrap_or(0);
                        let off = match &seg.offset {
                            Some(OffsetExpr::Const { value }) => value.to_string(),
                            Some(OffsetExpr::GlobalGet { global_index }) => {
                                format!("global.get {global_index}")
                            }
                            Some(OffsetExpr::Unsupported { reason }) => {
                                format!("unsupported ({reason})")
                            }
                            None => "?".to_string(),
                        };
                        println!(
                            "    [{index}] active mem={mem} offset={off} payload={len}B",
                            index = seg.index,
                            len = seg.payload_len
                        );
                    }
                    DataSegmentMode::Passive => {
                        println!(
                            "    [{index}] passive payload={len}B",
                            index = seg.index,
                            len = seg.payload_len
                        );
                    }
                }
            }
        }
        if s.element_segments > 0 {
            println!("  element segments: {}", s.element_segments);
            for seg in &s.element_segment_details {
                let mode = match seg.mode {
                    ElementSegmentMode::Active => "active",
                    ElementSegmentMode::Passive => "passive",
                    ElementSegmentMode::Declared => "declared",
                };
                let mut line = format!("    [{index}] {mode}", index = seg.index);
                if let Some(t) = seg.table_index {
                    line.push_str(&format!(" table={t}"));
                }
                if let Some(offset) = &seg.offset {
                    let off = match offset {
                        OffsetExpr::Const { value } => value.to_string(),
                        OffsetExpr::GlobalGet { global_index } => {
                            format!("global.get {global_index}")
                        }
                        OffsetExpr::Unsupported { reason } => {
                            format!("unsupported ({reason})")
                        }
                    };
                    line.push_str(&format!(" offset={off}"));
                }
                match &seg.kind {
                    ElementKind::Functions => {
                        line.push_str(&format!(" funcs count={}", seg.element_count));
                    }
                    ElementKind::Expressions { element_type } => {
                        line.push_str(&format!(
                            " exprs type={element_type} count={}",
                            seg.element_count
                        ));
                    }
                }
                println!("{line}");
                for item in &seg.items {
                    match item {
                        ElementItem::FuncIndex(f) => {
                            let res = match &f.resolution {
                                ElementRefResolution::Imported { module, name } => {
                                    format!("imported {module}::{name}")
                                }
                                ElementRefResolution::Defined {
                                    declared_index,
                                    signature,
                                } => format!("defined[{declared_index}] {signature}"),
                                ElementRefResolution::Invalid => "invalid".to_string(),
                            };
                            println!(
                                "      item[{}] func idx={} -> {res}",
                                f.item_index, f.raw_index
                            );
                        }
                        ElementItem::Expr(e) => {
                            let res = match &e.expr {
                                ElementExpr::RefFunc {
                                    raw_index,
                                    resolution,
                                } => {
                                    let r = match resolution {
                                        ElementRefResolution::Imported { module, name } => {
                                            format!("imported {module}::{name}")
                                        }
                                        ElementRefResolution::Defined {
                                            declared_index,
                                            signature,
                                        } => format!("defined[{declared_index}] {signature}"),
                                        ElementRefResolution::Invalid => "invalid".to_string(),
                                    };
                                    format!("ref.func {raw_index} -> {r}")
                                }
                                ElementExpr::RefNull { heap_type } => {
                                    format!("ref.null {heap_type}")
                                }
                                ElementExpr::Unsupported { reason } => {
                                    format!("unsupported ({reason})")
                                }
                            };
                            println!(
                                "      item[{}] expr type={} {res}",
                                e.item_index, e.element_type
                            );
                        }
                    }
                }
            }
        }
        if let Some(f) = s.start_func {
            println!("  start function: {f}");
        }
        if let Some(sf) = &s.start_function {
            match sf.resolution.as_str() {
                "imported" => match &sf.import {
                    Some(i) => {
                        println!("    resolves to imported function {}::{}", i.module, i.name)
                    }
                    None => println!("    resolves to imported function"),
                },
                "defined" => match &sf.function {
                    Some(f) => println!(
                        "    resolves to defined function[{}] {}",
                        f.declared_index, f.signature
                    ),
                    None => println!("    resolves to defined function"),
                },
                other => println!("    index {other} does not resolve to a function"),
            }
        }
    }
    if let Some(a) = &report.analysis {
        println!("--- resource analysis ---");
        if !a.imported_memories.is_empty() {
            println!("  imported memories: {}", a.imported_memories.join(", "));
        }
        if !a.defined_memories.is_empty() {
            for (i, m) in a.defined_memories.iter().enumerate() {
                match m.max_pages {
                    Some(max) => println!(
                        "  defined memory[{i}]: {}{} pages (max {max})",
                        m.min_pages,
                        if m.is64 { " (64-bit)" } else { "" }
                    ),
                    None => println!(
                        "  defined memory[{i}]: min {} pages{}",
                        m.min_pages,
                        if m.is64 { " (64-bit)" } else { "" }
                    ),
                }
            }
        }
        if !a.imported_tables.is_empty() {
            println!("  imported tables: {}", a.imported_tables.join(", "));
        }
        if !a.defined_tables.is_empty() {
            for (i, t) in a.defined_tables.iter().enumerate() {
                match t.max_size {
                    Some(max) => println!(
                        "  defined table[{i}]: {} min {} max {}",
                        t.element_type, t.min_size, max
                    ),
                    None => println!(
                        "  defined table[{i}]: {} min {}",
                        t.element_type, t.min_size
                    ),
                }
            }
        }
        if !a.imported_globals.is_empty() {
            println!("  imported globals: {}", a.imported_globals.join(", "));
        }
        if !a.defined_globals.is_empty() {
            for (i, g) in a.defined_globals.iter().enumerate() {
                println!(
                    "  defined global[{i}]: {} {}",
                    g.value_type,
                    if g.mutable {
                        "(mutable)"
                    } else {
                        "(immutable)"
                    }
                );
            }
        }
        println!("  functions: {}", a.function_count);
        println!("  data segments: {}", a.data_segment_count);
        println!("  element segments: {}", a.element_segment_count);
        if !a.findings.is_empty() {
            println!("--- compatibility findings ---");
            for f in &a.findings {
                println!("  [{}] {}: {}", f.severity, f.code, f.message);
            }
        }
        println!("--- coverage ---");
        println!("  checked: {}", a.coverage.checked.join(", "));
        println!("  not checked: {}", a.coverage.not_checked.join(", "));
    }
    if let Some(i) = &report.interface {
        println!("--- interface ---");
        if !i.imports_by_kind.is_empty() {
            println!(
                "  imports: {}",
                i.imports_by_kind
                    .iter()
                    .map(|k| format!("{} {}", k.count, k.kind))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !i.exports_by_kind.is_empty() {
            println!(
                "  exports: {}",
                i.exports_by_kind
                    .iter()
                    .map(|k| format!("{} {}", k.count, k.kind))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !i.exported_functions.is_empty() {
            for f in &i.exported_functions {
                match &f.signature {
                    Some(sig) => println!("  fn {} idx={} {sig}", f.name, f.index),
                    None => println!("  fn {} idx={} (signature unavailable)", f.name, f.index),
                }
            }
        }
        if !i.imported_functions.is_empty() {
            for f in &i.imported_functions {
                match &f.signature {
                    Some(sig) => println!("  import {}::{} {sig}", f.module, f.name),
                    None => println!("  import {}::{} (signature unavailable)", f.module, f.name),
                }
            }
        }
        println!(
            "  contract spec: {}",
            if i.has_contract_spec {
                "present"
            } else {
                "absent"
            }
        );
    }
}

#[derive(Debug, Serialize)]
struct DiffReport {
    old_size_bytes: usize,
    new_size_bytes: usize,
    imports_added: Vec<String>,
    imports_removed: Vec<String>,
    exports_added: Vec<String>,
    exports_removed: Vec<String>,
    custom_sections_added: Vec<String>,
    custom_sections_removed: Vec<String>,
    /// Always present so callers cannot mistake structural diff for ABI verdict.
    abi_compatibility: &'static str,
    /// Structural export comparison by resolved signature/bounds, independent
    /// of `contractspecv0`. Reported separately from the spec-level verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    structural_exports: Option<sorob_inspect::soroban::structural::StructuralExportDiff>,
}

fn key_set(items: impl Iterator<Item = String>) -> BTreeSet<String> {
    items.collect()
}

fn build_diff(old: &WasmReport, new: &WasmReport) -> DiffReport {
    let import_key = |r: &WasmReport| {
        key_set(
            r.imports
                .iter()
                .map(|i| format!("{}::{} [{}]", i.module, i.name, i.kind)),
        )
    };
    let export_key = |r: &WasmReport| {
        key_set(
            r.exports
                .iter()
                .map(|e| format!("{} [{}] idx={}", e.name, e.kind, e.index)),
        )
    };
    let section_key = |r: &WasmReport| key_set(r.custom_sections.iter().map(|s| s.name.clone()));

    let (oi, ni) = (import_key(old), import_key(new));
    let (oe, ne) = (export_key(old), export_key(new));
    let (os, ns) = (section_key(old), section_key(new));

    DiffReport {
        old_size_bytes: old.size_bytes,
        new_size_bytes: new.size_bytes,
        imports_added: ni.difference(&oi).cloned().collect(),
        imports_removed: oi.difference(&ni).cloned().collect(),
        exports_added: ne.difference(&oe).cloned().collect(),
        exports_removed: oe.difference(&ne).cloned().collect(),
        custom_sections_added: ns.difference(&os).cloned().collect(),
        custom_sections_removed: os.difference(&ns).cloned().collect(),
        abi_compatibility: "not-assessed",
        structural_exports: Some(sorob_inspect::soroban::structural::diff_exports(
            &old.exports,
            &new.exports,
        )),
    }
}

/// Render one side of an environment-interface-version comparison.
fn fmt_env_meta_side(side: Option<&sorob_inspect::soroban::EnvMetaReport>) -> String {
    match side {
        None => "absent".to_string(),
        Some(r) if r.status == "decoded" => format!(
            "protocol {} (pre-release {})",
            r.protocol.unwrap_or(0),
            r.pre_release.unwrap_or(0)
        ),
        Some(r) => format!(
            "undecodable ({})",
            r.error.clone().unwrap_or_else(|| "no reason".to_string())
        ),
    }
}

/// Human-readable description of an environment-interface-version comparison.
fn describe_env_meta_diff(d: &sorob_inspect::soroban::diff::EnvMetaDiff) -> String {
    match d.status.as_str() {
        "identical" => format!("unchanged ({})", fmt_env_meta_side(d.new.as_ref())),
        "changed" => format!(
            "CHANGED {} -> {}",
            fmt_env_meta_side(d.old.as_ref()),
            fmt_env_meta_side(d.new.as_ref())
        ),
        "added" => format!("added ({})", fmt_env_meta_side(d.new.as_ref())),
        "removed" => format!("removed (was {})", fmt_env_meta_side(d.old.as_ref())),
        "absent_both" => "absent in both modules".to_string(),
        "old_undecodable" => format!("old undecodable, new {}", fmt_env_meta_side(d.new.as_ref())),
        "new_undecodable" => format!("new undecodable, old {}", fmt_env_meta_side(d.old.as_ref())),
        "undecodable_both" => "undecodable in both modules".to_string(),
        other => other.to_string(),
    }
}

/// Render one side of an env-interface-version assessment as a text line.
fn print_env_meta_side(label: &str, side: Option<&sorob_inspect::soroban::EnvMetaReport>) {
    match side.and_then(|r| r.assessment.as_ref()) {
        Some(a) => println!(
            "  {}: {} — {} (got proto {}/pre {}, want_proto {})",
            label,
            a.verdict.to_uppercase(),
            a.reason,
            a.got_protocol,
            a.got_pre_release,
            a.want_protocol
        ),
        None => println!("  {label}: not assessable"),
    }
}

/// Render a transition token as a human-readable arrow, e.g.
/// `accepted_to_rejected` -> `accepted -> rejected`.
fn format_transition(token: &str) -> String {
    token.replace("_to_", " -> ")
}

fn print_diff(old: &Path, new: &Path, d: &DiffReport) {
    println!("old: {} ({} bytes)", old.display(), d.old_size_bytes);
    println!("new: {} ({} bytes)", new.display(), d.new_size_bytes);

    let section = |title: &str, added: &[String], removed: &[String]| {
        if added.is_empty() && removed.is_empty() {
            return;
        }
        println!("{title}:");
        for a in added {
            println!("  + {a}");
        }
        for r in removed {
            println!("  - {r}");
        }
    };

    section("imports", &d.imports_added, &d.imports_removed);
    section("exports", &d.exports_added, &d.exports_removed);
    section(
        "custom sections",
        &d.custom_sections_added,
        &d.custom_sections_removed,
    );

    if d.imports_added.is_empty()
        && d.imports_removed.is_empty()
        && d.exports_added.is_empty()
        && d.exports_removed.is_empty()
    {
        println!("no structural import/export changes");
    }

    if let Some(se) = &d.structural_exports {
        if !se.changes.is_empty() {
            println!();
            println!("structural export changes (independent of contract spec):");
            for c in &se.changes {
                let marker = match c.compatibility {
                    sorob_inspect::soroban::structural::StructuralCompatibility::Breaking => {
                        "BREAKING"
                    }
                    sorob_inspect::soroban::structural::StructuralCompatibility::NonBreaking => {
                        "non-breaking"
                    }
                    sorob_inspect::soroban::structural::StructuralCompatibility::Unknown => {
                        "unknown"
                    }
                };
                let action = match c.change {
                    sorob_inspect::soroban::structural::StructuralChangeKind::Added => "+",
                    sorob_inspect::soroban::structural::StructuralChangeKind::Removed => "-",
                    sorob_inspect::soroban::structural::StructuralChangeKind::Changed => "~",
                    sorob_inspect::soroban::structural::StructuralChangeKind::Unresolved => "?",
                };
                match (&c.old, &c.new) {
                    (Some(o), Some(n)) => {
                        println!("  {action} {} [{}]: {o} -> {n} ({marker})", c.name, c.kind)
                    }
                    (Some(o), None) => {
                        println!("  {action} {} [{}]: was {o} ({marker})", c.name, c.kind)
                    }
                    (None, Some(n)) => {
                        println!("  {action} {} [{}]: {n} ({marker})", c.name, c.kind)
                    }
                    (None, None) => {
                        println!("  {action} {} [{}] ({marker})", c.name, c.kind)
                    }
                }
            }
            println!("  structural export compatibility: {}", se.compatibility);
        }
    }

    println!();
    println!("abi compatibility: structural diff only — see spec-level result below");
}
