//! `sorob-inspect` CLI — inspect, validate, and diff Soroban WASM artifacts.

use clap::{Parser, Subcommand};
use serde::Serialize;
use sorob_inspect::soroban::inspect_soroban;
use sorob_inspect::wasm::{inspect, WasmReport};
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
    },
    /// Structural diff between two WASM artifacts.
    ///
    /// Reports added/removed imports and exports, plus a spec-level
    /// compatibility verdict when both contract specs decode.
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
        #[arg(long)]
        fail_on_breaking: bool,
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

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Inspect { file, json } => {
            let bytes = read_wasm(&file)?;
            let report = inspect(&bytes, false).map_err(|e| e.to_string())?;
            if json {
                print_json(&report)?;
            } else {
                print_wasm_report(&file, &report);
            }
        }
        Command::Validate { file, json } => {
            let bytes = read_wasm(&file)?;
            let report = inspect_soroban(&bytes, true).map_err(|e| e.to_string())?;
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
                println!("summary: {}", report.summary);
                println!();
                println!(
                    "note: contract-spec decoding implemented; full ABI compatibility not assessed."
                );
            }
        }
        Command::Diff {
            old,
            new,
            json,
            fail_on_breaking,
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

            if json {
                print_json(&serde_json::json!({
                    "structural": diff,
                    "spec": spec_diff,
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
        match &i.type_sig {
            Some(sig) => println!("  {}::{} [{}] {sig}", i.module, i.name, i.kind),
            None => println!("  {}::{} [{}]", i.module, i.name, i.kind),
        }
    }
    println!("exports: {}", report.exports.len());
    for e in &report.exports {
        println!("  {} [{}] idx={}", e.name, e.kind, e.index);
    }
    println!("custom sections: {}", report.custom_sections.len());
    for s in &report.custom_sections {
        println!("  {} ({} bytes)", s.name, s.len_bytes);
    }
    println!("defined functions: {}", report.functions.len());
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
    }
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

    println!();
    println!("abi compatibility: structural diff only — see spec-level result below");
}
