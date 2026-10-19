# SorobInspect

Inspect, validate, and diff Soroban WASM artifacts from the command line.

## What this tool does today

- `inspect` — parse a `.wasm` file and report imports, exports, custom sections, and defined function signatures.
- `validate` — run generic WASM validation, detect Soroban contract markers (`contractspecv0`, `contractenvmetav0`), and decode the contract spec into structured data (functions, params, return types, UDTs) via `stellar-xdr`.
- `diff` — structural diff (imports/exports/custom sections) plus spec-level compatibility diff when both sides decode successfully.

Stable JSON output is available for every command via `--json`.

## What this tool does NOT do yet

- Simulate or execute Soroban contracts.
- Detect or classify events emitted by contracts.
- Claim semantic equivalence — compatibility is structural only.

## Install

```sh
cargo install --git https://github.com/bomniop/sorob-inspect.git
```

Or from source:

```sh
cargo build --release
# binary at target/release/sorob-inspect
```

## Usage

```sh
# Inspect a WASM artifact
sorob-inspect inspect target/wasm32-unknown-unknown/release/contract.wasm

# Inspect + JSON
sorob-inspect inspect contract.wasm --json

# Validate + decode contract spec
sorob-inspect validate contract.wasm
sorob-inspect validate contract.wasm --json

# Structural + spec-level diff between two artifacts
sorob-inspect diff old.wasm new.wasm
sorob-inspect diff old.wasm new.wasm --json
```

## Contract-spec decoding

The `contractspecv0` custom section is decoded using the official `stellar-xdr`
crate (28.0.1) with the same resource limits as `soroban-spec` (depth 500,
16 MiB). Decoded data is exposed in the `spec` field of the `validate` output
and includes:

- Function names, parameter names/types, return types
- User-defined type declarations (structs, unions, enums, error enums, events)

## Compatibility diff rules

The `diff` command reports structural changes (imports/exports/custom sections)
and, when both specs decode, a spec-level compatibility verdict with these rules:

| Change | Verdict |
|--------|---------|
| Function added | non-breaking |
| Function removed | breaking |
| Param count changed | breaking |
| Param type changed | breaking |
| Param renamed (positional callers) | non-breaking |
| Return type changed | breaking |
| UDT added | non-breaking |
| UDT removed | breaking |
| One or both specs fail to decode | unknown (never guessed) |

Semantic equivalence is NOT inferred from matching names alone.

## Output format

- Human-readable text by default.
- `--json` emits pretty-printed JSON suitable for piping into `jq` or other tooling.
- Every error path prints to stderr and exits with a non-zero status.

## Limitations

- Very large WASM files are fully loaded into memory during inspection (no streaming).
- Only `contractspecv0` is decoded; other Soroban custom sections (e.g. `contractmetav0`) are listed but not parsed.
- No network access; purely local analysis.

## Contributing

1. Fork the repo and create a feature branch.
2. Add tests for any new parsing or reporting behavior.
3. Run `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --all-targets --all-features -- -D warnings` before opening a PR.
4. Keep dependencies minimal — avoid pulling in heavy crates for small features.
5. Do not claim compatibility verdicts beyond the documented structural rules.

## License

MIT OR Apache-2.0
