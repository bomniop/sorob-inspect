# SorobInspect

Inspect, validate, and diff Soroban WASM artifacts from the command line.

## What this tool does today

- `inspect` — parse a `.wasm` file and report imports, exports, custom sections, and defined function signatures.
- `validate` — run generic WebAssembly validation **and** detect Soroban contract markers (`contractspecv0`, `contractenvmetav0`).
- `diff` — structural diff between two `.wasm` files: added/removed imports, exports, and custom sections.

Stable JSON output is available for every command via `--json`.

## What this tool does NOT do yet

- Decode or compare Soroban contract specs (`contractspecv0`) bytes.
- Emit any ABI-compatibility verdict.
- Simulate or execute Soroban contracts.

We deliberately do not guess custom-section formats or report compatibility results until contract-spec decoding is implemented and tested.

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

# Validate generic WASM structure + detect Soroban markers
sorob-inspect validate contract.wasm
sorob-inspect validate contract.wasm --json

# Structural diff between two artifacts
sorob-inspect diff old.wasm new.wasm
sorob-inspect diff old.wasm new.wasm --json
```

## Output format

- Human-readable text by default.
- `--json` emits pretty-printed JSON suitable for piping into `jq` or other tooling.
- Every error path prints to stderr and exits with a non-zero status.

## Limitations

- Soroban custom sections are detected **by name only**. Their bytes are not decoded.
- `diff` reports structural changes only — it is not an upgrade-safety or ABI-compatibility check.
- Very large WASM files are fully loaded into memory during inspection (no streaming).
- No network access; purely local analysis.

## Contributing

1. Fork the repo and create a feature branch.
2. Add tests for any new parsing or reporting behavior.
3. Run `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --all-targets --all-features -- -D warnings` before opening a PR.
4. Keep dependencies minimal — avoid pulling in heavy crates for small features.
5. Do not claim compatibility verdicts until contract-spec decoding is implemented and tested.

## License

MIT OR Apache-2.0
