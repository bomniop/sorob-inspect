# SorobInspect

Inspect, validate, and diff Soroban WASM artifacts from the command line.

## What this tool does today

- `inspect` — parse a `.wasm` file and report imports, exports, custom sections, and defined function signatures.
- `validate` — run generic WASM validation, detect Soroban contract markers (`contractspecv0`, `contractenvmetav0`), and decode the contract spec into structured data (functions, params, return types, UDTs, events) via `stellar-xdr`.
- `diff` — structural diff (imports/exports/custom sections) plus spec-level compatibility diff when both sides decode successfully.

Stable JSON output is available for every command via `--json`.

## What this tool does NOT do yet

- Simulate or execute Soroban contracts.
- Claim semantic equivalence — compatibility is structural only.

## Install

```sh
cargo install --locked --git https://github.com/bomniop/sorob-inspect.git
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
| Struct field added / removed / type changed | breaking |
| Struct field renamed | breaking (reported as removal + addition) |
| Enum or union variant added | non-breaking |
| Enum or union variant removed | breaking |
| Enum/error-enum discriminant changed | breaking |
| Union tuple-case payload types changed | breaking |
| Union case kind changed (void ↔ tuple) | breaking |
| Discriminant present on only one side | unknown |
| UDT kind changed (e.g. struct → enum) | breaking |
| Event added | non-breaking |
| Event removed | breaking |
| Event param added / removed / type changed / location changed | breaking |
| Event param renamed | breaking (reported as removal + addition) |
| Event topic list or data format changed | breaking |
| One or both specs fail to decode | unknown (never guessed) |

Semantic equivalence is NOT inferred from matching names alone.

`unknown` is emitted whenever the decoded specs do not carry enough information
for a definite verdict (e.g. a discriminant present on only one side). It is
never downgraded to `non-breaking`.

## JSON schema notes

`spec.types[].cases` is an array of objects (not strings):

```json
{ "name": "Circle", "kind": "tuple", "payload": ["U32"] }
{ "name": "A", "kind": "enum", "value": 0 }
{ "name": "Unit", "kind": "void" }
```

- `kind`: `"void"` | `"tuple"` | `"enum"` | `"error_enum"`.
- `payload`: union tuple-case payload types, omitted when empty.
- `value`: discriminant for enum/error-enum cases, omitted when the spec form
  carries none (union cases).

`spec.types_changed[].uncertain` is emitted only when true, marking changes that
forced the overall `unknown` verdict.

`spec.events[]` carries the event's data format in `data_format`, decoded from
the spec XDR (`ScSpecEventDataFormat`). All three values are represented:

- `"single_value"` — the `data` segment is a single value
- `"vec"` — the `data` segment is a vector of values
- `"map"` — the `data` segment is a map from symbols to values

Changing an event's `data_format` between any of these is reported as breaking
(see the compatibility table above).

## Output format

- Human-readable text by default.
- `--json` emits pretty-printed JSON suitable for piping into `jq` or other tooling.
- Every error path prints to stderr and exits with a non-zero status.

## Limitations

- Very large WASM files are fully loaded into memory during inspection (no streaming).
- Only `contractspecv0` is decoded; other Soroban custom sections (e.g. `contractmetav0`) are listed but not parsed.
- No network access; purely local analysis.
- Fixture provenance is documented in `tests/fixtures/README.md`. The committed
  UDT binaries were built from the original session's contract source, which is
  not embedded in the repo, so a rebuild is not guaranteed to be byte-identical
  (WASM layout varies with source and toolchain). Fixture integrity in CI is
  enforced by decode + size checks, not byte equality.

## Contributing

1. Fork the repo and create a feature branch.
2. Add tests for any new parsing or reporting behavior.
3. Run `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --all-targets --all-features -- -D warnings` before opening a PR.
4. Keep dependencies minimal — avoid pulling in heavy crates for small features.
5. Do not claim compatibility verdicts beyond the documented structural rules.

## License

MIT OR Apache-2.0
