# SorobInspect

Inspect, validate, and diff Soroban WASM artifacts from the command line.

## What this tool does today

- `inspect` — parse a `.wasm` file and report imports (with structured function/memory/table/global details), exports, custom sections, defined function signatures, a module-structure summary (memory limits, table bounds, global types, data/element segment counts, start function), and a resource + compatibility analysis (imported vs defined resources, function/segment counts, and Soroban compatibility findings).
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

## Spec/export consistency (`validate`)

`validate` also compares the decoded spec against the module's raw WASM
exports and reports a `consistency` object. One rule is implemented:

- `spec_function_export_missing` — the spec declares function `X` but the
  module has no same-named WASM function export. The host resolves a contract
  invocation by looking up the WASM export whose name equals the function
  symbol, and fails with `MissingValue` ("trying to invoke non-existent
  contract function") when absent (`soroban-env-host 28.0.2`
  `src/vm.rs:286-301`). So the name equality is enforced by the host, not
  assumed.

The `__constructor` export is exempt: the host explicitly permits a contract
with no constructor (`src/host/lifecycle.rs:22`, `121-131`).

Everything else is deliberately not compared:

- **Extra raw WASM exports are never flagged.** Nothing requires every export
  to be described by the spec; internal helpers and linker-provided exports
  are normal. They are listed informationally under `unmatched_exports`.
- **Signature/ABI comparison is `not_checked`.** Name equality is host-enforced,
  but signature compatibility is not verifiable from the spec's type vocabulary
  plus the WASM type section alone.

The report has a `status` field — `checked`, or `not_applicable` (with a
`reason`) when there is no decodable spec. `checked` plus empty `findings`
means no implemented rule reported a mismatch, not that the ABI is compatible;
`not_checked` lists the areas that were never evaluated.

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

## Compatibility findings (inspect)

`inspect` emits a `findings` array in the JSON `analysis` object. Each finding
has a stable `code`, a `severity` (`incompatible` | `unsupported` | `unknown`),
and a `message`. An empty array means no finding was raised — it does **not**
mean the module is guaranteed Soroban-compatible.

| Code | Severity | Rule and evidence |
|------|----------|-------------------|
| `float_ops` | incompatible | Soroban host rejects WASM containing float instructions. Detected by validating the module with `floats: false` and observing a failure that the unrestricted validator accepts. Evidence: `soroban-env-host` pre-validates every uploaded module with `wasmparser::validate` (`src/vm/parsed_module.rs`) and its e2e suite asserts float WASM upload fails (`test_wasm_upload_failure_due_to_unsupported_wasm_features`). |
| `memory64` | unsupported | A memory declared with 64-bit indices. The host's pre-validation uses default `wasmparser` feature flags, where `memory64` is off by default. |

Rules deliberately **not** implemented, because the repository has no verified
Soroban rule for them: SIMD, threads, exceptions, GC, component model, tail
calls, and multi-memory. These produce no finding rather than a guess.

`unsupported` means the feature is outside what the host's pre-validation
accepts. `incompatible` means a documented or tested rejection. Neither is
inferred from metadata alone — both come from running a validator.

### Coverage

The `analysis` object also carries a `coverage` field distinguishing checks
that ran from areas never evaluated:

```json
{
  "checked": ["float_ops"],
  "not_checked": [
    "component_model", "exceptions", "gc", "memory64",
    "multi_memory", "simd", "tail_calls", "threads"
  ]
}
```

- `checked` — areas where a rule actually ran. `float_ops` appears here only
  when the module validated successfully and the float-restricted validator
  probe was executed against it.
- `not_checked` — compatibility areas with no implemented rule. These are
  never evaluated and never produce findings.

An empty `findings` array together with a non-empty `not_checked` list means
no implemented rule reported a finding, but Soroban compatibility is NOT
established for the unchecked areas.

### Import details

Each entry in the `imports` array carries the pre-existing `module`, `name`,
and `kind` fields plus optional structured detail objects, present only for
the matching import kind:

- `type_index` + `type_sig` — functions. `type_index` is the module's type
  section index; `type_sig` is the rendered signature.
- `memory` — memories. `min_pages` and, when declared, `max_pages`; `is64`
  and `shared` reflect the limits flags. `max_pages` is absent when no
  maximum is declared (never inferred, never `0`).
- `table` — tables. `element_type`, `min_size` and, when declared,
  `max_size`.
- `global` — globals. `value_type` and `mutable`.

Fields for other kinds are omitted, so a function import never carries a
`memory` object. Value types render as wasmparser's debug names (`I32`,
`I64`, `F32`, `F64`, `V128`, `externref`, `funcref`).

### Export details

Each entry in the `exports` array carries the pre-existing `name`, `kind`,
and `index` fields plus optional structured detail objects, present only
for the matching export kind:

- `type_index` + `type_sig` — functions.
- `memory` — memories, same shape as import memory details.
- `table` — tables, same shape as import table details.
- `global` — globals, same shape as import global details.

Export `index` values are resolved against the full WASM index space:
imports occupy the lowest indices of each kind's space, followed by locally
defined items. An exported memory at index 1 in a module with one imported
memory therefore reports the defined memory's bounds, not the import's.
Unresolvable indices (e.g. a tag export) keep only the pre-existing fields.

### Interface summary

The `inspect` report now includes a top-level `interface` object — a
concise developer overview derived from the already-resolved import/export
lists (no reparsing, no re-resolution):

- `imports_by_kind` / `exports_by_kind` — per-kind counts (`function`/`memory`/
  `table`/`global`), sorted by kind name for deterministic output.
- `exported_functions` / `imported_functions` — function entries with their
  signature (`() -> ()` etc.) or `null` when unresolvable.
- `exports` — every export name paired with its resource kind, in declaration
  order.
- `has_contract_spec` — whether a `contractspecv0` custom section was detected.

Contract-spec functions (from `validate`) and raw WASM exports are two
distinct views and are never merged: `exported_functions` lists only raw
WASM function exports.

### Start function

`inspect` reports a module's start section under `structure`:

```json
{
  "structure": {
    "start_func": 2,
    "start_function": {
      "index": 2,
      "resolution": "defined",
      "function": { "declared_index": 0, "signature": "() -> ()" }
    }
  }
}
```

- `start_func` — the raw function index from the start section. Omitted
  entirely when the module has no start section; absence is never encoded
  as index `0`.
- `start_function.resolution` — `"imported"`, `"defined"`, or `"invalid"`.
- `start_function.import` — `{ "module", "name" }`, present only for
  `"imported"`.
- `start_function.function` — `{ "declared_index", "signature" }`, present
  only for `"defined"`. `declared_index` is the 0-based position among
  *defined* functions, not the raw WASM index.

Index resolution follows the WASM function index space: imported functions
occupy the lowest indices, then locally defined functions in declaration
order. A start index below the imported-function count resolves to the
matching import; an index at or above it resolves to a defined function.
An index that names no function at all is reported as `"invalid"` rather
than being silently dropped or panicking.

Limitations:

- The tool reports *what* the start section declares. It does not claim a
  start function is invalid for Soroban — no such rule is established by
  the evidence this tool relies on, so no compatibility finding is emitted.
- `"invalid"` only means the index does not name a function in this module's
  index space. Whether the host would reject the module is not decided here.
- A malformed start section (truncated or otherwise unparseable) is
  rejected as malformed input, consistent with the rest of the parser.

### Data segments

`inspect` reports per-segment detail under `structure.data_segment_details`,
in declaration order. The existing aggregate count
(`structure.data_segments`) is unchanged.

```json
{
  "structure": {
    "data_segments": 2,
    "data_segment_details": [
      {
        "index": 0,
        "mode": "active",
        "memory_index": 0,
        "offset": { "const": { "value": 42 } },
        "payload_len": 5
      },
      { "index": 1, "mode": "passive", "payload_len": 0 }
    ]
  }
}
```

- `index` — 0-based position in the data section (declaration order).
- `mode` — `active` or `passive`, as parsed. The reference-interpreter
  "declared" form has no representation in wasmparser 0.121.2, so it is
  never emitted.
- `memory_index` — present for active segments only; absent for passive
  segments.
- `offset` — present for active segments only. Represented conservatively:
  - `{ "const": { "value": N } }` for a single `i32.const` / `i64.const`.
  - `{ "global_get": { "global_index": X } }` for a single `global.get`.
    The global's value is not evaluated, so it is never reported as a
    constant.
  - `{ "unsupported": { "reason": "..." } }` for any other form. The tool
    never guesses an evaluated offset.
- `payload_len` — payload byte length. **Payload bytes are never emitted.**
- The field is omitted entirely when the module has no data section.

Limitations:

- Offsets are reported as written, not evaluated. A `global.get` offset
  stays a reference; this tool does not compute globals.
- Segment metadata says nothing about runtime memory contents, contract
  storage state, or Soroban compatibility. No such inference is made.
- The parser rejects a data segment with an invalid flags byte as malformed
  input, consistent with the rest of the module parser.

## JSON schema notes

`diff --json` emits a top-level object with a `schema_version` integer that
identifies the shape of the JSON document. The current value is `1`. Consumers
should treat an unrecognised (higher) `schema_version` as a signal that fields
may have been added, renamed, or removed, and handle it deliberately rather than
assuming the shape documented here still applies.

This is a version marker, not a formal stability guarantee: fields may be added
in a backward-compatible way within a version, but a change to `schema_version`
means the shape changed.

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
- The `inspect` JSON output includes a `structure` object (when the module has
  any) with `memories`, `tables`, `globals` (each with `mutable` and
  `value_type`), `data_segments`, `element_segments`, and optional `start_func`.
- Custom sections are reported twice: `custom_sections` (name + payload length)
  and, additively, `custom_section_details` (index, name, payload length, and
  classification). Example:

```json
"custom_section_details": [
  { "index": 0, "name": "name", "len_bytes": 12, "classification": "name" },
  { "index": 1, "name": "dSYM", "len_bytes": 64, "classification": "unknown" }
]
```

  `len_bytes` is the data payload length only — the bytes after the encoded
  section name, excluding the name and the section header. `classification` is
  derived from the name alone: `name`, `producers`, or `unknown`. It carries no
  trust or security meaning. The array is omitted entirely when the module has
  no custom sections.
- Defined-function bodies are reported in `code_body_metrics` when the module
  has any. Example:

```json
"code_body_metrics": [
  {
    "defined_index": 0,
    "function_index": 0,
    "signature": "(i32) -> i32",
    "body_len_bytes": 4,
    "local_decl_count": 0,
    "local_total": 0,
    "operator_count": 1,
    "max_control_depth": 0,
    "instruction_inventory": {
      "compare": 1
    }
  }
]
```

  `body_len_bytes` is the encoded size of the body (locals + operators,
  excluding the body-size prefix). `local_decl_count` is the number of distinct
  `count:type` pairs; `local_total` is the sum of all counts. `operator_count`
  excludes the function-body `end` operator. `max_control_depth` counts only
  `block`, `loop`, and `if` nesting.

  `instruction_inventory` is an additive per-function map of instruction-family
  names to counts. Each operator is counted in exactly one family; the
  classifications are exclusive (not overlapping). The map is omitted when empty.
  Families:

  | family | operators |
  |---|---|
  | `control` | `block`, `loop`, `if`, `else`, `end`, `br`, `br_if`, `br_table`, `return`, `call`, `call_indirect`, `return_call`, `return_call_indirect`, `br_on_null`, `br_on_non_null` |
  | `call` | `call`, `call_indirect`, `return_call`, `return_call_indirect`, `call_ref`, `return_call_ref` |
  | `local` | `local.get`, `local.set`, `local.tee` |
  | `global` | `global.get`, `global.set` |
  | `load` | all `i32/i64/f32/f64` load and extended-load variants |
  | `store` | all `i32/i64/f32/f64` store and extended-store variants |
  | `memory` | `memory.size`, `memory.grow` |
  | `bulk` | `memory.init`, `memory.copy`, `memory.fill`, `data.drop`, `table.init`, `table.copy`, `elem.drop` |
  | `table` | `table.fill`, `table.get`, `table.set`, `table.grow`, `table.size` |
  | `const` | `i32.const`, `i64.const`, `f32.const`, `f64.const`, `v128.const` |
  | `reference` | `ref.null`, `ref.is_null`, `ref.func`, `ref.eq`, `ref.as_non_null` |
  | `gc` | struct/array ops, ref-test/cast, i31, `any.convert_extern`, `extern.convert_any` |
  | `compare` | integer and float eq/ne/lt/gt/le/ge, `i32.eqz` |
  | `numeric` | integer and float arithmetic (add/sub/mul/div/rem/and/or/xor/shift/rot, abs/neg/ceil/floor/trunc/nearest/sqrt/min/max/copysign) |
  | `conversion` | wrap, extend, trunc (trapping and saturating), reinterpret, promote/demote |
  | `select` | `select`, `typed.select` |
  | `misc` | `drop`, `nop`, `unreachable` |
  | `atomic` | all `threads`-proposal atomic load/store/rmw/fence ops |
  | `simd` | all `simd` and `relaxed_simd` `0xFD` operators |
  | `other` | any operator not classified above (should not occur with pinned wasmparser versions) |

  The function-body `end` operator is excluded from both `operator_count` and
  the inventory. The array is omitted when the module has no defined functions.
  These are static structural counts — they are not gas estimates,
  execution-time proxies, complexity scores, or security signals.
- Every error path prints to stderr and exits with a non-zero status.

## Limitations

- Very large WASM files are fully loaded into memory during inspection (no streaming).
- Only `contractspecv0` is decoded; other Soroban custom sections (e.g. `contractmetav0`) are listed but not parsed.
- Custom-section classification is name-based only; payloads are never
  inspected, so a section named `name` is not guaranteed to be a valid name
  section.
- Code-body metrics are static counts from the encoded body; they do not
  reflect runtime behavior, gas costs, or execution complexity.
- `value_type` for globals is formatted via wasmparser's `Debug` impl (e.g. `I32`,
  `I64`); this is an opaque string and may change with upstream versions.
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
