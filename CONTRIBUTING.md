# Contributing to SorobInspect

Thank you for your interest in contributing. This document explains how to work with the repository so contributions are reviewable and mergeable.

## Getting Started

### Prerequisites

- Rust toolchain compatible with the crate's declared MSRV (`rust-version = 1.85` in `Cargo.toml`).
- `cargo`, `rustfmt`, and `clippy` components installed.

### Setup

```sh
git clone https://github.com/bomniop/sorob-inspect.git
cd sorob-inspect
cargo build --locked
cargo test --locked
```

The binary is `target/debug/sorob-inspect` (or `target/release/sorob-inspect` after `cargo build --release`).

## Before Starting Work

- Search open issues and recent commits before opening a new issue or starting work.
- If a requirement is unclear, ask on the issue before writing code.
- Keep changes aligned with the agreed issue scope; avoid adding adjacent refactoring or unrequested features.
- Do not duplicate work already in progress or merged.

## Development and Testing

Run these commands from the repository root before submitting:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
git diff --check
```

CI runs the same checks plus fixture integrity (committed WASM fixtures must still decode and retain their committed sizes). If your change affects fixture behavior, do not modify fixture files without maintainer approval.

## Code and Compatibility Expectations

- Keep changes focused. One logical change per PR.
- Add regression tests for bug fixes and tests for new behavior.
- Preserve existing CLI behavior unless the issue explicitly authorizes a change.
- Treat JSON output schemas and exit codes as compatibility-sensitive; do not rename or remove existing fields.
- Keep output deterministic (sorted collections, stable formatting).
- Do not claim complete Soroban ABI compatibility from raw WASM exports alone. The `contractspecv0` section is the richest ABI source; raw exports are a separate structural observation.
- Distinguish verified facts from assumptions in code comments and documentation. Document meaningful limitations.

## Pull Request Requirements

- Explain the problem and the proposed solution.
- Link the relevant issue when one exists.
- Summarize behavior changes and compatibility implications.
- List the verification commands you ran and their results.
- Disclose known limitations and tests not performed.
- Keep each PR focused; avoid unrelated refactoring.

## Safety and Scope

- Never commit secrets, credentials, private keys, or unrelated generated artifacts.
- Do not introduce network calls, new dependencies, or new CLI flags outside the agreed scope.
- Do not rewrite shared Git history or force-push to project branches.
- Ask the maintainer before making significant architectural or compatibility decisions.

## Review and Merge

- Contributions require maintainer review.
- Required CI checks must pass before merge.
- The maintainer makes final scope and merge decisions. Do not promise or expect automatic approval, merge timelines, funding, or acceptance.
