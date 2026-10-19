//! WASM structure inspection and validation for Soroban contract artifacts.
//!
//! Two layers, deliberately separated:
//! - `wasm`: generic WebAssembly module parsing (imports, exports, custom sections).
//! - `soroban`: Soroban-specific checks on top of a parsed module
//!   (contract-spec custom section detection + minimal decoding).

pub mod soroban;
pub mod wasm;

// Re-export for external test use.
pub use soroban::diff::{diff_specs, Compatibility, SpecDiff};
