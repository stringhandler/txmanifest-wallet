//! Everything needed to hash, check and sign a transaction manifest — and nothing else.
//!
//! Split out of `tx-manifest-lib` so that publishing a manifest does not require the
//! machinery for *executing* one. A registry, a CI check or an air-gapped signing box
//! needs the canonical form, the id and a Schnorr verification; it has no use for a
//! wallet, an Esplora client or a SimplicityHL compiler, and should not have to build
//! them. `tx-manifest-lib` re-exports this crate, so nothing downstream sees the split.

pub mod canonical;
pub mod checks;
pub mod report;
pub mod signature;

pub use report::{Issue, Report, Severity};
