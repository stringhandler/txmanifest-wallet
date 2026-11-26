//! Transaction manifests without a wallet.
//!
//! Everything here works from a manifest and its programs alone: the model and its JSON
//! Schema, validation, program pins, SimplicityHL compilation, and the covenant addresses
//! and witnesses that follow from them. Nothing in this crate builds, signs or broadcasts a
//! transaction, prompts, or talks to a node, so it builds for `wasm32-unknown-unknown`.
//!
//! `tx-manifest-lib` adds the wallet on top and re-exports every module here, so code that
//! already depends on it sees no difference.

pub mod canonical;
pub mod chain;
pub mod context;
pub mod covenant;
pub mod eval;
pub mod instance;
pub mod manifest;
pub mod params;
pub mod programs;
pub mod schema;
pub mod state;
pub mod validate;
