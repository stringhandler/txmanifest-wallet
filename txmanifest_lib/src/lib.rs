//! The wallet side of transaction manifests: resolving an action against a wallet and a
//! chain, building and signing its transaction, and broadcasting it.
//!
//! The parts that need no wallet live in `txmanifest-core` and are re-exported here.

pub use txmanifest_core::{
    canonical, chain, context, covenant, eval, instance, manifest, params, programs, schema, state,
    validate,
};

pub mod assembly;
pub mod backend;
pub mod bitcoin_backend;
pub mod bitcoin_review;
pub mod bitcoin_rpc;
pub mod bitcoin_wallet;
pub mod config;
pub mod describe;
pub mod lifecycle;
pub mod prepare;
pub mod preview;
pub mod prompt;
pub mod psbt_builder;
pub mod pset_builder;
pub mod session;
pub mod target;
pub mod wallet;
