pub mod manifest;

/// Canonical form, registry id and publisher signatures.
///
/// Re-exported from `tx-manifest-core`, which carries them without the wallet and
/// covenant machinery, so a registry or signing tool can depend on that crate alone.
/// Existing `tx_manifest_lib::canonical::…` paths keep working.
pub use tx_manifest_core::{canonical, signature};

pub mod backend;
pub mod config;
pub mod describe;
pub mod context;
pub mod covenant;
pub mod eval;
pub mod instance;
pub mod lifecycle;
pub mod params;
pub mod prepare;
pub mod preview;
pub mod prompt;
pub mod pset_builder;
pub mod schema;
pub mod state;
pub mod validate;
pub mod wallet;
