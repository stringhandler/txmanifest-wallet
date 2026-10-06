//! Cross-toolchain parity checks: each module rebuilds covenant addresses, OP_RETURN
//! payloads or witness sets with this engine and compares them to what another
//! implementation (simplicity-lending, its indexer, a longhand taproot derivation) or the
//! chain produced.
//!
//! These pin the engine against outside ground truth, so a SimplicityHL bump or an
//! encoding change that moves a live address fails here rather than on chain.
//!
//!   cargo test -p tx-manifest-lib --test interop

mod issuance_factory;
mod issuance_factory_opreturn;
mod lending_active;
mod lending_collateral;
mod lending_opreturn;
mod pre_lock;
mod tapdata_leaf;
