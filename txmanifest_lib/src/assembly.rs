//! What the lifecycle's input/output assembly needs from a wallet and a chain.
//!
//! [`lifecycle::run`](crate::lifecycle::run) contains roughly eight hundred lines that
//! resolve destinations, derive covenant addresses, evaluate amounts and record state
//! metadata. Almost none of it is chain-specific — and duplicating it for Bitcoin would
//! produce two copies that agree on the day they are written and drift by the next
//! release, in ways only a funded transaction would reveal.
//!
//! So there is one assembly path, and this trait is the whole of what it asks of the
//! chain underneath. Six things, no more:
//!
//! 1. a covenant's scriptPubKey,
//! 2. an asset label resolved to an id,
//! 3. a change address,
//! 4. the next receive address,
//! 5. the chain's own unit of account,
//! 6. whether outputs are confidential unless told otherwise.
//!
//! # Why the assembly still speaks Elements
//!
//! The assembly builds [`PsetOutputSpec`](crate::pset_builder::PsetOutputSpec) values,
//! which carry an `AssetId` and an optional blinding key, on both chains. On Bitcoin the
//! asset is a single synthetic constant and the blinding key is always `None`.
//!
//! That looks like a leak, and it is a deliberate one. The alternative — a neutral
//! vocabulary both chains widen from — means every one of those eight hundred lines has to
//! be rewritten against it, which is exactly the risk this trait exists to avoid. Instead
//! the assembly keeps the richer vocabulary and
//! [`psbt_builder::from_pset_request`](crate::psbt_builder::from_pset_request) narrows it,
//! *refusing* anything Bitcoin cannot express. So the synthetic asset is not a fiction
//! that has to hold together on its own: if the assembly ever produced a second asset or a
//! blinding key on a Bitcoin run, the narrowing would reject it rather than let it through.

use anyhow::Result;
use lwk_wollet::elements::bitcoin::PublicKey;
use lwk_wollet::elements::{AssetId, Script};

use crate::chain::{ChainFamily, Network};
use crate::covenant::CompileOpts;

/// An address the assembly is about to pay.
pub struct AddressInfo {
    pub script_pubkey: Script,
    /// The address as a user would read it, encoded for this chain.
    ///
    /// Carried alongside the script because the assembly genuinely needs both: the script
    /// goes into the transaction, and the encoding goes into the line a user reads to
    /// check where their money went. Deriving one from the other at the call site would
    /// mean the shared assembly picking an encoding, which is precisely what it must not
    /// do — a Liquid address and a Bitcoin one are different strings for the same script.
    pub display: String,
    /// The blinding key, when the address has one. Always `None` on Bitcoin.
    pub blinding_pubkey: Option<PublicKey>,
    /// The derivation index this address came from, so the caller can ask for the next one
    /// and not hand out the same address twice in one transaction.
    pub index: u32,
}

/// An address written in a manifest, resolved for the chain in play.
#[derive(Debug)]
pub struct ParsedDestination {
    pub script_pubkey: Script,
    /// The blinding key the address carries, if any. Always `None` on Bitcoin.
    pub blinding_pubkey: Option<PublicKey>,
}

/// Parse an address a manifest names as a destination or an input pin.
///
/// Keyed on the network rather than hardcoded, because the two chains' address encodings
/// are disjoint: an `elements::Address` parser rejects every Bitcoin address outright.
/// That mattered more than it sounds. Both call sites treated a parse failure as "skip
/// this" — the output loop dropped the output and carried on, and the input pin fell back
/// to selecting from anywhere. So on a Bitcoin run a manifest paying a literal address
/// built a transaction with that payment simply missing, the value falling into change,
/// with nothing but a warning in a long interactive log to say so.
///
/// A free function rather than only a trait method because input selection runs before any
/// context exists, and the two must agree — an address the selector rejects and the
/// assembly accepts would pin nothing while appearing to.
pub fn parse_destination(address: &str, network: Network) -> Result<ParsedDestination> {
    let trimmed = address.trim();
    match network.family() {
        ChainFamily::Elements => {
            let addr: lwk_wollet::elements::Address = trimmed.parse().map_err(|e| {
                anyhow::anyhow!("'{trimmed}' is not a valid {network} address: {e}")
            })?;
            Ok(ParsedDestination {
                script_pubkey: addr.script_pubkey(),
                blinding_pubkey: addr.blinding_pubkey.map(compressed),
            })
        }
        ChainFamily::Bitcoin => {
            use lwk_wollet::elements::bitcoin as btc;
            let parsed: btc::Address<btc::address::NetworkUnchecked> = trimmed
                .parse()
                .map_err(|e| anyhow::anyhow!("'{trimmed}' is not a valid Bitcoin address: {e}"))?;
            // Checked against the run's network, not merely parsed. A mainnet address on a
            // signet run parses perfectly well and would send real-network funds nowhere
            // recoverable.
            let btc_net = bitcoin_network(network)?;
            let addr = parsed
                .require_network(btc_net)
                .map_err(|e| anyhow::anyhow!("'{trimmed}' is not a {network} address: {e}"))?;
            Ok(ParsedDestination {
                script_pubkey: Script::from(addr.script_pubkey().to_bytes()),
                blinding_pubkey: None,
            })
        }
    }
}

/// The `rust-bitcoin` network for one of our Bitcoin networks.
pub(crate) fn bitcoin_network(network: Network) -> Result<lwk_wollet::elements::bitcoin::Network> {
    use lwk_wollet::elements::bitcoin as btc;
    Ok(match network {
        Network::Bitcoin => btc::Network::Bitcoin,
        Network::BitcoinTestnet => btc::Network::Testnet,
        Network::BitcoinSignet => btc::Network::Signet,
        Network::BitcoinRegtest => btc::Network::Regtest,
        other => anyhow::bail!("{other} is not a Bitcoin network"),
    })
}

/// The chain-specific half of the lifecycle's assembly.
pub trait AssemblyContext {
    /// Which ledger this run targets.
    fn family(&self) -> ChainFamily;

    /// The concrete network, for address parsing and encoding.
    fn network(&self) -> Network;

    /// The chain's own unit of account — L-BTC's asset id on Elements, a synthetic
    /// constant on Bitcoin.
    fn policy_asset(&self) -> AssetId;

    /// Resolve a manifest asset label (`"lbtc"`, or a hex id) to an asset id.
    ///
    /// On Bitcoin every label that survives `validate` denotes the policy asset, so this
    /// is near-trivial there — but it stays on the trait rather than being special-cased
    /// in the assembly, because "which asset is this" is precisely the question the two
    /// chains answer differently.
    fn resolve_asset(&self, label: &str) -> Result<AssetId>;

    /// The scriptPubKey of a covenant with these compile parameters and extra leaves.
    ///
    /// Chain-specific in three independent ways — the jet set fixes the CMR, the TapBranch
    /// tag fixes the merkle root, and the TapTweak tag fixes the output key — so this can
    /// never be hoisted into the shared assembly.
    fn covenant_script_pubkey(
        &self,
        simf_path: &std::path::Path,
        compile_params: &std::collections::HashMap<String, String>,
        type_hints: &std::collections::HashMap<String, String>,
        extra_leaf_payloads: &[Vec<u8>],
        opts: &CompileOpts,
    ) -> Result<Script>;

    /// An address to return a surplus to.
    fn change_address(&self) -> Result<AddressInfo>;

    /// A receive address. `after` is the last index already used in this transaction, so
    /// successive outputs do not collide on one address.
    fn receive_address(&self, after: Option<u32>) -> Result<AddressInfo>;

    /// The wallet UTXOs available to fund this transaction.
    ///
    /// Returned in LWK's `WalletTxOut` shape on both chains, for the same reason the
    /// assembly speaks Elements throughout: the input-resolution code that consumes these
    /// is several hundred lines of amount and asset matching, and rewriting it against a
    /// neutral type would put the change squarely in the path funds move along. On Bitcoin
    /// the value is synthesized — see [`BitcoinContext::spendable_utxos`] — and every
    /// synthetic part of it is dropped by `psbt_builder::from_pset_request`.
    fn spendable_utxos(&self) -> Result<Vec<lwk_wollet::WalletTxOut>>;

    /// Whether an output with no explicit `confidential` setting is blinded.
    ///
    /// True on Liquid, false everywhere else — Bitcoin has no confidential outputs, and an
    /// Elements regtest chain is not assumed to be running with them.
    fn confidential_by_default(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Elements
// ---------------------------------------------------------------------------

/// The Elements implementation, over an LWK wallet.
pub struct ElementsContext<'a> {
    pub wollet: &'a lwk_wollet::Wollet,
    pub network: lwk_wollet::ElementsNetwork,
}

impl AssemblyContext for ElementsContext<'_> {
    fn family(&self) -> ChainFamily {
        ChainFamily::Elements
    }

    fn network(&self) -> Network {
        Network::from(self.network)
    }

    fn policy_asset(&self) -> AssetId {
        self.network.policy_asset()
    }

    fn resolve_asset(&self, label: &str) -> Result<AssetId> {
        crate::lifecycle::resolve_asset_id(label, self.network)
    }

    fn covenant_script_pubkey(
        &self,
        simf_path: &std::path::Path,
        compile_params: &std::collections::HashMap<String, String>,
        type_hints: &std::collections::HashMap<String, String>,
        extra_leaf_payloads: &[Vec<u8>],
        opts: &CompileOpts,
    ) -> Result<Script> {
        crate::pset_builder::covenant_script_pubkey(
            simf_path,
            compile_params,
            type_hints,
            extra_leaf_payloads,
            self.network,
            opts,
        )
    }

    fn change_address(&self) -> Result<AddressInfo> {
        let addr = self
            .wollet
            .change(None)
            .map_err(|e| anyhow::anyhow!("Cannot derive change address: {e}"))?;
        Ok(AddressInfo {
            script_pubkey: addr.address().script_pubkey(),
            display: addr.address().to_string(),
            blinding_pubkey: addr.address().blinding_pubkey.map(compressed),
            index: addr.index(),
        })
    }

    fn receive_address(&self, after: Option<u32>) -> Result<AddressInfo> {
        let addr = self
            .wollet
            .address(after)
            .map_err(|e| anyhow::anyhow!("Cannot derive wallet address: {e}"))?;
        Ok(AddressInfo {
            script_pubkey: addr.address().script_pubkey(),
            display: addr.address().to_string(),
            blinding_pubkey: addr.address().blinding_pubkey.map(compressed),
            index: addr.index(),
        })
    }

    fn spendable_utxos(&self) -> Result<Vec<lwk_wollet::WalletTxOut>> {
        self.wollet
            .utxos()
            .map_err(|e| anyhow::anyhow!("Cannot list wallet UTXOs: {e}"))
    }

    fn confidential_by_default(&self) -> bool {
        // Regtest is excluded deliberately: it is whatever the operator started, and
        // blinding by default there would surprise a chain configured without it.
        matches!(
            self.network,
            lwk_wollet::ElementsNetwork::Liquid | lwk_wollet::ElementsNetwork::LiquidTestnet
        )
    }
}

fn compressed(inner: lwk_wollet::elements::secp256k1_zkp::PublicKey) -> PublicKey {
    PublicKey {
        inner,
        compressed: true,
    }
}

// ---------------------------------------------------------------------------
// Bitcoin
// ---------------------------------------------------------------------------

/// The asset id standing in for BTC inside the shared assembly.
///
/// All zeroes, which is not a real Elements asset and cannot collide with one. It never
/// reaches a transaction: `psbt_builder::from_pset_request` checks every input, output and
/// change entry against the policy asset and refuses anything else, then drops the field.
/// So this constant's only job is to be *consistent* — and the narrowing is what enforces
/// that, rather than this module having to be trusted.
pub fn bitcoin_policy_asset() -> AssetId {
    AssetId::from_inner(lwk_wollet::elements::hashes::sha256::Midstate([0u8; 32]))
}

/// The Bitcoin implementation, over [`BitcoinWallet`](crate::bitcoin_wallet::BitcoinWallet).
///
/// Addresses come from the wallet's own derivation rather than from a scan, so assembly
/// works offline. Handing out an address that has already been paid is a privacy fault
/// rather than a loss, and the caller supplies the starting index.
pub struct BitcoinContext<'a> {
    pub wallet: &'a crate::bitcoin_wallet::BitcoinWallet,
    pub network: Network,
    /// First receive index to hand out — normally the first unused one, from a scan.
    pub receive_start: u32,
    /// Change index to use.
    pub change_index: u32,
    /// Unspent outputs this wallet can fund from, from an Esplora scan.
    pub utxos: Vec<crate::bitcoin_backend::Utxo>,
}

impl BitcoinContext<'_> {
    fn address_at(&self, branch: crate::bitcoin_wallet::Branch, index: u32) -> Result<AddressInfo> {
        let address = self.wallet.address(branch, index)?;
        Ok(AddressInfo {
            script_pubkey: Script::from(address.script_pubkey().to_bytes()),
            display: address.to_string(),
            blinding_pubkey: None,
            index,
        })
    }
}

impl AssemblyContext for BitcoinContext<'_> {
    fn family(&self) -> ChainFamily {
        ChainFamily::Bitcoin
    }

    fn network(&self) -> Network {
        self.network
    }

    fn policy_asset(&self) -> AssetId {
        bitcoin_policy_asset()
    }

    fn resolve_asset(&self, label: &str) -> Result<AssetId> {
        // Either spelling of the one asset: the manifest's label (`lbtc`), or the synthetic
        // id it resolves to. The id comes back from places that record a *resolved* asset
        // and feed it in again — the state file most of all, which is how a covenant this
        // engine created a moment ago became unspendable by it.
        if crate::manifest::names_policy_asset_str(label)
            || label.eq_ignore_ascii_case(&bitcoin_policy_asset().to_string())
        {
            return Ok(self.policy_asset());
        }
        // Anything else is a second asset, which `validate` rejects on Bitcoin. Checking
        // rather than assuming: a label that slipped past means that check has a hole, and
        // quietly treating an unknown asset as BTC would spend the wrong thing.
        anyhow::bail!(
            "asset '{label}' cannot be resolved on Bitcoin, which has only one asset; \
             this manifest should have been rejected by `validate`"
        )
    }

    fn covenant_script_pubkey(
        &self,
        simf_path: &std::path::Path,
        compile_params: &std::collections::HashMap<String, String>,
        type_hints: &std::collections::HashMap<String, String>,
        extra_leaf_payloads: &[Vec<u8>],
        opts: &CompileOpts,
    ) -> Result<Script> {
        let bytes = crate::covenant::covenant_script_pubkey_for(
            simf_path,
            compile_params,
            type_hints,
            extra_leaf_payloads,
            self.network,
            opts,
        )?;
        // Re-wrapped as an Elements `Script` because that is the vocabulary the shared
        // assembly speaks; the bytes were derived for Bitcoin and `from_pset_request`
        // carries them across unchanged.
        Ok(Script::from(bytes))
    }

    fn change_address(&self) -> Result<AddressInfo> {
        self.address_at(crate::bitcoin_wallet::Branch::Change, self.change_index)
    }

    fn receive_address(&self, after: Option<u32>) -> Result<AddressInfo> {
        let index = after.map_or(self.receive_start, |i| i + 1);
        self.address_at(crate::bitcoin_wallet::Branch::Receive, index)
    }

    /// Present the scanned Bitcoin UTXOs in the shape the shared assembly expects.
    ///
    /// The input-side counterpart of [`bitcoin_policy_asset`], and safe for the same
    /// reason: every synthesized field is either accurate or discarded. The outpoint,
    /// value and scriptPubKey are real. The asset is the synthetic constant, and the
    /// blinding factors are zero — both of which `psbt_builder::from_pset_request` checks
    /// and then drops, so neither can reach a transaction.
    ///
    /// The `address` field is reconstructed from the scriptPubKey rather than carried,
    /// because an Elements address for a Bitcoin output would be a lie in a way the others
    /// are not: it would render, and it would render wrongly. It is unused on this path,
    /// and building it from the script keeps it at least self-consistent.
    fn spendable_utxos(&self) -> Result<Vec<lwk_wollet::WalletTxOut>> {
        bitcoin_spendable_utxos(&self.utxos)
    }

    fn confidential_by_default(&self) -> bool {
        false
    }
}

/// Present scanned Bitcoin UTXOs in the shape the shared assembly expects.
///
/// The input-side counterpart of [`bitcoin_policy_asset`], and safe for the same reason:
/// every synthesized field is either accurate or discarded. The outpoint, value and
/// scriptPubKey are real. The asset is the synthetic constant and the blinding factors are
/// zero — both of which `psbt_builder::from_pset_request` checks and then drops, so neither
/// can reach a transaction.
///
/// A free function rather than only a trait method because input *selection* runs before
/// any context exists, and both paths must see the same list — a wallet whose UTXOs look
/// one way to the selector and another to the builder would pick inputs it then cannot
/// spend.
pub fn bitcoin_spendable_utxos(
    utxos: &[crate::bitcoin_backend::Utxo],
) -> Result<Vec<lwk_wollet::WalletTxOut>> {
    use lwk_wollet::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
    use lwk_wollet::elements::{Address, AddressParams, TxOutSecrets};

    utxos
        .iter()
        .map(|u| {
            let script_pubkey = Script::from(u.script_pubkey.to_bytes());
            // Reconstructed from the script rather than carried: an Elements address for a
            // Bitcoin output would be a lie in a way the other synthetic fields are not —
            // it would render, and it would render wrongly. Nothing on this path reads it.
            let address = Address::from_script(&script_pubkey, None, &AddressParams::ELEMENTS)
                .ok_or_else(|| {
                    anyhow::anyhow!("UTXO {} pays a script with no address form", u.outpoint)
                })?;
            Ok(lwk_wollet::WalletTxOut {
                // Both txid types wrap the same sha256d digest; parsing the display form
                // keeps the byte order right without reaching into either.
                outpoint: lwk_wollet::elements::OutPoint {
                    txid: u.outpoint.txid.to_string().parse().map_err(|e| {
                        anyhow::anyhow!("cannot convert txid {}: {e}", u.outpoint.txid)
                    })?,
                    vout: u.outpoint.vout,
                },
                script_pubkey,
                height: u.height,
                unblinded: TxOutSecrets {
                    asset: bitcoin_policy_asset(),
                    value: u.value,
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                },
                wildcard_index: u.index,
                ext_int: match u.branch {
                    crate::bitcoin_wallet::Branch::Receive => lwk_wollet::Chain::External,
                    crate::bitcoin_wallet::Branch::Change => lwk_wollet::Chain::Internal,
                },
                is_spent: false,
                address,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_wallet::BitcoinWallet;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon about";

    fn ctx(wallet: &BitcoinWallet) -> BitcoinContext<'_> {
        BitcoinContext {
            wallet,
            network: Network::BitcoinSignet,
            receive_start: 0,
            change_index: 0,
            utxos: Vec::new(),
        }
    }

    #[test]
    fn bitcoin_outputs_are_never_confidential_and_never_carry_a_blinding_key() {
        let w = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let c = ctx(&w);
        assert!(!c.confidential_by_default());
        assert!(c.change_address().unwrap().blinding_pubkey.is_none());
        assert!(c.receive_address(None).unwrap().blinding_pubkey.is_none());
    }

    /// Successive receive addresses must differ, or two outputs in one transaction would
    /// land on the same address.
    #[test]
    fn receive_addresses_advance() {
        let w = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let c = ctx(&w);
        let first = c.receive_address(None).unwrap();
        let second = c.receive_address(Some(first.index)).unwrap();
        assert_eq!((first.index, second.index), (0, 1));
        assert_ne!(first.script_pubkey, second.script_pubkey);
    }

    /// Change and receive come from different branches, so change is never handed out as a
    /// receive address.
    /// Both halves of an address are needed: the script goes into the transaction, the
    /// encoding goes into the line a user reads. They must describe the same output.
    #[test]
    fn the_display_encoding_matches_the_script() {
        let w = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let c = ctx(&w);
        let info = c.receive_address(None).unwrap();
        assert!(
            info.display.starts_with("tb1p"),
            "signet P2TR encoding: {}",
            info.display
        );
        let parsed: lwk_wollet::elements::bitcoin::Address<_> =
            info.display.parse().expect("display is a real address");
        assert_eq!(
            parsed.assume_checked().script_pubkey().to_bytes(),
            info.script_pubkey.to_bytes()
        );
    }

    #[test]
    fn change_and_receive_are_distinct_branches() {
        let w = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let c = ctx(&w);
        assert_ne!(
            c.change_address().unwrap().script_pubkey,
            c.receive_address(None).unwrap().script_pubkey
        );
    }

    /// Every label `validate` permits on Bitcoin resolves to the one asset; anything else
    /// is refused rather than quietly treated as BTC.
    #[test]
    fn only_policy_asset_labels_resolve_on_bitcoin() {
        let w = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let c = ctx(&w);
        for label in ["lbtc", "bitcoin", "L-BTC"] {
            assert_eq!(c.resolve_asset(label).unwrap(), c.policy_asset());
        }
        let err = c
            .resolve_asset("38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5")
            .expect_err("a second asset must not resolve")
            .to_string();
        assert!(err.contains("only one asset"), "{err}");
    }

    /// The synthesized UTXO must survive the round trip it exists for: through the shared
    /// assembly's vocabulary and back out through the narrowing, with the real fields
    /// intact and the synthetic ones discarded.
    #[test]
    fn a_synthesized_utxo_narrows_back_to_its_real_fields() {
        use crate::bitcoin_backend::Utxo;
        use crate::bitcoin_wallet::Branch;

        let w = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let spk = w.script_pubkey(Branch::Receive, 0).unwrap();
        let outpoint = lwk_wollet::elements::bitcoin::OutPoint {
            txid: "2d3f2a2a71f12377fd502c2555be9f43e12b207bbc48c9905814e824034dc348"
                .parse()
                .unwrap(),
            vout: 1,
        };
        let utxos = vec![Utxo {
            outpoint,
            value: 250_000,
            script_pubkey: spk.clone(),
            branch: Branch::Receive,
            index: 0,
            height: Some(320_630),
            coinbase: None,
        }];

        let synthesized = bitcoin_spendable_utxos(&utxos).expect("synthesizes");
        assert_eq!(synthesized.len(), 1);
        let s = &synthesized[0];

        // Real fields survive verbatim. The txid especially: the two chains' types wrap
        // the same digest, and a byte-order slip here would name a transaction that does
        // not exist.
        assert_eq!(s.outpoint.txid.to_string(), outpoint.txid.to_string());
        assert_eq!(s.outpoint.vout, 1);
        assert_eq!(s.unblinded.value, 250_000);
        assert_eq!(s.script_pubkey.as_bytes(), spk.as_bytes());

        // Synthetic fields are the ones the narrowing checks and drops.
        assert_eq!(s.unblinded.asset, bitcoin_policy_asset());

        let req = crate::pset_builder::BuildPsetRequest {
            inputs: vec![crate::pset_builder::PsetInput::Wallet {
                input_id: "i0".to_string(),
                utxo: s.clone(),
                issuance: None,
                sequence: None,
            }],
            outputs: vec![],
            fee_rate: 1.0,
            policy_asset: bitcoin_policy_asset(),
            change_assets: Default::default(),
        };
        let narrowed = crate::psbt_builder::from_pset_request(&req, None).expect("narrows");
        let crate::psbt_builder::PsbtInput::Wallet {
            outpoint: back,
            witness_utxo,
            ..
        } = &narrowed.inputs[0]
        else {
            panic!("a wallet input must narrow to a wallet input");
        };
        assert_eq!(*back, outpoint, "the outpoint must come back unchanged");
        assert_eq!(witness_utxo.value.to_sat(), 250_000);
        assert_eq!(witness_utxo.script_pubkey, spk);
    }

    /// The synthetic asset must be one the narrowing accepts as *the* policy asset, since
    /// that check is what keeps it from ever reaching a transaction.
    #[test]
    fn the_synthetic_asset_is_what_the_narrowing_expects() {
        let w = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let c = ctx(&w);
        assert_eq!(c.policy_asset(), bitcoin_policy_asset());

        // A request built entirely from this context's policy asset narrows cleanly...
        let req = crate::pset_builder::BuildPsetRequest {
            inputs: vec![],
            outputs: vec![crate::pset_builder::PsetOutputSpec {
                script_pubkey: c.receive_address(None).unwrap().script_pubkey,
                amount: 1_000,
                asset: c.policy_asset(),
                blinding_key: None,
                blinding: None,
            }],
            fee_rate: 1.0,
            policy_asset: c.policy_asset(),
            change_assets: Default::default(),
        };
        assert!(crate::psbt_builder::from_pset_request(&req, None).is_ok());

        // ...and one carrying any other asset does not, which is what makes the synthetic
        // constant safe rather than merely conventional.
        let mut wrong = req;
        wrong.outputs[0].asset = lwk_wollet::elements::AssetId::from_slice(&[9u8; 32]).unwrap();
        assert!(crate::psbt_builder::from_pset_request(&wrong, None).is_err());
    }
}
