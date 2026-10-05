//! Bitcoin key derivation, addresses and signing — the counterpart to the LWK-backed
//! half of [`crate::wallet`].
//!
//! Built directly on `rust-bitcoin` rather than on a wallet framework. What this engine
//! actually asks of a wallet is small: derive a key, produce an address, sign a hash, and
//! know which UTXOs are ours. Covenant inputs are self-describing — a taproot sighash
//! commits to a spent output's value and scriptPubKey and nothing else, so
//! `psbt_builder` reconstructs their prevouts rather than looking them up — and the
//! descriptor is single-key. A framework would bring its own descriptor language,
//! persistence model and coin-selection policy, none of which this engine would use.
//!
//! # BIP86, not a choice
//!
//! Addresses are single-key P2TR under BIP86: `m/86'/coin'/account'/change/index`, with
//! the derived key as the taproot internal key and **no script tree**, so the output key
//! is `internal + H_TapTweak(internal)·G`.
//!
//! This is the one part of the module that must not be improvised. An address derived a
//! slightly different way — a different path, or the untweaked key used directly — is
//! still a perfectly valid address that this wallet will happily hand out, watch, and
//! never be able to spend from, because the key it signs with does not match the output.
//! Nothing catches that except getting it right, so the tests below check against the
//! published BIP86 vectors rather than against this implementation's own output.

use std::str::FromStr;

use anyhow::{Context, Result};
use lwk_wollet::elements::bitcoin::{
    self,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    key::{Keypair, TapTweak, TweakedKeypair},
    secp256k1::{All, Message, Secp256k1},
    Address, ScriptBuf, XOnlyPublicKey,
};

use crate::chain::{ChainFamily, Network};

/// BIP86 purpose: single-key P2TR.
const PURPOSE: u32 = 86;

/// SLIP-44 coin type. `0'` is Bitcoin mainnet; every test network shares `1'`.
const COIN_MAINNET: u32 = 0;
const COIN_TESTNET: u32 = 1;

/// Which branch of an account a key sits on. A bool would read as `derive(.., true, 0)` at
/// the call site, where the reader has to remember which way round it goes — and handing
/// out a change address as a receive address is the kind of mistake that is invisible
/// until someone audits the wallet's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    /// Addresses handed out to receive funds.
    Receive,
    /// Addresses that take a transaction's surplus.
    Change,
}

impl Branch {
    fn index(self) -> u32 {
        match self {
            Branch::Receive => 0,
            Branch::Change => 1,
        }
    }
}

/// A single-account BIP86 Bitcoin wallet derived from a mnemonic.
pub struct BitcoinWallet {
    root: Xpriv,
    network: Network,
    account: u32,
    secp: Secp256k1<All>,
}

impl BitcoinWallet {
    /// Derive a wallet from a BIP39 mnemonic.
    ///
    /// No passphrase. The Elements side does not take one either, and accepting one here
    /// would mean the same mnemonic yields different wallets on the two chains for reasons
    /// invisible in the wallet file.
    pub fn from_mnemonic(mnemonic: &str, network: Network) -> Result<Self> {
        if network.family() != ChainFamily::Bitcoin {
            anyhow::bail!(
                "BitcoinWallet cannot be built for '{network}', which is an Elements network"
            );
        }
        let parsed = bip39::Mnemonic::parse(mnemonic.trim())
            .map_err(|e| anyhow::anyhow!("invalid mnemonic: {e}"))?;
        let seed = parsed.to_seed("");
        let root = Xpriv::new_master(bitcoin_network(network), &seed)
            .map_err(|e| anyhow::anyhow!("cannot derive master key: {e}"))?;
        Ok(Self {
            root,
            network,
            account: 0,
            secp: Secp256k1::new(),
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// `m/86'/coin'/account'` — the account this wallet's addresses hang off.
    pub fn account_path(&self) -> DerivationPath {
        let coin = if self.network.is_mainnet() {
            COIN_MAINNET
        } else {
            COIN_TESTNET
        };
        DerivationPath::from(vec![
            hardened(PURPOSE),
            hardened(coin),
            hardened(self.account),
        ])
    }

    /// Full path to one address key: `m/86'/coin'/account'/branch/index`.
    pub fn key_path(&self, branch: Branch, index: u32) -> DerivationPath {
        self.account_path().extend([
            ChildNumber::from_normal_idx(branch.index()).expect("branch index is in range"),
            ChildNumber::from_normal_idx(index).expect("address index is in range"),
        ])
    }

    /// The keypair at one address path, untweaked — the taproot *internal* key.
    ///
    /// Signing a key-path spend requires the tweaked keypair, not this one; see
    /// [`Self::sign_key_path`]. This is exposed for callers that need the internal key
    /// itself, such as building a control block.
    pub fn keypair(&self, branch: Branch, index: u32) -> Result<Keypair> {
        let xpriv = self
            .root
            .derive_priv(&self.secp, &self.key_path(branch, index))
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        Ok(Keypair::from_secret_key(&self.secp, &xpriv.private_key))
    }

    /// The x-only internal key at one address path.
    pub fn internal_key(&self, branch: Branch, index: u32) -> Result<XOnlyPublicKey> {
        Ok(self.keypair(branch, index)?.x_only_public_key().0)
    }

    /// The BIP86 address at one path: P2TR over the internal key with no script tree.
    pub fn address(&self, branch: Branch, index: u32) -> Result<Address> {
        let internal = self.internal_key(branch, index)?;
        Ok(Address::p2tr(
            &self.secp,
            internal,
            // No merkle root. This is what makes it BIP86 rather than an arbitrary P2TR:
            // the output key commits to an empty script tree, so only the key path spends.
            None,
            bitcoin_network(self.network),
        ))
    }

    pub fn script_pubkey(&self, branch: Branch, index: u32) -> Result<ScriptBuf> {
        Ok(self.address(branch, index)?.script_pubkey())
    }

    /// Sign `sighash` for a key-path spend of the output at `branch`/`index`.
    ///
    /// The signature must be made with the **tweaked** key, because that is the key the
    /// output commits to. Signing with the internal key produces a well-formed BIP340
    /// signature that simply does not verify — which is why the tweak happens here rather
    /// than being left to the caller to remember.
    pub fn sign_key_path(
        &self,
        branch: Branch,
        index: u32,
        sighash: &[u8; 32],
    ) -> Result<[u8; 64]> {
        let keypair = self.keypair(branch, index)?;
        let tweaked: TweakedKeypair = keypair.tap_tweak(&self.secp, None);
        let msg = Message::from_digest(*sighash);
        let sig = self
            .secp
            .sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
        Ok(sig.serialize())
    }

    /// Sign `sighash` with the raw (untweaked) key at an arbitrary path.
    ///
    /// This is what a covenant witness wants: a Simplicity program checks a BIP340
    /// signature against a public key baked into the program, and that key is the
    /// untweaked one. Distinct from [`Self::sign_key_path`] for exactly that reason —
    /// the two produce different signatures and are not interchangeable.
    pub fn sign_with_path(&self, path: &str, sighash: &[u8; 32]) -> Result<[u8; 64]> {
        let dp = DerivationPath::from_str(path)
            .with_context(|| format!("invalid derivation path '{path}'"))?;
        let xpriv = self
            .root
            .derive_priv(&self.secp, &dp)
            .map_err(|e| anyhow::anyhow!("key derivation failed for '{path}': {e}"))?;
        let keypair = Keypair::from_secret_key(&self.secp, &xpriv.private_key);
        let msg = Message::from_digest(*sighash);
        Ok(self
            .secp
            .sign_schnorr_no_aux_rand(&msg, &keypair)
            .serialize())
    }

    /// The x-only public key at an arbitrary path, as 64 hex chars.
    ///
    /// Mirrors [`crate::wallet::derive_schnorr_pubkey`] so a manifest's `wallet` witness
    /// resolves the same way on both chains.
    pub fn schnorr_pubkey_at(&self, path: &str) -> Result<String> {
        let dp = DerivationPath::from_str(path)
            .with_context(|| format!("invalid derivation path '{path}'"))?;
        let xpriv = self
            .root
            .derive_priv(&self.secp, &dp)
            .map_err(|e| anyhow::anyhow!("key derivation failed for '{path}': {e}"))?;
        let keypair = Keypair::from_secret_key(&self.secp, &xpriv.private_key);
        Ok(format!("{}", keypair.x_only_public_key().0))
    }

    pub fn master_fingerprint(&self) -> Fingerprint {
        self.root.fingerprint(&self.secp)
    }

    /// The account-level xpub, for watch-only export.
    pub fn account_xpub(&self) -> Result<Xpub> {
        let xpriv = self
            .root
            .derive_priv(&self.secp, &self.account_path())
            .map_err(|e| anyhow::anyhow!("account derivation failed: {e}"))?;
        Ok(Xpub::from_priv(&self.secp, &xpriv))
    }

    /// Output descriptor for this account, in the form other wallets accept.
    ///
    /// `tr(...)` with no script tree, matching what [`Self::address`] builds. Emitted
    /// without a checksum, which every consumer this engine targets computes itself.
    pub fn descriptor(&self) -> Result<String> {
        Ok(format!(
            "tr([{}/{}]{}/<0;1>/*)",
            self.master_fingerprint(),
            self.account_path().to_string().trim_start_matches("m/"),
            self.account_xpub()?
        ))
    }
}

/// Redacted by hand rather than derived. `Xpriv`'s own `Debug` prints the extended
/// private key, so a derived impl would put spendable key material into any log line,
/// panic message or `{:?}` a caller reaches for — including the assertion messages in
/// this module's own tests.
impl std::fmt::Debug for BitcoinWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinWallet")
            .field("network", &self.network)
            .field("account", &self.account)
            .field("fingerprint", &self.master_fingerprint())
            .field("root", &"<redacted>")
            .finish()
    }
}

fn hardened(n: u32) -> ChildNumber {
    ChildNumber::from_hardened_idx(n).expect("constant index is in range")
}

/// The `rust-bitcoin` network for one of our Bitcoin networks.
///
/// Panics for an Elements network, which [`BitcoinWallet::from_mnemonic`] has already
/// refused — the two cannot be confused past that point.
fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Bitcoin => bitcoin::Network::Bitcoin,
        Network::BitcoinTestnet => bitcoin::Network::Testnet,
        Network::BitcoinSignet => bitcoin::Network::Signet,
        Network::BitcoinRegtest => bitcoin::Network::Regtest,
        other => unreachable!("{other} is not a Bitcoin network"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BIP86 test mnemonic.
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon about";

    fn wallet() -> BitcoinWallet {
        BitcoinWallet::from_mnemonic(MNEMONIC, Network::Bitcoin).expect("wallet builds")
    }

    /// Checked against the vectors published in BIP86 itself, not against this code's own
    /// output.
    ///
    /// This is the assertion the module turns on. A wrong derivation still produces valid
    /// addresses that this wallet will hand out and watch, and the error only becomes
    /// visible when a spend fails — by which point the funds are at an address whose key
    /// this wallet cannot reproduce. Comparing against an external source is the only way
    /// to catch it.
    #[test]
    fn addresses_match_the_published_bip86_vectors() {
        let w = wallet();

        assert_eq!(
            w.address(Branch::Receive, 0).unwrap().to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(
            w.address(Branch::Receive, 1).unwrap().to_string(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
        assert_eq!(
            w.address(Branch::Change, 0).unwrap().to_string(),
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
        );
    }

    /// BIP86 also publishes the internal (untweaked) key for each address. Checking it
    /// separately localises a failure: a wrong internal key is a derivation-path bug, a
    /// right internal key with a wrong address is a tweak bug.
    #[test]
    fn internal_keys_match_the_published_bip86_vectors() {
        let w = wallet();
        assert_eq!(
            w.internal_key(Branch::Receive, 0).unwrap().to_string(),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
        assert_eq!(
            w.internal_key(Branch::Receive, 1).unwrap().to_string(),
            "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"
        );
        assert_eq!(
            w.internal_key(Branch::Change, 0).unwrap().to_string(),
            "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"
        );
    }

    #[test]
    fn account_path_is_bip86_and_coin_type_follows_the_network() {
        assert_eq!(wallet().account_path().to_string(), "86'/0'/0'");
        let signet = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        assert_eq!(signet.account_path().to_string(), "86'/1'/0'");
        // Every test network shares coin type 1'.
        let regtest = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinRegtest).unwrap();
        assert_eq!(regtest.account_path(), signet.account_path());
        assert_eq!(
            wallet().key_path(Branch::Change, 7).to_string(),
            "86'/0'/0'/1/7"
        );
    }

    /// Test networks share a derivation path but not an address encoding, so the same key
    /// must render differently — otherwise a signet address would be spendable-looking on
    /// mainnet.
    #[test]
    fn test_networks_share_keys_but_not_address_encodings() {
        let signet = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap();
        let regtest = BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinRegtest).unwrap();
        assert_eq!(
            signet.internal_key(Branch::Receive, 0).unwrap(),
            regtest.internal_key(Branch::Receive, 0).unwrap()
        );
        let signet_addr = signet.address(Branch::Receive, 0).unwrap().to_string();
        let regtest_addr = regtest.address(Branch::Receive, 0).unwrap().to_string();
        assert!(signet_addr.starts_with("tb1p"), "{signet_addr}");
        assert!(regtest_addr.starts_with("bcrt1p"), "{regtest_addr}");
    }

    /// A key-path signature must verify against the *tweaked* output key, and the
    /// untweaked one must not — the mistake this API exists to prevent.
    #[test]
    fn key_path_signatures_verify_against_the_tweaked_key() {
        use lwk_wollet::elements::bitcoin::secp256k1::schnorr::Signature;

        let w = wallet();
        let secp = Secp256k1::new();
        let sighash = [7u8; 32];
        let sig = Signature::from_slice(&w.sign_key_path(Branch::Receive, 0, &sighash).unwrap())
            .expect("valid signature encoding");
        let msg = Message::from_digest(sighash);

        let internal = w.internal_key(Branch::Receive, 0).unwrap();
        let tweaked = internal.tap_tweak(&secp, None).0.to_x_only_public_key();

        assert!(secp.verify_schnorr(&sig, &msg, &tweaked).is_ok());
        assert!(
            secp.verify_schnorr(&sig, &msg, &internal).is_err(),
            "a key-path signature must not verify against the untweaked key"
        );
    }

    /// A covenant signature is checked against a key baked into the program — the
    /// untweaked one. The two signing methods are therefore not interchangeable.
    #[test]
    fn covenant_signatures_use_the_untweaked_key() {
        use lwk_wollet::elements::bitcoin::secp256k1::schnorr::Signature;

        let w = wallet();
        let secp = Secp256k1::new();
        let sighash = [9u8; 32];
        let path = "m/86'/0'/0'/0/0";

        let sig = Signature::from_slice(&w.sign_with_path(path, &sighash).unwrap()).unwrap();
        let msg = Message::from_digest(sighash);
        let internal = w.internal_key(Branch::Receive, 0).unwrap();

        assert!(secp.verify_schnorr(&sig, &msg, &internal).is_ok());
        // ...and the advertised pubkey at that path is the one it verifies against.
        assert_eq!(w.schnorr_pubkey_at(path).unwrap(), internal.to_string());
    }

    #[test]
    fn an_elements_network_is_refused_rather_than_silently_reinterpreted() {
        let err = BitcoinWallet::from_mnemonic(MNEMONIC, Network::LiquidTestnet)
            .expect_err("Elements network must be refused")
            .to_string();
        assert!(err.contains("Elements network"), "{err}");
    }

    #[test]
    fn descriptor_names_the_account_and_both_branches() {
        let d = wallet().descriptor().unwrap();
        assert!(d.starts_with("tr(["), "{d}");
        assert!(d.contains("86'/0'/0'"), "{d}");
        assert!(d.ends_with("/<0;1>/*)"), "{d}");
    }
}
