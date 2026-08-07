use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use elements_miniscript::bitcoin::bip32::{DerivationPath, Xpriv};
use lwk_common::{singlesig_desc, DescriptorBlindingKey, Signer, Singlesig};
use lwk_signer::SwSigner;
use lwk_wollet::{ElementsNetwork, NoPersist, WolletDescriptor};
use serde::{Deserialize, Serialize};

// BIP86 (taproot) derivation paths — m/86h/<coin_type>h/<account>h/0/0
// coin_type: 0 = mainnet, 1 = testnet
// account: 0 = general signing key ("wallet key"), 1 = oracle key
const WALLET_KEY_PATH_MAINNET: &str = "m/86h/0h/0h/0/0";
const WALLET_KEY_PATH_TESTNET: &str = "m/86h/1h/0h/0/0";
const ORACLE_PATH_MAINNET: &str = "m/86h/0h/1h/0/0";
const ORACLE_PATH_TESTNET: &str = "m/86h/1h/1h/0/0";

/// Persisted wallet file — stores the mnemonic.
///
/// WARNING: the mnemonic is stored in plaintext. This is intentional for a
/// demo CLI; production wallets should encrypt at rest.
#[derive(Debug, Serialize, Deserialize)]
#[derive(Clone)]
pub struct WalletFile {
    pub network: String,
    pub mnemonic: String,
}

impl WalletFile {
    pub fn is_mainnet(&self) -> bool {
        self.network == "mainnet"
    }
}

/// Generate a new random 12-word mnemonic and return the wallet file contents.
pub fn create_wallet(is_mainnet: bool) -> Result<WalletFile> {
    let (_, mnemonic) = SwSigner::random(is_mainnet)
        .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {e}"))?;
    Ok(WalletFile {
        network: if is_mainnet { "mainnet" } else { "testnet" }.to_string(),
        mnemonic: mnemonic.to_string(),
    })
}

/// Load a wallet file from disk.
pub fn load_wallet(path: &Path) -> Result<WalletFile> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read wallet file: {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Cannot parse wallet file: {}", path.display()))
}

/// Persist a wallet file to disk.
pub fn save_wallet(wallet: &WalletFile, path: &Path) -> Result<()> {
    let raw = serde_json::to_string_pretty(wallet)?;
    std::fs::write(path, &raw)
        .with_context(|| format!("Cannot write wallet file: {}", path.display()))
}

/// Build a `SwSigner` from a wallet file.
pub fn signer(wallet: &WalletFile) -> Result<SwSigner> {
    SwSigner::new(&wallet.mnemonic, wallet.is_mainnet())
        .map_err(|e| anyhow::anyhow!("Failed to create signer: {e}"))
}

/// Wallet info shown by the `info` command.
pub struct WalletInfo {
    pub network: String,
    pub fingerprint: String,
    pub master_xpub: String,
    /// First receive address (index 0). Send funds here to fund the wallet.
    pub receive_address: String,
    /// 32-byte x-only Schnorr pubkey at the general signing key path (64 hex chars).
    pub wallet_pubkey: String,
    /// Derivation path used for the general signing key.
    pub wallet_key_path: String,
    /// 32-byte x-only Schnorr pubkey at the oracle derivation path (64 hex chars).
    pub oracle_pubkey: String,
    /// The derivation path used for the oracle key.
    pub oracle_path: String,
}

/// Derive a BIP340 x-only Schnorr pubkey (64 hex chars) at `path` from `wallet`.
pub fn derive_schnorr_pubkey(wallet: &WalletFile, path: &str) -> Result<String> {
    let s = signer(wallet)?;
    let dp = DerivationPath::from_str(path)
        .map_err(|e| anyhow::anyhow!("Invalid derivation path '{path}': {e}"))?;
    let xpub = s
        .derive_xpub(&dp)
        .map_err(|e| anyhow::anyhow!("Key derivation failed for '{path}': {e}"))?;
    let (xonly, _) = xpub.public_key.x_only_public_key();
    Ok(format!("{xonly}"))
}

/// Return the BIP340 x-only Schnorr pubkey for the wallet's general signing key.
pub fn wallet_signing_pubkey(wallet: &WalletFile) -> Result<(String, &'static str)> {
    let path = if wallet.is_mainnet() {
        WALLET_KEY_PATH_MAINNET
    } else {
        WALLET_KEY_PATH_TESTNET
    };
    Ok((derive_schnorr_pubkey(wallet, path)?, path))
}

/// Return the default data directory for wallet state:
/// `<user data dir>/tx-manifest-wallet` on each platform.
pub fn default_data_dir() -> PathBuf {
    dirs_next::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tx-manifest-wallet")
}

/// Build the `ElementsNetwork` from a wallet file.
pub fn elements_network(wallet: &WalletFile) -> ElementsNetwork {
    if wallet.is_mainnet() {
        ElementsNetwork::Liquid
    } else {
        ElementsNetwork::LiquidTestnet
    }
}

/// Build a `WolletDescriptor` (singlesig wpkh + slip77 blinding) from the signer.
pub fn descriptor(wallet: &WalletFile) -> Result<WolletDescriptor> {
    let s = signer(wallet)?;
    let desc_str = singlesig_desc(
        &s,
        Singlesig::Wpkh,
        DescriptorBlindingKey::Slip77,
        wallet.is_mainnet(),
    )
    .map_err(|e| anyhow::anyhow!("Descriptor generation failed: {e}"))?;
    desc_str
        .parse::<WolletDescriptor>()
        .map_err(|e| anyhow::anyhow!("Descriptor parse failed: {e}"))
}

/// Sync the wallet against the given chain backend, persisting state to `data_dir`.
/// Returns the block height after sync.
pub fn sync(
    wallet: &WalletFile,
    backend_kind: crate::backend::BackendKind,
    server_url: &str,
    data_dir: &Path,
) -> Result<SyncResult> {
    let network = elements_network(wallet);
    let desc = descriptor(wallet)?;
    println!(
        "Syncing wallet with {} at '{server_url}'...",
        backend_kind.as_str()
    );
    println!(" desc: {desc}");

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("Cannot create data dir: {}", data_dir.display()))?;

    let mut wollet = lwk_wollet::Wollet::with_fs_persist(network, desc, data_dir)
        .map_err(|e| anyhow::anyhow!("Failed to open wallet: {e}"))?;

    let mut client = crate::backend::Backend::connect(backend_kind, server_url, network)?;

    let update = client.full_scan(&wollet)?;

    let tip = if let Some(update) = update {
        let tip = update.tip.height;
        wollet
            .apply_update(update)
            .map_err(|e| anyhow::anyhow!("Failed to apply update: {e}"))?;
        tip
    } else {
        wollet.tip().height()
    };

    let utxos = wollet
        .utxos()
        .map_err(|e| anyhow::anyhow!("Failed to read UTXOs: {e}"))?;
    let explicit_utxos = wollet
        .explicit_utxos()
        .map_err(|e| anyhow::anyhow!("Failed to read explicit UTXOs: {e}"))?;

    Ok(SyncResult { tip, utxos, explicit_utxos })
}

/// Load confidential UTXOs from persisted state (no network call).
pub fn utxos(wallet: &WalletFile, data_dir: &Path) -> Result<Vec<lwk_wollet::WalletTxOut>> {
    let network = elements_network(wallet);
    let desc = descriptor(wallet)?;
    let wollet = lwk_wollet::Wollet::with_fs_persist(network, desc, data_dir)
        .map_err(|e| anyhow::anyhow!("Failed to open wallet: {e}"))?;
    wollet.utxos().map_err(|e| anyhow::anyhow!("Failed to read UTXOs: {e}"))
}

/// Load explicit (non-confidential) UTXOs from persisted state (no network call).
pub fn explicit_utxos(wallet: &WalletFile, data_dir: &Path) -> Result<Vec<lwk_wollet::ExternalUtxo>> {
    let network = elements_network(wallet);
    let desc = descriptor(wallet)?;
    let wollet = lwk_wollet::Wollet::with_fs_persist(network, desc, data_dir)
        .map_err(|e| anyhow::anyhow!("Failed to open wallet: {e}"))?;
    wollet.explicit_utxos().map_err(|e| anyhow::anyhow!("Failed to read explicit UTXOs: {e}"))
}

pub struct SyncResult {
    pub tip: u32,
    pub utxos: Vec<lwk_wollet::WalletTxOut>,
    pub explicit_utxos: Vec<lwk_wollet::ExternalUtxo>,
}

/// Sign a 32-byte hash with BIP340 Schnorr using the wallet key that matches `pubkey_hex`.
///
/// Tries the wallet signing key path and oracle key path. Errors if neither matches.
pub fn sign_schnorr_for_pubkey(
    wallet: &WalletFile,
    pubkey_hex: &str,
    hash: &[u8; 32],
) -> Result<[u8; 64]> {
    use elements_miniscript::bitcoin::secp256k1::{Keypair, Message, Secp256k1};

    let path_str = find_path_for_pubkey(wallet, pubkey_hex)?;
    let secp = Secp256k1::new();
    let mnemonic: bip39::Mnemonic = wallet.mnemonic.parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("");
    let network = if wallet.is_mainnet() {
        elements_miniscript::bitcoin::Network::Bitcoin
    } else {
        elements_miniscript::bitcoin::Network::Testnet
    };
    let root = Xpriv::new_master(network, &seed)
        .context("Failed to derive master xpriv")?;
    let path: DerivationPath = path_str.parse()
        .map_err(|e| anyhow::anyhow!("Invalid derivation path '{path_str}': {e}"))?;
    let child = root.derive_priv(&secp, &path)
        .with_context(|| format!("Key derivation failed at '{path_str}'"))?;
    let keypair = Keypair::from_secret_key(&secp, &child.private_key);
    let msg = Message::from_digest(*hash);
    let sig = secp.sign_schnorr(&msg, &keypair);
    Ok(sig.serialize())
}

/// Find the derivation path in this wallet that produces `pubkey_hex` (64-char x-only hex).
fn find_path_for_pubkey(wallet: &WalletFile, pubkey_hex: &str) -> Result<&'static str> {
    let wallet_path = if wallet.is_mainnet() { WALLET_KEY_PATH_MAINNET } else { WALLET_KEY_PATH_TESTNET };
    let wallet_pub = derive_schnorr_pubkey(wallet, wallet_path)?;
    if wallet_pub == pubkey_hex {
        return Ok(wallet_path);
    }
    let oracle_path = if wallet.is_mainnet() { ORACLE_PATH_MAINNET } else { ORACLE_PATH_TESTNET };
    let oracle_pub = derive_schnorr_pubkey(wallet, oracle_path)?;
    if oracle_pub == pubkey_hex {
        return Ok(oracle_path);
    }
    anyhow::bail!(
        "Key '{pubkey_hex}' does not match any known wallet key path\n  \
         wallet key ({wallet_path}): {wallet_pub}\n  \
         oracle key ({oracle_path}): {oracle_pub}\n  \
         Check that you are using the correct wallet for this action."
    )
}

/// Derive wallet info from a wallet file.
pub fn wallet_info(wallet: &WalletFile) -> Result<WalletInfo> {
    let s = signer(wallet)?;

    let fingerprint = format!("{}", s.fingerprint());
    let master_xpub = format!("{}", s.xpub());

    let wallet_key_path = if wallet.is_mainnet() {
        WALLET_KEY_PATH_MAINNET
    } else {
        WALLET_KEY_PATH_TESTNET
    };
    let oracle_path_str = if wallet.is_mainnet() {
        ORACLE_PATH_MAINNET
    } else {
        ORACLE_PATH_TESTNET
    };

    let derive = |path_str: &str| -> Result<String> {
        let path = DerivationPath::from_str(path_str)
            .map_err(|e| anyhow::anyhow!("Invalid derivation path '{path_str}': {e}"))?;
        let xpub = s
            .derive_xpub(&path)
            .map_err(|e| anyhow::anyhow!("Key derivation failed for '{path_str}': {e}"))?;
        let (xonly, _) = xpub.public_key.x_only_public_key();
        Ok(format!("{xonly}"))
    };

    let wallet_pubkey = derive(wallet_key_path)?;
    let oracle_pubkey = derive(oracle_path_str)?;

    let desc = descriptor(wallet)?;
    let network = elements_network(wallet);
    let wollet = lwk_wollet::Wollet::new(network, NoPersist::new(), desc)
        .map_err(|e| anyhow::anyhow!("Failed to create wollet: {e}"))?;
    let receive_address = format!(
        "{}",
        wollet
            .address(Some(0))
            .map_err(|e| anyhow::anyhow!("Failed to derive address: {e}"))?
            .address()
    );

    Ok(WalletInfo {
        network: wallet.network.clone(),
        fingerprint,
        master_xpub,
        receive_address,
        wallet_pubkey,
        wallet_key_path: wallet_key_path.to_string(),
        oracle_pubkey,
        oracle_path: oracle_path_str.to_string(),
    })
}

/// The wallet's committed payout target: the *explicit* (unblinded) index-0
/// address and the SHA-256 of its scriptPubKey, both in natural byte order.
///
/// This mirrors how the `simplicity-lending` protocol commits a borrower's payout:
/// it bakes `sha256(borrower_wallet_scriptPubKey)` into the pre-lock covenant (as
/// both `PRINCIPAL_OUTPUT_SCRIPT_HASH` and `BORROWER_NFT_OUTPUT_SCRIPT_HASH`) and
/// then pays the principal and the borrower NFT to that explicit address. The
/// covenant enforces the payout with the `output_script_hash` jet, which returns
/// `sha256(scriptPubKey)` — so this hash must match byte-for-byte.
///
/// Returns `(explicit_address_string, sha256_hex)`. The address is the unblinded
/// P2WPKH form so that, when used as an output destination, the wallet builds an
/// *explicit* (non-confidential) output — required because the covenant introspects
/// the output's asset and amount, which are only readable on explicit outputs.
///
/// The index-0 address is also the wallet's advertised receive address, so
/// collateral funded into the wallet naturally lives at the same scriptPubKey the
/// covenant commits to — which is what lets a third-party lender (e.g. the
/// `simplicity-lending` CLI) reconstruct and spend the offer.
/// `sha256(scriptPubKey)` of an address, lowercase hex in natural byte order — the value
/// the Simplicity `input_script_hash` / `output_script_hash` jets return for a UTXO paying
/// that address.
///
/// Confidential and unconfidential forms of an address share a scriptPubKey (the blinding
/// key travels beside it, not in it), so both produce the same hash. A covenant can
/// therefore commit to a payout target without caring whether the recipient blinds it.
pub fn script_hash_of_address(address: &str) -> Result<String> {
    use lwk_wollet::elements::hashes::{sha256, Hash};

    let address: lwk_wollet::elements::Address = address
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("'{}' is not a valid address: {e}", address.trim()))?;
    let hash = sha256::Hash::hash(address.script_pubkey().as_bytes());
    Ok(hash.to_byte_array().iter().map(|b| format!("{b:02x}")).collect())
}

pub fn committed_output(wallet: &WalletFile) -> Result<(String, String)> {
    use lwk_wollet::elements::hashes::{sha256, Hash};

    let desc = descriptor(wallet)?;
    let network = elements_network(wallet);
    let wollet = lwk_wollet::Wollet::new(network, NoPersist::new(), desc)
        .map_err(|e| anyhow::anyhow!("Failed to create wollet: {e}"))?;
    let addr = wollet
        .address(Some(0))
        .map_err(|e| anyhow::anyhow!("Failed to derive address: {e}"))?
        .address()
        .clone();
    let explicit = addr.to_unconfidential();
    let spk = explicit.script_pubkey();
    let hash = sha256::Hash::hash(spk.as_bytes());
    let hash_hex: String = hash.to_byte_array().iter().map(|b| format!("{b:02x}")).collect();
    Ok((explicit.to_string(), hash_hex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements_miniscript::bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
    use std::str::FromStr;

    // BIP39 test vector — all-zeros entropy ("abandon" × 11 + "about").
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> WalletFile {
        WalletFile { network: "testnet".to_string(), mnemonic: TEST_MNEMONIC.to_string() }
    }

    #[test]
    fn sign_schnorr_roundtrip_wallet_key() {
        let wallet = test_wallet();
        let pubkey_hex = derive_schnorr_pubkey(&wallet, WALLET_KEY_PATH_TESTNET).unwrap();
        let hash = [0x42u8; 32];
        let sig_bytes = sign_schnorr_for_pubkey(&wallet, &pubkey_hex, &hash).unwrap();

        let secp = Secp256k1::new();
        let xonly = XOnlyPublicKey::from_str(&pubkey_hex).unwrap();
        let msg = Message::from_digest(hash);
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        secp.verify_schnorr(&sig, &msg, &xonly).expect("wallet key signature should verify");
    }

    #[test]
    fn sign_schnorr_roundtrip_oracle_key() {
        let wallet = test_wallet();
        let pubkey_hex = derive_schnorr_pubkey(&wallet, ORACLE_PATH_TESTNET).unwrap();
        let hash = [0xdeu8; 32];
        let sig_bytes = sign_schnorr_for_pubkey(&wallet, &pubkey_hex, &hash).unwrap();

        let secp = Secp256k1::new();
        let xonly = XOnlyPublicKey::from_str(&pubkey_hex).unwrap();
        let msg = Message::from_digest(hash);
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        secp.verify_schnorr(&sig, &msg, &xonly).expect("oracle key signature should verify");
    }

    #[test]
    fn find_path_finds_wallet_key() {
        let wallet = test_wallet();
        let pubkey_hex = derive_schnorr_pubkey(&wallet, WALLET_KEY_PATH_TESTNET).unwrap();
        let found = find_path_for_pubkey(&wallet, &pubkey_hex).unwrap();
        assert_eq!(found, WALLET_KEY_PATH_TESTNET);
    }

    #[test]
    fn find_path_finds_oracle_key() {
        let wallet = test_wallet();
        let pubkey_hex = derive_schnorr_pubkey(&wallet, ORACLE_PATH_TESTNET).unwrap();
        let found = find_path_for_pubkey(&wallet, &pubkey_hex).unwrap();
        assert_eq!(found, ORACLE_PATH_TESTNET);
    }

    #[test]
    fn find_path_rejects_unknown_key() {
        let wallet = test_wallet();
        let unknown = "a".repeat(64);
        let err = find_path_for_pubkey(&wallet, &unknown).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("does not match"), "error should mention mismatch: {msg}");
        assert!(msg.contains("wallet key"), "error should show wallet key path: {msg}");
        assert!(msg.contains("oracle key"), "error should show oracle key path: {msg}");
    }

    #[test]
    fn sign_rejects_unknown_key() {
        let wallet = test_wallet();
        let unknown = "b".repeat(64);
        let err = sign_schnorr_for_pubkey(&wallet, &unknown, &[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    /// The address → script-hash conversion a covenant's payout target depends on.
    ///
    /// Two claims are pinned because both are load-bearing and neither is obvious:
    /// the hash is `sha256(scriptPubKey)` in natural byte order (what the Simplicity
    /// `output_script_hash` jet returns), and a confidential address hashes identically
    /// to its unconfidential form — so an author may paste either and the covenant that
    /// commits to the hash still matches the output that pays it.
    #[test]
    fn address_script_hash_ignores_blinding() {
        use lwk_wollet::elements::hashes::{sha256, Hash};

        // A confidential Liquid testnet address.
        let confidential = "tlq1qq2tmze58e74rl0tw9cx23j47zxk0ddas95gdy0j2wzkcuejxwj8yypv93ju8yay2s3r4y6fwpuw0l322965qvse6u6zdd5mf5";
        let parsed: lwk_wollet::elements::Address = confidential.parse().expect("valid address");
        assert!(parsed.blinding_pubkey.is_some(), "fixture must be confidential");

        let hash = script_hash_of_address(confidential).expect("hash");
        let expected: String = sha256::Hash::hash(parsed.script_pubkey().as_bytes())
            .to_byte_array()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hash, expected);
        assert_eq!(hash.len(), 64);

        // Stripping the blinding key must not move the hash.
        let explicit = parsed.to_unconfidential().to_string();
        assert_eq!(script_hash_of_address(&explicit).unwrap(), hash);

        // Surrounding whitespace is tolerated; a non-address is an error naming itself.
        assert_eq!(script_hash_of_address(&format!("  {confidential} ")).unwrap(), hash);
        let err = script_hash_of_address("not-an-address").unwrap_err();
        assert!(err.to_string().contains("not-an-address"), "{err}");
    }
}
