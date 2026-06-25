use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use elements_miniscript::bitcoin::bip32::{DerivationPath, Xpriv};
use lwk_common::{singlesig_desc, DescriptorBlindingKey, Signer, Singlesig};
use lwk_signer::SwSigner;
use lwk_wollet::{blocking, ElementsNetwork, NoPersist, WolletDescriptor};
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

/// Sync the wallet against the given Esplora URL, persisting state to `data_dir`.
/// Returns the block height after sync.
pub fn sync(wallet: &WalletFile, esplora_url: &str, data_dir: &Path) -> Result<SyncResult> {
    let network = elements_network(wallet);
    let desc = descriptor(wallet)?;
    println!("Syncing wallet with Esplora at '{esplora_url}'...");
    println!(" desc: {desc}");

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("Cannot create data dir: {}", data_dir.display()))?;

    let mut wollet = lwk_wollet::Wollet::with_fs_persist(network, desc, data_dir)
        .map_err(|e| anyhow::anyhow!("Failed to open wallet: {e}"))?;

    let mut client = blocking::EsploraClient::new(esplora_url, network)
        .map_err(|e| anyhow::anyhow!("Failed to connect to Esplora at '{esplora_url}': {e}"))?;

    let update = blocking::BlockchainBackend::full_scan(&mut client, &wollet)
        .map_err(|e| anyhow::anyhow!("Sync failed: {e}"))?;

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
}
