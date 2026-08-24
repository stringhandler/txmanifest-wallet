//! `tx-manifest-sign` — put a publisher's signature on a manifest, and check one.
//!
//! Separate from the wallet CLI because signing and executing are different jobs done by
//! different people on different machines. A publisher signs; the wallet spends. Nothing
//! here can build, sign or broadcast a transaction, and nothing here needs a network.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tx_manifest_core::canonical;
use tx_manifest_core::checks;
use tx_manifest_core::signature::{self, ManifestSignature};

#[derive(Parser)]
#[command(name = "tx-manifest-sign")]
#[command(version)]
#[command(about = "Sign and verify transaction manifests")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the manifest's registry id — the tagged SHA-256 of its canonical form.
    Id {
        manifest_file: PathBuf,
        /// Print the exact bytes the id is computed over instead of the id.
        #[arg(long)]
        canonical: bool,
    },

    /// Print the 32 bytes a publisher signs, for an offline or hardware signer.
    ///
    /// This is not the manifest id: it is `tagged("txmanifest/signature/v1", id)`, so a
    /// signature made here can never be replayed as a signature over anything else.
    Digest { manifest_file: PathBuf },

    /// Sign a manifest and write a new file carrying the signature.
    ///
    /// The input is never modified: the signature lands in `<name>.signed.json` beside
    /// it, so the repository copy of a manifest stays unsigned and editable.
    Sign {
        manifest_file: PathBuf,
        /// File holding the 32-byte secret key as 64 hex characters.
        ///
        /// A file rather than an argument: a key on the command line is visible to every
        /// process on the machine and lands in the shell history.
        #[arg(long)]
        key: PathBuf,
        /// Output path (default: `<name>.signed.json` beside the input).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Attach a signature produced elsewhere — an air-gapped machine, an HSM.
    Attach {
        manifest_file: PathBuf,
        /// The signer's x-only BIP340 public key, 64 hex characters.
        #[arg(long)]
        public_key: String,
        /// The BIP340 signature over `digest`, 128 hex characters.
        #[arg(long)]
        signature: String,
        /// Output path (default: `<name>.signed.json` beside the input).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Report which keys have signed this manifest.
    ///
    /// Without `--require`, this prints keys and says nothing about trust — the file
    /// supplied those keys, so a checkmark here would be one an attacker can also write.
    /// With `--require`, it asks the only question worth asking: did *this* key sign?
    Verify {
        manifest_file: PathBuf,
        /// Exit non-zero unless this x-only public key has signed. Repeatable.
        #[arg(long = "require", value_name = "PUBKEY")]
        require: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Id { manifest_file, canonical } => cmd_id(&manifest_file, canonical),
        Commands::Digest { manifest_file } => cmd_digest(&manifest_file),
        Commands::Sign { manifest_file, key, out } => cmd_sign(&manifest_file, &key, out.as_deref()),
        Commands::Attach { manifest_file, public_key, signature, out } => {
            cmd_attach(&manifest_file, &public_key, &signature, out.as_deref())
        }
        Commands::Verify { manifest_file, require } => cmd_verify(&manifest_file, &require),
    }
}

/// Read a manifest and refuse to go further if its id would be ambiguous.
///
/// Every command here funnels through this. An id that another implementation would
/// compute differently is worse than no id, and worst of all once a signature exists over
/// it — so the hazard is caught before a key is ever touched, not after.
fn load(manifest_path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("cannot read manifest file: {}", manifest_path.display()))?;

    let hazards = checks::validate_canonical(&raw);
    if !hazards.is_ok() {
        for issue in &hazards.issues {
            eprintln!("  {} — {}", issue.location, issue.message);
        }
        bail!(
            "{} has no unambiguous id ({} problem(s) above)",
            manifest_path.display(),
            hazards.errors()
        );
    }
    Ok(raw)
}

/// `<dir>/<stem>.signed.json`, the default output for a signing command.
fn signed_path(manifest_path: &Path) -> PathBuf {
    let stem = manifest_path.file_stem().map_or_else(
        || "manifest".to_string(),
        |stem| stem.to_string_lossy().trim_end_matches(".signed").to_string(),
    );
    manifest_path.with_file_name(format!("{stem}.signed.json"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn cmd_id(manifest_path: &Path, canonical_form: bool) -> Result<()> {
    let raw = load(manifest_path)?;
    if canonical_form {
        // Raw bytes, no trailing newline: this is the preimage, and piping it to a
        // hasher must agree with the id rather than hash a stray '\n'.
        use std::io::Write as _;
        std::io::stdout()
            .write_all(&canonical::canonical_bytes(&raw)?)
            .context("cannot write canonical form to stdout")?;
    } else {
        println!("{}", canonical::manifest_id_hex(&raw)?);
    }
    Ok(())
}

fn cmd_digest(manifest_path: &Path) -> Result<()> {
    let raw = load(manifest_path)?;
    let id = canonical::manifest_id(&raw)?;
    println!("{}", hex(&signature::signing_message(&id)));
    Ok(())
}

/// Read a 32-byte secret key written as hex, ignoring surrounding whitespace.
fn read_key(key_path: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(key_path)
        .with_context(|| format!("cannot read key file: {}", key_path.display()))?;
    let text = text.trim();
    if text.len() != 64 {
        bail!(
            "{} should hold a 32-byte secret key as 64 hex characters, found {}",
            key_path.display(),
            text.len()
        );
    }
    let mut secret = [0u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("{} is not valid hex", key_path.display()))?;
    }
    Ok(secret)
}

fn write_signed(manifest_path: &Path, out: Option<&Path>, text: &str) -> Result<()> {
    let destination = out.map_or_else(|| signed_path(manifest_path), Path::to_path_buf);
    std::fs::write(&destination, text)
        .with_context(|| format!("cannot write {}", destination.display()))?;
    println!("{}", destination.display());
    Ok(())
}

fn cmd_sign(manifest_path: &Path, key_path: &Path, out: Option<&Path>) -> Result<()> {
    let raw = load(manifest_path)?;
    let id = canonical::manifest_id(&raw)?;
    let entry = signature::sign(&id, &read_key(key_path)?)?;
    eprintln!("signed {} as {}", canonical::manifest_id_hex(&raw)?, entry.public_key);
    write_signed(manifest_path, out, &signature::attach(&raw, entry)?)
}

fn cmd_attach(
    manifest_path: &Path,
    public_key: &str,
    sig: &str,
    out: Option<&Path>,
) -> Result<()> {
    let raw = load(manifest_path)?;
    let entry = ManifestSignature {
        public_key: public_key.trim().to_lowercase(),
        signature: sig.trim().to_lowercase(),
    };

    // Verified before it is written, not after: a file that says "signed" and is not is
    // the one outcome this tool must never produce.
    let id = canonical::manifest_id(&raw)?;
    signature::verify(&id, &entry).context("refusing to attach a signature that does not verify")?;

    write_signed(manifest_path, out, &signature::attach(&raw, entry)?)
}

fn cmd_verify(manifest_path: &Path, required: &[String]) -> Result<()> {
    let raw = load(manifest_path)?;

    // Report shape problems (a stale entry, a duplicate key) before listing what passed,
    // so a file with one good and one broken signature never looks simply fine.
    let report = signature::check_signatures(&raw);
    for issue in &report.issues {
        eprintln!("  [{:?}] {} — {}", issue.severity, issue.location, issue.message);
    }

    let verified = signature::verified_keys(&raw)?;
    println!("{}", canonical::manifest_id_hex(&raw)?);
    for key in &verified {
        println!("  signed by {key}");
    }
    if verified.is_empty() {
        println!("  (no valid signatures)");
    }

    let missing: Vec<&String> = required
        .iter()
        .filter(|key| !verified.contains(&key.trim().to_lowercase()))
        .collect();
    if !missing.is_empty() {
        // Fail closed. Absence of a required signature is a rejection, never a warning:
        // stripping an entry from an unhashed block costs an attacker nothing.
        bail!("required key(s) have not signed this manifest: {missing:?}");
    }
    if !report.is_ok() {
        bail!("{} signature problem(s)", report.errors());
    }
    Ok(())
}
