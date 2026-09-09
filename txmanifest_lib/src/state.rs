use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Derive the history file path from the state file path:
/// `foo.state.json` → `foo.state.history.json`
pub fn history_path(state_path: &Path) -> std::path::PathBuf {
    let stem = state_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("contract.state.json");
    // Insert ".history" before the final ".json"
    let history_name = if let Some(base) = stem.strip_suffix(".json") {
        format!("{base}.history.json")
    } else {
        format!("{stem}.history.json")
    };
    state_path.with_file_name(history_name)
}

/// Derive the next immutable snapshot path from the state file path, one higher
/// than the highest version already on disk:
/// `foo.state.json` → `foo.state.1.json`, then `foo.state.2.json`, …
///
/// This is the default output path for a run when no explicit `--state-out` /
/// `--instance-out` is given: each action writes a fresh numbered file, so the
/// input state is preserved and nothing is overwritten. The `foo.state.json` base
/// is only a naming seed (and the anchor for the single `.history.json` log) — it
/// is not itself written. The number is one higher than the highest snapshot
/// currently present, so during normal append-only use it increases by one each
/// action; deleting the highest snapshot can let its number be reused, but a
/// snapshot below the top is never clobbered. The `.history.json` sibling is
/// never miscounted as a version.
pub fn next_version_path(state_path: &Path) -> std::path::PathBuf {
    let stem = state_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("contract.state.json");
    let base = stem.strip_suffix(".json").unwrap_or(stem);
    let prefix = format!("{base}.");

    // Find the highest existing `<base>.<N>.json` in the same directory.
    let mut max_n: u64 = 0;
    let dir = state_path.parent().filter(|p| !p.as_os_str().is_empty());
    let read = dir
        .map(std::fs::read_dir)
        .unwrap_or_else(|| std::fs::read_dir("."));
    if let Ok(entries) = read {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Some(n) = name
                    .strip_prefix(&prefix)
                    .and_then(|s| s.strip_suffix(".json"))
                    .and_then(|mid| mid.parse::<u64>().ok())
                {
                    max_n = max_n.max(n);
                }
            }
        }
    }
    state_path.with_file_name(format!("{base}.{}.json", max_n + 1))
}

/// One entry in the state history file — records the live UTXO set produced by a single action.
#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Action that triggered this state change.
    pub action: String,
    /// The txid broadcast for this action.
    pub txid: String,
    /// Live covenant UTXOs after this action completed.
    pub utxos: Vec<StateUtxo>,
}

/// Append-only log of every state transition for a contract instance.
/// Stored alongside the state file as `<stem>.state.history.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StateHistory {
    pub entries: Vec<HistoryEntry>,
}

impl StateHistory {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read history file: {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("Cannot parse history file: {}", path.display()))
    }

    pub fn append(&mut self, entry: HistoryEntry, path: &Path) -> Result<()> {
        self.entries.push(entry);
        let json = serde_json::to_string_pretty(self).context("Cannot serialise history file")?;
        std::fs::write(path, json)
            .with_context(|| format!("Cannot write history file: {}", path.display()))
    }
}

/// One live on-chain UTXO belonging to this contract instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUtxo {
    /// The utxo_type name from the manifest file (e.g. `"pre_lock"`).
    pub utxo_type: String,
    /// The output `id` from the action that produced this UTXO (e.g. `"borrower_nft_released"`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub utxo_id: String,
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub asset: String,
}

/// Live on-chain position of a deployed contract instance.
/// Updated after every confirmed action.
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractState {
    /// Relative path to the `.instance.json` this state belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Name of the last action that produced this state.
    pub last_action: String,
    /// All live covenant UTXOs belonging to the contract.
    pub utxos: Vec<StateUtxo>,
}

impl ContractState {
    pub fn new(last_action: &str) -> Self {
        Self {
            instance: None,
            last_action: last_action.to_string(),
            utxos: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read state file: {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("Cannot parse state file: {}", path.display()))
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("Cannot serialise state file")?;
        std::fs::write(path, json)
            .with_context(|| format!("Cannot write state file: {}", path.display()))
    }

    /// All UTXOs of a given utxo_type, ordered by vout.
    pub fn utxos_for_type(&self, utxo_type: &str) -> Vec<&StateUtxo> {
        self.utxos
            .iter()
            .filter(|u| u.utxo_type == utxo_type)
            .collect()
    }

    /// Remove the UTXO at the given outpoint (spent as an input).
    pub fn remove_spent(&mut self, txid: &str, vout: u32) {
        self.utxos.retain(|u| !(u.txid == txid && u.vout == vout));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_path_inserts_history_segment() {
        let p = Path::new("/data/if.state.json");
        assert_eq!(history_path(p), Path::new("/data/if.state.history.json"));
    }

    #[test]
    fn next_version_increments_and_ignores_siblings() {
        // Isolate in a fresh temp dir under the OS temp root.
        let dir = std::env::temp_dir().join(format!("state_ver_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("if.state.json");

        // No snapshots yet → .1
        assert_eq!(next_version_path(&state), dir.join("if.state.1.json"));

        // Create .1 and .2 plus decoy siblings that must NOT be counted.
        for name in [
            "if.state.1.json",
            "if.state.2.json",
            "if.state.history.json",
            "if.state.json",
        ] {
            std::fs::write(dir.join(name), "{}").unwrap();
        }
        assert_eq!(next_version_path(&state), dir.join("if.state.3.json"));

        // Delete the highest (.2): next is highest-present(.1)+1 = .2 again.
        std::fs::remove_file(dir.join("if.state.2.json")).unwrap();
        assert_eq!(next_version_path(&state), dir.join("if.state.2.json"));
        // ^ .1 is preserved; only the just-deleted top number is reused.

        std::fs::remove_dir_all(&dir).ok();
    }
}
