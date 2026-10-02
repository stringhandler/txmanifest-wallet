//! What a Bitcoin transaction does, shown before it is broadcast.
//!
//! The Elements path previews from the manifest's `ui` metadata and then from LWK's view of
//! the built PSET. Neither carries over: the manifest legs are author-supplied, and LWK knows
//! nothing of a Bitcoin wallet. So this reads the *finalized* transaction instead — every
//! input it spends, every output it pays, and which of those outputs come back to this
//! wallet. That makes it the check on what will actually be broadcast, not on what the
//! manifest says will be: a destination or amount the author got wrong, or chose badly,
//! shows up here as it is.

use anyhow::Result;
use console::style;
use lwk_wollet::elements::bitcoin::{Address, Transaction};

use crate::bitcoin_wallet::{BitcoinWallet, Branch};
use crate::chain::Network;
use crate::psbt_builder::PsbtInput;

/// Whose an output is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// This wallet's change address.
    Change(u32),
    /// One of this wallet's receive addresses.
    Receive(u32),
    /// Anyone else — a payee, or a covenant this transaction creates.
    Other,
}

impl Owner {
    fn is_wallet(self) -> bool {
        !matches!(self, Owner::Other)
    }
}

#[derive(Debug)]
pub struct ReviewInput {
    pub id: String,
    pub amount: u64,
    /// Spent by a wallet key, as opposed to a covenant program.
    pub wallet: bool,
}

#[derive(Debug)]
pub struct ReviewOutput {
    pub amount: u64,
    /// The address, or the raw script for an output that has none (`OP_RETURN`).
    pub destination: String,
    pub owner: Owner,
}

/// A finalized transaction, described for the person about to send it.
#[derive(Debug)]
pub struct TxReview {
    pub network: Network,
    pub inputs: Vec<ReviewInput>,
    pub outputs: Vec<ReviewOutput>,
    pub fee: u64,
    pub vsize: u64,
}

impl TxReview {
    /// Describe `tx`, whose inputs are `inputs` in order.
    ///
    /// Wallet outputs are recognized by script: the change address at `change_index`, and
    /// the receive addresses the run hands out from `receive_start` — one per output at
    /// most, which bounds how far to look.
    pub fn new(
        tx: &Transaction,
        inputs: &[PsbtInput],
        wallet: &BitcoinWallet,
        network: Network,
        change_index: u32,
        receive_start: u32,
    ) -> Result<Self> {
        let btc_network = crate::assembly::bitcoin_network(network)?;

        let change = wallet.script_pubkey(Branch::Change, change_index)?;
        let receive: Vec<(u32, _)> = (receive_start..receive_start + tx.output.len() as u32)
            .map(|i| wallet.script_pubkey(Branch::Receive, i).map(|s| (i, s)))
            .collect::<Result<_>>()?;

        let outputs = tx
            .output
            .iter()
            .map(|o| {
                let owner = if o.script_pubkey == change {
                    Owner::Change(change_index)
                } else if let Some((i, _)) = receive.iter().find(|(_, s)| *s == o.script_pubkey) {
                    Owner::Receive(*i)
                } else {
                    Owner::Other
                };
                let destination = Address::from_script(&o.script_pubkey, btc_network)
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| format!("script {}", o.script_pubkey.to_hex_string()));
                ReviewOutput { amount: o.value.to_sat(), destination, owner }
            })
            .collect::<Vec<_>>();

        let inputs: Vec<ReviewInput> = inputs
            .iter()
            .map(|i| ReviewInput {
                id: i.input_id().to_string(),
                amount: i.amount(),
                wallet: matches!(i, PsbtInput::Wallet { .. }),
            })
            .collect();

        // Recomputed from what the transaction spends and pays, not taken from the builder:
        // this screen is the last look before the money moves, so it should not inherit an
        // error from the code it is checking.
        let total_in = inputs.iter().try_fold(0u64, |acc, i| acc.checked_add(i.amount));
        let total_out = outputs.iter().try_fold(0u64, |acc, o| acc.checked_add(o.amount));
        let fee = match (total_in, total_out) {
            (Some(i), Some(o)) if i >= o => i - o,
            _ => anyhow::bail!("transaction pays out more than it spends"),
        };

        Ok(TxReview { network, inputs, outputs, fee, vsize: tx.vsize() as u64 })
    }

    /// What this wallet gains (positive) or loses (negative): outputs paying it, minus the
    /// inputs its keys spend. Covenant inputs are not counted as the wallet's — the coins
    /// were already locked away — so unlocking one to the wallet reads as a gain.
    pub fn wallet_net(&self) -> i64 {
        let gained: u64 =
            self.outputs.iter().filter(|o| o.owner.is_wallet()).map(|o| o.amount).sum();
        let spent: u64 = self.inputs.iter().filter(|i| i.wallet).map(|i| i.amount).sum();
        gained as i64 - spent as i64
    }

    pub fn fee_rate(&self) -> f64 {
        self.fee as f64 / self.vsize.max(1) as f64
    }

    /// Print the review. `intent` is the action's interpolated `intent` line, if it has one.
    pub fn render(&self, intent: Option<&str>) {
        println!();
        println!(
            "{}",
            style(format!("=== Review transaction ({}) ===", self.network)).bold().cyan()
        );
        if self.network.is_mainnet() {
            println!("  {}", style("MAINNET — this spends real bitcoin.").bold().red());
        }
        if let Some(intent) = intent {
            println!("  {}", style(intent).bold());
        }

        println!("  Spends");
        for i in &self.inputs {
            let kind = if i.wallet { "wallet" } else { "covenant" };
            println!(
                "    {:>15}  {}  {}",
                style(sats(i.amount)).yellow(),
                i.id,
                style(format!("({kind})")).dim()
            );
        }

        println!("  Pays");
        for o in &self.outputs {
            let whose = match o.owner {
                Owner::Change(i) => style(format!("your wallet — change #{i}")).green(),
                Owner::Receive(i) => style(format!("your wallet — receive #{i}")).green(),
                Owner::Other => style("not your wallet".to_string()).red(),
            };
            println!(
                "    {:>15}  → {}  {}",
                style(sats(o.amount)).yellow(),
                o.destination,
                whose
            );
        }

        println!(
            "  Fee  {}  {}",
            style(sats(self.fee)).yellow(),
            style(format!("({:.2} sat/vB over {} vB)", self.fee_rate(), self.vsize)).dim()
        );

        let net = self.wallet_net();
        let net_text = format!("{}{}", if net >= 0 { "+" } else { "−" }, sats(net.unsigned_abs()));
        let net_text = if net >= 0 { style(net_text).green() } else { style(net_text).red() };
        println!("  Net effect on your wallet: {}", net_text.bold());
    }
}

/// `1234567` → `1,234,567 sat`.
fn sats(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    format!("{out} sat")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_wollet::elements::bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, TxIn,
        TxOut, Witness,
    };

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> BitcoinWallet {
        BitcoinWallet::from_mnemonic(MNEMONIC, Network::BitcoinSignet).unwrap()
    }

    fn tx(outputs: Vec<TxOut>, n_inputs: usize) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..n_inputs)
                .map(|_| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[[0u8; 64]]),
                })
                .collect(),
            output: outputs,
        }
    }

    fn wallet_input(amount: u64, w: &BitcoinWallet) -> PsbtInput {
        PsbtInput::Wallet {
            input_id: "funding".to_string(),
            outpoint: OutPoint::null(),
            witness_utxo: TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: w.script_pubkey(Branch::Receive, 0).unwrap(),
            },
            sequence: None,
        }
    }

    fn out(amount: u64, script_pubkey: ScriptBuf) -> TxOut {
        TxOut { value: Amount::from_sat(amount), script_pubkey }
    }

    /// A payment: the payee is "not your wallet", the change is, and the net effect is what
    /// left — payment plus fee.
    #[test]
    fn a_payment_shows_who_gets_what() {
        let w = wallet();
        let payee = ScriptBuf::from_bytes(vec![0x51, 0x20].into_iter().chain([7u8; 32]).collect());
        let change = w.script_pubkey(Branch::Change, 4).unwrap();
        let t = tx(vec![out(150_000, payee), out(849_700, change)], 1);

        let r = TxReview::new(&t, &[wallet_input(1_000_000, &w)], &w, Network::BitcoinSignet, 4, 0)
            .unwrap();
        assert_eq!(r.outputs[0].owner, Owner::Other);
        assert_eq!(r.outputs[1].owner, Owner::Change(4));
        assert_eq!(r.fee, 300);
        assert_eq!(r.wallet_net(), -150_300);
        assert!(r.outputs[0].destination.starts_with("tb1p"), "{}", r.outputs[0].destination);
    }

    /// Unlocking a covenant to the wallet is a gain: the covenant input is not the wallet's.
    #[test]
    fn unlocking_a_covenant_to_the_wallet_is_a_gain() {
        let w = wallet();
        let covenant = PsbtInput::Covenant {
            input_id: "vault_in".to_string(),
            outpoint: OutPoint::null(),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20].into_iter().chain([9u8; 32]).collect()),
            amount: 1_000_000,
            sequence: None,
        };
        let t = tx(vec![out(999_700, w.script_pubkey(Branch::Receive, 3).unwrap())], 1);

        let r = TxReview::new(&t, &[covenant], &w, Network::BitcoinSignet, 0, 3).unwrap();
        assert_eq!(r.outputs[0].owner, Owner::Receive(3));
        assert_eq!(r.fee, 300);
        assert_eq!(r.wallet_net(), 999_700);
    }

    /// An output with no address form is still shown, as its script.
    #[test]
    fn an_op_return_output_is_shown_as_its_script() {
        let w = wallet();
        let t = tx(vec![out(0, ScriptBuf::from_bytes(vec![0x6a, 0x01, 0xff]))], 1);
        let r = TxReview::new(&t, &[wallet_input(1_000, &w)], &w, Network::BitcoinSignet, 0, 0)
            .unwrap();
        assert_eq!(r.outputs[0].destination, "script 6a01ff");
    }

    #[test]
    fn a_transaction_paying_out_more_than_it_spends_is_refused() {
        let w = wallet();
        let t = tx(vec![out(2_000, w.script_pubkey(Branch::Change, 0).unwrap())], 1);
        assert!(TxReview::new(&t, &[wallet_input(1_000, &w)], &w, Network::BitcoinSignet, 0, 0)
            .is_err());
    }

    #[test]
    fn sats_are_grouped_by_thousands() {
        assert_eq!(sats(0), "0 sat");
        assert_eq!(sats(999), "999 sat");
        assert_eq!(sats(1_000), "1,000 sat");
        assert_eq!(sats(1_234_567), "1,234,567 sat");
    }
}
