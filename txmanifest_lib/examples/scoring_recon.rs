// Fantasy Dota — Unit 2 (scoring) table-driven reconciliation.
//
//   cargo run -p tx-manifest-lib --example scoring_recon
//
// Unit 2's claim is that a weighted linear fantasy score can be computed inside a
// spending condition. This example checks that claim the only way that means anything:
// it EXECUTES the compiled covenant on a table of stat vectors and compares the result
// against an independent reference implementation in Rust.
//
// Every vector is run TWICE — once with the reference answer as EXPECTED (must satisfy)
// and once with a deliberately wrong answer (must fail). A covenant that accepted both
// would be computing nothing at all, and only the negative half catches that.
//
// scoring.simf touches no transaction introspection — it is pure arithmetic — so a dummy
// Elements environment is a faithful place to run it. Nothing here needs a chain.
//
// The weight table is read from the unit's own params.json, the same file the manifest
// wires into the covenant. That is deliberate: if the reference implementation carried
// its own copy, the two could drift and every vector would still pass.
use std::collections::HashMap;

use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::parse::ParseFromStr as _;
use simplicityhl::simplicity::BitMachine;
use simplicityhl::str::WitnessName;
use simplicityhl::value::Value;
use simplicityhl::{dummy_env, Arguments, CompiledProgram, WitnessValues};

const UNIT_DIR: &str = "../fantasy-dota/units/02-scoring";

/// A role's weight set, scale 10^4. Field order matches `Weights` in scoring.simf.
#[derive(Clone, Copy, Debug)]
struct Weights {
    kills: u64,
    deaths: u64,
    assists: u64,
    last_hits: u64,
    gpm: u64,
}

/// A stat vector. Field order matches `Facts` in scoring.simf.
#[derive(Clone, Copy, Debug)]
struct Facts {
    kills: u32,
    deaths: u32,
    assists: u32,
    last_hits: u32,
    gpm: u32,
}

impl Facts {
    /// The SimplicityHL literal for this vector, as the covenant's `(u32, u32, u32, u32,
    /// u32)` witness.
    fn literal(&self) -> String {
        format!(
            "({}, {}, {}, {}, {})",
            self.kills, self.deaths, self.assists, self.last_hits, self.gpm
        )
    }
}

const CORE: u32 = 0;
const MID: u32 = 1;
const SUPPORT: u32 = 2;

fn role_name(trait_id: u32) -> &'static str {
    match trait_id {
        CORE => "CORE",
        MID => "MID",
        SUPPORT => "SUPPORT",
        _ => "INVALID",
    }
}

/// THE REFERENCE IMPLEMENTATION.
///
/// Deliberately written straight, with no shared code with the covenant: the covenant
/// folds its terms pairwise through overflow-checked helpers, this sums them left to
/// right. If both are correct they agree on every vector; if the covenant's associativity
/// or its clamp were wrong, they would not.
fn trait_fn(w: &Weights, f: &Facts) -> u64 {
    let term = |weight: u64, fact: u32| {
        weight
            .checked_mul(u64::from(fact))
            .expect("reference overflowed — the vector is outside the documented bound")
    };
    let earned = term(w.kills, f.kills)
        + term(w.assists, f.assists)
        + term(w.last_hits, f.last_hits)
        + term(w.gpm, f.gpm);
    let lost = term(w.deaths, f.deaths);

    // Floored at zero, matching clamped_subtract. PROVISIONAL alongside F1 — but a
    // wrapping subtraction is not an option under any weight set, since the award becomes
    // a quantity of fpoints to mint.
    earned.saturating_sub(lost)
}

/// Load the weight table from the unit's params.json — the same file the manifest wires
/// into the covenant, so there is exactly one copy of these numbers in the project.
fn load_weights() -> (HashMap<String, String>, [Weights; 3]) {
    let path = format!("{UNIT_DIR}/params.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let table: HashMap<String, String> =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}"));

    let get = |name: &str| -> u64 {
        table
            .get(name)
            .unwrap_or_else(|| panic!("{path} is missing {name}"))
            .parse()
            .unwrap_or_else(|e| panic!("{name} is not a u64: {e}"))
    };
    let role = |prefix: &str| Weights {
        kills: get(&format!("W_{prefix}_KILLS")),
        deaths: get(&format!("W_{prefix}_DEATHS")),
        assists: get(&format!("W_{prefix}_ASSISTS")),
        last_hits: get(&format!("W_{prefix}_LAST_HITS")),
        gpm: get(&format!("W_{prefix}_GPM")),
    };

    (table.clone(), [role("CORE"), role("MID"), role("SUPPORT")])
}

/// Compile scoring.simf with the weight table baked in as compile params.
fn compile(table: &HashMap<String, String>) -> CompiledProgram {
    let args_json = {
        let mut entries: Vec<String> = table
            .iter()
            .map(|(name, value)| format!(r#""{name}": {{ "value": "{value}", "type": "u64" }}"#))
            .collect();
        entries.sort();
        format!("{{{}}}", entries.join(", "))
    };
    let arguments: Arguments = serde_json::from_str(&args_json).expect("arguments");
    let source = std::fs::read_to_string(format!("{UNIT_DIR}/scoring.simf")).expect("read simf");
    CompiledProgram::new(source, arguments, false, Box::new(ElementsJetHinter::new()))
        .expect("compile scoring.simf")
}

/// Run the covenant with one witness triple. `Ok(())` means the spend would be valid.
fn run(program: &CompiledProgram, facts: &Facts, trait_id: u32, expected: u64) -> Result<(), String> {
    let types = program.witness_types();
    let mut map = HashMap::new();
    for (name, literal) in [
        ("FACTS", facts.literal()),
        ("TRAIT_ID", trait_id.to_string()),
        ("EXPECTED", expected.to_string()),
    ] {
        let witness_name = WitnessName::parse_from_str(name).expect("witness name");
        let ty = types
            .get(&witness_name)
            .unwrap_or_else(|| panic!("scoring.simf declares no witness {name}"));
        let value = Value::parse_from_str(&literal, ty)
            .unwrap_or_else(|e| panic!("cannot parse {name} = {literal}: {e}"));
        map.insert(witness_name, value);
    }

    let satisfied = program
        .satisfy(WitnessValues::from(map))
        .map_err(|e| format!("satisfy: {e}"))?;
    let redeem = satisfied.redeem();
    let env = dummy_env::dummy();
    let mut mac = BitMachine::for_program(redeem).map_err(|e| format!("bit machine: {e}"))?;
    mac.exec(redeem, &env).map(|_| ()).map_err(|e| format!("exec: {e}"))
}

fn main() {
    let (table, weights) = load_weights();
    let program = compile(&table);

    // The vector table. Every case the M2 gate names, plus per-role coverage.
    //
    // MAX is the overflow probe: u32::MAX in every field is far outside anything Dota
    // produces, but FACTS is a witness and therefore attacker-chosen, so the documented
    // bound has to hold across the whole u32 range — not across plausible stat lines.
    let zero = Facts { kills: 0, deaths: 0, assists: 0, last_hits: 0, gpm: 0 };
    let typical = Facts { kills: 8, deaths: 3, assists: 14, last_hits: 260, gpm: 545 };
    let max = Facts {
        kills: u32::MAX,
        deaths: u32::MAX,
        assists: u32::MAX,
        last_hits: u32::MAX,
        gpm: u32::MAX,
    };
    // Deaths dominate: the raw score goes negative and must floor at zero rather than
    // wrapping to ~1.8e19 fpoints.
    let death_heavy = Facts { kills: 0, deaths: 12, assists: 1, last_hits: 4, gpm: 90 };

    let vectors: [(&str, Facts, u32); 8] = [
        ("zero", zero, CORE),
        ("typical", typical, CORE),
        ("typical", typical, MID),
        ("typical", typical, SUPPORT),
        ("max (overflow probe)", max, CORE),
        ("death-heavy (clamp)", death_heavy, CORE),
        ("death-heavy (clamp)", death_heavy, MID),
        ("death-heavy (clamp)", death_heavy, SUPPORT),
    ];

    eprintln!("---- result ----");
    println!(
        "{:<22} {:<8} {:>22}  {:>8}  {:>8}",
        "vector", "role", "award (scale 1e4)", "satisfy", "reject"
    );

    let mut clamp_seen = false;
    for (label, facts, trait_id) in vectors {
        let expected = trait_fn(&weights[trait_id as usize], &facts);
        if expected == 0 && facts.deaths > 0 {
            clamp_seen = true;
        }

        // Positive half: the reference answer must satisfy the covenant.
        run(&program, &facts, trait_id, expected).unwrap_or_else(|e| {
            panic!(
                "{label} / {}: the covenant REJECTED the reference award {expected}. \
                 The on-chain arithmetic and the reference implementation disagree, which \
                 is the one thing Unit 2 exists to rule out.\n  {e}",
                role_name(trait_id)
            )
        });

        // Negative half: a wrong answer must NOT satisfy it. Off by one, because an
        // off-by-one is the smallest error a real scoring bug produces and the hardest
        // for a sloppy check to catch.
        let wrong = expected.wrapping_add(1);
        if run(&program, &facts, trait_id, wrong).is_ok() {
            panic!(
                "{label} / {}: the covenant ACCEPTED a wrong award ({wrong} instead of \
                 {expected}). It is not checking the computation.",
                role_name(trait_id)
            );
        }

        println!(
            "{label:<22} {:<8} {expected:>22}  {:>8}  {:>8}",
            role_name(trait_id),
            "ok",
            "ok"
        );
    }

    // An unknown role must be rejected outright rather than silently scoring as SUPPORT.
    // TRAIT_ID is a witness, so this is an attacker-reachable input.
    let rogue_trait = 3u32;
    let as_support = trait_fn(&weights[SUPPORT as usize], &typical);
    if run(&program, &typical, rogue_trait, as_support).is_ok() {
        panic!(
            "TRAIT_ID = {rogue_trait} was accepted and scored as SUPPORT. An unknown role \
             must fail the le_32 bound, or every id above 2 becomes a free extra role."
        );
    }
    println!("{:<22} {:<8} {:>22}  {:>8}  {:>8}", "unknown role", "3", "-", "n/a", "ok");

    assert!(
        clamp_seen,
        "no vector actually exercised the zero clamp — the death-heavy case is not \
         death-heavy enough, so clamped_subtract is untested"
    );

    println!(
        "\nOK: {} vectors, each satisfying with the reference award and rejecting an \
         off-by-one, plus the clamp and the unknown-role bound.",
        vectors.len()
    );
}
