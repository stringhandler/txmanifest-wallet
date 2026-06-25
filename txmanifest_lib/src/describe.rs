//! Interactive explorer for a manifest file.
//!
//! `describe` presents a menu of the contract's classes and actions so you can
//! drill into any one and see its params, inputs, outputs, witnesses, and
//! validations without reading the raw JSON. When stdout is not a terminal
//! (e.g. piped to a file), it prints a full non-interactive dump instead.

use anyhow::Result;
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Select};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::manifest::{
    Action, ClassDef, Manifest, InstanceCreate, Input, Output, ParamDef, Validation,
};

/// Entry point: explore the contract interactively, or dump it if non-interactive.
pub fn describe(manifest: &Manifest) -> Result<()> {
    if !Term::stdout().is_term() {
        return dump_all(manifest);
    }
    main_menu(manifest)
}

/// What a top-level menu entry maps to.
enum Target {
    Overview,
    Class(String),
    Action(String),
    Quit,
}

fn main_menu(manifest: &Manifest) -> Result<()> {
    loop {
        let mut labels: Vec<String> = Vec::new();
        let mut targets: Vec<Target> = Vec::new();

        labels.push("Overview".to_string());
        targets.push(Target::Overview);

        if let Some(classes) = &manifest.classes {
            for (cname, cdef) in classes {
                labels.push(format!("class   {cname}  ({} methods)", cdef.methods.len()));
                targets.push(Target::Class(cname.clone()));
            }
        }
        for aname in manifest.actions.keys() {
            labels.push(format!("action  {aname}"));
            targets.push(Target::Action(aname.clone()));
        }

        labels.push("Quit".to_string());
        targets.push(Target::Quit);

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Explore contract")
            .items(&labels)
            .default(0)
            .interact_opt()?;

        let Some(idx) = selection else { break };
        match &targets[idx] {
            Target::Overview => print_overview(manifest),
            Target::Class(name) => class_menu(manifest, name)?,
            Target::Action(name) => {
                if let Some(action) = manifest.actions.get(name) {
                    print_action(name, action);
                }
            }
            Target::Quit => break,
        }
    }
    Ok(())
}

fn class_menu(manifest: &Manifest, class_name: &str) -> Result<()> {
    let class = match manifest.classes.as_ref().and_then(|c| c.get(class_name)) {
        Some(c) => c,
        None => return Ok(()),
    };
    print_class_header(class_name, class);

    loop {
        let mut labels: Vec<String> = Vec::new();
        let method_names: Vec<&String> = class.methods.keys().collect();
        for mname in &method_names {
            labels.push(format!("method  {mname}"));
        }
        labels.push("← Back".to_string());

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("class {class_name}"))
            .items(&labels)
            .default(0)
            .interact_opt()?;

        let Some(idx) = selection else { break };
        if idx == method_names.len() {
            break; // "← Back"
        }
        let mname = method_names[idx];
        if let Some(method) = class.methods.get(mname) {
            print_action(&format!("{class_name}.{mname}"), method);
        }
    }
    Ok(())
}

/// Full non-interactive listing (used when stdout is not a TTY).
fn dump_all(manifest: &Manifest) -> Result<()> {
    print_overview(manifest);
    if let Some(classes) = &manifest.classes {
        for (cname, cdef) in classes {
            print_class_header(cname, cdef);
            for (mname, method) in &cdef.methods {
                print_action(&format!("{cname}.{mname}"), method);
            }
        }
    }
    for (aname, action) in &manifest.actions {
        print_action(aname, action);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Printers
// ---------------------------------------------------------------------------

fn print_overview(manifest: &Manifest) {
    println!();
    println!("{}", style("══ Overview").bold().magenta());
    println!("  protocol : {}", style(&manifest.protocol).green());
    if let Some(d) = &manifest.description {
        println!("  {}", style(d).italic());
    }
    println!("  chain    : {}", manifest.chain.as_deref().unwrap_or("elements (default)"));
    println!("  version  : {}", manifest.manifest_version);

    let (user, derived) = manifest.compile_param_sets();
    if !user.is_empty() || !derived.is_empty() {
        println!("  {}", style("Compile params").bold());
        for (name, def) in &user {
            println!("    {} : {}", style(name).green(), def.type_);
        }
        for (name, def) in &derived {
            println!("    {} : {} {}", style(name).green(), def.type_, style("(derived)").dim());
        }
    }

    if let Some(utxo_types) = &manifest.utxo_types {
        if !utxo_types.is_empty() {
            println!("  {}", style("UTXO types").bold());
            for (name, t) in utxo_types {
                println!("    {} — {}", style(name).green(), style(&t.description).dim());
            }
        }
    }

    if let Some(classes) = &manifest.classes {
        if !classes.is_empty() {
            let names: Vec<&str> = classes.keys().map(String::as_str).collect();
            println!("  {}: {}", style("Classes").bold(), names.join(", "));
        }
    }
    if !manifest.actions.is_empty() {
        let names: Vec<&str> = manifest.actions.keys().map(String::as_str).collect();
        println!("  {}: {}", style("Standalone actions").bold(), names.join(", "));
    }

    if let Some(lifecycle) = &manifest.lifecycle {
        if let Some(states) = lifecycle.get("states").and_then(Value::as_array) {
            let s: Vec<String> = states.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            if !s.is_empty() {
                println!("  {}: {}", style("Lifecycle states").bold(), s.join(" → "));
            }
        }
    }
}

fn print_class_header(name: &str, class: &ClassDef) {
    println!();
    println!("{}", style(format!("══ class {name}")).bold().magenta());
    if let Some(d) = &class.description {
        println!("  {}", style(d).italic());
    }
    if !class.fields.is_empty() {
        println!("  {}", style("Fields").bold());
        for (fname, def) in &class.fields {
            let desc = def.description.as_deref().map(|d| format!(" — {d}")).unwrap_or_default();
            let default = def.default.as_deref().map(|d| format!("  [default: {d}]")).unwrap_or_default();
            println!("    {} : {}{}{}", style(fname).green(), def.type_, style(desc).dim(), style(default).yellow());
        }
    }
    println!("  {}: {}", style("Methods").bold(), class.methods.keys().cloned().collect::<Vec<_>>().join(", "));
}

fn print_action(title: &str, action: &Action) {
    println!();
    println!("{}", style(format!("━━ {title}")).bold().cyan());
    if let Some(d) = &action.description {
        println!("  {}", style(d).italic());
    }

    let mut flags = Vec::new();
    if action.is_constructor {
        flags.push("constructor");
    }
    if action.deploy {
        flags.push("deploy");
    }
    if !flags.is_empty() {
        println!("  {}", style(format!("[{}]", flags.join(", "))).yellow());
    }

    print_param_map("Params", &action.params);
    print_param_map("Args", &action.args);
    print_inputs(&action.inputs);
    print_outputs(&action.outputs);
    print_witnesses("Witnesses", &action.witnesses);
    print_validations(&action.validations);
    print_create_instance(&action.create_instance);
}

fn print_param_map(label: &str, params: &Option<BTreeMap<String, ParamDef>>) {
    let Some(params) = params else { return };
    if params.is_empty() {
        return;
    }
    println!("  {}", style(label).bold());
    for (name, def) in params {
        let mut extra = String::new();
        if def.derived.unwrap_or(false) {
            extra.push_str(" (derived)");
        }
        if let Some(src) = &def.source {
            extra.push_str(&format!(" [source: {}]", src.type_));
        }
        let desc = def.description.as_deref().map(|d| format!(" — {d}")).unwrap_or_default();
        println!("    {} : {}{}{}", style(name).green(), def.type_, style(extra).yellow(), style(desc).dim());
    }
}

fn print_inputs(inputs: &Option<Vec<Input>>) {
    let Some(inputs) = inputs else { return };
    if inputs.is_empty() {
        return;
    }
    println!("  {}", style("Inputs").bold());
    for inp in inputs {
        let src = if inp.is_wallet_source() {
            "wallet".to_string()
        } else if let Some(t) = inp.utxo_type_name() {
            format!("utxo_type:{t}")
        } else {
            val_str(&inp.utxo_source)
        };
        let asset = inp.asset.as_ref().map(|a| format!("  asset={}", val_str(a))).unwrap_or_default();
        let amount = inp.amount_sat.as_ref().map(|a| format!("  amount={}", val_str(a))).unwrap_or_default();
        println!("    {} ← {}{}{}", style(&inp.id).green(), src, style(asset).dim(), style(amount).dim());
        if let Some(Value::Object(m)) = &inp.witnesses {
            if !m.is_empty() {
                let keys: Vec<&str> = m.keys().map(String::as_str).collect();
                println!("        {} {}", style("witnesses:").dim(), style(keys.join(", ")).dim());
            }
        }
        if inp.issuance.is_some() {
            println!("        {}", style("issuance: yes").dim());
        }
    }
}

fn print_outputs(outputs: &Option<Vec<Output>>) {
    let Some(outputs) = outputs else { return };
    if outputs.is_empty() {
        return;
    }
    println!("  {}", style("Outputs").bold());
    for o in outputs {
        let amount = o
            .amount_sat
            .as_ref()
            .map(|a| format!("  amount={}", val_str(a)))
            .unwrap_or_else(|| "  amount=(auto)".to_string());
        let asset = o.asset.as_ref().map(|a| format!("  asset={}", val_str(a))).unwrap_or_default();
        let opt = if o.optional.unwrap_or(false) { "  (optional)" } else { "" };
        println!(
            "    {} → {}{}{}{}",
            style(&o.id).green(),
            o.destination_summary(),
            style(amount).dim(),
            style(asset).dim(),
            style(opt).dim(),
        );
    }
}

fn print_witnesses(label: &str, witnesses: &Option<Value>) {
    let Some(Value::Object(m)) = witnesses else { return };
    if m.is_empty() {
        return;
    }
    println!("  {}", style(label).bold());
    for (name, spec) in m {
        let ty = spec.get("type").and_then(Value::as_str).unwrap_or("?");
        println!("    {} : {}", style(name).green(), ty);
    }
}

fn print_validations(validations: &Option<Vec<Validation>>) {
    let Some(validations) = validations else { return };
    if validations.is_empty() {
        return;
    }
    println!("  {}", style("Validations").bold());
    for v in validations {
        let detail = match v.rule.type_.as_str() {
            "arithmetic" => v.rule.expr.clone().unwrap_or_default(),
            "utxo_exists" => format!("utxo_type {}", v.rule.utxo_type.clone().unwrap_or_default()),
            _ => String::new(),
        };
        println!("    {} [{}] {}", style(&v.id).green(), v.rule.type_, style(detail).dim());
    }
}

fn print_create_instance(create_instance: &Option<InstanceCreate>) {
    let Some(ci) = create_instance else { return };
    println!("  {}", style("Creates instance").bold());
    println!("    class: {}", style(&ci.class).green());
    let fields: Vec<&str> = ci.fields.keys().map(String::as_str).collect();
    if !fields.is_empty() {
        println!("    fields: {}", style(fields.join(", ")).dim());
    }
}

/// Render a JSON value compactly for display: strings as-is, everything else as JSON.
fn val_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "—".to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}
