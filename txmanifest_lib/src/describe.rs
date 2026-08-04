//! Interactive explorer for a manifest file.
//!
//! `describe` presents a menu of the contract's templates and actions so you can
//! drill into any one and see its params, inputs, outputs, and witnesses
//! without reading the raw JSON. When stdout is not a terminal
//! (e.g. piped to a file), it prints a full non-interactive dump instead.

use anyhow::Result;
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Select};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::manifest::{
    Action, ContractTemplate, Manifest, InstanceCreate, Input, Output, ParamDef,
};

/// Entry point: explore the contract interactively, or dump it if non-interactive.
///
/// When `action` names a standalone action or a template action, its docs are printed
/// directly and no menu is shown.
pub fn describe(manifest: &Manifest, action: Option<&str>) -> Result<()> {
    if let Some(name) = action {
        return describe_action(manifest, name);
    }
    if !Term::stdout().is_term() {
        return dump_all(manifest);
    }
    main_menu(manifest)
}

/// Print one action's docs: a standalone action, or a `Template.action`.
fn describe_action(manifest: &Manifest, name: &str) -> Result<()> {
    if let Some(action) = manifest.actions.get(name) {
        print_action(name, action);
        return Ok(());
    }
    if let Some((template_id, _template_def, action)) = manifest.find_template_action(name) {
        print_action(&format!("{template_id}.{name}"), action);
        return Ok(());
    }

    let mut available: Vec<String> = manifest.actions.keys().cloned().collect();
    if let Some(contract_templates) = &manifest.contract_templates {
        for (template_id, cls) in contract_templates {
            available.extend(cls.actions.keys().map(|m| format!("{template_id}.{m}")));
        }
    }
    anyhow::bail!(
        "Action '{name}' not found in this manifest. Available: {}",
        available.join(", ")
    )
}

/// What a top-level menu entry maps to.
enum Target {
    Overview,
    Template(String),
    Action(String),
    Quit,
}

fn main_menu(manifest: &Manifest) -> Result<()> {
    loop {
        let mut labels: Vec<String> = Vec::new();
        let mut targets: Vec<Target> = Vec::new();

        labels.push("Overview".to_string());
        targets.push(Target::Overview);

        if let Some(contract_templates) = &manifest.contract_templates {
            for (cname, cdef) in contract_templates {
                labels.push(format!("template  {cname}  ({} actions)", cdef.actions.len()));
                targets.push(Target::Template(cname.clone()));
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
            Target::Template(name) => template_menu(manifest, name)?,
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

fn template_menu(manifest: &Manifest, template_name: &str) -> Result<()> {
    let template = match manifest.contract_templates.as_ref().and_then(|c| c.get(template_name)) {
        Some(c) => c,
        None => return Ok(()),
    };
    print_template_header(template_name, template);

    loop {
        let mut labels: Vec<String> = Vec::new();
        let action_names: Vec<&String> = template.actions.keys().collect();
        for aname in &action_names {
            labels.push(format!("action  {aname}"));
        }
        labels.push("← Back".to_string());

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("template {template_name}"))
            .items(&labels)
            .default(0)
            .interact_opt()?;

        let Some(idx) = selection else { break };
        if idx == action_names.len() {
            break; // "← Back"
        }
        let aname = action_names[idx];
        if let Some(action) = template.actions.get(aname) {
            print_action(&format!("{template_name}.{aname}"), action);
        }
    }
    Ok(())
}

/// Full non-interactive listing (used when stdout is not a TTY).
fn dump_all(manifest: &Manifest) -> Result<()> {
    print_overview(manifest);
    if let Some(contract_templates) = &manifest.contract_templates {
        for (cname, cdef) in contract_templates {
            print_template_header(cname, cdef);
            for (aname, action) in &cdef.actions {
                print_action(&format!("{cname}.{aname}"), action);
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

    if let Some(utxo_types) = &manifest.utxo_types {
        if !utxo_types.is_empty() {
            println!("  {}", style("UTXO types").bold());
            for (name, t) in utxo_types {
                println!("    {} — {}", style(name).green(), style(&t.description).dim());
            }
        }
    }

    if let Some(contract_templates) = &manifest.contract_templates {
        if !contract_templates.is_empty() {
            let names: Vec<&str> = contract_templates.keys().map(String::as_str).collect();
            println!("  {}: {}", style("Contract templates").bold(), names.join(", "));
        }
    }
    if !manifest.actions.is_empty() {
        let names: Vec<&str> = manifest.actions.keys().map(String::as_str).collect();
        println!("  {}: {}", style("Standalone actions").bold(), names.join(", "));
    }
}

fn print_template_header(name: &str, template: &ContractTemplate) {
    println!();
    println!("{}", style(format!("══ template {name}")).bold().magenta());
    if let Some(d) = &template.description {
        println!("  {}", style(d).italic());
    }
    if !template.fields.is_empty() {
        println!("  {}", style("Fields").bold());
        for (fname, def) in &template.fields {
            let desc = def.description.as_deref().map(|d| format!(" — {d}")).unwrap_or_default();
            let default = def.default.as_deref().map(|d| format!("  [default: {d}]")).unwrap_or_default();
            println!("    {} : {}{}{}", style(fname).green(), def.type_, style(desc).dim(), style(default).yellow());
        }
    }
    println!("  {}: {}", style("Actions").bold(), template.actions.keys().cloned().collect::<Vec<_>>().join(", "));
}

fn print_action(title: &str, action: &Action) {
    println!();
    println!("{}", style(format!("━━ {title}")).bold().cyan());
    if let Some(d) = &action.description {
        println!("  {}", style(d).italic());
    }

    let mut flags = Vec::new();
    if action.create_instance.is_some() {
        flags.push("constructor");
    }
    if !flags.is_empty() {
        println!("  {}", style(format!("[{}]", flags.join(", "))).yellow());
    }

    print_param_map("Params", &action.params);
    print_inputs(&action.inputs);
    print_outputs(&action.outputs);
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
        if def.compute.is_some() {
            extra.push_str(" (computed)");
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
        println!("    {}{} ← {}{}{}", style(&inp.id).green(), role_tag(inp.ui_role()), src, style(asset).dim(), style(amount).dim());
        if let Some(label) = inp.ui_label() {
            println!("        {}", style(label).dim());
        }
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
            "    {}{} → {}{}{}{}",
            style(&o.id).green(),
            role_tag(o.ui_role()),
            o.destination_summary(),
            style(amount).dim(),
            style(asset).dim(),
            style(opt).dim(),
        );
        if let Some(label) = o.ui_label() {
            println!("        {}", style(label).dim());
        }
    }
}

/// Render a `ui.role` as an inline `[tag]`, or nothing when the leg declares no role.
fn role_tag(role: Option<&str>) -> String {
    role.map(|r| format!(" {}", style(format!("[{r}]")).cyan()))
        .unwrap_or_default()
}

fn print_create_instance(create_instance: &Option<InstanceCreate>) {
    let Some(ci) = create_instance else { return };
    println!("  {}", style("Creates instance").bold());
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
