//! The Simplicity programs a manifest references: resolved once, checked against what pins
//! them, and read once.
//!
//! A manifest's id is derived from the manifest file alone, so the only way it can cover a
//! program is for the manifest to carry the program's hash. Every reference to a `.simf`
//! file may therefore carry a content hash and a compiler-version requirement, in either of
//! two forms that may be mixed:
//!
//! - **On the reference** — `source` / `source_hash` / `simplicity_hl_version` on a
//!   `utxo_type` script, `simf` / `simf_hash` / `simplicity_hl_version` on a `tapleaf` or
//!   `simf_fn` compute.
//! - **In the `programs` table** — `"program": "<name>"` on the reference, with the path,
//!   hash and version on the named entry.
//!
//! Every reference to one file must agree on its hash and version. A reference that states
//! neither inherits them from the others; one that states a different value is an error.
//!
//! # Pinned and unpinned
//!
//! A program is **pinned** when it has a hash and a compiler-version requirement — from the
//! manifest, or from the source's own `simc "<range>";` directive. A manifest with any
//! unpinned program is itself unpinned: fine while developing, refused by a wallet. Here
//! that choice is [`Unpinned`], and only this crate's own CLI ever passes
//! [`Unpinned::Allow`].
//!
//! # Single-file programs
//!
//! A program is compiled from the text of the one file it names; nothing here resolves
//! imports from other files. That is what makes one hash per file enough. If multi-file
//! programs are ever supported, the hash rule has to grow to cover their dependencies.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use lwk_wollet::elements::hashes::{sha256, Hash};
use simplicityhl::version::{SimcDirective, VersionRequirement};

use crate::manifest::{ComputeSpec, HookBlock, Manifest, ParamCompute, UtxoScript};

/// The file a `simplicity` script without a `source` or `program` falls back to, beside
/// the manifest. Kept for older manifests; such a reference can never be pinned, because
/// there is nowhere to put its hash.
pub const DEFAULT_SOURCE: &str = "covenant.simf";

/// A self-describing content hash: `"<algorithm>:<lowercase hex>"`.
///
/// `sha256` is the only algorithm defined. An unknown one is an error rather than
/// something to skip — a hash a wallet cannot check pins nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    pub fn of(bytes: &[u8]) -> Self {
        ContentHash(sha256::Hash::hash(bytes).to_byte_array())
    }

    pub fn parse(s: &str) -> Result<Self> {
        let (algorithm, hex) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("\"{s}\" is not a hash: expected \"sha256:<hex>\""))?;
        if algorithm != "sha256" {
            bail!("unknown hash algorithm \"{algorithm}\" in \"{s}\": only sha256 is defined");
        }
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("\"{s}\" is not a sha256 hash: expected 64 lowercase hex digits");
        }
        let mut digest = [0u8; 32];
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("checked hex");
        }
        Ok(ContentHash(digest))
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// A program's source text, as read by the checked loader (or, in tests and tooling,
/// deliberately unchecked). The covenant functions take this rather than a path, so no
/// code compiles a `.simf` it has not been handed through here.
#[derive(Clone, Debug)]
pub struct ProgramSource {
    path: PathBuf,
    text: Arc<str>,
}

impl ProgramSource {
    /// Read a `.simf` file with no pin check, for tests and tools that work on one file
    /// directly. Anything acting on a manifest goes through [`Programs::load`] instead.
    pub fn read_unpinned(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read simf file: {}", path.display()))?;
        Ok(ProgramSource {
            path: path.to_path_buf(),
            text: text.into(),
        })
    }

    pub(crate) fn new(path: PathBuf, text: String) -> Self {
        ProgramSource {
            path,
            text: text.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

/// One place a manifest names a program file, with whatever it states about it.
#[derive(Clone, Debug)]
pub struct ProgramRef {
    /// Where in the manifest, as a dot-path, for messages.
    pub location: String,
    /// The file, as written in the manifest (relative to it).
    pub source: String,
    pub hash: Option<String>,
    pub version: Option<String>,
}

/// A structural problem with a program reference, found without reading any file.
#[derive(Clone, Debug)]
pub struct RefIssue {
    pub location: String,
    pub message: String,
}

/// Every program reference in `manifest`, plus the reference problems found on the way.
///
/// `program` names are resolved through the `programs` table here, so each returned
/// reference carries a file path whichever form it was written in.
pub fn references(manifest: &Manifest) -> (Vec<ProgramRef>, Vec<RefIssue>) {
    let mut out = Refs {
        table: manifest.programs.as_ref(),
        refs: Vec::new(),
        issues: Vec::new(),
    };

    for (name, def) in manifest.programs.iter().flatten() {
        out.refs.push(ProgramRef {
            location: format!("programs.{name}"),
            source: def.source.clone(),
            hash: def.hash.clone(),
            version: def.simplicity_hl_version.clone(),
        });
    }

    for (name, ut) in manifest.utxo_types.iter().flatten() {
        let Some(script) = &ut.script else { continue };
        if script.type_ == "simplicity" {
            out.script(script, format!("utxo_types.{name}.script"));
        }
    }

    let mut actions: Vec<(String, &crate::manifest::Action)> = manifest
        .actions
        .iter()
        .map(|(n, a)| (format!("actions.{n}"), a))
        .collect();
    for (tname, t) in manifest.contract_templates.iter().flatten() {
        for (aname, a) in &t.actions {
            actions.push((format!("contract_templates.{tname}.actions.{aname}"), a));
        }
    }
    for (loc, action) in actions {
        for (pname, def) in action.params.iter().flatten() {
            if let Some(spec) = &def.compute {
                out.compute(spec, format!("{loc}.params.{pname}.compute"));
            }
        }
        out.hook(
            action.on_pre_broadcast.as_ref(),
            &format!("{loc}.on_pre_broadcast"),
        );
        out.hook(
            action.on_post_broadcast.as_ref(),
            &format!("{loc}.on_post_broadcast"),
        );
        for input in action.inputs.iter().flatten() {
            let hloc = format!("{loc}.inputs.{}.on_resolved", input.id);
            out.hook(input.on_resolved.as_ref(), &hloc);
        }
        if let Some(ci) = &action.create_instance {
            for (fname, spec) in &ci.fields {
                out.compute(spec, format!("{loc}.create_instance.fields.{fname}"));
            }
        }
    }

    (out.refs, out.issues)
}

/// Accumulator for [`references`].
struct Refs<'a> {
    table: Option<&'a BTreeMap<String, crate::manifest::ProgramDef>>,
    refs: Vec<ProgramRef>,
    issues: Vec<RefIssue>,
}

impl Refs<'_> {
    fn by_name(&mut self, location: String, name: &str) {
        match self.table.and_then(|t| t.get(name)) {
            Some(def) => self.refs.push(ProgramRef {
                location,
                source: def.source.clone(),
                hash: def.hash.clone(),
                version: def.simplicity_hl_version.clone(),
            }),
            None => self.issues.push(RefIssue {
                location,
                message: format!("names program \"{name}\", which is not in \"programs\""),
            }),
        }
    }

    fn script(&mut self, script: &UtxoScript, location: String) {
        match (&script.program, &script.source) {
            (Some(_), Some(_)) => self.issues.push(RefIssue {
                location,
                message: "gives both \"program\" and \"source\"; give one".into(),
            }),
            (Some(name), None) => {
                if script.source_hash.is_some() || script.simplicity_hl_version.is_some() {
                    self.issues.push(RefIssue {
                        location: location.clone(),
                        message: "\"source_hash\" and \"simplicity_hl_version\" belong on the \
                                  \"programs\" entry when the script names a \"program\""
                            .into(),
                    });
                }
                self.by_name(location, name);
            }
            (None, source) => self.refs.push(ProgramRef {
                location,
                source: source.clone().unwrap_or_else(|| DEFAULT_SOURCE.to_string()),
                hash: script.source_hash.clone(),
                version: script.simplicity_hl_version.clone(),
            }),
        }
    }

    fn compute(&mut self, spec: &ComputeSpec, location: String) {
        let (simf, simf_hash, version, program) = match spec.as_spec() {
            Some(ParamCompute::Tapleaf {
                simf,
                simf_hash,
                simplicity_hl_version,
                program,
                ..
            })
            | Some(ParamCompute::SimfFn {
                simf,
                simf_hash,
                simplicity_hl_version,
                program,
                ..
            }) => (simf, simf_hash, simplicity_hl_version, program),
            _ => return,
        };
        // Parsing guarantees exactly one of `simf` / `program`.
        match (simf, program) {
            (Some(simf), _) => self.refs.push(ProgramRef {
                location,
                source: simf.clone(),
                hash: simf_hash.clone(),
                version: version.clone(),
            }),
            (None, Some(name)) => self.by_name(location, name),
            (None, None) => {}
        }
    }

    fn hook(&mut self, hook: Option<&HookBlock>, location: &str) {
        for (target, spec) in hook.iter().flat_map(|h| &h.set) {
            self.compute(spec, format!("{location}.set.{target}"));
        }
    }
}

/// `./a/../b.simf` and `b.simf` name one file; references are grouped by this key.
/// Lexical only — nothing here touches the filesystem.
fn normalise(source: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in Path::new(source).components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            other => parts.push(other.as_os_str().to_str().unwrap_or_default()),
        }
    }
    parts.join("/")
}

/// What a manifest says about one program file, merged across every reference to it.
#[derive(Clone, Debug, Default)]
pub struct Pin {
    /// The file, relative to the manifest, as first written.
    pub source: String,
    pub hash: Option<ContentHash>,
    /// The manifest's requirement: per program, else the manifest-wide one.
    pub version: Option<VersionRequirement>,
    pub version_text: Option<String>,
    pub locations: Vec<String>,
}

/// Every program file a manifest references, keyed by normalised path, with the problems
/// found merging their references. Needs no filesystem.
pub fn resolve(manifest: &Manifest) -> (BTreeMap<String, Pin>, Vec<RefIssue>) {
    let (refs, mut issues) = references(manifest);
    let global = manifest
        .simplicity_hl
        .as_ref()
        .and_then(|s| s.version.clone());
    if let Some(v) = &global {
        if let Err(e) = VersionRequirement::parse(v) {
            issues.push(RefIssue {
                location: "simplicity_hl.version".into(),
                message: format!("\"{v}\" is not a semver requirement: {e}"),
            });
        }
    }

    let mut pins: BTreeMap<String, Pin> = BTreeMap::new();
    for r in refs {
        let pin = pins.entry(normalise(&r.source)).or_insert_with(|| Pin {
            source: r.source.clone(),
            ..Pin::default()
        });
        pin.locations.push(r.location.clone());

        if let Some(h) = &r.hash {
            match ContentHash::parse(h) {
                Ok(hash) => match pin.hash {
                    Some(existing) if existing != hash => issues.push(RefIssue {
                        location: r.location.clone(),
                        message: format!(
                            "gives {} the hash {hash}, but another reference gives {existing}",
                            r.source
                        ),
                    }),
                    _ => pin.hash = Some(hash),
                },
                Err(e) => issues.push(RefIssue {
                    location: r.location.clone(),
                    message: format!("{e:#}"),
                }),
            }
        }

        let Some(v) = r.version.clone().or_else(|| global.clone()) else {
            continue;
        };
        match VersionRequirement::parse(&v) {
            Ok(req) => match &pin.version_text {
                Some(existing) if *existing != v => issues.push(RefIssue {
                    location: r.location.clone(),
                    message: format!(
                        "gives {} the compiler requirement \"{v}\", but another reference \
                         gives \"{existing}\"",
                        r.source
                    ),
                }),
                _ => {
                    pin.version = Some(req);
                    pin.version_text = Some(v);
                }
            },
            // The manifest-wide value is reported once, above.
            Err(e) if r.version.is_some() => issues.push(RefIssue {
                location: r.location.clone(),
                message: format!("\"{v}\" is not a semver requirement: {e}"),
            }),
            Err(_) => {}
        }
    }
    (pins, issues)
}

/// What to do with a program that is not pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unpinned {
    /// Refuse to load. What a wallet does, and the default for a run.
    Refuse,
    /// Load anyway, recording why each program is unpinned — including a program whose
    /// file no longer matches its pinned hash, which is what a program looks like between
    /// editing it and re-pinning. For development only.
    Allow,
}

/// The running compiler's version, without any pre-release suffix — a requirement cannot
/// name a pre-release, so SimplicityHL compares against the base version too.
pub fn compiler_version() -> semver::Version {
    let base = SimcDirective::current_version()
        .split('-')
        .next()
        .unwrap_or_default();
    semver::Version::parse(base).expect("SimplicityHL's own version is valid semver")
}

/// One program file, checked against its pin by [`check`].
#[derive(Debug)]
pub struct Checked {
    pub text: String,
    /// Why the program is unpinned, if it is: no hash, or no compiler requirement.
    pub unpinned: Option<String>,
    /// Set when the file does not match its pinned hash. Whether that is fatal is the
    /// caller's choice: a wallet refuses, a developer who has edited the file and not yet
    /// re-pinned it may carry on (see [`Unpinned::Allow`]).
    pub mismatch: Option<String>,
}

/// Check one program file against its pin. Errors are problems no policy excuses: a file
/// that is not UTF-8 or has a malformed `simc` directive, a requirement this compiler does
/// not meet, or a manifest requirement the source's own directive rules out for this
/// compiler. A hash mismatch is reported in [`Checked::mismatch`] instead.
pub fn check(pin: &Pin, bytes: &[u8]) -> Result<Checked> {
    let actual = ContentHash::of(bytes);
    let mismatch = pin
        .hash
        .filter(|expected| *expected != actual)
        .map(|expected| {
            format!(
                "{} does not match its pinned hash: the manifest gives {expected}, the file is \
             {actual}",
                pin.source
            )
        });
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| anyhow!("{} is not valid UTF-8", pin.source))?;

    let directive = SimcDirective::requirement_of(&text)
        .map_err(|e| anyhow!("{}: malformed simc directive: {e}", pin.source))?;
    let current = compiler_version();
    if let Some(req) = &pin.version {
        if !req.matches(&current) {
            bail!(
                "{} requires SimplicityHL \"{}\", but this build has {current}",
                pin.source,
                pin.version_text.as_deref().unwrap_or_default()
            );
        }
        // Range containment is not decidable with the `semver` crate, so check the case
        // that matters: this compiler satisfies the manifest but not the source, which
        // would refuse to compile. A manifest requirement can narrow a directive, never
        // widen it.
        if let Some(d) = &directive {
            if !d.matches(&current) {
                bail!(
                    "{}: the manifest allows SimplicityHL {current}, but the file's own simc \
                     directive excludes it; the manifest can only narrow the directive",
                    pin.source
                );
            }
        }
    }

    let unpinned = match (pin.hash, pin.version.is_some() || directive.is_some()) {
        _ if mismatch.is_some() => Some(format!("{} has changed since it was pinned", pin.source)),
        (Some(_), true) => None,
        (None, true) => Some(format!("{} has no hash (it is {actual})", pin.source)),
        (Some(_), false) => Some(format!(
            "{} has no compiler-version requirement, in the manifest or the file",
            pin.source
        )),
        (None, false) => Some(format!(
            "{} has no hash (it is {actual}) and no compiler-version requirement",
            pin.source
        )),
    };
    Ok(Checked {
        text,
        unpinned,
        mismatch,
    })
}

/// A manifest's programs, each read once and checked against its pin. The default holds
/// none, for a manifest with no Simplicity programs.
#[derive(Debug, Default)]
pub struct Programs {
    by_path: BTreeMap<String, ProgramSource>,
    names: BTreeMap<String, String>,
    unpinned: Vec<String>,
}

impl Programs {
    /// Resolve, read and check every program `manifest` references, relative to
    /// `base_dir` (the manifest's directory).
    pub fn load(manifest: &Manifest, base_dir: &Path, policy: Unpinned) -> Result<Self> {
        let (pins, issues) = resolve(manifest);
        if !issues.is_empty() {
            let lines: Vec<String> = issues
                .iter()
                .map(|i| format!("  {}: {}", i.location, i.message))
                .collect();
            bail!("program references are inconsistent:\n{}", lines.join("\n"));
        }

        let mut by_path = BTreeMap::new();
        let mut unpinned = Vec::new();
        for (key, pin) in &pins {
            let path = base_dir.join(&pin.source);
            let bytes = std::fs::read(&path)
                .with_context(|| format!("Cannot read simf file: {}", path.display()))?;
            let checked = check(pin, &bytes)?;
            match (&checked.mismatch, policy) {
                (Some(mismatch), Unpinned::Refuse) => bail!("{mismatch}"),
                (Some(mismatch), Unpinned::Allow) => unpinned.push(mismatch.clone()),
                (None, _) => unpinned.extend(checked.unpinned),
            }
            let text = checked.text;
            by_path.insert(
                key.clone(),
                ProgramSource {
                    path,
                    text: text.into(),
                },
            );
        }

        if policy == Unpinned::Refuse && !unpinned.is_empty() {
            bail!(
                "this manifest is unpinned, and only pinned manifests can be run:\n  {}\n\
                 Add the hashes with `tx-manifest-wallet pin`, or pass --allow-unpinned \
                 (or --debug) while developing.",
                unpinned.join("\n  ")
            );
        }

        let names = manifest
            .programs
            .iter()
            .flatten()
            .map(|(name, def)| (name.clone(), normalise(&def.source)))
            .collect();
        Ok(Programs {
            by_path,
            names,
            unpinned,
        })
    }

    /// Why each unpinned program is unpinned; empty for a pinned manifest.
    pub fn unpinned(&self) -> &[String] {
        &self.unpinned
    }

    /// The program a `utxo_type` script runs.
    pub fn for_script(&self, script: Option<&UtxoScript>) -> Result<&ProgramSource> {
        match script {
            Some(s) => self.lookup(s.source.as_deref(), s.program.as_deref()),
            None => self.lookup(None, None),
        }
    }

    /// The program a `tapleaf` / `simf_fn` compute names.
    pub fn for_compute(&self, simf: Option<&str>, program: Option<&str>) -> Result<&ProgramSource> {
        self.lookup(simf, program)
    }

    fn lookup(&self, source: Option<&str>, program: Option<&str>) -> Result<&ProgramSource> {
        let key = match program {
            Some(name) => self
                .names
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("no program named \"{name}\" in \"programs\""))?,
            None => normalise(source.unwrap_or(DEFAULT_SOURCE)),
        };
        self.by_path
            .get(&key)
            .ok_or_else(|| anyhow!("{key} was not loaded with this manifest's programs"))
    }
}

/// What [`pin_text`] did: the new manifest text, and one line per hash written.
#[derive(Debug)]
pub struct PinOutcome {
    pub text: String,
    pub changes: Vec<String>,
}

/// Write the current hash of every referenced program into a manifest's text, leaving the
/// rest of the text exactly as it was — key order, layout and all. A reference that already
/// carries a hash has it replaced; one without gets the field inserted after its path.
///
/// Compiler versions are left alone: choosing a requirement is the author's call.
pub fn pin_text(text: &str, base_dir: &Path) -> Result<PinOutcome> {
    let manifest = Manifest::from_json_str(text)?;
    let (pins, issues) = resolve(&manifest);
    // Conflicting hashes are about to be overwritten; anything else must be fixed first.
    if let Some(i) = issues
        .iter()
        .find(|i| !i.message.contains("another reference gives"))
    {
        bail!("cannot pin: {}: {}", i.location, i.message);
    }
    let mut hashes = BTreeMap::new();
    for (key, pin) in &pins {
        let path = base_dir.join(&pin.source);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("Cannot read simf file: {}", path.display()))?;
        hashes.insert(key.clone(), ContentHash::of(&bytes));
    }

    let objects = scan_objects(text)?;
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut changes = Vec::new();
    for obj in &objects {
        let in_table = obj.path.len() == 2 && obj.path[0] == "programs";
        for (key, _, end, value) in &obj.strings {
            let hash_key = match key.as_str() {
                "source" if in_table => "hash",
                "source" => "source_hash",
                "simf" => "simf_hash",
                _ => continue,
            };
            // A `source` that is not a program path (a witness's, say) is not in `pins`.
            let Some(hash) = hashes.get(&normalise(value)) else {
                continue;
            };
            let location = obj.path.join(".");
            let quoted = format!("\"{hash}\"");
            match obj.strings.iter().find(|(k, ..)| k == hash_key) {
                Some((_, s, e, current)) if *current != hash.to_string() => {
                    edits.push((*s, *e, quoted));
                    changes.push(format!("{location}.{hash_key}: {current} -> {hash}"));
                }
                Some(_) => {}
                None => {
                    let field = format!("\"{hash_key}\": {quoted}");
                    edits.push((*end, *end, insertion(text, *end, &field)));
                    changes.push(format!("{location}.{hash_key}: {hash}"));
                }
            }
        }
    }

    edits.sort_by_key(|(s, ..)| std::cmp::Reverse(*s));
    let mut out = text.to_string();
    for (s, e, with) in edits {
        out.replace_range(s..e, &with);
    }
    // The edit must leave a manifest whose every program is hashed, and hashed right.
    let pinned = Manifest::from_json_str(&out).context("pinning produced an invalid manifest")?;
    let (after, issues) = resolve(&pinned);
    if let Some(i) = issues.first() {
        bail!(
            "pinning left an inconsistent manifest: {}: {}",
            i.location,
            i.message
        );
    }
    for (key, pin) in &after {
        if pin.hash != hashes.get(key).copied() {
            bail!("pinning missed {}", pin.source);
        }
    }
    Ok(PinOutcome { text: out, changes })
}

/// The text that puts `field` after the value ending at `end`: on a line of its own, at the
/// same indentation, when the value's member sits alone on its line; inline otherwise.
fn insertion(text: &str, end: usize, field: &str) -> String {
    let line_start = text[..end].rfind('\n').map_or(0, |i| i + 1);
    let line = &text[line_start..end];
    let indent: &str = &line[..line.len() - line.trim_start().len()];
    let rest = text[end..].trim_start_matches([' ', '\t']);
    let alone = line.trim_start().starts_with('"')
        && line.matches("\":").count() == 1
        && (rest.starts_with('\n') || rest.starts_with("\r\n") || rest.starts_with(','));
    let ends_line = rest.starts_with('\n') || rest.starts_with("\r\n");
    let next_line_after_comma = rest.strip_prefix(',').is_some_and(|r| {
        let r = r.trim_start_matches([' ', '\t']);
        r.starts_with('\n') || r.starts_with("\r\n")
    });
    if alone && (ends_line || next_line_after_comma) {
        let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
        format!(",{newline}{indent}{field}")
    } else {
        format!(", {field}")
    }
}

/// One JSON object in a document: where it sits, and its string-valued members with the
/// byte span of each value (quotes included) and the decoded value.
struct ScannedObject {
    path: Vec<String>,
    strings: Vec<(String, usize, usize, String)>,
}

/// Every object in `text`, for editing values in place. A minimal JSON reader: it tracks
/// positions, which `serde_json` does not expose, and leaves validation to `serde_json`,
/// which has already parsed the same text by the time this runs.
fn scan_objects(text: &str) -> Result<Vec<ScannedObject>> {
    struct Scanner<'a> {
        text: &'a str,
        i: usize,
        objects: Vec<ScannedObject>,
    }
    impl Scanner<'_> {
        fn peek(&self) -> Option<u8> {
            self.text.as_bytes().get(self.i).copied()
        }
        fn ws(&mut self) {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.i += 1;
            }
        }
        fn expect(&mut self, c: u8) -> Result<()> {
            self.ws();
            if self.peek() != Some(c) {
                bail!("expected '{}' at byte {}", c as char, self.i);
            }
            self.i += 1;
            Ok(())
        }
        /// A string token; returns its span and decoded value.
        fn string(&mut self) -> Result<(usize, usize, String)> {
            self.ws();
            let start = self.i;
            self.expect(b'"')?;
            loop {
                match self.peek() {
                    Some(b'\\') => self.i += 2,
                    Some(b'"') => {
                        self.i += 1;
                        break;
                    }
                    Some(_) => self.i += 1,
                    None => bail!("unterminated string at byte {start}"),
                }
            }
            let value = serde_json::from_str(&self.text[start..self.i])?;
            Ok((start, self.i, value))
        }
        fn value(&mut self, path: &mut Vec<String>) -> Result<()> {
            self.ws();
            match self.peek() {
                Some(b'{') => self.object(path),
                Some(b'[') => {
                    self.i += 1;
                    let mut n = 0;
                    loop {
                        self.ws();
                        if self.peek() == Some(b']') {
                            self.i += 1;
                            return Ok(());
                        }
                        path.push(n.to_string());
                        self.value(path)?;
                        path.pop();
                        n += 1;
                        self.ws();
                        if self.peek() == Some(b',') {
                            self.i += 1;
                        }
                    }
                }
                Some(b'"') => self.string().map(|_| ()),
                Some(_) => {
                    while !matches!(self.peek(), None | Some(b',' | b'}' | b']')) {
                        self.i += 1;
                    }
                    Ok(())
                }
                None => bail!("unexpected end of input"),
            }
        }
        fn object(&mut self, path: &mut Vec<String>) -> Result<()> {
            self.expect(b'{')?;
            let mut obj = ScannedObject {
                path: path.clone(),
                strings: Vec::new(),
            };
            loop {
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    break;
                }
                let (_, _, key) = self.string()?;
                self.expect(b':')?;
                self.ws();
                if self.peek() == Some(b'"') {
                    let (s, e, v) = self.string()?;
                    obj.strings.push((key, s, e, v));
                } else {
                    path.push(key);
                    self.value(path)?;
                    path.pop();
                }
                self.ws();
                if self.peek() == Some(b',') {
                    self.i += 1;
                }
            }
            self.objects.push(obj);
            Ok(())
        }
    }
    let mut scanner = Scanner {
        text,
        i: 0,
        objects: Vec::new(),
    };
    scanner.value(&mut Vec::new())?;
    Ok(scanner.objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "fn main() {}\n";

    fn manifest(json: &str) -> Manifest {
        Manifest::from_json_str(json).expect("manifest parses")
    }

    fn with_script(script: &str, extra: &str) -> Manifest {
        manifest(&format!(
            r#"{{ "manifest_version": "0.3.0", "protocol": "t", "requires": ["simplicity"],
                 {extra}
                 "utxo_types": {{ "c": {{ "description": "c", "script": {script} }} }} }}"#
        ))
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("txm-programs-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.simf"), SRC).unwrap();
        dir
    }

    fn src_hash() -> String {
        ContentHash::of(SRC.as_bytes()).to_string()
    }

    #[test]
    fn hashes_are_self_describing_and_round_trip() {
        let h = ContentHash::of(b"abc");
        assert_eq!(
            h.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(ContentHash::parse(&h.to_string()).unwrap(), h);
        for bad in [
            "ba7816bf",
            "md5:abcd",
            "sha256:XYZ",
            "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        ] {
            assert!(ContentHash::parse(bad).is_err(), "{bad} must not parse");
        }
    }

    #[test]
    fn a_pinned_program_loads_and_a_tampered_one_does_not() {
        let dir = scratch("tamper");
        let m = with_script(
            &format!(
                r#"{{ "type": "simplicity", "source": "./a.simf", "source_hash": "{}",
                      "simplicity_hl_version": ">= 0.0.0" }}"#,
                src_hash()
            ),
            "",
        );
        let programs = Programs::load(&m, &dir, Unpinned::Refuse).expect("pinned loads");
        assert!(programs.unpinned().is_empty());
        assert_eq!(
            programs
                .for_script(m.utxo_type("c").unwrap().script.as_ref())
                .unwrap()
                .text(),
            SRC
        );

        std::fs::write(dir.join("a.simf"), "fn main() { }\n").unwrap();
        let err = Programs::load(&m, &dir, Unpinned::Refuse)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match its pinned hash"), "{err}");

        // While developing, an edited-but-not-re-pinned file loads, with the mismatch as a
        // warning and the file's current text.
        let programs = Programs::load(&m, &dir, Unpinned::Allow).expect("allowed");
        assert_eq!(programs.unpinned().len(), 1);
        assert!(programs.unpinned()[0].contains("does not match its pinned hash"));
        let script = m.utxo_type("c").unwrap().script.as_ref();
        assert_eq!(
            programs.for_script(script).unwrap().text(),
            "fn main() { }\n"
        );
    }

    #[test]
    fn unpinned_is_refused_unless_allowed() {
        let dir = scratch("unpinned");
        let m = with_script(r#"{ "type": "simplicity", "source": "./a.simf" }"#, "");
        let err = Programs::load(&m, &dir, Unpinned::Refuse)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unpinned"), "{err}");
        let programs = Programs::load(&m, &dir, Unpinned::Allow).expect("allowed");
        assert_eq!(programs.unpinned().len(), 1);
    }

    #[test]
    fn the_programs_table_and_inline_fields_are_equivalent() {
        let dir = scratch("forms");
        let table = with_script(
            r#"{ "type": "simplicity", "program": "a" }"#,
            &format!(
                r#""programs": {{ "a": {{ "source": "a.simf", "hash": "{}" }} }},
                   "simplicity_hl": {{ "version": ">= 0.0.0" }},"#,
                src_hash()
            ),
        );
        let p = Programs::load(&table, &dir, Unpinned::Refuse).expect("table form loads");
        assert_eq!(
            p.for_script(table.utxo_type("c").unwrap().script.as_ref())
                .unwrap()
                .text(),
            SRC
        );
    }

    #[test]
    fn references_to_one_file_must_agree() {
        let other = ContentHash::of(b"other").to_string();
        let m = manifest(&format!(
            r#"{{ "manifest_version": "0.3.0", "protocol": "t", "requires": ["simplicity"],
                 "utxo_types": {{
                   "x": {{ "description": "x", "script": {{ "type": "simplicity", "source": "./a.simf", "source_hash": "{}" }} }},
                   "y": {{ "description": "y", "script": {{ "type": "simplicity", "source": "a.simf", "source_hash": "{other}" }} }},
                   "z": {{ "description": "z", "script": {{ "type": "simplicity", "source": "a.simf" }} }} }} }}"#,
            src_hash()
        ));
        let (pins, issues) = resolve(&m);
        assert_eq!(pins.len(), 1, "./a.simf and a.simf are one file");
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert!(issues[0].message.contains("another reference"));
    }

    #[test]
    fn version_precedence_is_reference_then_manifest() {
        let m = with_script(
            r#"{ "type": "simplicity", "source": "a.simf", "simplicity_hl_version": "0.7" }"#,
            r#""simplicity_hl": { "version": "0.6" },"#,
        );
        let (pins, issues) = resolve(&m);
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(pins["a.simf"].version_text.as_deref(), Some("0.7"));
    }

    #[test]
    fn the_source_directive_pins_the_version_and_cannot_be_widened() {
        let dir = scratch("directive");
        let current = compiler_version();
        let pin = Pin {
            source: "a.simf".into(),
            hash: None,
            ..Pin::default()
        };
        let src = format!("simc \">= {current}\";\nfn main() {{}}\n");
        let checked = check(&pin, src.as_bytes()).unwrap();
        assert!(
            checked.unpinned.unwrap().contains("no hash"),
            "the directive supplies the version"
        );

        let excluding = "simc \">= 99.0.0\";\nfn main() {}\n";
        let widened = Pin {
            source: "a.simf".into(),
            version: Some(VersionRequirement::parse(">= 0.0.0").unwrap()),
            version_text: Some(">= 0.0.0".into()),
            ..Pin::default()
        };
        let err = check(&widened, excluding.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(err.contains("can only narrow"), "{err}");
        let _ = dir;
    }

    #[test]
    fn a_requirement_this_compiler_does_not_meet_is_refused() {
        let pin = Pin {
            source: "a.simf".into(),
            version: Some(VersionRequirement::parse(">= 99.0.0").unwrap()),
            version_text: Some(">= 99.0.0".into()),
            ..Pin::default()
        };
        let err = check(&pin, SRC.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("requires SimplicityHL"), "{err}");
    }

    #[test]
    fn a_missing_program_name_is_reported() {
        let m = with_script(r#"{ "type": "simplicity", "program": "nope" }"#, "");
        let (_, issues) = resolve(&m);
        assert!(issues
            .iter()
            .any(|i| i.message.contains("not in \"programs\"")));
    }

    #[test]
    fn pin_text_adds_and_refreshes_hashes_without_reformatting() {
        let dir = scratch("pin");
        let text = r#"{
    "manifest_version": "0.3.0",
    "protocol": "t",
    "requires": ["simplicity"],
    "programs": { "p": { "source": "a.simf" } },
    "utxo_types": {
        "x": { "description": "x", "script": { "type": "simplicity", "source": "./a.simf", "source_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000" } },
        "y": { "description": "y", "script": { "type": "simplicity", "program": "p" } }
    }
}"#;
        let out = pin_text(text, &dir).expect("pins");
        let h = src_hash();
        assert_eq!(out.changes.len(), 2, "{:?}", out.changes);
        assert!(out
            .text
            .contains(&format!(r#""source": "a.simf", "hash": "{h}""#)));
        assert!(out.text.contains(&format!(r#""source_hash": "{h}""#)));
        // Everything else is byte-for-byte what it was.
        assert_eq!(
            out.text
                .replace(&format!(r#", "hash": "{h}""#), "")
                .replace(&h, &format!("sha256:{}", "0".repeat(64))),
            text
        );
        // Pinning a pinned manifest changes nothing.
        let again = pin_text(&out.text, &dir).unwrap();
        assert!(again.changes.is_empty());
        assert_eq!(again.text, out.text);
    }

    #[test]
    fn paths_normalise_lexically() {
        assert_eq!(normalise("./a.simf"), "a.simf");
        assert_eq!(normalise("x/../a.simf"), "a.simf");
        assert_eq!(normalise("../shared/a.simf"), "../shared/a.simf");
    }
}
