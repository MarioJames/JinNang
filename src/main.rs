use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use clap::{CommandFactory, Parser, Subcommand};
use serde_json::json;

use jinnang::crypto::{self, KeyMaterial};
use jinnang::input;
use jinnang::refs::{EntryRef, Reference};
use jinnang::run;
use jinnang::schema::{EntryType, Fields};
use jinnang::selector::{self, Labels, Selector};
use jinnang::store::{EntryRecord, PendingMeta, Vault};

/// Local credential vault for AI agents. Agents hold `jn://` references; secrets stay sealed.
///
/// References are free-form names (`jn://<path>[#field][@vN]`); classify entries with
/// labels (`-l key=value`) and select them with label selectors (`-l 'k=v,k2 in (a,b)'`).
#[derive(Parser)]
#[command(
    name = "jinnang",
    version,
    after_help = "Agents: SKIP if the Jinnang skill is already in your context. Otherwise run: jinnang --skill\nFind an account: jinnang find <keywords>   (no passphrase needed; never prints secret values)"
)]
struct Cli {
    /// Vault directory [env: JINNANG_VAULT] [default: $XDG_DATA_HOME/jinnang/vault]
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Print the agent skill file and exit
    #[arg(long)]
    skill: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

const SKILL: &str = include_str!("../skills/jinnang/SKILL.md");

/// An entry given by name, or by a selector that must match exactly one entry.
#[derive(clap::Args)]
struct Target {
    /// Entry reference (jn://<path>)
    reference: Option<String>,
    /// Label selector instead of a reference; must match exactly one entry
    #[arg(short = 'l', long = "selector", conflicts_with = "reference")]
    selector: Option<String>,
}

impl Target {
    fn parse(&self) -> Result<(Option<EntryRef>, Option<Selector>)> {
        let r = self
            .reference
            .as_deref()
            .map(Reference::parse_entry)
            .transpose()?;
        let s = self.selector.as_deref().map(Selector::parse).transpose()?;
        ensure!(
            r.is_some() || s.is_some(),
            "give a jn:// reference or -l <selector>"
        );
        Ok((r, s))
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create a vault and write its offline recovery kit
    Init {
        /// Where to write the recovery kit (must not exist). Keep it offline.
        #[arg(long)]
        recovery_kit: PathBuf,
        /// Let jinnang generate and hold a random passphrase (sealed with systemd-creds);
        /// nobody knows it, the recovery kit is the only way back
        #[arg(long)]
        self_held: bool,
    },
    /// Store a new entry (values are prompted on the terminal or read from --stdin-json)
    Set {
        reference: String,
        #[arg(long = "type", value_enum, default_value = "generic")]
        ty: EntryType,
        #[command(flatten)]
        write: WriteOpts,
    },
    /// Store a new version of an existing entry (labels are kept unless overridden)
    Rotate {
        reference: String,
        #[command(flatten)]
        write: WriteOpts,
    },
    /// Store a .env file as an env_bundle entry (new entry or new version)
    ImportEnv {
        file: PathBuf,
        reference: String,
        /// Keys whose values are not secret (comma separated)
        #[arg(long, value_delimiter = ',')]
        public: Vec<String>,
        /// key=value label (repeatable)
        #[arg(short = 'l', long = "label", value_name = "KEY=VALUE")]
        labels: Vec<String>,
        /// One line saying what the entry is for (shown to agents choosing an entry)
        #[arg(long)]
        desc: Option<String>,
        /// Only write a pending candidate; do not ask for the passphrase
        #[arg(long)]
        pending: bool,
    },
    /// Print instructions for a human to add a missing entry (agents use this instead of asking for values)
    Need {
        reference: String,
        #[arg(long = "type", value_enum, default_value = "generic")]
        ty: EntryType,
        /// key=value label the new entry should carry (repeatable)
        #[arg(short = 'l', long = "label", value_name = "KEY=VALUE")]
        labels: Vec<String>,
        /// What the entry is for; becomes its --desc
        #[arg(long)]
        desc: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Let jinnang unlock the vault by itself (passphrase sealed with systemd-creds)
    Unlock {
        #[command(subcommand)]
        action: UnlockAction,
    },
    /// Manage candidates written without the passphrase
    Pending {
        #[command(subcommand)]
        action: PendingAction,
    },
    /// Find entries whose name, labels, description or field names contain every keyword
    ///
    /// Example: jinnang find poc sales
    Find {
        #[arg(required = true)]
        terms: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List entries, optionally filtered by a label selector (no secret values)
    Ls {
        #[arg(short = 'l', long = "selector")]
        selector: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show an entry's labels, fields and versions (no secret values)
    Inspect {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        json: bool,
    },
    /// Set (key=value) or remove (key-) labels
    Label {
        reference: String,
        #[arg(required = true, value_name = "KEY=VALUE|KEY-")]
        changes: Vec<String>,
    },
    /// Set or clear an entry's description (what it is for)
    Describe {
        reference: String,
        #[arg(required_unless_present = "clear")]
        description: Option<String>,
        #[arg(long, conflicts_with = "description")]
        clear: bool,
    },
    /// Rename an entry
    Mv { from: String, to: String },
    /// Run a command with fields of one entry injected (L1: prevents accidental exposure)
    ///
    /// Example: jinnang run jn://acme/db --env PGPASSWORD=password -- psql -h db -U app
    Run {
        #[command(flatten)]
        target: Target,
        /// NAME=FIELD environment variable (repeatable)
        #[arg(long = "env", value_name = "NAME=FIELD")]
        env: Vec<String>,
        /// Export every field (env_bundle/generic keys as-is, others as JN_<FIELD>)
        #[arg(long)]
        all_env: bool,
        /// Write this field to the command's stdin
        #[arg(long, value_name = "FIELD")]
        stdin: Option<String>,
        /// NAME=FIELD: write the field to a private file; $NAME and the argument {NAME} become its path
        #[arg(long = "file", value_name = "NAME=FIELD")]
        files: Vec<String>,
        /// NAME: write all fields as a dotenv file; $NAME and the argument {NAME} become its path
        #[arg(long = "env-file", value_name = "NAME")]
        env_files: Vec<String>,
        /// Pass output through unchanged (needed for interactive programs)
        #[arg(long)]
        no_redact: bool,
        #[arg(required = true, allow_hyphen_values = true, last = true)]
        command: Vec<String>,
    },
    /// Delete an entry (tombstone; stored versions remain for recovery)
    Rm { reference: String },
    /// Verify signatures, digests and trust state; --deep also decrypts every version
    Verify {
        #[arg(long)]
        deep: bool,
    },
    /// Write an encrypted backup (decryptable with the device key or the recovery kit)
    Backup {
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore a backup into an empty --vault directory using the recovery kit
    Restore {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        recovery_kit: PathBuf,
        /// Replace the device key with a new one sealed by a new passphrase
        #[arg(long)]
        rekey: bool,
        /// Accept restoring an older manifest than this path last saw
        #[arg(long)]
        accept_rollback: bool,
    },
}

#[derive(clap::Args)]
struct WriteOpts {
    /// key=value label (repeatable)
    #[arg(short = 'l', long = "label", value_name = "KEY=VALUE")]
    labels: Vec<String>,
    /// Custom field to prompt for, in addition to the type's fields (repeatable)
    #[arg(long = "field", value_name = "NAME")]
    fields: Vec<String>,
    /// Custom fields whose values are not secret (comma separated)
    #[arg(long, value_delimiter = ',')]
    public: Vec<String>,
    /// One line saying what the entry is for (shown to agents choosing an entry)
    #[arg(long)]
    desc: Option<String>,
    /// Read field values as a JSON object from stdin
    #[arg(long)]
    stdin_json: bool,
    /// Only write a pending candidate; do not ask for the passphrase
    #[arg(long)]
    pending: bool,
}

#[derive(Subcommand)]
enum UnlockAction {
    /// Seal the passphrase for unattended use (typed once and verified)
    Enroll {
        /// Replace the passphrase with a random 256-bit one that only jinnang holds
        #[arg(long)]
        generate: bool,
    },
    /// Show whether a sealed passphrase exists and still unlocks the vault
    Status,
    /// Delete the sealed passphrase (commands prompt on a terminal again)
    Remove,
}

#[derive(Subcommand)]
enum PendingAction {
    /// List pending candidates
    Ls,
    /// Verify and publish candidates
    Activate {
        ids: Vec<String>,
        #[arg(long, conflicts_with = "ids")]
        all: bool,
    },
    /// Discard a candidate
    Reject { id: String },
}

fn vault_dir(cli: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(p.clone());
    }
    if let Some(p) = std::env::var_os("JINNANG_VAULT") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(p).join("jinnang/vault"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/jinnang/vault"))
}

fn main() -> ExitCode {
    jinnang::harden_process();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("jinnang: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn parse_labels(raw: &[String]) -> Result<Labels> {
    raw.iter().map(|l| selector::parse_label(l)).collect()
}

fn run(cli: Cli) -> Result<()> {
    if cli.skill {
        print!("{SKILL}");
        return Ok(());
    }
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        return Ok(());
    };
    let dir = vault_dir(&cli.vault)?;
    match command {
        Command::Init {
            recovery_kit,
            self_held,
        } => {
            let passphrase = if self_held {
                jinnang::seal::probe(&jinnang::store::state_base()?)
                    .context("--self-held needs user-scoped systemd credentials")?;
                jinnang::seal::generate()?
            } else {
                input::new_passphrase()?
            };
            let meta = Vault::init(&dir, &passphrase, &recovery_kit)?;
            if self_held {
                jinnang::seal::enroll(&dir, &passphrase)?;
                println!("passphrase generated and sealed; nobody knows it, keep the recovery kit");
            }
            println!("vault {} created at {}", meta.vault_id, dir.display());
            println!(
                "signing key fingerprint {}",
                crypto::fingerprint(&meta.signing_public_key)
            );
            println!(
                "recovery kit written to {} -- move it offline; it decrypts every entry",
                recovery_kit.display()
            );
        }
        Command::Set {
            reference,
            ty,
            write,
        } => {
            let entry = Reference::parse_entry(&reference)?;
            store(&dir, &entry, ty, write, false)?;
        }
        Command::Rotate { reference, write } => {
            let entry = Reference::parse_entry(&reference)?;
            let ty = Vault::open(&dir, false)?
                .find(&entry)
                .map(|e| e.ty)
                .with_context(|| format!("{entry} does not exist"))?;
            store(&dir, &entry, ty, write, true)?;
        }
        Command::ImportEnv {
            file,
            reference,
            public,
            labels,
            desc,
            pending,
        } => {
            let entry = Reference::parse_entry(&reference)?;
            let fields = input::read_env_file(&file)?;
            let exists = Vault::open(&dir, false)?.find(&entry).is_some();
            submit(
                &dir,
                &entry,
                EntryType::EnvBundle,
                fields,
                public,
                parse_labels(&labels)?,
                desc,
                pending,
                exists,
            )?;
        }
        Command::Need {
            reference,
            ty,
            labels,
            desc,
            reason,
        } => {
            let entry = Reference::parse_entry(&reference)?;
            let labels = parse_labels(&labels)?;
            let vault = Vault::open(&dir, false)?;
            if let Some(e) = vault.find(&entry) {
                println!(
                    "{entry} already exists ({}, v{}); use it by reference.",
                    e.ty.as_str(),
                    e.current
                );
                return Ok(());
            }
            println!("{entry} is not in the vault.");
            if let Some(reason) = reason {
                println!("Needed for: {reason}");
            }
            let mut label_args: String =
                labels.iter().map(|(k, v)| format!(" -l {k}={v}")).collect();
            if let Some(d) = desc {
                jinnang::store::check_description(&d)?;
                label_args.push_str(&format!(" --desc '{}'", d.replace('\'', "'\\''")));
            }
            let cmd = match ty {
                EntryType::EnvBundle => format!("jinnang import-env <file> {entry}{label_args}"),
                EntryType::Generic => format!("jinnang set {entry} --field <NAME>...{label_args}"),
                _ => format!("jinnang set {entry} --type {}{label_args}", ty.as_str()),
            };
            println!("Ask the user to run this in their own terminal:\n\n    {cmd}\n");
            println!("Do not ask the user to paste the value into the conversation.");
        }
        Command::Pending { action } => pending(&dir, action)?,
        Command::Unlock { action } => match action {
            UnlockAction::Enroll { generate: false } => {
                let vault = Vault::open(&dir, false)?;
                let passphrase = input::human_passphrase("Vault passphrase: ")?;
                vault.unlock(&passphrase)?;
                let file = jinnang::seal::enroll(&dir, &passphrase)?;
                println!(
                    "passphrase sealed to this machine and user at {}; jinnang now unlocks without prompting",
                    file.display()
                );
            }
            UnlockAction::Enroll { generate: true } => {
                let vault = Vault::open(&dir, true)?;
                let keys = vault.unlock(&input::passphrase(&dir, "Current vault passphrase: ")?)?;
                let new = jinnang::seal::generate()?;
                // Seal and verify the new passphrase before the device key changes.
                let staged = jinnang::seal::stage(&dir, &new)?;
                vault.change_passphrase(&keys, &new)?;
                jinnang::seal::commit_staged(&dir, &staged)?;
                let sealed = jinnang::seal::load(&dir)?.context("sealed passphrase missing")?;
                vault.unlock(&sealed).context(
                    "new sealed passphrase does not unlock; restore with the recovery kit",
                )?;
                println!(
                    "passphrase replaced with a random one held only by jinnang (sealed at {}); the old passphrase no longer works",
                    jinnang::seal::path(&dir)?.display()
                );
            }
            UnlockAction::Status => {
                let vault = Vault::open(&dir, false)?;
                let file = jinnang::seal::path(&dir)?;
                match jinnang::seal::load(&dir)? {
                    None => println!(
                        "not enrolled: commands that decrypt need a terminal (run `jinnang unlock enroll`)"
                    ),
                    Some(p) => {
                        vault.unlock(&p).context("sealed passphrase no longer unlocks this vault; run `jinnang unlock enroll`")?;
                        println!("enrolled: {} unseals and unlocks the vault", file.display());
                    }
                }
            }
            UnlockAction::Remove => {
                let removed = jinnang::seal::remove(&dir)?;
                println!(
                    "{}",
                    if removed {
                        "sealed passphrase removed"
                    } else {
                        "nothing to remove"
                    }
                );
            }
        },
        Command::Ls { selector, json } => {
            let selector = selector.as_deref().map(Selector::parse).transpose()?;
            let vault = Vault::open(&dir, false)?;
            let entries: Vec<&EntryRecord> = match &selector {
                Some(s) => vault.select(s),
                None => vault.entries().collect(),
            };
            print_entries(entries, json)?;
        }
        Command::Find { terms, json } => {
            let vault = Vault::open(&dir, false)?;
            let entries = vault.search(&terms);
            if entries.is_empty() && !json {
                eprintln!(
                    "no entry matches {terms:?}; try fewer keywords, `jinnang ls`, or ask the user (jinnang need)"
                );
            }
            print_entries(entries, json)?;
        }
        Command::Inspect { target, json } => {
            let (r, s) = target.parse()?;
            let vault = Vault::open(&dir, false)?;
            let e = vault.resolve(r.as_ref(), s.as_ref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entry_json(e))?);
            } else {
                println!("ref      {}", e.entry_ref);
                println!("id       {}", e.id);
                println!("type     {}", e.ty.as_str());
                println!("labels   {}", labels_str(&e.labels));
                if let Some(d) = &e.description {
                    println!("desc     {d}");
                }
                println!("version  v{} (updated {})", e.current, e.updated_at);
                println!("fields");
                for (k, v) in &e.public {
                    println!("  {k:<24} {v}");
                }
                for k in &e.secret_fields {
                    println!("  {k:<24} <secret>");
                }
                println!(
                    "versions {}",
                    e.versions
                        .iter()
                        .map(|v| format!("v{}", v.version))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
        Command::Label { reference, changes } => {
            let entry = Reference::parse_entry(&reference)?;
            let mut set = Labels::new();
            let mut remove = Vec::new();
            for c in &changes {
                match c.strip_suffix('-') {
                    Some(k) if !c.contains('=') => remove.push(k.to_string()),
                    _ => {
                        let (k, v) = selector::parse_label(c)?;
                        set.insert(k, v);
                    }
                }
            }
            let mut vault = Vault::open(&dir, true)?;
            ensure!(vault.find(&entry).is_some(), "{entry} does not exist");
            let keys = vault.unlock(&input::passphrase(&dir, "Vault passphrase: ")?)?;
            let labels = vault.relabel(&keys, &entry, set, &remove)?;
            println!("{entry} labels: {}", labels_str(&labels));
        }
        Command::Describe {
            reference,
            description,
            clear,
        } => {
            let entry = Reference::parse_entry(&reference)?;
            let mut vault = Vault::open(&dir, true)?;
            ensure!(vault.find(&entry).is_some(), "{entry} does not exist");
            let keys = vault.unlock(&input::passphrase(&dir, "Vault passphrase: ")?)?;
            vault.describe(&keys, &entry, if clear { None } else { description })?;
            println!(
                "{entry} description {}",
                if clear { "cleared" } else { "updated" }
            );
        }
        Command::Mv { from, to } => {
            let (from, to) = (Reference::parse_entry(&from)?, Reference::parse_entry(&to)?);
            let mut vault = Vault::open(&dir, true)?;
            ensure!(vault.find(&from).is_some(), "{from} does not exist");
            let keys = vault.unlock(&input::passphrase(&dir, "Vault passphrase: ")?)?;
            vault.rename(&keys, &from, &to)?;
            println!("renamed {from} -> {to}");
        }
        Command::Run {
            target,
            env,
            all_env,
            stdin,
            files,
            env_files,
            no_redact,
            command,
        } => {
            let (r, s) = target.parse()?;
            let spec = run::RunSpec {
                env: env
                    .iter()
                    .map(|m| run::parse_mapping(m))
                    .collect::<Result<_>>()?,
                all_env,
                stdin,
                files: files
                    .iter()
                    .map(|m| run::parse_mapping(m))
                    .collect::<Result<_>>()?,
                env_files,
                redact: !no_redact,
            };
            let passphrase = input::passphrase(&dir, "Vault passphrase: ")?;
            let code = run::run(&dir, r.as_ref(), s.as_ref(), &spec, &command, &passphrase)?;
            std::process::exit(code);
        }
        Command::Rm { reference } => {
            let entry = Reference::parse_entry(&reference)?;
            let mut vault = Vault::open(&dir, true)?;
            ensure!(vault.find(&entry).is_some(), "{entry} does not exist");
            let keys = vault.unlock(&input::passphrase(&dir, "Vault passphrase: ")?)?;
            vault.remove(&keys, &entry)?;
            println!("removed {entry}");
        }
        Command::Verify { deep } => {
            let vault = Vault::open(&dir, false)?;
            let keys = if deep {
                Some(vault.unlock(&input::passphrase(&dir, "Vault passphrase: ")?)?)
            } else {
                None
            };
            let report = vault.verify(keys.as_ref().map(|k| &k.age))?;
            println!(
                "vault {} seq {}: {} entries, {} versions{}",
                vault.meta.vault_id,
                vault.manifest.seq,
                report.entries,
                report.versions,
                if deep {
                    format!(", {} decrypted", report.decrypted)
                } else {
                    String::new()
                }
            );
            if !report.problems.is_empty() {
                for p in &report.problems {
                    eprintln!("problem: {p}");
                }
                bail!(
                    "verification failed with {} problem(s)",
                    report.problems.len()
                );
            }
            println!("ok");
        }
        Command::Backup { out } => {
            let vault = Vault::open(&dir, false)?;
            vault.backup(&out)?;
            println!(
                "backup of seq {} written to {}",
                vault.manifest.seq,
                out.display()
            );
        }
        Command::Restore {
            from,
            recovery_kit,
            rekey,
            accept_rollback,
        } => {
            let kit = KeyMaterial::from_recovery_kit(
                &fs::read(&recovery_kit).context("cannot read recovery kit")?,
            )?;
            let passphrase = if rekey {
                Some(input::new_passphrase()?)
            } else {
                None
            };
            let report = Vault::restore(&from, &dir, &kit, passphrase.as_ref(), accept_rollback)?;
            println!(
                "restored {} entries ({} versions, all decrypted with the recovery kit) to {}{}",
                report.entries,
                report.versions,
                dir.display(),
                if rekey { "; device key replaced" } else { "" }
            );
        }
    }
    Ok(())
}

fn store(
    dir: &Path,
    entry: &EntryRef,
    ty: EntryType,
    write: WriteOpts,
    rotate: bool,
) -> Result<()> {
    let public: BTreeSet<String> = write.public.iter().cloned().collect();
    let fields: Fields = if write.stdin_json {
        input::stdin_fields()?
    } else {
        input::prompt_fields(ty, &write.fields, &public)?
    };
    submit(
        dir,
        entry,
        ty,
        fields,
        write.public,
        parse_labels(&write.labels)?,
        write.desc,
        write.pending,
        rotate,
    )
}

#[allow(clippy::too_many_arguments)]
fn submit(
    dir: &Path,
    entry: &EntryRef,
    ty: EntryType,
    fields: Fields,
    public: Vec<String>,
    labels: Labels,
    description: Option<String>,
    pending_only: bool,
    rotate: bool,
) -> Result<()> {
    let mut vault = Vault::open(dir, true)?;
    let candidate = vault.submit(
        entry,
        ty,
        fields,
        public.into_iter().collect(),
        labels,
        description,
        rotate,
    )?;
    let passphrase = if pending_only {
        None
    } else {
        input::try_passphrase(dir, "Vault passphrase (to activate): ")?
    };
    let Some(passphrase) = passphrase else {
        println!(
            "{entry} v{} written as pending candidate {}; activate with `jinnang pending activate {}`",
            candidate.header.version, candidate.id, candidate.id
        );
        return Ok(());
    };
    let keys = vault
        .unlock(&passphrase)
        .with_context(|| format!("candidate {} left pending", candidate.id))?;
    let record = vault.activate(&keys, &candidate.id)?;
    println!("stored {} v{}", record.entry_ref, record.current);
    Ok(())
}

fn pending(dir: &Path, action: PendingAction) -> Result<()> {
    match action {
        PendingAction::Ls => {
            let vault = Vault::open(dir, false)?;
            for p in vault.pending()? {
                print_pending(&p);
            }
        }
        PendingAction::Activate { ids, all } => {
            let mut vault = Vault::open(dir, true)?;
            let ids: Vec<String> = if all {
                vault.pending()?.into_iter().map(|p| p.id).collect()
            } else {
                ids
            };
            ensure!(!ids.is_empty(), "nothing to activate");
            let keys = vault.unlock(&input::passphrase(dir, "Vault passphrase: ")?)?;
            let mut failed = 0;
            for id in ids {
                match vault.activate(&keys, &id) {
                    Ok(r) => println!("activated {id}: {} v{}", r.entry_ref, r.current),
                    Err(e) => {
                        failed += 1;
                        eprintln!("not activated {id}: {e:#}");
                    }
                }
            }
            ensure!(failed == 0, "{failed} candidate(s) not activated");
        }
        PendingAction::Reject { id } => {
            let vault = Vault::open(dir, true)?;
            let p = vault.reject(&id)?;
            println!("rejected {} ({} v{})", p.id, p.entry_ref, p.header.version);
        }
    }
    Ok(())
}

fn print_pending(p: &PendingMeta) {
    println!(
        "{}  {} v{} ({}) [{}]  submitted {} by uid {} via {}",
        p.id,
        p.entry_ref,
        p.header.version,
        p.header.ty.as_str(),
        labels_str(&p.labels),
        p.created_at,
        p.submitter.uid,
        p.submitter.parent_exe.as_deref().unwrap_or("?")
    );
}

fn labels_str(labels: &Labels) -> String {
    labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn print_entries(mut entries: Vec<&EntryRecord>, json: bool) -> Result<()> {
    entries.sort_by(|a, b| a.entry_ref.cmp(&b.entry_ref));
    if json {
        let list: Vec<_> = entries.iter().map(|e| entry_json(e)).collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }
    for e in entries {
        println!(
            "{:<40} {:<11} v{:<4} {}",
            e.entry_ref.to_string(),
            e.ty.as_str(),
            e.current,
            labels_str(&e.labels)
        );
        if let Some(d) = &e.description {
            println!("    {d}");
        }
    }
    Ok(())
}

fn entry_json(e: &EntryRecord) -> serde_json::Value {
    json!({
        "ref": e.entry_ref.to_string(),
        "id": e.id,
        "type": e.ty,
        "labels": e.labels,
        "description": e.description,
        "version": e.current,
        "updated_at": e.updated_at,
        "public": e.public,
        "secret_fields": e.secret_fields,
        "versions": e.versions.iter().map(|v| v.version).collect::<Vec<_>>(),
    })
}
