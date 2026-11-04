//! Human-side input: passphrases, field values and .env files. Values never go
//! through argv.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

use crate::schema::{EntryType, Fields};

pub const PASSPHRASE_FILE_ENV: &str = "JINNANG_PASSPHRASE_FILE";
const MIN_PASSPHRASE: usize = 12;

fn tty() -> Option<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
}

fn passphrase_from_file() -> Result<Option<SecretString>> {
    let Some(path) = std::env::var_os(PASSPHRASE_FILE_ENV) else {
        return Ok(None);
    };
    let mut raw = Zeroizing::new(
        fs::read_to_string(&path).with_context(|| format!("cannot read {PASSPHRASE_FILE_ENV}"))?,
    );
    while raw.ends_with('\n') || raw.ends_with('\r') {
        raw.pop();
    }
    ensure!(!raw.is_empty(), "{PASSPHRASE_FILE_ENV} is empty");
    Ok(Some(SecretString::from(raw.to_string())))
}

/// Passphrase for the vault at `dir`, from (in order) `JINNANG_PASSPHRASE_FILE`, the
/// passphrase sealed by `jinnang unlock enroll`, or the controlling terminal.
/// `None` when none is available. Callers never pass the passphrase themselves.
pub fn try_passphrase(dir: &Path, prompt: &str) -> Result<Option<SecretString>> {
    if let Some(p) = passphrase_from_file()? {
        return Ok(Some(p));
    }
    if let Some(p) = crate::seal::load(dir)? {
        return Ok(Some(p));
    }
    typed_passphrase(prompt)
}

/// Passphrase typed by a human (or `JINNANG_PASSPHRASE_FILE`), never the sealed one.
pub fn human_passphrase(prompt: &str) -> Result<SecretString> {
    if let Some(p) = passphrase_from_file()? {
        return Ok(p);
    }
    typed_passphrase(prompt)?.context("no terminal to read the passphrase")
}

fn typed_passphrase(prompt: &str) -> Result<Option<SecretString>> {
    if tty().is_none() {
        return Ok(None);
    }
    let p = Zeroizing::new(rpassword::prompt_password(prompt)?);
    ensure!(!p.is_empty(), "empty passphrase");
    Ok(Some(SecretString::from(p.to_string())))
}

pub fn passphrase(dir: &Path, prompt: &str) -> Result<SecretString> {
    try_passphrase(dir, prompt)?.context(
        "vault is locked: no sealed passphrase and no terminal. The user enables unattended \
         use once with `jinnang unlock enroll` in their own terminal",
    )
}

pub fn new_passphrase() -> Result<SecretString> {
    if let Some(p) = passphrase_from_file()? {
        check_strength(&p)?;
        return Ok(p);
    }
    ensure!(
        tty().is_some(),
        "no terminal to read a new passphrase (or set {PASSPHRASE_FILE_ENV})"
    );
    let a = Zeroizing::new(rpassword::prompt_password("New vault passphrase: ")?);
    let b = Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
    ensure!(a == b, "passphrases do not match");
    let p = SecretString::from(a.to_string());
    check_strength(&p)?;
    Ok(p)
}

fn check_strength(p: &SecretString) -> Result<()> {
    use age::secrecy::ExposeSecret;
    ensure!(
        p.expose_secret().chars().count() >= MIN_PASSPHRASE,
        "passphrase must be at least {MIN_PASSPHRASE} characters"
    );
    Ok(())
}

fn prompt_line(tty: &mut File, prompt: &str) -> Result<String> {
    write!(tty, "{prompt}")?;
    tty.flush()?;
    let mut line = String::new();
    BufReader::new(tty.try_clone()?).read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Prompts on the terminal for every field of `ty`, then for each custom field in
/// `extra`. Secret values are read without echo; multi-line values from a file path.
/// Fields already given another way (`--from-file`) are in `skip` and not prompted.
pub fn prompt_fields(
    ty: EntryType,
    extra: &[String],
    public: &std::collections::BTreeSet<String>,
    skip: &std::collections::BTreeSet<String>,
) -> Result<Fields> {
    ensure!(
        ty != EntryType::EnvBundle,
        "env_bundle entries come from `jinnang import-env` or --stdin-json"
    );
    ensure!(
        ty != EntryType::Generic || !extra.is_empty(),
        "generic entries need --field NAME for each field to prompt (or --stdin-json)"
    );
    let mut tty = tty().context("no terminal for prompts; use --stdin-json")?;
    let mut fields = Fields::new();
    for spec in ty.fields().iter().filter(|s| !skip.contains(s.name)) {
        let label = format!(
            "{}{}",
            spec.name,
            if spec.required { "" } else { " (optional)" }
        );
        let value = if spec.multiline {
            let path = prompt_line(&mut tty, &format!("{label}, path to file: "))?;
            if path.is_empty() {
                continue;
            }
            Zeroizing::new(
                fs::read_to_string(&path)
                    .with_context(|| format!("cannot read file for {}", spec.name))?,
            )
        } else if spec.secret {
            let hint = if ty == EntryType::Totp && spec.name == "seed" {
                " (base32 or otpauth:// URI)"
            } else {
                ""
            };
            Zeroizing::new(rpassword::prompt_password(format!("{label}{hint}: "))?)
        } else {
            Zeroizing::new(prompt_line(&mut tty, &format!("{label}: "))?)
        };
        if !value.is_empty() {
            fields.insert(spec.name.to_string(), value);
        }
    }
    for name in extra {
        ensure!(
            crate::refs::valid_field_name(name),
            "invalid field name {name:?}"
        );
        let value = if public.contains(name) {
            Zeroizing::new(prompt_line(&mut tty, &format!("{name}: "))?)
        } else {
            Zeroizing::new(rpassword::prompt_password(format!("{name}: "))?)
        };
        fields.insert(name.clone(), value);
    }
    Ok(fields)
}

/// Reads a whole file as one field value. UTF-8 text without NUL bytes is kept as
/// is; anything else is stored as base64 and the field is marked binary (`true`).
pub fn read_file_field(path: &Path) -> Result<(Zeroizing<String>, bool)> {
    let bytes =
        Zeroizing::new(fs::read(path).with_context(|| format!("cannot read {}", path.display()))?);
    match std::str::from_utf8(&bytes) {
        Ok(text) if !text.contains('\0') => Ok((Zeroizing::new(text.to_string()), false)),
        _ => Ok((crate::schema::encode_binary(&bytes), true)),
    }
}

/// Reads `{"field": "value", ...}` from stdin.
pub fn stdin_fields() -> Result<Fields> {
    let mut raw = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut raw)?;
    let map: BTreeMap<String, Zeroizing<String>> = serde_json::from_str(&raw)
        .map_err(|_| anyhow::anyhow!("stdin must be a JSON object of string values"))?;
    Ok(map)
}

/// Minimal .env parser: `KEY=VALUE`, optional `export`, `#` comments, single or
/// double quotes around the whole value.
pub fn read_env_file(path: &Path) -> Result<Fields> {
    let raw = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?,
    );
    let mut fields = Fields::new();
    for (n, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            bail!("{}:{}: expected KEY=VALUE", path.display(), n + 1);
        };
        let value = value.trim();
        let value = match value.as_bytes().first() {
            Some(q @ (b'"' | b'\'')) => {
                let q = *q as char;
                value
                    .strip_prefix(q)
                    .and_then(|v| v.strip_suffix(q))
                    .with_context(|| format!("{}:{}: unterminated quote", path.display(), n + 1))?
            }
            _ => value,
        };
        fields.insert(key.trim().to_string(), Zeroizing::new(value.to_string()));
    }
    Ok(fields)
}
