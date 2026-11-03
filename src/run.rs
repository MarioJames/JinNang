//! `jinnang run`: L1 exit. Injects fields of one entry into a child process via
//! environment variables, stdin or private temporary files, redacts the values from
//! the child's output and records the use in the audit log.
//!
//! L1 means: it prevents accidental exposure, not a determined agent that runs
//! `printenv` itself.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::refs::{EntryRef, valid_field_name};
use crate::schema::{self, EntryType};
use crate::selector::Selector;
use crate::store::{Payload, Vault};

pub const REDACTED: &[u8] = b"[jinnang:redacted]";
const MIN_REDACT_LEN: usize = 4;

#[derive(Debug, Default)]
pub struct RunSpec {
    /// `NAME=FIELD` environment variables.
    pub env: Vec<(String, String)>,
    /// Export every field (env_bundle/generic keys as-is, other types as `JN_<FIELD>`).
    pub all_env: bool,
    /// Field written to the child's stdin.
    pub stdin: Option<String>,
    /// `NAME=FIELD`: field written to a private file; `NAME` holds its path.
    pub files: Vec<(String, String)>,
    /// `NAME`: all fields written as a dotenv file; `NAME` holds its path.
    pub env_files: Vec<String>,
    pub redact: bool,
}

pub fn parse_mapping(s: &str) -> Result<(String, String)> {
    let (name, field) = s.split_once('=').unwrap_or((s, s));
    ensure!(
        valid_field_name(name) && valid_field_name(field),
        "invalid mapping {s:?}; expected NAME=FIELD"
    );
    Ok((name.to_string(), field.to_string()))
}

fn env_name(ty: EntryType, field: &str) -> String {
    match ty {
        EntryType::EnvBundle | EntryType::Generic => field.to_string(),
        _ => format!("JN_{}", field.to_ascii_uppercase()),
    }
}

fn field<'a>(payload: &'a Payload, name: &str) -> Result<&'a Zeroizing<String>> {
    payload
        .fields
        .get(name)
        .with_context(|| format!("entry has no field {name:?}"))
}

fn dotenv(payload: &Payload) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::new());
    for (k, v) in &payload.fields {
        ensure!(
            !v.contains('\n'),
            "field {k:?} is multi-line and cannot go into a dotenv file; use --file"
        );
        out.push_str(&format!(
            "{}={}\n",
            env_name(payload.header.ty, k),
            v.as_str()
        ));
    }
    Ok(out)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!("jinnang-run-{}", Uuid::new_v4().simple()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .context("cannot create private run directory")?;
        Ok(Self(dir))
    }

    fn write(&self, name: &str, data: &[u8]) -> Result<PathBuf> {
        let path = self.0.join(name);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(data)?;
        Ok(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Streams bytes through, replacing secret values. Holds back just enough bytes to
/// catch a value split across reads.
pub struct Redactor {
    secrets: Vec<Zeroizing<Vec<u8>>>,
    keep: usize,
    buf: Zeroizing<Vec<u8>>,
    pub hits: usize,
}

impl Redactor {
    pub fn new(values: impl IntoIterator<Item = Zeroizing<Vec<u8>>>) -> Self {
        let mut secrets: Vec<_> = values
            .into_iter()
            .filter(|v| v.len() >= MIN_REDACT_LEN)
            .collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        let keep = secrets.first().map_or(0, |s| s.len() - 1);
        Self {
            secrets,
            keep,
            buf: Zeroizing::new(Vec::new()),
            hits: 0,
        }
    }

    pub fn push(&mut self, data: &[u8], eof: bool) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        let limit = if eof {
            self.buf.len()
        } else {
            self.buf.len().saturating_sub(self.keep)
        };
        let mut out = Vec::with_capacity(limit);
        let mut i = 0;
        while i < limit {
            if let Some(s) = self.secrets.iter().find(|s| self.buf[i..].starts_with(s)) {
                out.extend_from_slice(REDACTED);
                i += s.len();
                self.hits += 1;
            } else {
                out.push(self.buf[i]);
                i += 1;
            }
        }
        let consumed = i.min(self.buf.len());
        self.buf.drain(..consumed);
        out
    }
}

fn pump(mut from: impl Read, mut to: impl Write, mut redactor: Redactor) -> usize {
    let mut chunk = [0u8; 8192];
    loop {
        let (n, eof) = match from.read(&mut chunk) {
            Ok(0) | Err(_) => (0, true),
            Ok(n) => (n, false),
        };
        let out = redactor.push(&chunk[..n], eof);
        if to.write_all(&out).and_then(|_| to.flush()).is_err() || eof {
            return redactor.hits;
        }
    }
}

fn secret_values(payload: &Payload) -> Vec<Zeroizing<Vec<u8>>> {
    payload
        .fields
        .iter()
        .filter(|(k, _)| schema::is_secret(payload.header.ty, k, &payload.public_fields))
        .map(|(_, v)| Zeroizing::new(v.as_bytes().to_vec()))
        .collect()
}

fn session_hints() -> serde_json::Value {
    let mut hints = BTreeMap::new();
    for key in [
        "CLAUDE_CODE_SESSION_ID",
        "CODEX_THREAD_ID",
        "HERDR_PANE_ID",
        "WEAVER_RUN_ID",
        "JINNANG_TASK",
    ] {
        if let Ok(v) = std::env::var(key) {
            hints.insert(key, v);
        }
    }
    json!(hints)
}

/// Runs `argv` with the requested fields injected. Returns the child's exit code.
pub fn run(
    vault_dir: &Path,
    entry_ref: Option<&EntryRef>,
    selector: Option<&Selector>,
    spec: &RunSpec,
    argv: &[String],
    passphrase: &age::secrecy::SecretString,
) -> Result<i32> {
    ensure!(!argv.is_empty(), "missing command after --");
    let vault = Vault::open(vault_dir, false)?;
    let target = vault.resolve(entry_ref, selector)?.entry_ref.clone();
    let keys = vault.unlock(passphrase)?;
    let (record, payload) = vault.read_current(&keys.age, &target)?;
    drop(keys);
    let ty = payload.header.ty;

    let mut env: Vec<(String, Zeroizing<String>)> = Vec::new();
    if spec.all_env {
        for (k, v) in &payload.fields {
            env.push((env_name(ty, k), v.clone()));
        }
    }
    for (name, f) in &spec.env {
        env.push((name.clone(), field(&payload, f)?.clone()));
    }
    let stdin_value = spec
        .stdin
        .as_deref()
        .map(|f| field(&payload, f).cloned())
        .transpose()?;

    let tmp = if spec.files.is_empty() && spec.env_files.is_empty() {
        None
    } else {
        Some(TempDir::new()?)
    };
    let mut paths: BTreeMap<String, PathBuf> = BTreeMap::new();
    for (name, f) in &spec.files {
        let path = tmp
            .as_ref()
            .unwrap()
            .write(name, field(&payload, f)?.as_bytes())?;
        paths.insert(name.clone(), path);
    }
    for name in &spec.env_files {
        ensure!(valid_field_name(name), "invalid name {name:?}");
        let path = tmp
            .as_ref()
            .unwrap()
            .write(name, dotenv(&payload)?.as_bytes())?;
        paths.insert(name.clone(), path);
    }
    let argv: Vec<String> = argv
        .iter()
        .map(|a| {
            a.strip_prefix('{')
                .and_then(|a| a.strip_suffix('}'))
                .and_then(|n| paths.get(n))
                .map_or_else(|| a.clone(), |p| p.display().to_string())
        })
        .collect();

    let used: Vec<String> = {
        let mut u: Vec<String> = spec.env.iter().map(|(_, f)| f.clone()).collect();
        u.extend(spec.files.iter().map(|(_, f)| f.clone()));
        u.extend(spec.stdin.iter().cloned());
        if spec.all_env || !spec.env_files.is_empty() {
            u.extend(payload.fields.keys().cloned());
        }
        u.sort();
        u.dedup();
        u
    };
    // argv is recorded, but never with a secret value in it.
    let logged_argv: Vec<String> = argv
        .iter()
        .map(|a| {
            String::from_utf8_lossy(
                &Redactor::new(secret_values(&payload)).push(a.as_bytes(), true),
            )
            .into_owned()
        })
        .collect();
    let op = Uuid::new_v4();
    let caller = crate::store::submitter();
    vault.audit(json!({
        "event": "run.start", "operation_id": op, "ref": record.entry_ref.to_string(), "entry_id": record.id,
        "version": record.current, "fields": used, "argv": logged_argv,
        "cwd": std::env::current_dir().ok().map(|p| p.display().to_string()),
        "caller": caller, "session": session_hints(), "redact": spec.redact,
    }))
    .context("audit log unavailable; refusing to run")?;

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (k, v) in &env {
        cmd.env(k, v.as_str());
    }
    for (k, p) in &paths {
        cmd.env(k, p);
    }
    cmd.stdin(if stdin_value.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    if spec.redact {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = vault
                .audit(json!({"event": "run.end", "operation_id": op, "error": "spawn failed"}));
            bail!("cannot start {}: {e}", argv[0]);
        }
    };
    drop(env);

    let writer = stdin_value.map(|v| {
        let mut stdin = child.stdin.take().unwrap();
        thread::spawn(move || {
            let _ = stdin.write_all(v.as_bytes());
        })
    });
    let pumps: Vec<_> = if spec.redact {
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let (a, b) = (secret_values(&payload), secret_values(&payload));
        vec![
            thread::spawn(move || pump(out, std::io::stdout(), Redactor::new(a))),
            thread::spawn(move || pump(err, std::io::stderr(), Redactor::new(b))),
        ]
    } else {
        Vec::new()
    };
    drop(payload);
    let status = child.wait()?;
    if let Some(w) = writer {
        let _ = w.join();
    }
    let redactions: usize = pumps.into_iter().map(|p| p.join().unwrap_or(0)).sum();
    drop(tmp);

    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    vault.audit(json!({"event": "run.end", "operation_id": op, "exit_code": code, "redactions": redactions}))?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact_all(secret: &str, chunks: &[&str]) -> String {
        let mut r = Redactor::new([Zeroizing::new(secret.as_bytes().to_vec())]);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(r.push(c.as_bytes(), false));
        }
        out.extend(r.push(b"", true));
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn redacts_values_split_across_reads() {
        assert_eq!(
            redact_all("hunter22", &["user=x pass=hun", "ter22 ok"]),
            "user=x pass=[jinnang:redacted] ok"
        );
        assert_eq!(
            redact_all("hunter22", &["hunter2", "2hunter22"]),
            "[jinnang:redacted][jinnang:redacted]"
        );
        assert_eq!(
            redact_all("hunter22", &["no secret", " here hunt"]),
            "no secret here hunt"
        );
    }
}
