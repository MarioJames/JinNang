//! Unattended unlock: the vault passphrase sealed with a user-scoped systemd
//! credential (`systemd-creds --user`). The ciphertext is bound to this machine's
//! credential key and to the user; jinnang decrypts it itself, so callers (agents)
//! never see or pass the passphrase.
//!
//! Without a separate broker UID (M2) any process of the same user can ask
//! systemd to decrypt it as well; sealing removes the plaintext file, it is not
//! process isolation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

use crate::store;

const CRED_NAME: &str = "jinnang";

fn systemd_creds() -> Command {
    let bin = ["/usr/bin/systemd-creds", "/bin/systemd-creds"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("systemd-creds");
    let mut c = Command::new(bin);
    c.args(["--user", "--name", CRED_NAME]);
    c
}

/// Where the sealed passphrase of the vault at `dir` lives.
pub fn path(dir: &Path) -> Result<PathBuf> {
    store::state_file(dir, "passphrase.cred")
}

/// Decrypts the sealed passphrase, if one is enrolled for this vault.
pub fn load(dir: &Path) -> Result<Option<SecretString>> {
    let Ok(file) = path(dir) else { return Ok(None) };
    if !file.exists() {
        return Ok(None);
    }
    let out = systemd_creds()
        .arg("decrypt")
        .arg(&file)
        .arg("-")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("cannot run systemd-creds to unseal the vault passphrase")?;
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        bail!(
            "cannot unseal the vault passphrase ({}): {}; re-enroll with `jinnang unlock enroll`",
            file.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = std::str::from_utf8(&stdout).context("sealed passphrase is not UTF-8")?;
    ensure!(!text.is_empty(), "sealed passphrase is empty");
    Ok(Some(SecretString::from(text.to_string())))
}

/// Seals `passphrase` for unattended use of the vault at `dir`.
pub fn enroll(dir: &Path, passphrase: &SecretString) -> Result<PathBuf> {
    let file = path(dir)?;
    let parent = file.parent().context("state directory")?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut child = systemd_creds()
        .arg("encrypt")
        .arg("-")
        .arg(&tmp)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run systemd-creds (needs systemd 256+ with user-scoped credentials)")?;
    child
        .stdin
        .take()
        .context("systemd-creds stdin")?
        .write_all(passphrase.expose_secret().as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let _ = fs::remove_file(&tmp);
        bail!(
            "systemd-creds encrypt failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, &file)?;
    Ok(file)
}

/// Removes the sealed passphrase; returns whether one existed.
pub fn remove(dir: &Path) -> Result<bool> {
    match fs::remove_file(path(dir)?) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
