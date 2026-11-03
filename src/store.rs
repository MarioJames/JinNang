//! On-disk vault: layout, signed manifest, pending candidates, backup and restore.
//!
//! ```text
//! <vault>/vault.json             identity of the vault (recipients, signing public key)
//! <vault>/identity.age           device key material, sealed with the passphrase
//! <vault>/manifest.json          signed manifest: entries, versions, ciphertext digests, seq
//! <vault>/entries/<id>/v<N>.age  one age file per entry version
//! <vault>/pending/<pid>.{age,json} candidates written with public keys only
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use age::secrecy::SecretString;
use age::x25519;
use anyhow::{Context, Result, anyhow, bail, ensure};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, KeyMaterial};
use crate::refs::EntryRef;
use crate::schema::{self, EntryType, Fields};
use crate::selector::{Labels, Selector};

pub const FORMAT: u32 = 1;
const VAULT_FILE: &str = "vault.json";
const IDENTITY_FILE: &str = "identity.age";
const MANIFEST_FILE: &str = "manifest.json";
const LOCK_FILE: &str = ".lock";
const AUDIT_FILE: &str = "audit.jsonl";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    pub format: u32,
    pub vault_id: Uuid,
    pub created_at: String,
    pub device_recipient: String,
    pub recovery_recipient: String,
    pub signing_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRecord {
    pub version: u32,
    pub digest: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryRecord {
    pub id: Uuid,
    #[serde(rename = "ref")]
    pub entry_ref: EntryRef,
    #[serde(rename = "type")]
    pub ty: EntryType,
    pub labels: Labels,
    /// What the entry is for, so agents can pick the right one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Non-secret field values of the current version.
    pub public: BTreeMap<String, String>,
    pub secret_fields: Vec<String>,
    pub current: u32,
    pub deleted: bool,
    pub updated_at: String,
    pub versions: Vec<VersionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub vault_id: Uuid,
    pub seq: u64,
    pub issued_at: String,
    pub device_recipient: String,
    pub recovery_recipient: String,
    pub signing_public_key: String,
    pub entries: Vec<EntryRecord>,
}

#[derive(Serialize, Deserialize)]
struct SignedManifest {
    body: String,
    signature: String,
}

/// Inner header bound into every ciphertext so files cannot be swapped between
/// entries, versions or vaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub vault_id: Uuid,
    pub entry_id: Uuid,
    pub version: u32,
    #[serde(rename = "type")]
    pub ty: EntryType,
}

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub header: Header,
    /// Name and labels requested at submission; applied on activation.
    #[serde(rename = "ref")]
    pub entry_ref: EntryRef,
    pub labels: Labels,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub fields: Fields,
    pub public_fields: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submitter {
    pub uid: u32,
    pub pid: u32,
    pub parent_pid: u32,
    pub parent_exe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMeta {
    pub id: String,
    pub header: Header,
    #[serde(rename = "ref")]
    pub entry_ref: EntryRef,
    pub labels: Labels,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub digest: String,
    pub created_at: String,
    pub submitter: Submitter,
}

#[derive(Serialize, Deserialize)]
struct TrustState {
    vault_dir: String,
    vault_id: Uuid,
    signing_public_key: String,
    seq: u64,
}

pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC 3339 formatting")
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Write-to-temp, fsync, rename, fsync directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        Uuid::new_v4().simple()
    ));
    write_new(&tmp, bytes)?;
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn mkdir_private(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .with_context(|| format!("cannot create {}", path.display()))
}

pub fn state_base() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("JINNANG_STATE_DIR") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(p).join("jinnang"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/state/jinnang"))
}

fn state_path(dir: &Path) -> Result<PathBuf> {
    state_file(dir, "json")
}

/// Per-vault file in the state directory, keyed by the canonical vault path.
pub fn state_file(dir: &Path, extension: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(dir)?;
    let digest = crypto::sha256(canonical.as_os_str().as_encoded_bytes());
    Ok(state_base()?.join(format!(
        "{}.{extension}",
        &digest["sha256:".len().."sha256:".len() + 24]
    )))
}

pub fn submitter() -> Submitter {
    let ppid = rustix::process::getppid()
        .map(|p| p.as_raw_nonzero().get() as u32)
        .unwrap_or(0);
    Submitter {
        uid: rustix::process::getuid().as_raw(),
        pid: rustix::process::getpid().as_raw_nonzero().get() as u32,
        parent_pid: ppid,
        parent_exe: fs::read_link(format!("/proc/{ppid}/exe"))
            .ok()
            .map(|p| p.display().to_string()),
    }
}

fn valid_pending_id(id: &str) -> bool {
    id.len() == 32
        && id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub struct Vault {
    pub dir: PathBuf,
    pub meta: VaultMeta,
    pub manifest: Manifest,
    _lock: File,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub entries: usize,
    pub versions: usize,
    pub decrypted: usize,
    pub problems: Vec<String>,
}

impl Vault {
    /// Creates a new vault and writes the recovery kit. Returns the vault metadata.
    pub fn init(dir: &Path, passphrase: &SecretString, recovery_kit: &Path) -> Result<VaultMeta> {
        if dir.exists() {
            ensure!(dir.is_dir(), "{} is not a directory", dir.display());
            ensure!(
                fs::read_dir(dir)?.next().is_none(),
                "{} is not empty",
                dir.display()
            );
        }
        ensure!(
            !recovery_kit.exists(),
            "{} already exists; refusing to overwrite",
            recovery_kit.display()
        );
        mkdir_private(dir)?;
        mkdir_private(&dir.join("entries"))?;
        mkdir_private(&dir.join("pending"))?;

        let vault_id = Uuid::new_v4();
        let signing = crypto::new_signing_key()?;
        let device = KeyMaterial::generate(vault_id, &signing);
        let recovery = KeyMaterial::generate(vault_id, &signing);
        let meta = VaultMeta {
            format: FORMAT,
            vault_id,
            created_at: now(),
            device_recipient: device.recipient().to_string(),
            recovery_recipient: recovery.recipient().to_string(),
            signing_public_key: crypto::verifying_key_hex(&signing),
        };
        write_new(recovery_kit, &recovery.recovery_kit()?)?;
        write_new(&dir.join(IDENTITY_FILE), &device.seal(passphrase)?)?;
        write_new(&dir.join(VAULT_FILE), &serde_json::to_vec_pretty(&meta)?)?;

        let lock = Self::lock(dir, true)?;
        let mut vault = Self {
            dir: dir.to_path_buf(),
            manifest: Self::empty_manifest(&meta),
            meta: meta.clone(),
            _lock: lock,
        };
        vault.manifest.seq = 0;
        vault.commit(&device, vault.manifest.clone())?;
        Ok(meta)
    }

    fn empty_manifest(meta: &VaultMeta) -> Manifest {
        Manifest {
            format: FORMAT,
            vault_id: meta.vault_id,
            seq: 0,
            issued_at: now(),
            device_recipient: meta.device_recipient.clone(),
            recovery_recipient: meta.recovery_recipient.clone(),
            signing_public_key: meta.signing_public_key.clone(),
            entries: Vec::new(),
        }
    }

    fn lock(dir: &Path, exclusive: bool) -> Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(LOCK_FILE))
            .with_context(|| format!("cannot open vault lock in {}", dir.display()))?;
        let op = if exclusive {
            FlockOperation::LockExclusive
        } else {
            FlockOperation::LockShared
        };
        flock(&f, op).context("cannot lock vault")?;
        Ok(f)
    }

    /// Opens and verifies a vault: manifest signature, binding to `vault.json`, and the
    /// locally pinned trust state (signing key and highest seen manifest seq).
    pub fn open(dir: &Path, exclusive: bool) -> Result<Self> {
        ensure!(
            dir.join(VAULT_FILE).is_file(),
            "no vault at {} (run `jinnang init`)",
            dir.display()
        );
        let lock = Self::lock(dir, exclusive)?;
        let meta: VaultMeta = serde_json::from_slice(&fs::read(dir.join(VAULT_FILE))?)
            .context("vault.json is corrupt")?;
        ensure!(
            meta.format == FORMAT,
            "unsupported vault format {}",
            meta.format
        );
        let signed: SignedManifest = serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE))?)
            .context("manifest.json is corrupt")?;
        crypto::verify(
            &meta.signing_public_key,
            signed.body.as_bytes(),
            &signed.signature,
        )
        .context("manifest signature is invalid")?;
        let manifest: Manifest =
            serde_json::from_str(&signed.body).context("manifest body is corrupt")?;
        ensure!(
            manifest.vault_id == meta.vault_id
                && manifest.device_recipient == meta.device_recipient
                && manifest.recovery_recipient == meta.recovery_recipient
                && manifest.signing_public_key == meta.signing_public_key,
            "manifest does not match vault.json"
        );
        let vault = Self {
            dir: dir.to_path_buf(),
            meta,
            manifest,
            _lock: lock,
        };
        vault.check_trust()?;
        Ok(vault)
    }

    fn check_trust(&self) -> Result<()> {
        let path = state_path(&self.dir)?;
        if let Ok(bytes) = fs::read(&path) {
            let state: TrustState =
                serde_json::from_slice(&bytes).context("trust state is corrupt")?;
            ensure!(
                state.vault_id == self.meta.vault_id
                    && state.signing_public_key == self.meta.signing_public_key,
                "vault identity at {} changed since it was last used (trust state {})",
                self.dir.display(),
                path.display()
            );
            ensure!(
                self.manifest.seq >= state.seq,
                "manifest rollback detected: seq {} is older than the last seen seq {}",
                self.manifest.seq,
                state.seq
            );
            if self.manifest.seq == state.seq {
                return Ok(());
            }
        }
        self.save_trust()
    }

    fn save_trust(&self) -> Result<()> {
        let path = state_path(&self.dir)?;
        mkdir_private(path.parent().unwrap())?;
        let state = TrustState {
            vault_dir: fs::canonicalize(&self.dir)?.display().to_string(),
            vault_id: self.meta.vault_id,
            signing_public_key: self.meta.signing_public_key.clone(),
            seq: self.manifest.seq,
        };
        write_atomic(&path, &serde_json::to_vec_pretty(&state)?)
    }

    /// Forgets the pinned trust state (used for an explicitly accepted rollback).
    pub fn forget_trust(dir: &Path) -> Result<()> {
        match fs::remove_file(state_path(dir)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    fn commit(&mut self, keys: &KeyMaterial, mut manifest: Manifest) -> Result<()> {
        ensure!(
            crypto::verifying_key_hex(&keys.signing) == self.meta.signing_public_key,
            "signing key mismatch"
        );
        manifest.seq = self.manifest.seq + 1;
        manifest.issued_at = now();
        let body = serde_json::to_string(&manifest)?;
        let signed = SignedManifest {
            signature: crypto::sign(&keys.signing, body.as_bytes()),
            body,
        };
        write_atomic(&self.dir.join(MANIFEST_FILE), &serde_json::to_vec(&signed)?)?;
        self.manifest = manifest;
        self.save_trust()
    }

    pub fn unlock(&self, passphrase: &SecretString) -> Result<KeyMaterial> {
        let keys = KeyMaterial::unseal(&fs::read(self.dir.join(IDENTITY_FILE))?, passphrase)?;
        ensure!(
            keys.vault_id == self.meta.vault_id
                && keys.recipient().to_string() == self.meta.device_recipient
                && crypto::verifying_key_hex(&keys.signing) == self.meta.signing_public_key,
            "device key file does not belong to this vault"
        );
        Ok(keys)
    }

    /// Re-seals the device key under a new passphrase (atomic replace).
    pub fn change_passphrase(&self, keys: &KeyMaterial, new: &SecretString) -> Result<()> {
        write_atomic(&self.dir.join(IDENTITY_FILE), &keys.seal(new)?)
    }

    /// Checks that a recovery kit belongs to this vault.
    pub fn check_recovery_kit(&self, kit: &KeyMaterial) -> Result<()> {
        ensure!(
            kit.vault_id == self.meta.vault_id
                && kit.recipient().to_string() == self.meta.recovery_recipient
                && crypto::verifying_key_hex(&kit.signing) == self.meta.signing_public_key,
            "recovery kit does not belong to this vault"
        );
        Ok(())
    }

    fn recipients(&self) -> Result<Vec<x25519::Recipient>> {
        [&self.meta.device_recipient, &self.meta.recovery_recipient]
            .iter()
            .map(|r| {
                r.parse::<x25519::Recipient>()
                    .map_err(|e| anyhow!("bad recipient in vault.json: {e}"))
            })
            .collect()
    }

    pub fn find(&self, entry_ref: &EntryRef) -> Option<&EntryRecord> {
        self.manifest
            .entries
            .iter()
            .find(|e| !e.deleted && &e.entry_ref == entry_ref)
    }

    pub fn entries(&self) -> impl Iterator<Item = &EntryRecord> {
        self.manifest.entries.iter().filter(|e| !e.deleted)
    }

    fn version_path(&self, id: Uuid, version: u32) -> PathBuf {
        self.dir
            .join("entries")
            .join(id.to_string())
            .join(format!("v{version}.age"))
    }

    /// Encrypts a candidate with the public recipients only and stores it as pending.
    /// No passphrase is needed; activation verifies and publishes it. For a rotation,
    /// `labels` are merged over the entry's current labels.
    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &self,
        entry_ref: &EntryRef,
        ty: EntryType,
        mut fields: Fields,
        public_fields: BTreeSet<String>,
        mut labels: Labels,
        mut description: Option<String>,
        rotate: bool,
    ) -> Result<PendingMeta> {
        if let Some(d) = &description {
            check_description(d)?;
        }
        let (entry_id, version) = match (self.find(entry_ref), rotate) {
            (Some(_), false) => {
                bail!("{entry_ref} already exists; use `jinnang rotate` for a new version")
            }
            (None, true) => bail!("{entry_ref} does not exist"),
            (Some(e), true) => {
                ensure!(
                    e.ty == ty,
                    "{entry_ref} is a {} entry, not {}",
                    e.ty.as_str(),
                    ty.as_str()
                );
                let mut merged = e.labels.clone();
                merged.append(&mut labels);
                labels = merged;
                if description.is_none() {
                    description = e.description.clone();
                }
                (e.id, e.current + 1)
            }
            (None, false) => (Uuid::new_v4(), 1),
        };
        schema::normalize(ty, &mut fields, &public_fields)?;
        let header = Header {
            vault_id: self.meta.vault_id,
            entry_id,
            version,
            ty,
        };
        let payload = Payload {
            header: header.clone(),
            entry_ref: entry_ref.clone(),
            labels: labels.clone(),
            description: description.clone(),
            fields,
            public_fields,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
        let ciphertext = crypto::encrypt(&self.recipients()?, &plaintext)?;
        let pending = PendingMeta {
            id: Uuid::new_v4().simple().to_string(),
            header,
            entry_ref: entry_ref.clone(),
            labels,
            description,
            digest: crypto::sha256(&ciphertext),
            created_at: now(),
            submitter: submitter(),
        };
        let dir = self.dir.join("pending");
        write_new(&dir.join(format!("{}.age", pending.id)), &ciphertext)?;
        write_new(
            &dir.join(format!("{}.json", pending.id)),
            &serde_json::to_vec_pretty(&pending)?,
        )?;
        Ok(pending)
    }

    pub fn pending(&self) -> Result<Vec<PendingMeta>> {
        let mut out = Vec::new();
        for item in fs::read_dir(self.dir.join("pending"))? {
            let path = item?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let meta: PendingMeta = serde_json::from_slice(&fs::read(&path)?)
                    .with_context(|| format!("corrupt pending record {}", path.display()))?;
                out.push(meta);
            }
        }
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(out)
    }

    fn read_pending(&self, id: &str) -> Result<(PendingMeta, Vec<u8>)> {
        ensure!(valid_pending_id(id), "invalid pending id {id:?}");
        let dir = self.dir.join("pending");
        let meta: PendingMeta = serde_json::from_slice(
            &fs::read(dir.join(format!("{id}.json")))
                .with_context(|| format!("no pending candidate {id}"))?,
        )?;
        let ct = fs::read(dir.join(format!("{id}.age")))?;
        ensure!(
            meta.id == id && meta.digest == crypto::sha256(&ct),
            "pending candidate {id} was modified"
        );
        Ok((meta, ct))
    }

    pub fn reject(&self, id: &str) -> Result<PendingMeta> {
        let (meta, _) = self.read_pending(id)?;
        self.drop_pending(id)?;
        Ok(meta)
    }

    fn drop_pending(&self, id: &str) -> Result<()> {
        let dir = self.dir.join("pending");
        fs::remove_file(dir.join(format!("{id}.age")))?;
        fs::remove_file(dir.join(format!("{id}.json")))?;
        Ok(())
    }

    fn decrypt_payload(&self, identity: &x25519::Identity, ciphertext: &[u8]) -> Result<Payload> {
        let plain = crypto::decrypt(identity, ciphertext)?;
        serde_json::from_slice(&plain).context("decrypted payload is malformed")
    }

    /// Verifies a pending candidate with the device key and publishes it as the next version.
    pub fn activate(&mut self, keys: &KeyMaterial, id: &str) -> Result<EntryRecord> {
        let (pending, ct) = self.read_pending(id)?;
        let payload = self.decrypt_payload(&keys.age, &ct)?;
        let h = &payload.header;
        ensure!(
            h == &pending.header
                && payload.entry_ref == pending.entry_ref
                && payload.labels == pending.labels
                && payload.description == pending.description,
            "pending candidate {id}: payload does not match its record"
        );
        ensure!(
            h.vault_id == self.meta.vault_id,
            "pending candidate {id} belongs to another vault"
        );
        let mut check = payload.fields.clone();
        schema::normalize(h.ty, &mut check, &payload.public_fields)
            .with_context(|| format!("pending candidate {id} is invalid"))?;
        ensure!(
            check == payload.fields,
            "pending candidate {id} is not normalized"
        );

        let mut manifest = self.manifest.clone();
        let existing = manifest
            .entries
            .iter()
            .position(|e| !e.deleted && e.id == h.entry_id);
        match existing {
            Some(i) => {
                let e = &manifest.entries[i];
                ensure!(
                    e.ty == h.ty && e.current + 1 == h.version,
                    "conflict: {} is now at v{}; candidate {id} targets v{}",
                    e.entry_ref,
                    e.current,
                    h.version
                );
            }
            None => {
                ensure!(
                    h.version == 1 && manifest.entries.iter().all(|e| e.id != h.entry_id),
                    "conflict: candidate {id} targets an entry that no longer exists"
                );
                ensure!(
                    !manifest
                        .entries
                        .iter()
                        .any(|e| !e.deleted && e.entry_ref == payload.entry_ref),
                    "conflict: {} already exists",
                    payload.entry_ref
                );
            }
        }

        let path = self.version_path(h.entry_id, h.version);
        mkdir_private(path.parent().unwrap())?;
        write_new(&path, &ct).with_context(|| {
            format!(
                "conflict: {} v{} already stored",
                payload.entry_ref, h.version
            )
        })?;

        let (public, secret_fields) = split_fields(h.ty, &payload);
        let version = VersionRecord {
            version: h.version,
            digest: pending.digest.clone(),
            created_at: now(),
        };
        let record = match existing {
            Some(i) => {
                let e = &mut manifest.entries[i];
                e.versions.push(version);
                e.current = h.version;
                e.labels = payload.labels.clone();
                e.description = payload.description.clone();
                e.public = public;
                e.secret_fields = secret_fields;
                e.updated_at = now();
                e.clone()
            }
            None => {
                let e = EntryRecord {
                    id: h.entry_id,
                    entry_ref: payload.entry_ref.clone(),
                    ty: h.ty,
                    labels: payload.labels.clone(),
                    description: payload.description.clone(),
                    public,
                    secret_fields,
                    current: 1,
                    deleted: false,
                    updated_at: now(),
                    versions: vec![version],
                };
                manifest.entries.push(e.clone());
                e
            }
        };
        self.commit(keys, manifest)?;
        self.drop_pending(id)?;
        Ok(record)
    }

    fn live_mut<'a>(
        manifest: &'a mut Manifest,
        entry_ref: &EntryRef,
    ) -> Result<&'a mut EntryRecord> {
        manifest
            .entries
            .iter_mut()
            .find(|e| !e.deleted && &e.entry_ref == entry_ref)
            .with_context(|| format!("{entry_ref} does not exist"))
    }

    /// Tombstones an entry. Ciphertexts stay for history and recovery.
    pub fn remove(&mut self, keys: &KeyMaterial, entry_ref: &EntryRef) -> Result<()> {
        let mut manifest = self.manifest.clone();
        let e = Self::live_mut(&mut manifest, entry_ref)?;
        e.deleted = true;
        e.updated_at = now();
        self.commit(keys, manifest)
    }

    /// Sets and removes labels (no new version; the signed manifest changes).
    pub fn relabel(
        &mut self,
        keys: &KeyMaterial,
        entry_ref: &EntryRef,
        mut set: Labels,
        remove: &[String],
    ) -> Result<Labels> {
        let mut manifest = self.manifest.clone();
        let e = Self::live_mut(&mut manifest, entry_ref)?;
        for k in remove {
            ensure!(
                e.labels.remove(k).is_some(),
                "{entry_ref} has no label {k:?}"
            );
        }
        e.labels.append(&mut set);
        e.updated_at = now();
        let labels = e.labels.clone();
        self.commit(keys, manifest)?;
        Ok(labels)
    }

    /// Sets (Some) or clears (None) the description (no new version).
    pub fn describe(
        &mut self,
        keys: &KeyMaterial,
        entry_ref: &EntryRef,
        description: Option<String>,
    ) -> Result<()> {
        if let Some(d) = &description {
            check_description(d)?;
        }
        let mut manifest = self.manifest.clone();
        let e = Self::live_mut(&mut manifest, entry_ref)?;
        e.description = description;
        e.updated_at = now();
        self.commit(keys, manifest)
    }

    /// Entries whose metadata contains every term (case-insensitive): name, type,
    /// labels, description, public field names and values, and secret field names.
    pub fn search(&self, terms: &[String]) -> Vec<&EntryRecord> {
        let terms: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();
        self.entries()
            .filter(|e| {
                let mut hay = vec![e.entry_ref.path.clone(), e.ty.as_str().to_string()];
                hay.extend(e.labels.iter().map(|(k, v)| format!("{k}={v}")));
                hay.extend(e.description.clone());
                hay.extend(e.public.iter().map(|(k, v)| format!("{k}={v}")));
                hay.extend(e.secret_fields.iter().cloned());
                let hay = hay.join("\n").to_lowercase();
                terms.iter().all(|t| hay.contains(t.as_str()))
            })
            .collect()
    }

    /// Renames an entry. Ciphertexts are bound to the entry id, not the name.
    pub fn rename(&mut self, keys: &KeyMaterial, from: &EntryRef, to: &EntryRef) -> Result<()> {
        ensure!(self.find(to).is_none(), "{to} already exists");
        let mut manifest = self.manifest.clone();
        let e = Self::live_mut(&mut manifest, from)?;
        e.entry_ref = to.clone();
        e.updated_at = now();
        self.commit(keys, manifest)
    }

    pub fn select(&self, selector: &Selector) -> Vec<&EntryRecord> {
        self.entries()
            .filter(|e| selector.matches(&e.labels))
            .collect()
    }

    /// Resolves exactly one entry by name or selector; zero or several matches fail.
    pub fn resolve(
        &self,
        entry_ref: Option<&EntryRef>,
        selector: Option<&Selector>,
    ) -> Result<&EntryRecord> {
        match (entry_ref, selector) {
            (Some(r), None) => self.find(r).with_context(|| format!("{r} does not exist")),
            (None, Some(sel)) => {
                let hits = self.select(sel);
                match hits.as_slice() {
                    [one] => Ok(one),
                    [] => bail!("no entry matches the selector"),
                    many => bail!(
                        "{} entries match the selector ({}); narrow it down",
                        many.len(),
                        many.iter()
                            .map(|e| e.entry_ref.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                }
            }
            _ => bail!("give either a reference or -l <selector>"),
        }
    }

    fn read_version(
        &self,
        identity: &x25519::Identity,
        e: &EntryRecord,
        v: &VersionRecord,
    ) -> Result<Payload> {
        let ct = fs::read(self.version_path(e.id, v.version))
            .with_context(|| format!("{} v{}: ciphertext missing", e.entry_ref, v.version))?;
        ensure!(
            crypto::sha256(&ct) == v.digest,
            "{} v{}: ciphertext digest mismatch",
            e.entry_ref,
            v.version
        );
        let payload = self.decrypt_payload(identity, &ct)?;
        let expected = Header {
            vault_id: self.meta.vault_id,
            entry_id: e.id,
            version: v.version,
            ty: e.ty,
        };
        ensure!(
            payload.header == expected,
            "{} v{}: ciphertext belongs to another entry or version",
            e.entry_ref,
            v.version
        );
        Ok(payload)
    }

    /// Decrypts the current version of an entry (digest and header checked).
    pub fn read_current(
        &self,
        identity: &x25519::Identity,
        entry_ref: &EntryRef,
    ) -> Result<(EntryRecord, Payload)> {
        let e = self
            .find(entry_ref)
            .with_context(|| format!("{entry_ref} does not exist"))?
            .clone();
        let v = e
            .versions
            .iter()
            .find(|v| v.version == e.current)
            .context("current version missing from manifest")?;
        let payload = self.read_version(identity, &e, v)?;
        Ok((e, payload))
    }

    /// Appends one usage event to `<vault>/audit.jsonl` (no secret values).
    pub fn audit(&self, mut event: serde_json::Value) -> Result<()> {
        event["ts"] = serde_json::Value::String(now());
        event["vault_id"] = serde_json::json!(self.meta.vault_id);
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.dir.join(AUDIT_FILE))
            .context("cannot open audit log")?;
        f.write_all(&line).context("cannot write audit log")?;
        f.sync_data().context("cannot sync audit log")?;
        Ok(())
    }

    /// Checks every stored version against the manifest. With an identity it also
    /// decrypts and validates each payload.
    pub fn verify(&self, identity: Option<&x25519::Identity>) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        let mut known = BTreeSet::new();
        for e in &self.manifest.entries {
            report.entries += usize::from(!e.deleted);
            for v in &e.versions {
                report.versions += 1;
                known.insert(self.version_path(e.id, v.version));
                let Some(identity) = identity else {
                    match fs::read(self.version_path(e.id, v.version)) {
                        Ok(ct) if crypto::sha256(&ct) == v.digest => {}
                        Ok(_) => report.problems.push(format!(
                            "{} v{}: ciphertext digest mismatch",
                            e.entry_ref, v.version
                        )),
                        Err(_) => report.problems.push(format!(
                            "{} v{}: ciphertext missing",
                            e.entry_ref, v.version
                        )),
                    }
                    continue;
                };
                match self.read_version(identity, e, v) {
                    Ok(p) => {
                        report.decrypted += 1;
                        let mut check = p.fields.clone();
                        if schema::normalize(e.ty, &mut check, &p.public_fields).is_err() {
                            report.problems.push(format!(
                                "{} v{}: payload fails validation",
                                e.entry_ref, v.version
                            ));
                        } else if v.version == e.current
                            && split_fields(e.ty, &p) != (e.public.clone(), e.secret_fields.clone())
                        {
                            report.problems.push(format!(
                                "{} v{}: public fields differ from manifest",
                                e.entry_ref, v.version
                            ));
                        }
                    }
                    Err(err) => report.problems.push(format!("{err:#}")),
                }
            }
        }
        for dir in fs::read_dir(self.dir.join("entries"))? {
            for file in fs::read_dir(dir?.path())? {
                let path = file?.path();
                if !known.contains(&path) {
                    report
                        .problems
                        .push(format!("unexpected file {}", path.display()));
                }
            }
        }
        Ok(report)
    }

    /// Writes an age-encrypted tar of the vault (decryptable by device or recovery key).
    pub fn backup(&self, out: &Path) -> Result<()> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut files: Vec<PathBuf> = [VAULT_FILE, IDENTITY_FILE, MANIFEST_FILE]
            .iter()
            .map(PathBuf::from)
            .collect();
        for e in &self.manifest.entries {
            for v in &e.versions {
                files.push(
                    PathBuf::from("entries")
                        .join(e.id.to_string())
                        .join(format!("v{}.age", v.version)),
                );
            }
        }
        if self.dir.join(AUDIT_FILE).is_file() {
            files.push(PathBuf::from(AUDIT_FILE));
        }
        for p in self.pending()? {
            files.push(PathBuf::from("pending").join(format!("{}.age", p.id)));
            files.push(PathBuf::from("pending").join(format!("{}.json", p.id)));
        }
        for rel in &files {
            let data = fs::read(self.dir.join(rel))
                .with_context(|| format!("cannot read {}", rel.display()))?;
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o600);
            header.set_entry_type(tar::EntryType::Regular);
            builder.append_data(&mut header, rel, data.as_slice())?;
        }
        let tar = Zeroizing::new(builder.into_inner()?);
        write_new(out, &crypto::encrypt(&self.recipients()?, &tar)?)
    }

    /// Restores a backup into an empty directory using the recovery kit. With `rekey`,
    /// a new device key sealed with the given passphrase replaces the old one and all
    /// ciphertexts are re-encrypted to it.
    pub fn restore(
        backup: &Path,
        target: &Path,
        kit: &KeyMaterial,
        rekey: Option<&SecretString>,
        accept_rollback: bool,
    ) -> Result<VerifyReport> {
        let tar = crypto::decrypt(&kit.age, &fs::read(backup).context("cannot read backup")?)
            .context("backup cannot be decrypted with this recovery kit")?;
        if target.exists() {
            ensure!(
                fs::read_dir(target)?.next().is_none(),
                "{} is not empty",
                target.display()
            );
        }
        mkdir_private(target)?;
        let result = (|| {
            mkdir_private(&target.join("entries"))?;
            mkdir_private(&target.join("pending"))?;
            extract(&tar, target)?;
            if accept_rollback {
                Self::forget_trust(target)?;
            }
            let mut vault = Self::open(target, true)?;
            vault.check_recovery_kit(kit)?;
            let report = vault.verify(Some(&kit.age))?;
            ensure!(
                report.problems.is_empty(),
                "backup failed verification: {}",
                report.problems.join("; ")
            );
            if let Some(passphrase) = rekey {
                vault.rekey(kit, passphrase)?;
            }
            vault.verify(Some(&kit.age))
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(target);
        }
        result
    }

    fn rekey(&mut self, kit: &KeyMaterial, passphrase: &SecretString) -> Result<()> {
        let device = KeyMaterial::generate(self.meta.vault_id, &kit.signing);
        let recipients = vec![device.recipient(), kit.recipient()];
        let mut manifest = self.manifest.clone();
        for e in &mut manifest.entries {
            for v in &mut e.versions {
                let path = self.version_path(e.id, v.version);
                let plain = crypto::decrypt(&kit.age, &fs::read(&path)?)?;
                let ct = crypto::encrypt(&recipients, &plain)?;
                v.digest = crypto::sha256(&ct);
                write_atomic(&path, &ct)?;
            }
        }
        for mut p in self.pending()? {
            let dir = self.dir.join("pending");
            let plain = crypto::decrypt(&kit.age, &fs::read(dir.join(format!("{}.age", p.id)))?)?;
            let ct = crypto::encrypt(&recipients, &plain)?;
            p.digest = crypto::sha256(&ct);
            write_atomic(&dir.join(format!("{}.age", p.id)), &ct)?;
            write_atomic(
                &dir.join(format!("{}.json", p.id)),
                &serde_json::to_vec_pretty(&p)?,
            )?;
        }
        self.meta.device_recipient = device.recipient().to_string();
        manifest.device_recipient = self.meta.device_recipient.clone();
        fs::remove_file(self.dir.join(IDENTITY_FILE))?;
        write_new(&self.dir.join(IDENTITY_FILE), &device.seal(passphrase)?)?;
        write_atomic(
            &self.dir.join(VAULT_FILE),
            &serde_json::to_vec_pretty(&self.meta)?,
        )?;
        self.commit(&device, manifest)
    }
}

fn split_fields(ty: EntryType, payload: &Payload) -> (BTreeMap<String, String>, Vec<String>) {
    let mut public = BTreeMap::new();
    let mut secret = Vec::new();
    for (k, v) in &payload.fields {
        if schema::is_secret(ty, k, &payload.public_fields) {
            secret.push(k.clone());
        } else {
            public.insert(k.clone(), v.to_string());
        }
    }
    (public, secret)
}

/// Extracts only the expected vault files; rejects anything else.
fn extract(tar_bytes: &[u8], target: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(tar_bytes);
    for item in archive.entries()? {
        let mut item = item?;
        ensure!(
            item.header().entry_type() == tar::EntryType::Regular,
            "backup contains a non-regular file"
        );
        let rel = item.path()?.into_owned();
        ensure!(
            allowed_backup_path(&rel),
            "backup contains unexpected path {}",
            rel.display()
        );
        let dest = target.join(&rel);
        mkdir_private(dest.parent().unwrap())?;
        let mut data = Vec::new();
        item.read_to_end(&mut data)?;
        write_new(&dest, &data)?;
    }
    Ok(())
}

fn allowed_backup_path(rel: &Path) -> bool {
    let parts: Vec<&str> = rel
        .components()
        .map(|c| match c {
            Component::Normal(s) => s.to_str().unwrap_or("\0"),
            _ => "\0",
        })
        .collect();
    match parts.as_slice() {
        [f] => [VAULT_FILE, IDENTITY_FILE, MANIFEST_FILE, AUDIT_FILE].contains(f),
        ["entries", id, file] => {
            Uuid::parse_str(id).is_ok()
                && file
                    .strip_prefix('v')
                    .and_then(|f| f.strip_suffix(".age"))
                    .is_some_and(|n| n.parse::<u32>().is_ok())
        }
        ["pending", file] => file
            .strip_suffix(".age")
            .or_else(|| file.strip_suffix(".json"))
            .is_some_and(valid_pending_id),
        _ => false,
    }
}

/// Descriptions are one line of plain text shown to agents choosing an entry.
pub fn check_description(d: &str) -> Result<()> {
    ensure!(!d.trim().is_empty(), "description is empty");
    ensure!(
        d.chars().count() <= 500,
        "description is longer than 500 characters"
    );
    ensure!(
        !d.chars().any(char::is_control),
        "description must be a single line without control characters"
    );
    Ok(())
}
