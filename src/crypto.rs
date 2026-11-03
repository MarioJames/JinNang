//! age encryption, key material and signatures.

use std::io::{Read, Write};
use std::iter;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Secret key material of one vault participant: the device (unlocked with the
/// passphrase) or the offline recovery kit. Both carry the manifest signing key so
/// that a recovery can re-sign without changing the trust anchor.
pub struct KeyMaterial {
    pub vault_id: Uuid,
    pub age: x25519::Identity,
    pub signing: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct KeyDoc {
    format: u32,
    kind: String,
    vault_id: Uuid,
    age_identity: Zeroizing<String>,
    signing_seed: Zeroizing<String>,
}

pub const DEVICE: &str = "device";
pub const RECOVERY: &str = "recovery";

impl KeyMaterial {
    pub fn generate(vault_id: Uuid, signing: &SigningKey) -> Self {
        Self {
            vault_id,
            age: x25519::Identity::generate(),
            signing: signing.clone(),
        }
    }

    pub fn recipient(&self) -> x25519::Recipient {
        self.age.to_public()
    }

    fn to_doc(&self, kind: &str) -> KeyDoc {
        KeyDoc {
            format: 1,
            kind: kind.into(),
            vault_id: self.vault_id,
            age_identity: Zeroizing::new(self.age.to_string().expose_secret().to_string()),
            signing_seed: Zeroizing::new(hex::encode(self.signing.to_bytes())),
        }
    }

    fn from_doc(doc: KeyDoc, kind: &str) -> Result<Self> {
        if doc.format != 1 || doc.kind != kind {
            bail!("not a jinnang {kind} key file");
        }
        let age = doc
            .age_identity
            .parse::<x25519::Identity>()
            .map_err(|e| anyhow!("{e}"))?;
        let mut seed = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(doc.signing_seed.as_bytes(), seed.as_mut())
            .context("bad signing seed")?;
        Ok(Self {
            vault_id: doc.vault_id,
            age,
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Device key file: JSON key document sealed with the user's passphrase (age scrypt).
    pub fn seal(&self, passphrase: &SecretString) -> Result<Vec<u8>> {
        let json = Zeroizing::new(serde_json::to_vec(&self.to_doc(DEVICE))?);
        let encryptor = age::Encryptor::with_user_passphrase(passphrase.clone());
        let mut out = Vec::new();
        let mut w = encryptor.wrap_output(&mut out)?;
        w.write_all(&json)?;
        w.finish()?;
        Ok(out)
    }

    pub fn unseal(sealed: &[u8], passphrase: &SecretString) -> Result<Self> {
        let decryptor =
            age::Decryptor::new_buffered(sealed).context("device key file is corrupt")?;
        if !decryptor.is_scrypt() {
            bail!("device key file is not passphrase-protected");
        }
        let identity = age::scrypt::Identity::new(passphrase.clone());
        let mut r = decryptor
            .decrypt(iter::once(&identity as &dyn age::Identity))
            .map_err(|_| anyhow!("wrong passphrase or corrupt device key file"))?;
        let mut json = Zeroizing::new(Vec::new());
        r.read_to_end(&mut json)?;
        Self::from_doc(
            serde_json::from_slice(&json).context("device key file is corrupt")?,
            DEVICE,
        )
    }

    /// Recovery kit: plain JSON, meant to be kept offline.
    pub fn recovery_kit(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut json = Zeroizing::new(serde_json::to_vec_pretty(&self.to_doc(RECOVERY))?);
        json.push(b'\n');
        Ok(json)
    }

    pub fn from_recovery_kit(bytes: &[u8]) -> Result<Self> {
        Self::from_doc(
            serde_json::from_slice(bytes).context("not a jinnang recovery kit")?,
            RECOVERY,
        )
    }
}

pub fn encrypt(recipients: &[x25519::Recipient], plaintext: &[u8]) -> Result<Vec<u8>> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?;
    let mut out = Vec::new();
    let mut w = encryptor.wrap_output(&mut out)?;
    w.write_all(plaintext)?;
    w.finish()?;
    Ok(out)
}

pub fn decrypt(identity: &x25519::Identity, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let decryptor = age::Decryptor::new_buffered(ciphertext).context("ciphertext is corrupt")?;
    let mut r = decryptor
        .decrypt(iter::once(identity as &dyn age::Identity))
        .map_err(|_| anyhow!("ciphertext cannot be decrypted with this key"))?;
    let mut out = Zeroizing::new(Vec::new());
    r.read_to_end(&mut out).context("ciphertext is corrupt")?;
    Ok(out)
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn new_signing_key() -> Result<SigningKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| anyhow!("random source failed: {e}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn sign(key: &SigningKey, msg: &[u8]) -> String {
    hex::encode(key.sign(msg).to_bytes())
}

pub fn verifying_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

pub fn verify(public_hex: &str, msg: &[u8], sig_hex: &str) -> Result<()> {
    let mut pk = [0u8; 32];
    hex::decode_to_slice(public_hex, &mut pk).context("bad signing public key")?;
    let key = VerifyingKey::from_bytes(&pk).context("bad signing public key")?;
    let mut sig = [0u8; 64];
    hex::decode_to_slice(sig_hex, &mut sig).context("bad signature encoding")?;
    key.verify_strict(msg, &Signature::from_bytes(&sig))
        .map_err(|_| anyhow!("signature does not verify"))
}

pub fn fingerprint(public_hex: &str) -> String {
    let d = sha256(public_hex.as_bytes());
    d["sha256:".len().."sha256:".len() + 16].to_string()
}
