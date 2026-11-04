//! Entry types, their fields and validation.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::refs::valid_field_name;

pub type Fields = BTreeMap<String, Zeroizing<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum EntryType {
    Password,
    Account,
    Totp,
    Ssh,
    CloudKey,
    Dsn,
    Kubeconfig,
    ApiToken,
    EnvBundle,
    Generic,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub name: &'static str,
    pub secret: bool,
    pub required: bool,
    /// Multi-line values (keys, kubeconfigs) are read from a file when prompting.
    pub multiline: bool,
}

const fn f(name: &'static str, secret: bool, required: bool) -> FieldSpec {
    FieldSpec {
        name,
        secret,
        required,
        multiline: false,
    }
}
const fn ml(name: &'static str, secret: bool, required: bool) -> FieldSpec {
    FieldSpec {
        name,
        secret,
        required,
        multiline: true,
    }
}

impl EntryType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Account => "account",
            Self::Totp => "totp",
            Self::Ssh => "ssh",
            Self::CloudKey => "cloud_key",
            Self::Dsn => "dsn",
            Self::Kubeconfig => "kubeconfig",
            Self::ApiToken => "api_token",
            Self::EnvBundle => "env_bundle",
            Self::Generic => "generic",
        }
    }

    /// Fields defined by the type; `env_bundle` and `generic` only have custom fields.
    pub fn fields(self) -> &'static [FieldSpec] {
        match self {
            Self::Password => const { &[f("password", true, true)] },
            Self::Account => {
                const {
                    &[
                        f("username", false, true),
                        f("password", true, true),
                        f("login_url", false, false),
                        f("totp_ref", false, false),
                    ]
                }
            }
            Self::Totp => {
                const {
                    &[
                        f("seed", true, true),
                        f("algorithm", false, false),
                        f("digits", false, false),
                        f("period", false, false),
                        f("issuer", false, false),
                        f("account", false, false),
                    ]
                }
            }
            Self::Ssh => {
                const {
                    &[
                        f("host", false, true),
                        f("port", false, false),
                        f("user", false, true),
                        f("host_key", false, false),
                        ml("private_key", true, false),
                        f("passphrase", true, false),
                        f("password", true, false),
                    ]
                }
            }
            Self::CloudKey => {
                const {
                    &[
                        f("provider", false, true),
                        f("region", false, false),
                        f("access_key_id", true, true),
                        f("secret_access_key", true, true),
                        f("session_token", true, false),
                    ]
                }
            }
            Self::Dsn => {
                const {
                    &[
                        f("driver", false, true),
                        f("host", false, true),
                        f("port", false, false),
                        f("database", false, true),
                        f("username", false, true),
                        f("password", true, true),
                        f("sslmode", false, false),
                    ]
                }
            }
            Self::Kubeconfig => {
                const {
                    &[
                        ml("kubeconfig", true, true),
                        f("context", false, false),
                        f("namespace", false, false),
                    ]
                }
            }
            Self::ApiToken => {
                const {
                    &[
                        f("token", true, true),
                        f("base_url", false, false),
                        f("audience", false, false),
                    ]
                }
            }
            Self::EnvBundle | Self::Generic => &[],
        }
    }

    pub fn spec(self, field: &str) -> Option<&'static FieldSpec> {
        self.fields().iter().find(|s| s.name == field)
    }
}

/// Decides whether a field is secret. Fields defined by the type have fixed
/// secrecy; any other (custom) field is secret unless listed in `public_fields`.
pub fn is_secret(ty: EntryType, field: &str, public_fields: &BTreeSet<String>) -> bool {
    match ty.spec(field) {
        Some(spec) => spec.secret,
        None => !public_fields.contains(field),
    }
}

/// Fills defaults, accepts an `otpauth://` URI for TOTP and checks the field set.
/// Every type accepts custom fields in addition to its own.
pub fn normalize(
    ty: EntryType,
    fields: &mut Fields,
    public_fields: &BTreeSet<String>,
) -> Result<()> {
    // A blank answer to a typed field means "not set"; custom fields (and .env keys)
    // keep explicitly empty values.
    fields.retain(|k, v| !v.is_empty() || ty.spec(k).is_none());

    if ty == EntryType::Totp {
        if let Some(uri) = fields.remove("uri") {
            parse_otpauth(&uri, fields)?;
        } else if fields
            .get("seed")
            .is_some_and(|s| s.starts_with("otpauth://"))
        {
            let uri = fields.remove("seed").unwrap();
            parse_otpauth(&uri, fields)?;
        }
    }

    if fields.is_empty() {
        bail!("an entry needs at least one field");
    }
    if let Some(bad) = fields.keys().find(|k| !valid_field_name(k)) {
        bail!("invalid field name {bad:?}");
    }
    for name in public_fields {
        if !fields.contains_key(name) {
            bail!("public field {name:?} is not part of the entry");
        }
        if ty.spec(name).is_some() {
            bail!(
                "field {name:?} is defined by type {}; its secrecy is fixed",
                ty.as_str()
            );
        }
    }
    for spec in ty.fields() {
        if spec.required && !fields.contains_key(spec.name) {
            bail!(
                "missing required field {:?} for type {}",
                spec.name,
                ty.as_str()
            );
        }
    }

    match ty {
        EntryType::Totp => {
            let seed: String = fields["seed"]
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '=')
                .collect();
            let seed = Zeroizing::new(seed.to_ascii_uppercase());
            if data_encoding::BASE32_NOPAD
                .decode(seed.as_bytes())
                .map(Zeroizing::new)
                .is_err()
                || seed.is_empty()
            {
                bail!("totp seed is not valid base32");
            }
            fields.insert("seed".into(), seed);
            let algo = fields
                .entry("algorithm".into())
                .or_insert_with(|| "SHA1".to_string().into());
            let upper = algo.to_ascii_uppercase();
            if !matches!(upper.as_str(), "SHA1" | "SHA256" | "SHA512") {
                bail!("totp algorithm must be SHA1, SHA256 or SHA512");
            }
            *algo = upper.into();
            let digits = fields
                .entry("digits".into())
                .or_insert_with(|| "6".to_string().into());
            if !matches!(digits.as_str(), "6" | "7" | "8") {
                bail!("totp digits must be 6, 7 or 8");
            }
            let period = fields
                .entry("period".into())
                .or_insert_with(|| "30".to_string().into());
            if !period.parse::<u32>().is_ok_and(|p| (1..=600).contains(&p)) {
                bail!("totp period must be 1..=600 seconds");
            }
        }
        EntryType::Ssh => {
            if !fields.contains_key("private_key") && !fields.contains_key("password") {
                bail!("ssh entries need private_key or password");
            }
            check_port(fields)?;
        }
        EntryType::Dsn => check_port(fields)?,
        _ => {}
    }
    Ok(())
}

/// Binary fields hold the standard base64 of the original bytes (for example a
/// `.p12` certificate read with `--from-file`); `run --file` and `--stdin` write
/// the decoded bytes, text channels (env, dotenv) carry the base64.
pub fn check_binary(fields: &Fields, binary: &BTreeSet<String>) -> Result<()> {
    for name in binary {
        let value = fields
            .get(name)
            .with_context(|| format!("binary field {name:?} is not part of the entry"))?;
        decode_binary(value)
            .with_context(|| format!("binary field {name:?} is not valid base64"))?;
    }
    Ok(())
}

pub fn encode_binary(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(data_encoding::BASE64.encode(bytes))
}

pub fn decode_binary(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    data_encoding::BASE64
        .decode(value.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| anyhow::anyhow!("not valid base64"))
}

fn check_port(fields: &Fields) -> Result<()> {
    if let Some(p) = fields.get("port")
        && !p.parse::<u16>().is_ok_and(|p| p > 0)
    {
        bail!("port must be 1..=65535");
    }
    Ok(())
}

fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex =
                    std::str::from_utf8(&bytes[i + 1..i + 3]).context("bad percent escape")?;
                out.push(u8::from_str_radix(hex, 16).context("bad percent escape")?);
                i += 3;
            }
            b'%' => bail!("bad percent escape"),
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).context("otpauth URI is not UTF-8")
}

/// `otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=...&digits=...&period=...`
fn parse_otpauth(uri: &str, fields: &mut Fields) -> Result<()> {
    let Some(rest) = uri.strip_prefix("otpauth://totp/") else {
        bail!("only otpauth://totp/ URIs are supported");
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label)?;
    if let Some((issuer, account)) = label.split_once(':') {
        fields
            .entry("issuer".into())
            .or_insert_with(|| issuer.trim().to_string().into());
        fields
            .entry("account".into())
            .or_insert_with(|| account.trim().to_string().into());
    } else if !label.is_empty() {
        fields
            .entry("account".into())
            .or_insert_with(|| label.clone().into());
    }
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = Zeroizing::new(percent_decode(v)?);
        let key = match k {
            "secret" => "seed",
            "issuer" | "algorithm" | "digits" | "period" => k,
            _ => continue,
        };
        fields.insert(key.into(), v);
    }
    if !fields.contains_key("seed") {
        bail!("otpauth URI has no secret");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> Fields {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }

    #[test]
    fn otpauth_uri_is_parsed_into_fields() {
        let mut f = fields(&[(
            "uri",
            "otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&digits=8",
        )]);
        normalize(EntryType::Totp, &mut f, &BTreeSet::new()).unwrap();
        assert_eq!(f["seed"].as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(f["issuer"].as_str(), "ACME Co");
        assert_eq!(f["account"].as_str(), "alice@example.com");
        assert_eq!(f["digits"].as_str(), "8");
        assert_eq!(f["algorithm"].as_str(), "SHA1");
        assert_eq!(f["period"].as_str(), "30");
    }

    #[test]
    fn rejects_invalid_totp_seed() {
        let mut bad_seed = fields(&[("seed", "not base32!")]);
        assert!(normalize(EntryType::Totp, &mut bad_seed, &BTreeSet::new()).is_err());
    }

    #[test]
    fn custom_fields_are_secret_unless_public_and_typed_secrecy_is_fixed() {
        let public: BTreeSet<String> = ["login_hint".to_string()].into();
        let mut f = fields(&[("password", "x"), ("pin", "1234"), ("login_hint", "sso")]);
        normalize(EntryType::Password, &mut f, &public).unwrap();
        assert!(is_secret(EntryType::Password, "pin", &public));
        assert!(!is_secret(EntryType::Password, "login_hint", &public));
        let make_password_public: BTreeSet<String> = ["password".to_string()].into();
        let mut f = fields(&[("password", "x")]);
        assert!(normalize(EntryType::Password, &mut f, &make_password_public).is_err());
        let mut empty = Fields::new();
        assert!(normalize(EntryType::Generic, &mut empty, &BTreeSet::new()).is_err());
    }

    #[test]
    fn ssh_requires_a_credential() {
        let mut f = fields(&[("host", "h"), ("user", "u")]);
        assert!(normalize(EntryType::Ssh, &mut f, &BTreeSet::new()).is_err());
    }

    #[test]
    fn env_bundle_keys_are_secret_unless_public() {
        let public: BTreeSet<String> = ["PORT".to_string()].into();
        let mut f = fields(&[
            ("PORT", "3000"),
            ("DATABASE_URL", "postgres://x"),
            ("EMPTY", ""),
        ]);
        normalize(EntryType::EnvBundle, &mut f, &public).unwrap();
        assert_eq!(
            f["EMPTY"].as_str(),
            "",
            "explicitly empty env values must survive"
        );
        assert!(!is_secret(EntryType::EnvBundle, "PORT", &public));
        assert!(is_secret(EntryType::EnvBundle, "DATABASE_URL", &public));
    }
}
