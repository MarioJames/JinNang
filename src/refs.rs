//! `jn://<path>[#field][@v<N>]` references. The path is a free-form name chosen by
//! the user (1–8 segments); it carries no built-in meaning. Classification lives in
//! labels (see `selector`).

use std::fmt;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub const SCHEME: &str = "jn://";
const MAX_SEGMENTS: usize = 8;

/// Identifies one entry by its path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryRef {
    pub path: String,
}

/// A full reference as written by users and agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub entry: EntryRef,
    pub field: Option<String>,
    pub version: Option<u32>,
}

fn valid_segment(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Field names: env-style identifiers (`password`, `DATABASE_URL`).
pub fn valid_field_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    s.len() <= 128 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Reference {
    pub fn parse(input: &str) -> Result<Self> {
        let Some(rest) = input.strip_prefix(SCHEME) else {
            bail!("reference must start with {SCHEME} (got {input:?})");
        };
        let (rest, version) = match rest.rsplit_once('@') {
            Some((rest, v)) => {
                let Some(n) = v.strip_prefix('v').and_then(|n| n.parse::<u32>().ok()) else {
                    bail!("invalid version suffix in {input:?}; expected @v<N>");
                };
                if n == 0 {
                    bail!("versions start at v1");
                }
                (rest, Some(n))
            }
            None => (rest, None),
        };
        let (path, field) = match rest.split_once('#') {
            Some((path, f)) => {
                if !valid_field_name(f) {
                    bail!("invalid field name {f:?}");
                }
                (path, Some(f.to_string()))
            }
            None => (rest, None),
        };
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() > MAX_SEGMENTS || !segments.iter().all(|s| valid_segment(s)) {
            bail!(
                "invalid path {path:?}: 1-{MAX_SEGMENTS} segments of lowercase letters, digits, '.', '_', '-' separated by '/'"
            );
        }
        Ok(Self {
            entry: EntryRef {
                path: path.to_string(),
            },
            field,
            version,
        })
    }

    /// Parses a reference that must name a whole entry (no field, no version).
    pub fn parse_entry(input: &str) -> Result<EntryRef> {
        let r = Self::parse(input)?;
        if r.field.is_some() || r.version.is_some() {
            bail!("expected an entry reference without #field or @version: {input:?}");
        }
        Ok(r.entry)
    }
}

impl fmt::Display for EntryRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}", self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_free_form_paths_with_field_and_version() {
        let r = Reference::parse("jn://work/poc/qa-sales#password@v3").unwrap();
        assert_eq!(r.entry.to_string(), "jn://work/poc/qa-sales");
        assert_eq!(r.field.as_deref(), Some("password"));
        assert_eq!(r.version, Some(3));
        assert_eq!(
            Reference::parse("jn://github-token").unwrap().entry.path,
            "github-token"
        );
        assert_eq!(
            Reference::parse("jn://a/b/c/d/e/f/g/h").unwrap().entry.path,
            "a/b/c/d/e/f/g/h"
        );
    }

    #[test]
    fn rejects_malformed_references() {
        for bad in [
            "github-token",
            "jn://",
            "jn://Work/poc",
            "jn://work//poc",
            "jn://work/poc/",
            "jn://../etc",
            "jn://a/b/c/d/e/f/g/h/i",
            "jn://work/poc@3",
            "jn://work/poc@v0",
            "jn://work/poc#1bad",
            "jn://work/poc#",
        ] {
            assert!(Reference::parse(bad).is_err(), "{bad} should be rejected");
        }
    }
}
