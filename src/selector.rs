//! Free-form labels and Kubernetes-style label selectors.
//!
//! Selector grammar (comma = AND): `k=v`, `k!=v`, `k`, `!k`, `k in (a,b)`, `k notin (a,b)`.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};

pub type Labels = BTreeMap<String, String>;

pub fn valid_label_key(k: &str) -> bool {
    let mut chars = k.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && k.len() <= 63
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '/')
        })
}

pub fn valid_label_value(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-:/@+".contains(c))
}

/// Parses `k=v` for setting a label.
pub fn parse_label(s: &str) -> Result<(String, String)> {
    let Some((k, v)) = s.split_once('=') else {
        bail!("label must be key=value (got {s:?})")
    };
    ensure!(
        valid_label_key(k),
        "invalid label key {k:?}: lowercase letters, digits, '.', '_', '-', '/'"
    );
    ensure!(
        valid_label_value(v),
        "invalid label value for {k:?}: letters, digits and . _ - : / @ +"
    );
    Ok((k.to_string(), v.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Req {
    Eq(String, String),
    Ne(String, String),
    Exists(String),
    Absent(String),
    In(String, Vec<String>),
    NotIn(String, Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector(Vec<Req>);

/// Splits on commas that are not inside parentheses.
fn split_top(s: &str) -> Result<Vec<&str>> {
    let (mut depth, mut start, mut parts) = (0i32, 0, Vec::new());
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        ensure!(
            (0..=1).contains(&depth),
            "unbalanced parentheses in selector"
        );
    }
    ensure!(depth == 0, "unbalanced parentheses in selector");
    parts.push(&s[start..]);
    Ok(parts)
}

fn set_values(s: &str) -> Result<Vec<String>> {
    let inner = s.trim().strip_prefix('(').and_then(|s| s.strip_suffix(')'));
    let Some(inner) = inner else {
        bail!("expected (a,b,...) after in/notin")
    };
    let values: Vec<String> = inner.split(',').map(|v| v.trim().to_string()).collect();
    ensure!(
        values.iter().all(|v| valid_label_value(v)),
        "invalid value in set {s:?}"
    );
    Ok(values)
}

impl Selector {
    pub fn parse(input: &str) -> Result<Self> {
        let mut reqs = Vec::new();
        for part in split_top(input)? {
            let p = part.trim();
            ensure!(!p.is_empty(), "empty requirement in selector {input:?}");
            let key_ok = |k: &str| -> Result<String> {
                ensure!(valid_label_key(k), "invalid label key {k:?} in selector");
                Ok(k.to_string())
            };
            let req = if let Some((k, v)) = p.split_once("!=") {
                ensure!(valid_label_value(v.trim()), "invalid value {v:?}");
                Req::Ne(key_ok(k.trim())?, v.trim().into())
            } else if let Some((k, v)) = p.split_once('=') {
                let v = v.trim().trim_start_matches('=');
                ensure!(valid_label_value(v), "invalid value {v:?}");
                Req::Eq(key_ok(k.trim())?, v.into())
            } else if let Some((k, set)) = p.split_once(" notin ") {
                Req::NotIn(key_ok(k.trim())?, set_values(set)?)
            } else if let Some((k, set)) = p.split_once(" in ") {
                Req::In(key_ok(k.trim())?, set_values(set)?)
            } else if let Some(k) = p.strip_prefix('!') {
                Req::Absent(key_ok(k.trim())?)
            } else {
                Req::Exists(key_ok(p)?)
            };
            reqs.push(req);
        }
        Ok(Self(reqs))
    }

    pub fn matches(&self, labels: &Labels) -> bool {
        self.0.iter().all(|r| match r {
            Req::Eq(k, v) => labels.get(k) == Some(v),
            Req::Ne(k, v) => labels.get(k) != Some(v),
            Req::Exists(k) => labels.contains_key(k),
            Req::Absent(k) => !labels.contains_key(k),
            Req::In(k, vs) => labels.get(k).is_some_and(|v| vs.contains(v)),
            Req::NotIn(k, vs) => labels.get(k).is_none_or(|v| !vs.contains(v)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn selector_semantics() {
        let l = labels(&[("tenant", "poc"), ("role", "sales"), ("env", "prod")]);
        for (sel, expected) in [
            ("tenant=poc,role=sales", true),
            ("tenant==poc", true),
            ("tenant=poc,role=root", false),
            ("env!=prod", false),
            ("pool!=x", true),
            ("role", true),
            ("!expires", true),
            ("!role", false),
            ("role in (sales,root)", true),
            ("role in (root,owner)", false),
            ("env notin (local,dev)", true),
            ("missing notin (a)", true),
            ("env in (prod), role=sales", true),
        ] {
            assert_eq!(Selector::parse(sel).unwrap().matches(&l), expected, "{sel}");
        }
    }

    #[test]
    fn rejects_bad_selectors_and_labels() {
        for bad in [
            "",
            "Tenant=poc",
            "a=b,,c",
            "role in (a",
            "role in a,b",
            "k=v w",
        ] {
            assert!(Selector::parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse_label("owner=alice@example.com").is_ok());
        assert!(parse_label("noequals").is_err());
        assert!(parse_label("k=has space").is_err());
    }
}
