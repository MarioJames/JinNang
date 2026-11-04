//! Random secrets for `jinnang gen`: the value goes straight from the OS random
//! source into the vault and is never printed.

use anyhow::{Result, ensure};
use zeroize::Zeroizing;

use crate::schema::EntryType;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Symbols most password forms accept and that need no quoting in a dotenv value.
const SYMBOLS: &[u8] = b"!#%*+-.=@^_~";
const HEX: &[u8] = b"0123456789abcdef";

pub const DEFAULT_LENGTH: usize = 24;
pub const MAX_LENGTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Charset {
    /// Letters, digits and symbols, at least one of each
    Strong,
    /// Letters and digits, at least one of each kind
    Alnum,
    /// Lowercase hex digits
    Hex,
}

impl Charset {
    fn classes(self) -> Vec<&'static [u8]> {
        match self {
            Self::Strong => vec![LOWER, UPPER, DIGITS, SYMBOLS],
            Self::Alnum => vec![LOWER, UPPER, DIGITS],
            Self::Hex => vec![HEX],
        }
    }
}

/// Uniform index in `0..n` by rejection sampling over random bytes.
fn index(n: usize) -> Result<usize> {
    debug_assert!(n > 0 && n <= 256);
    let limit = 256 - 256 % n;
    loop {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("random source failed: {e}"))?;
        if usize::from(b[0]) < limit {
            return Ok(usize::from(b[0]) % n);
        }
    }
}

/// A random string of `len` characters drawn uniformly from the charset; drawn
/// again until every character class of the charset occurs.
pub fn secret(len: usize, charset: Charset) -> Result<Zeroizing<String>> {
    let classes = charset.classes();
    ensure!(
        (classes.len().max(8)..=MAX_LENGTH).contains(&len),
        "length must be {}..={MAX_LENGTH}",
        classes.len().max(8)
    );
    let alphabet: Vec<u8> = classes.concat();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(len));
        for _ in 0..len {
            out.push(char::from(alphabet[index(alphabet.len())?]));
        }
        if classes.iter().all(|c| out.bytes().any(|b| c.contains(&b))) {
            return Ok(out);
        }
    }
}

/// A fresh 160-bit TOTP seed in base32, as authenticator apps expect.
pub fn totp_seed() -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new([0u8; 20]);
    getrandom::fill(raw.as_mut()).map_err(|e| anyhow::anyhow!("random source failed: {e}"))?;
    Ok(Zeroizing::new(
        data_encoding::BASE32_NOPAD.encode(raw.as_ref()),
    ))
}

/// Fields `gen` fills by default: the type's required secret fields.
pub fn default_fields(ty: EntryType) -> Vec<&'static str> {
    ty.fields()
        .iter()
        .filter(|s| s.secret && s.required)
        .map(|s| s.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_have_requested_length_and_every_class() {
        for (charset, len) in [
            (Charset::Strong, 8),
            (Charset::Strong, 64),
            (Charset::Alnum, 12),
            (Charset::Hex, 32),
        ] {
            for _ in 0..50 {
                let s = secret(len, charset).unwrap();
                assert_eq!(s.len(), len);
                for class in charset.classes() {
                    assert!(s.bytes().any(|b| class.contains(&b)), "{charset:?}: {}", *s);
                }
                let alphabet = charset.classes().concat();
                assert!(s.bytes().all(|b| alphabet.contains(&b)));
            }
        }
        assert_ne!(
            *secret(24, Charset::Strong).unwrap(),
            *secret(24, Charset::Strong).unwrap()
        );
    }

    #[test]
    fn rejects_lengths_too_short_for_the_charset_or_too_long() {
        assert!(secret(7, Charset::Hex).is_err());
        assert!(secret(MAX_LENGTH + 1, Charset::Strong).is_err());
    }

    #[test]
    fn totp_seed_is_valid_base32_of_20_bytes() {
        let seed = totp_seed().unwrap();
        assert_eq!(
            data_encoding::BASE32_NOPAD
                .decode(seed.as_bytes())
                .unwrap()
                .len(),
            20
        );
    }
}
