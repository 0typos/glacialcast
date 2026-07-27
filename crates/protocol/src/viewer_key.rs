//! Human-transferable viewer keys.
//!
//! A viewer key is 32 bytes of key material, and 32 random bytes written as
//! base64 is 43 characters that nobody can read over a phone or retype without
//! a mistake. Sharing one is the single manual step in setting up a stream, so
//! the shape it takes is a usability property of the whole system.
//!
//! A key is therefore carried as a word phrase drawn from a fixed 1024-word
//! list — ten bits a word, [`PHRASE_WORDS`] words, [`PHRASE_ENTROPY_BITS`] bits
//! in total. The phrase is the secret; the 32-byte key is derived from it with
//! PBKDF2-HMAC-SHA-256 over a per-publisher salt that the relay publishes as
//! ordinary stream metadata.
//!
//! Deriving rather than encoding is what keeps this honest. The phrase carries
//! less entropy than the key it produces, so the derivation is deliberately
//! expensive: [`PBKDF2_ITERATIONS`] iterations cost a fraction of a second once
//! per session and add roughly twenty bits to the work an offline guessing
//! attack has to do. The salt makes that work specific to one publisher rather
//! than reusable against every GlacialCast deployment at once.
//!
//! The browser performs the identical derivation in `viewer-key.js`; the two
//! wordlists are the same file and a test enforces it.

use sha2::Sha256;
use sha2::digest::{FixedOutput, KeyInit, Update};

/// The words a phrase is drawn from, one per line, in canonical order.
///
/// Every word is three to five ASCII letters and no two share their first
/// three letters, so a phrase can be typed by prefix and read aloud without
/// spelling it out.
const WORDLIST_SOURCE: &str = include_str!("../wordlist.txt");

/// Number of words in the list. Ten bits of choice per word.
pub const WORDLIST_LEN: usize = 1024;

/// Words in a generated phrase.
pub const PHRASE_WORDS: usize = 7;

/// Entropy of a generated phrase, in bits.
pub const PHRASE_ENTROPY_BITS: usize = PHRASE_WORDS * 10;

/// Length of a viewer-key salt in bytes.
pub const SALT_LEN: usize = 16;

/// PBKDF2 iterations used to turn a phrase into key material.
///
/// Matches the browser keyring's cost, which is OWASP's floor for
/// PBKDF2-HMAC-SHA-256. Paid once per publisher start and once per viewer
/// session.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Domain separator mixed into the salt.
///
/// Keeps this derivation from colliding with any other use of the same
/// passphrase and the same publisher salt.
const DERIVATION_CONTEXT: &[u8] = b"glacialcast-viewer-key-v1:";

/// Shortest prefix that identifies a word uniquely.
const PREFIX_LEN: usize = 3;

/// Errors from parsing a viewer-key phrase.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PhraseError {
    /// The phrase did not contain [`PHRASE_WORDS`] words.
    #[error("a viewer key is {PHRASE_WORDS} words, but {0} were given")]
    WrongLength(usize),
    /// A word was not in the list.
    #[error("\"{0}\" is not a GlacialCast viewer-key word")]
    UnknownWord(String),
}

/// Returns the canonical wordlist.
pub fn wordlist() -> &'static [&'static str] {
    use std::sync::OnceLock;
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            let words: Vec<&'static str> =
                WORDLIST_SOURCE.lines().filter(|l| !l.is_empty()).collect();
            assert_eq!(
                words.len(),
                WORDLIST_LEN,
                "the viewer-key wordlist must hold exactly {WORDLIST_LEN} words"
            );
            words
        })
        .as_slice()
}

/// Builds a phrase from `PHRASE_WORDS` ten-bit indices.
///
/// Callers supply the randomness so this stays testable and so the caller owns
/// the choice of generator.
pub fn phrase_from_indices(indices: &[u16; PHRASE_WORDS]) -> String {
    let words = wordlist();
    indices
        .iter()
        .map(|index| words[usize::from(*index) % WORDLIST_LEN])
        .collect::<Vec<_>>()
        .join("-")
}

/// Generates a fresh phrase using the operating system's random source.
pub fn generate_phrase() -> std::io::Result<String> {
    let mut bytes = [0u8; PHRASE_WORDS * 2];
    getrandom(&mut bytes)?;
    let mut indices = [0u16; PHRASE_WORDS];
    for (index, chunk) in indices.iter_mut().zip(bytes.chunks_exact(2)) {
        // Ten bits per word; the remaining six are discarded rather than folded
        // in, so every word stays exactly uniform.
        *index = u16::from_le_bytes([chunk[0], chunk[1]]) & 0x03ff;
    }
    Ok(phrase_from_indices(&indices))
}

/// Generates a fresh per-publisher salt.
pub fn generate_salt() -> std::io::Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom(&mut salt)?;
    Ok(salt)
}

/// Encodes a salt as the unpadded URL-safe base64 carried on the wire.
pub fn encode_salt(salt: &[u8; SALT_LEN]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(salt)
}

/// Decodes a salt from its wire form.
pub fn decode_salt(encoded: &str) -> Option<[u8; SALT_LEN]> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| <[u8; SALT_LEN]>::try_from(bytes.as_slice()).ok())
}

fn getrandom(buffer: &mut [u8]) -> std::io::Result<()> {
    // SAFETY: `getrandom` writes at most `len` bytes into `buf`, and the
    // pointer and length come from the same live slice.
    let filled = unsafe { libc::getrandom(buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if filled < 0 || filled as usize != buffer.len() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Normalizes a typed phrase to its canonical hyphenated form.
///
/// Words may be separated by spaces or hyphens and may be abbreviated to their
/// first three letters, which are unique across the list. Case is ignored.
/// This is what lets someone retype a dictated key without matching it
/// character for character.
pub fn normalize_phrase(input: &str) -> Result<String, PhraseError> {
    let tokens: Vec<&str> = input
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.len() != PHRASE_WORDS {
        return Err(PhraseError::WrongLength(tokens.len()));
    }
    let words = wordlist();
    let mut resolved = Vec::with_capacity(PHRASE_WORDS);
    for token in tokens {
        let lowered = token.to_ascii_lowercase();
        if lowered.len() < PREFIX_LEN {
            return Err(PhraseError::UnknownWord(lowered));
        }
        let prefix = &lowered[..PREFIX_LEN];
        let found = words
            .iter()
            .find(|word| word.starts_with(prefix))
            .ok_or_else(|| PhraseError::UnknownWord(lowered.clone()))?;
        resolved.push(*found);
    }
    Ok(resolved.join("-"))
}

/// Derives the 32-byte viewer key a phrase stands for.
///
/// `phrase` is normalized first, so a key typed with abbreviations or spaces
/// derives the same bytes as the canonical form.
pub fn derive_viewer_key(phrase: &str, salt: &[u8]) -> Result<[u8; 32], PhraseError> {
    let canonical = normalize_phrase(phrase)?;
    Ok(derive_viewer_key_normalized(&canonical, salt))
}

/// Derives a viewer key from an already-canonical phrase.
pub fn derive_viewer_key_normalized(canonical_phrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut salted = Vec::with_capacity(DERIVATION_CONTEXT.len() + salt.len());
    salted.extend_from_slice(DERIVATION_CONTEXT);
    salted.extend_from_slice(salt);
    let mut key = [0u8; 32];
    pbkdf2_sha256(
        canonical_phrase.as_bytes(),
        &salted,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    key
}

/// PBKDF2-HMAC-SHA-256 (RFC 8018) for a single 32-byte output block.
///
/// One block is all this needs, so the block loop RFC 8018 describes collapses
/// to the inner iteration below.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8; 32]) {
    type HmacSha256 = hmac::Hmac<Sha256>;

    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1u32.to_be_bytes());

    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(password)
        .expect("HMAC accepts a key of any length");
    Update::update(&mut mac, &block);
    let mut current: [u8; 32] = mac.finalize_fixed().into();
    *output = current;

    for _ in 1..iterations {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(password)
            .expect("HMAC accepts a key of any length");
        Update::update(&mut mac, &current);
        current = mac.finalize_fixed().into();
        for (accumulated, byte) in output.iter_mut().zip(current.iter()) {
            *accumulated ^= byte;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn wordlist_is_exactly_ten_bits_wide() {
        assert_eq!(wordlist().len(), WORDLIST_LEN);
    }

    #[test]
    fn every_word_is_short_lowercase_ascii() {
        for word in wordlist() {
            assert!(
                (3..=5).contains(&word.len()),
                "{word} is not three to five letters"
            );
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase()),
                "{word} is not lowercase ASCII"
            );
        }
    }

    #[test]
    fn no_two_words_share_a_three_letter_prefix() {
        // Prefix uniqueness is what makes abbreviated entry unambiguous, so it
        // is a property of the list rather than a convenience.
        let mut prefixes: Vec<&str> = wordlist().iter().map(|word| &word[..PREFIX_LEN]).collect();
        prefixes.sort_unstable();
        let unique = prefixes.len();
        prefixes.dedup();
        assert_eq!(
            prefixes.len(),
            unique,
            "two words share a three-letter prefix"
        );
    }

    #[test]
    fn generated_phrases_round_trip() {
        let phrase = generate_phrase().expect("random source");
        assert_eq!(phrase.split('-').count(), PHRASE_WORDS);
        assert_eq!(normalize_phrase(&phrase).unwrap(), phrase);
    }

    #[test]
    fn spacing_case_and_abbreviation_all_reach_the_same_key() {
        let indices = [0u16, 1, 2, 3, 4, 5, 6];
        let phrase = phrase_from_indices(&indices);
        let words: Vec<&str> = phrase.split('-').collect();
        let spaced = words.join(" ");
        let shouted = phrase.to_ascii_uppercase();
        let abbreviated = words
            .iter()
            .map(|word| &word[..PREFIX_LEN])
            .collect::<Vec<_>>()
            .join(" ");

        for variant in [spaced, shouted, abbreviated] {
            assert_eq!(
                normalize_phrase(&variant).unwrap(),
                phrase,
                "{variant} did not normalize to {phrase}"
            );
        }
    }

    #[test]
    fn a_wrong_word_count_is_rejected() {
        assert_eq!(
            normalize_phrase("able about above"),
            Err(PhraseError::WrongLength(3))
        );
    }

    #[test]
    fn an_unknown_word_is_rejected_rather_than_ignored() {
        let phrase = "zzzz-able-about-above-acid-acorn-acre";
        assert!(matches!(
            normalize_phrase(phrase),
            Err(PhraseError::UnknownWord(_))
        ));
    }

    #[test]
    fn the_salt_separates_publishers() {
        let phrase = phrase_from_indices(&[7, 8, 9, 10, 11, 12, 13]);
        let first = derive_viewer_key(&phrase, b"0123456789abcdef").unwrap();
        let second = derive_viewer_key(&phrase, b"fedcba9876543210").unwrap();
        assert_ne!(
            first, second,
            "one phrase must not produce the same key for two publishers"
        );
    }

    /// The browser must derive byte-for-byte what the publisher does, or a
    /// viewer holding the right phrase still cannot decrypt anything. This
    /// pins both sides to one file; `scripts/test-viewer-key.mjs` reads it too.
    #[test]
    fn the_shared_vectors_match_this_implementation() {
        let raw = include_str!("../../../test-vectors/viewer-key-vectors.json");
        let vectors: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(
            vectors["iterations"].as_u64().unwrap() as u32,
            PBKDF2_ITERATIONS
        );
        let cases = vectors["cases"].as_array().unwrap();
        assert!(
            !cases.is_empty(),
            "the vector file must hold at least one case"
        );
        for case in cases {
            let phrase = case["phrase"].as_str().unwrap();
            let salt = decode_salt(case["salt_b64"].as_str().unwrap()).unwrap();
            let key = derive_viewer_key(phrase, &salt).unwrap();
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
                case["viewer_key_b64"].as_str().unwrap(),
                "phrase \"{phrase}\" derived a different key than the recorded vector"
            );
        }
    }

    /// RFC 6070 fixes PBKDF2-HMAC-SHA-1 vectors; RFC 7914 section 11 gives the
    /// SHA-256 equivalents. This is the one that pins our implementation
    /// against a published answer rather than against itself.
    #[test]
    fn pbkdf2_matches_the_published_vector() {
        let mut out = [0u8; 32];
        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            out[..16],
            [
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
                0xb6, 0x05
            ]
        );

        let mut out = [0u8; 32];
        pbkdf2_sha256(b"Password", b"NaCl", 80_000, &mut out);
        assert_eq!(
            out[..16],
            [
                0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27,
                0x01, 0xf9
            ]
        );
    }
}
