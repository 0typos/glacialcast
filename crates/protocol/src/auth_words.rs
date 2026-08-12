//! Public word list used to render pairing authentication strings.

use std::sync::OnceLock;

const WORDLIST_SOURCE: &str = include_str!("../wordlist.txt");
const WORDLIST_LEN: usize = 1024;

/// Returns the fixed ten-bit word list used by pairing authentication strings.
pub(crate) fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            let words: Vec<_> = WORDLIST_SOURCE
                .lines()
                .filter(|line| !line.is_empty())
                .collect();
            assert_eq!(
                words.len(),
                WORDLIST_LEN,
                "the pairing word list must contain exactly {WORDLIST_LEN} words"
            );
            words
        })
        .as_slice()
}
