//! Sequencer: randomness / entropy analysis of a set of sampled tokens
//! (e.g. session IDs or CSRF tokens captured from an app).
//!
//! Computes Shannon entropy over the observed character distribution and an
//! estimated effective bits-per-token, plus duplicate detection. Pure and
//! deterministic (unit-tested). This is a first-order estimate, not a full
//! FIPS/NIST statistical battery.

use std::collections::{HashMap, HashSet};

#[derive(serde::Serialize)]
pub struct SeqReport {
    pub count: usize,
    pub unique: usize,
    pub min_len: usize,
    pub max_len: usize,
    pub charset_size: usize,
    pub shannon_bits_per_char: f64,
    pub est_bits_per_token: f64,
    pub verdict: String,
}

/// Analyze a slice of sampled tokens.
pub fn analyze(tokens: &[String]) -> SeqReport {
    let count = tokens.len();
    let unique = tokens.iter().collect::<HashSet<_>>().len();

    let mut min_len = usize::MAX;
    let mut max_len = 0usize;
    let mut freq: HashMap<char, u64> = HashMap::new();
    let mut total_chars: u64 = 0;
    for t in tokens {
        let len = t.chars().count();
        min_len = min_len.min(len);
        max_len = max_len.max(len);
        for c in t.chars() {
            *freq.entry(c).or_insert(0) += 1;
            total_chars += 1;
        }
    }
    let charset_size = freq.len();

    // Shannon entropy (bits per char) over the observed distribution.
    let mut h = 0.0f64;
    if total_chars > 0 {
        for &c in freq.values() {
            let p = c as f64 / total_chars as f64;
            h -= p * p.log2();
        }
    }
    let avg_len = if count > 0 {
        total_chars as f64 / count as f64
    } else {
        0.0
    };
    let est_bits = h * avg_len;

    let verdict = if count < 20 {
        "insufficient samples (collect >= 20 for a meaningful estimate)".to_string()
    } else if unique < count {
        format!(
            "WEAK: {} duplicate token(s) among {count} samples",
            count - unique
        )
    } else if est_bits >= 64.0 {
        format!("strong: ~{est_bits:.1} effective bits/token")
    } else if est_bits >= 32.0 {
        format!("moderate: ~{est_bits:.1} effective bits/token")
    } else {
        format!("weak: ~{est_bits:.1} effective bits/token")
    };

    SeqReport {
        count,
        unique,
        min_len: if count == 0 { 0 } else { min_len },
        max_len,
        charset_size,
        shannon_bits_per_char: h,
        est_bits_per_token: est_bits,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_duplicates_as_weak() {
        let toks: Vec<String> = (0..30).map(|_| "AAAA".to_string()).collect();
        let r = analyze(&toks);
        assert!(r.verdict.starts_with("WEAK"));
        assert_eq!(r.unique, 1);
    }

    #[test]
    fn distinct_tokens_have_entropy() {
        let toks: Vec<String> = (0..40u32)
            .map(|i| format!("{:08x}{:08x}", i.wrapping_mul(2654435761), i ^ 0xABCD))
            .collect();
        let r = analyze(&toks);
        assert_eq!(r.count, 40);
        assert_eq!(r.unique, 40);
        assert!(r.shannon_bits_per_char > 0.0);
        assert!(r.est_bits_per_token > 0.0);
    }

    #[test]
    fn empty_is_safe() {
        let r = analyze(&[]);
        assert_eq!(r.count, 0);
        assert_eq!(r.min_len, 0);
    }
}
