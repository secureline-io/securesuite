//! Comparer: structural diff between two blobs at line or word granularity.
//!
//! Classic LCS dynamic-programming diff, producing a run-length-merged list of
//! equal/added/removed segments. Pure and deterministic (unit-tested).

#[derive(serde::Serialize, PartialEq, Debug)]
pub struct Seg {
    /// "eq" (common), "add" (only in B), or "del" (only in A).
    pub op: &'static str,
    pub text: String,
}

fn tokenize(s: &str, mode: &str) -> Vec<String> {
    match mode {
        "words" => s
            .split_inclusive(char::is_whitespace)
            .map(|w| w.to_string())
            .collect(),
        _ => s.split_inclusive('\n').map(|l| l.to_string()).collect(),
    }
}

fn push(segs: &mut Vec<Seg>, op: &'static str, text: String) {
    if let Some(last) = segs.last_mut() {
        if last.op == op {
            last.text.push_str(&text);
            return;
        }
    }
    segs.push(Seg { op, text });
}

/// Diff `a` against `b`, splitting by `mode` ("lines" default, or "words").
pub fn diff(a: &str, b: &str, mode: &str) -> Vec<Seg> {
    let at = tokenize(a, mode);
    let bt = tokenize(b, mode);
    let (n, m) = (at.len(), bt.len());

    // dp[i][j] = LCS length of at[i..] and bt[j..].
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if at[i] == bt[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut segs = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if at[i] == bt[j] {
            push(&mut segs, "eq", at[i].clone());
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            push(&mut segs, "del", at[i].clone());
            i += 1;
        } else {
            push(&mut segs, "add", bt[j].clone());
            j += 1;
        }
    }
    while i < n {
        push(&mut segs, "del", at[i].clone());
        i += 1;
    }
    while j < m {
        push(&mut segs, "add", bt[j].clone());
        j += 1;
    }
    segs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_all_eq() {
        let d = diff("a\nb\nc\n", "a\nb\nc\n", "lines");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].op, "eq");
    }

    #[test]
    fn detects_add_and_del() {
        let d = diff("a\nb\nc\n", "a\nx\nc\n", "lines");
        let ops: Vec<_> = d.iter().map(|s| s.op).collect();
        assert!(ops.contains(&"del") && ops.contains(&"add"));
        let eq: String = d
            .iter()
            .filter(|s| s.op == "eq")
            .map(|s| s.text.clone())
            .collect();
        assert!(eq.contains('a') && eq.contains('c'));
    }

    #[test]
    fn word_mode_splits_on_space() {
        let d = diff("the quick fox", "the slow fox", "words");
        let dels: String = d
            .iter()
            .filter(|s| s.op == "del")
            .map(|s| s.text.clone())
            .collect();
        let adds: String = d
            .iter()
            .filter(|s| s.op == "add")
            .map(|s| s.text.clone())
            .collect();
        assert!(dels.contains("quick"));
        assert!(adds.contains("slow"));
    }
}
