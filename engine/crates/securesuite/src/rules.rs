//! Match & Replace: automatic request/response rewriting rules.
//!
//! Each [`Rule`] targets a `part` (`url`, `req_header`, `req_body`,
//! `resp_header`, `resp_body`) and replaces `pattern` with `replace`, either as
//! a literal substring or a Rust regex. Rules apply in order to all proxied
//! traffic when enabled.

use regex::Regex;

use crate::model::{Header, Rule};

fn apply_one(rule: &Rule, input: &str) -> String {
    if rule.regex {
        match Regex::new(&rule.pattern) {
            Ok(re) => re.replace_all(input, rule.replace.as_str()).into_owned(),
            Err(_) => input.to_string(), // invalid regex: leave unchanged
        }
    } else if rule.pattern.is_empty() {
        input.to_string()
    } else {
        input.replace(rule.pattern.as_str(), rule.replace.as_str())
    }
}

/// Apply all enabled rules for `part` to a text value (`url`/`req_body`/`resp_body`).
pub fn apply_text(rules: &[Rule], part: &str, input: &str) -> String {
    let mut out = input.to_string();
    for r in rules.iter().filter(|r| r.enabled && r.part == part) {
        out = apply_one(r, &out);
    }
    out
}

/// True if any enabled rule targets `part`.
pub fn has_rule(rules: &[Rule], part: &str) -> bool {
    rules.iter().any(|r| r.enabled && r.part == part)
}

/// Apply header rules by rewriting the `Name: Value` block and reparsing.
/// Blank result lines drop the header; this supports modify / remove / add.
pub fn rewrite_headers(rules: &[Rule], part: &str, headers: &[Header]) -> Vec<Header> {
    if !has_rule(rules, part) {
        return headers.to_vec();
    }
    let mut block = headers
        .iter()
        .map(|h| format!("{}: {}", h.name, h.value))
        .collect::<Vec<_>>()
        .join("\n");
    for r in rules.iter().filter(|r| r.enabled && r.part == part) {
        block = apply_one(r, &block);
    }
    block
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let i = line.find(':')?;
            Some(Header {
                name: line[..i].trim().to_string(),
                value: line[i + 1..].trim().to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(part: &str, pattern: &str, replace: &str, regex: bool) -> Rule {
        Rule {
            id: 1,
            enabled: true,
            part: part.into(),
            pattern: pattern.into(),
            replace: replace.into(),
            regex,
        }
    }

    #[test]
    fn literal_body_replace() {
        let rs = vec![rule("resp_body", "password", "REDACTED", false)];
        assert_eq!(
            apply_text(&rs, "resp_body", "my password here"),
            "my REDACTED here"
        );
    }

    #[test]
    fn regex_url_replace() {
        let rs = vec![rule("url", "/v1/", "/v2/", true)];
        assert_eq!(
            apply_text(&rs, "url", "https://h/api/v1/x"),
            "https://h/api/v2/x"
        );
    }

    #[test]
    fn header_modify_and_remove() {
        let h = vec![
            Header {
                name: "User-Agent".into(),
                value: "curl".into(),
            },
            Header {
                name: "X-Debug".into(),
                value: "1".into(),
            },
        ];
        let out = rewrite_headers(
            &[rule("req_header", "curl", "SecureSuite", false)],
            "req_header",
            &h,
        );
        assert_eq!(out[0].value, "SecureSuite");

        let out2 = rewrite_headers(
            &[rule("req_header", "(?m)^X-Debug:.*$", "", true)],
            "req_header",
            &h,
        );
        assert!(out2.iter().all(|x| x.name != "X-Debug"));
        assert_eq!(out2.len(), 1);
    }

    #[test]
    fn disabled_rule_is_noop() {
        let mut r = rule("resp_body", "a", "b", false);
        r.enabled = false;
        assert_eq!(
            apply_text(std::slice::from_ref(&r), "resp_body", "aaa"),
            "aaa"
        );
    }
}
