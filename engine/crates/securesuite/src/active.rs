//! Active-scanner primitives: insertion-point discovery, payload construction,
//! request mutation, and detection predicates. All pure + unit-tested; the
//! async probing (actually sending the mutated requests) lives in `web.rs`.
//!
//! Checks derive from OWASP Testing Guide concepts and public database error
//! strings — no payloads or logic copied from any proprietary scanner.

/// A discovered injection point in a request.
#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    /// "query" (URL query param) or "body" (form param).
    pub loc: &'static str,
    pub name: String,
}

fn parse_pairs(qs: &str) -> Vec<(String, String)> {
    qs.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (kv.to_string(), String::new()),
        })
        .collect()
}

fn split_url(url: &str) -> (&str, &str) {
    match url.split_once('?') {
        Some((base, qs)) => (base, qs),
        None => (url, ""),
    }
}

/// Insertion points: query params always; body params when form-encoded.
pub fn points(url: &str, body: &str, is_form: bool) -> Vec<Point> {
    let mut pts = Vec::new();
    let (_base, qs) = split_url(url);
    for (k, _) in parse_pairs(qs) {
        pts.push(Point {
            loc: "query",
            name: k,
        });
    }
    if is_form {
        for (k, _) in parse_pairs(body) {
            pts.push(Point {
                loc: "body",
                name: k,
            });
        }
    }
    pts
}

/// Rebuild `url` with `name`'s query value replaced by `value` (pre-encoded).
pub fn with_query_param(url: &str, name: &str, value: &str) -> String {
    let (base, qs) = split_url(url);
    let rebuilt: Vec<String> = parse_pairs(qs)
        .iter()
        .map(|(k, v)| {
            if k == name {
                format!("{k}={value}")
            } else {
                format!("{k}={v}")
            }
        })
        .collect();
    format!("{base}?{}", rebuilt.join("&"))
}

/// Rebuild a form `body` with `name`'s value replaced by `value`.
pub fn with_body_param(body: &str, name: &str, value: &str) -> String {
    parse_pairs(body)
        .iter()
        .map(|(k, v)| {
            if k == name {
                format!("{k}={value}")
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Inject `encoded_value` into the request at point `p`; returns (url, body).
pub fn inject(url: &str, body: &str, p: &Point, encoded_value: &str) -> (String, String) {
    match p.loc {
        "body" => (
            url.to_string(),
            with_body_param(body, &p.name, encoded_value),
        ),
        _ => (
            with_query_param(url, &p.name, encoded_value),
            body.to_string(),
        ),
    }
}

/// Percent-encode a raw value for safe placement in a URL/form param.
pub fn encode_value(v: &str) -> String {
    let mut o = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Common SQL error signatures (factual DB-engine messages, lowercased).
pub const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query():",
    "sqlstate",
    "sqlite error",
    "sqlite3::",
    "ora-01756",
    "ora-00933",
    "odbc sql server driver",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
    "npgsql.",
];

/// First SQL-error signature present in `body` (case-insensitive), if any.
pub fn sql_error_signature(body: &str) -> Option<&'static str> {
    let low = body.to_ascii_lowercase();
    SQL_ERRORS.iter().copied().find(|sig| low.contains(*sig))
}

/// An XSS probe payload carrying `token` plus raw break-out markup.
pub fn xss_payload(token: &str) -> String {
    format!("{token}<svg/onload=1>\"'")
}

/// True if the raw (unescaped) break-out appears in `body` — reflected XSS.
pub fn xss_reflected_raw(body: &str, token: &str) -> bool {
    body.contains(&format!("{token}<svg/onload=1>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_query_and_body_points() {
        let p = points("http://h/s?a=1&b=2", "c=3&d=4", true);
        let names: Vec<_> = p.iter().map(|x| (x.loc, x.name.as_str())).collect();
        assert!(names.contains(&("query", "a")) && names.contains(&("query", "b")));
        assert!(names.contains(&("body", "c")) && names.contains(&("body", "d")));
    }

    #[test]
    fn body_points_skipped_when_not_form() {
        let p = points("http://h/s?a=1", "c=3", false);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "a");
    }

    #[test]
    fn rebuilds_single_param_only() {
        assert_eq!(
            with_query_param("http://h/s?a=1&b=2", "b", "X"),
            "http://h/s?a=1&b=X"
        );
        assert_eq!(with_body_param("a=1&b=2", "a", "Z"), "a=Z&b=2");
    }

    #[test]
    fn inject_targets_right_location() {
        let p = Point {
            loc: "query",
            name: "q".into(),
        };
        let (u, b) = inject("http://h/s?q=1", "x=2", &p, "P");
        assert_eq!(u, "http://h/s?q=P");
        assert_eq!(b, "x=2");
    }

    #[test]
    fn encode_escapes_markup() {
        assert_eq!(encode_value("<a>\"'"), "%3Ca%3E%22%27");
    }

    #[test]
    fn detects_sql_error() {
        assert!(sql_error_signature("You have an error in your SQL syntax; near").is_some());
        assert!(sql_error_signature("all good here").is_none());
    }

    #[test]
    fn detects_raw_xss_reflection_but_not_encoded() {
        let t = "ssx123";
        let pay = xss_payload(t);
        assert!(xss_reflected_raw(&format!("<p>{pay}</p>"), t));
        let enc = format!("<p>{t}&lt;svg/onload=1&gt;</p>");
        assert!(!xss_reflected_raw(&enc, t));
    }
}
