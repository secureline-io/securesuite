//! Passive scanner: inspects captured exchanges and flags common issues
//! without sending any traffic of its own.
//!
//! Checks are derived from public guidance (OWASP Secure Headers project, MDN
//! web docs, RFC 6265bis cookie attributes) — not from any proprietary tool.

use crate::model::{Exchange, Header};

/// A single passive finding. The store assigns identity/host/url when recording.
pub struct Finding {
    pub severity: &'static str,
    pub name: String,
    pub detail: String,
}

fn header<'a>(hs: &'a [Header], name: &str) -> Option<&'a str> {
    hs.iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn has(hs: &[Header], name: &str) -> bool {
    header(hs, name).is_some()
}

/// Run every passive check against one exchange.
pub fn passive_scan(ex: &Exchange) -> Vec<Finding> {
    let mut f = Vec::new();
    if ex.status == 0 {
        return f; // no response captured
    }
    let https = ex.scheme.eq_ignore_ascii_case("https");
    let html = ex.mime.to_ascii_lowercase().contains("text/html");
    let h = &ex.resp_headers;

    if html && !has(h, "content-security-policy") {
        f.push(Finding {
            severity: "low",
            name: "Missing Content-Security-Policy".into(),
            detail:
                "HTML response has no CSP header; weakens defense-in-depth against XSS/injection."
                    .into(),
        });
    }
    if html && !has(h, "x-frame-options") {
        let csp = header(h, "content-security-policy").unwrap_or("");
        if !csp.to_ascii_lowercase().contains("frame-ancestors") {
            f.push(Finding {
                severity: "medium",
                name: "Missing clickjacking protection".into(),
                detail: "No X-Frame-Options and no CSP frame-ancestors; the page can be framed (clickjacking)."
                    .into(),
            });
        }
    }
    if !has(h, "x-content-type-options") {
        f.push(Finding {
            severity: "info",
            name: "Missing X-Content-Type-Options".into(),
            detail: "Response lacks 'nosniff'; browsers may MIME-sniff the body.".into(),
        });
    }
    if https && !has(h, "strict-transport-security") {
        f.push(Finding {
            severity: "low",
            name: "Missing HSTS".into(),
            detail: "HTTPS response has no Strict-Transport-Security header.".into(),
        });
    }
    if html && !has(h, "referrer-policy") {
        f.push(Finding {
            severity: "info",
            name: "Missing Referrer-Policy".into(),
            detail: "No Referrer-Policy header set.".into(),
        });
    }

    for hdr in h
        .iter()
        .filter(|x| x.name.eq_ignore_ascii_case("set-cookie"))
    {
        let v = hdr.value.to_ascii_lowercase();
        let cname = hdr.value.split('=').next().unwrap_or("cookie").trim();
        if https && !v.contains("secure") {
            f.push(Finding {
                severity: "medium",
                name: "Cookie without Secure flag".into(),
                detail: format!("Set-Cookie '{cname}' over HTTPS lacks the Secure attribute."),
            });
        }
        if !v.contains("httponly") {
            f.push(Finding {
                severity: "low",
                name: "Cookie without HttpOnly flag".into(),
                detail: format!("Set-Cookie '{cname}' lacks HttpOnly; readable from JavaScript."),
            });
        }
        if !v.contains("samesite") {
            f.push(Finding {
                severity: "info",
                name: "Cookie without SameSite attribute".into(),
                detail: format!("Set-Cookie '{cname}' has no SameSite attribute."),
            });
        }
    }

    if let Some(s) = header(h, "server") {
        if s.chars().any(|c| c.is_ascii_digit()) {
            f.push(Finding {
                severity: "info",
                name: "Server version disclosure".into(),
                detail: format!("Server header reveals software/version: {s}"),
            });
        }
    }
    if let Some(p) = header(h, "x-powered-by") {
        f.push(Finding {
            severity: "info",
            name: "Technology disclosure (X-Powered-By)".into(),
            detail: format!("X-Powered-By: {p}"),
        });
    }

    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(headers: Vec<(&str, &str)>, scheme: &str, mime: &str) -> Exchange {
        Exchange {
            id: 1,
            ts_ms: 0,
            method: "GET".into(),
            url: format!("{scheme}://host/"),
            host: "host".into(),
            scheme: scheme.into(),
            status: 200,
            mime: mime.into(),
            req_headers: vec![],
            req_body: String::new(),
            req_body_len: 0,
            resp_headers: headers
                .into_iter()
                .map(|(n, v)| Header {
                    name: n.into(),
                    value: v.into(),
                })
                .collect(),
            resp_body: String::new(),
            resp_body_len: 0,
            duration_ms: 1,
        }
    }

    #[test]
    fn flags_missing_headers_on_html() {
        let f = passive_scan(&mk(vec![], "https", "text/html"));
        let names: Vec<_> = f.iter().map(|x| x.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("Content-Security-Policy")));
        assert!(names.iter().any(|n| n.contains("clickjacking")));
        assert!(names.iter().any(|n| n.contains("HSTS")));
        assert!(names.iter().any(|n| n.contains("X-Content-Type-Options")));
    }

    #[test]
    fn clean_headers_suppress_those_findings() {
        let f = passive_scan(&mk(
            vec![
                (
                    "content-security-policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
                ("x-content-type-options", "nosniff"),
                ("strict-transport-security", "max-age=63072000"),
                ("referrer-policy", "no-referrer"),
            ],
            "https",
            "text/html",
        ));
        let names: Vec<String> = f.iter().map(|x| x.name.clone()).collect();
        assert!(
            !names.iter().any(|n| n.contains("Content-Security-Policy")),
            "unexpected: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("clickjacking")),
            "unexpected: {names:?}"
        );
        assert!(!names.iter().any(|n| n.contains("HSTS")));
    }

    #[test]
    fn flags_insecure_cookie_and_banner() {
        let f = passive_scan(&mk(
            vec![
                ("set-cookie", "sid=abc; Path=/"),
                ("server", "nginx/1.18.0"),
            ],
            "https",
            "text/html",
        ));
        assert!(f.iter().any(|x| x.name.contains("Secure")));
        assert!(f.iter().any(|x| x.name.contains("HttpOnly")));
        assert!(f.iter().any(|x| x.name.contains("version disclosure")));
    }
}
