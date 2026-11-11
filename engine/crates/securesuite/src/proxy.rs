//! The intercepting proxy handler: records request/response exchanges into the
//! [`Store`], supports request AND response interception (hold/edit/drop),
//! applies Match & Replace rules to both directions, and broadcasts live.
//!
//! Built on the `hudsucker` MITM core (HTTP/1.1 + HTTP/2, CONNECT TLS
//! interception). The tested `ss-ca` crate will replace the inline CA next.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hudsucker::hyper::{Request, Response};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};

use crate::model::{Exchange, Header, HeldReq};
use crate::rules::{apply_text, has_rule, rewrite_headers};
use crate::store::{Decision, Store};

/// Cap how much body we retain per message for display (not for forwarding).
const MAX_BODY: usize = 1_000_000;

#[derive(Clone)]
pub struct Recorder {
    store: Arc<Store>,
    pending: Option<Pending>,
}

#[derive(Clone)]
struct Pending {
    id: u64,
    started: Instant,
    ts_ms: u128,
    method: String,
    url: String,
    host: String,
    scheme: String,
    req_headers: Vec<Header>,
    req_body: String,
    req_body_len: usize,
}

impl Recorder {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            pending: None,
        }
    }
}

fn to_body(bytes: Bytes) -> Body {
    Body::from(Full::new(bytes))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn headers_of(map: &hudsucker::hyper::HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(k, v)| Header {
            name: k.as_str().to_string(),
            value: String::from_utf8_lossy(v.as_bytes()).to_string(),
        })
        .collect()
}

fn edited_headers(pairs: &[(String, String)]) -> Vec<Header> {
    pairs
        .iter()
        .map(|(n, v)| Header {
            name: n.clone(),
            value: v.clone(),
        })
        .collect()
}

impl HttpHandler for Recorder {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // CONNECT requests set up the TLS tunnel; hudsucker MITMs them and then
        // delivers the real decrypted requests here. Don't record the tunnel.
        if req.method() == hudsucker::hyper::Method::CONNECT {
            return req.into();
        }

        let (parts, body) = req.into_parts();
        let bytes = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();

        let host = parts
            .uri
            .host()
            .map(|s| s.to_string())
            .or_else(|| {
                parts
                    .headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        let scheme = parts.uri.scheme_str().unwrap_or("http").to_string();

        let mut method = parts.method.to_string();
        let mut url = parts.uri.to_string();
        let mut req_headers = headers_of(&parts.headers);
        let mut req_body = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BODY)]).to_string();
        let mut edited = false;

        // Interception: pause this request until the UI decides.
        if self.store.intercept() {
            let (_hold_id, rx) = self.store.hold(HeldReq {
                hold_id: 0,
                kind: "request".to_string(),
                method: method.clone(),
                url: url.clone(),
                status: 0,
                headers: req_headers.clone(),
                body: req_body.clone(),
            });
            match rx.await {
                Ok(Decision::Drop) => {
                    let resp = Response::builder()
                        .status(403)
                        .body(to_body(Bytes::from_static(
                            b"Request dropped by SecureSuite\n",
                        )))
                        .expect("drop response");
                    return RequestOrResponse::Response(resp);
                }
                Ok(Decision::Forward(Some(edit))) => {
                    method = edit.method;
                    url = edit.url;
                    req_headers = edited_headers(&edit.headers);
                    req_body = edit.body;
                    edited = true;
                }
                _ => {} // Forward(None) or the channel dropped: forward unchanged
            }
        }

        // Match & Replace (request side).
        let rules = self.store.rules();
        let url_before = url.clone();
        url = apply_text(&rules, "url", &url);
        let new_headers = rewrite_headers(&rules, "req_header", &req_headers);
        let new_body = apply_text(&rules, "req_body", &req_body);
        let url_changed = url != url_before;
        let headers_changed = new_headers != req_headers;
        let body_changed = new_body != req_body;
        req_headers = new_headers;
        req_body = new_body;

        let modified = edited || url_changed || headers_changed || body_changed;
        let out_bytes: Bytes = if edited || body_changed {
            Bytes::from(req_body.clone().into_bytes())
        } else {
            bytes.clone()
        };

        self.pending = Some(Pending {
            id: self.store.next_id(),
            started: Instant::now(),
            ts_ms: now_ms(),
            method: method.clone(),
            url: url.clone(),
            host,
            scheme,
            req_headers: req_headers.clone(),
            req_body: req_body.clone(),
            req_body_len: out_bytes.len(),
        });

        if modified {
            let mut rb = Request::builder().method(method.as_str()).uri(url.as_str());
            for h in &req_headers {
                if !h.name.is_empty() && !h.name.eq_ignore_ascii_case("content-length") {
                    rb = rb.header(h.name.as_str(), h.value.as_str());
                }
            }
            match rb.body(to_body(out_bytes)) {
                Ok(r) => r.into(),
                Err(_) => Request::from_parts(parts, to_body(bytes)).into(),
            }
        } else {
            Request::from_parts(parts, to_body(bytes)).into()
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let (parts, body) = res.into_parts();
        let bytes = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();

        let rules = self.store.rules();
        let status = parts.status.as_u16();
        let mime = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Match & Replace (response side), applied before any manual intercept.
        let orig_headers = headers_of(&parts.headers);
        let ruled_headers = rewrite_headers(&rules, "resp_header", &orig_headers);
        let rules_hdr_changed = ruled_headers != orig_headers;

        let (ruled_bytes, ruled_display, rules_body_changed) = if has_rule(&rules, "resp_body") {
            let full = String::from_utf8_lossy(&bytes).to_string();
            let rewritten = apply_text(&rules, "resp_body", &full);
            let changed = rewritten != full;
            let display: String = rewritten.chars().take(MAX_BODY).collect();
            (Bytes::from(rewritten.into_bytes()), display, changed)
        } else {
            let shown = &bytes[..bytes.len().min(MAX_BODY)];
            (
                bytes.clone(),
                String::from_utf8_lossy(shown).to_string(),
                false,
            )
        };

        // Response interception: pause the (rule-applied) response for the UI.
        let mut final_status = status;
        let mut final_headers = ruled_headers;
        let mut final_bytes = ruled_bytes;
        let mut final_display = ruled_display;
        let mut changed = rules_hdr_changed || rules_body_changed;
        let mut dropped = false;

        if self.store.intercept_resp() {
            let (pm, pu) = self
                .pending
                .as_ref()
                .map(|p| (p.method.clone(), p.url.clone()))
                .unwrap_or_default();
            let (_id, rx) = self.store.hold(HeldReq {
                hold_id: 0,
                kind: "response".to_string(),
                method: pm,
                url: pu,
                status: final_status,
                headers: final_headers.clone(),
                body: final_display.clone(),
            });
            match rx.await {
                Ok(Decision::Drop) => dropped = true,
                Ok(Decision::Forward(Some(edit))) => {
                    if edit.status != 0 {
                        final_status = edit.status;
                    }
                    final_headers = edited_headers(&edit.headers);
                    final_display = edit.body.clone();
                    final_bytes = Bytes::from(edit.body.into_bytes());
                    changed = true;
                }
                _ => {}
            }
        }

        if let Some(p) = self.pending.take() {
            self.store.push(Exchange {
                id: p.id,
                ts_ms: p.ts_ms,
                method: p.method,
                url: p.url,
                host: p.host,
                scheme: p.scheme,
                status: final_status,
                mime,
                req_headers: p.req_headers,
                req_body: p.req_body,
                req_body_len: p.req_body_len,
                resp_headers: final_headers.clone(),
                resp_body: final_display,
                resp_body_len: final_bytes.len(),
                duration_ms: p.started.elapsed().as_millis() as u64,
            });
        }

        if dropped {
            return Response::builder()
                .status(502)
                .body(to_body(Bytes::from_static(
                    b"Response dropped by SecureSuite\n",
                )))
                .expect("drop response");
        }
        if changed {
            let mut rb = Response::builder().status(final_status);
            for h in &final_headers {
                if !h.name.is_empty() && !h.name.eq_ignore_ascii_case("content-length") {
                    rb = rb.header(h.name.as_str(), h.value.as_str());
                }
            }
            rb.body(to_body(final_bytes))
                .unwrap_or_else(|_| Response::from_parts(parts, to_body(bytes)))
        } else {
            Response::from_parts(parts, to_body(bytes))
        }
    }
}
