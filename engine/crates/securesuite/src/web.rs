//! Local web UI + JSON/WebSocket API that drives the engine.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::uri::Authority;
use axum::http::{header, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Deserialize;

use crate::model::{Exchange, HeldReq, Issue, Rule};
use crate::store::{Decision, EditedReq, Store};

#[derive(Clone)]
pub struct WebState {
    pub store: Arc<Store>,
    pub ca_pem: String,
    pub client: reqwest::Client,
    pub proxy_port: u16,
    pub oast_port: u16,
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/info", get(info))
        .route("/api/exchanges", get(list))
        .route("/api/exchanges/{id}", get(detail))
        .route("/api/export", get(export_csv))
        .route("/api/log", get(log_list))
        .route("/api/ws", get(ws_handler))
        .route("/api/ca.pem", get(ca_pem))
        .route("/api/intercept", get(intercept_status).post(set_intercept))
        .route("/api/intercept/queue", get(intercept_queue))
        .route("/api/intercept/resolve", post(resolve_hold))
        .route("/api/repeater", post(repeater))
        .route("/api/intruder", post(intruder))
        .route("/api/decode", post(decode))
        .route("/api/scope", get(get_scope).post(set_scope_h))
        .route("/api/issues", get(list_issues))
        .route("/api/rules", get(get_rules).post(set_rules_h))
        .route("/api/sitemap", get(sitemap))
        .route("/api/discover", post(discover))
        .route("/api/compare", post(compare))
        .route("/api/sequencer", post(sequencer_h))
        .route("/api/activescan", post(active_scan))
        .route(
            "/api/extensions",
            get(get_extensions).post(set_extensions_h),
        )
        .route("/api/oast/generate", get(oast_generate))
        .route("/api/oast/interactions", get(oast_list))
        .route("/api/wslog", get(ws_log))
        .route(
            "/api/ws/intercept",
            get(ws_intercept_status).post(set_ws_intercept_h),
        )
        .route("/api/ws/intercept/queue", get(ws_intercept_queue))
        .route("/api/ws/intercept/resolve", post(ws_resolve))
        .layer(middleware::from_fn(local_only))
        .with_state(state)
}

/// The console holds captured traffic and has no login, so it answers only
/// callers that address it by a loopback name: a foreign `Host` is DNS
/// rebinding, a foreign `Origin` is another site's page (browsers send `Origin`
/// on every WebSocket upgrade and cross-site request).
// shortcut: stops browser-borne callers only, not other local processes; add a per-launch token before the API can listen off loopback.
fn is_local_request(host: Option<&str>, origin: Option<&str>) -> bool {
    let loopback = |h: Option<&str>| matches!(h, Some("127.0.0.1" | "localhost" | "[::1]"));
    let host_ok = host
        .and_then(|h| h.parse::<Authority>().ok())
        .is_some_and(|a| loopback(Some(a.host())));
    let origin_ok =
        origin.is_none_or(|o| o.parse::<Uri>().ok().is_some_and(|u| loopback(u.host())));
    host_ok && origin_ok
}

async fn local_only(req: Request, next: Next) -> Response {
    let local = {
        let headers = req.headers();
        let value = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
        is_local_request(value(header::HOST), value(header::ORIGIN))
    };
    if local {
        next.run(req).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("assets/index.html"))
}

async fn info(State(s): State<WebState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "proxy_port": s.proxy_port,
        "oast_port": s.oast_port,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list(State(s): State<WebState>) -> Json<Vec<Exchange>> {
    Json(s.store.all())
}

async fn log_list(State(s): State<WebState>) -> Json<Vec<crate::model::LogEntry>> {
    Json(s.store.log_entries())
}

async fn detail(State(s): State<WebState>, Path(id): Path<u64>) -> Response {
    match s.store.get(id) {
        Some(ex) => Json(ex).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Export captured history as CSV (one row per exchange).
async fn export_csv(State(s): State<WebState>) -> Response {
    fn esc(x: &str) -> String {
        format!("\"{}\"", x.replace('"', "\"\""))
    }
    let mut out =
        String::from("id,ts_ms,method,status,host,scheme,url,mime,req_len,resp_len,duration_ms\n");
    for e in s.store.all() {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            e.id,
            e.ts_ms,
            esc(&e.method),
            e.status,
            esc(&e.host),
            esc(&e.scheme),
            esc(&e.url),
            esc(&e.mime),
            e.req_body_len,
            e.resp_body_len,
            e.duration_ms,
        ));
    }
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"securesuite-history.csv\"",
            ),
        ],
        out,
    )
        .into_response()
}

async fn ca_pem(State(s): State<WebState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"securesuite-ca.pem\"",
            ),
        ],
        s.ca_pem.clone(),
    )
        .into_response()
}

#[derive(Deserialize)]
struct InterceptReq {
    #[serde(default)]
    requests: Option<bool>,
    #[serde(default)]
    responses: Option<bool>,
}

async fn intercept_status(State(s): State<WebState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "requests": s.store.intercept(),
        "responses": s.store.intercept_resp(),
    }))
}

async fn set_intercept(
    State(s): State<WebState>,
    Json(req): Json<InterceptReq>,
) -> Json<serde_json::Value> {
    if let Some(v) = req.requests {
        s.store.set_intercept(v);
    }
    if let Some(v) = req.responses {
        s.store.set_intercept_resp(v);
    }
    Json(serde_json::json!({
        "requests": s.store.intercept(),
        "responses": s.store.intercept_resp(),
    }))
}

async fn intercept_queue(State(s): State<WebState>) -> Json<Vec<HeldReq>> {
    Json(s.store.held())
}

/// A header accepted from the UI in EITHER `["name","value"]` pair form OR
/// `{"name":"..","value":".."}` object form. The intercept queue emits the
/// object shape, so this lets a held request round-trip straight back into
/// `/api/intercept/resolve` without the client reshaping headers (previously a
/// `{name,value}` body returned HTTP 422).
#[derive(Clone)]
struct HeaderPair {
    name: String,
    value: String,
}

impl<'de> Deserialize<'de> for HeaderPair {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Pair([String; 2]),
            Obj { name: String, value: String },
        }
        let (name, value) = match Raw::deserialize(d)? {
            Raw::Pair([a, b]) => (a, b),
            Raw::Obj { name, value } => (name, value),
        };
        Ok(HeaderPair { name, value })
    }
}

#[derive(Deserialize)]
struct ResolveReq {
    hold_id: u64,
    action: String,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    headers: Vec<HeaderPair>,
    #[serde(default)]
    body: String,
}

async fn resolve_hold(
    State(s): State<WebState>,
    Json(r): Json<ResolveReq>,
) -> Json<serde_json::Value> {
    let decision = if r.action == "drop" {
        Decision::Drop
    } else {
        Decision::Forward(Some(EditedReq {
            method: r.method,
            url: r.url,
            status: r.status,
            headers: r.headers.into_iter().map(|h| (h.name, h.value)).collect(),
            body: r.body,
        }))
    };
    let ok = s.store.resolve(r.hold_id, decision);
    Json(serde_json::json!({ "ok": ok }))
}

#[derive(Deserialize)]
struct ScopeReq {
    patterns: Vec<String>,
}

async fn get_scope(State(s): State<WebState>) -> Json<Vec<String>> {
    Json(s.store.scope())
}

async fn set_scope_h(
    State(s): State<WebState>,
    Json(r): Json<ScopeReq>,
) -> Json<serde_json::Value> {
    s.store.set_scope(r.patterns);
    Json(serde_json::json!({ "scope": s.store.scope() }))
}

async fn list_issues(State(s): State<WebState>) -> Json<Vec<Issue>> {
    Json(s.store.issues())
}

#[derive(Deserialize)]
struct RuleIn {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    part: String,
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    replace: String,
    #[serde(default)]
    regex: bool,
}

async fn get_rules(State(s): State<WebState>) -> Json<Vec<Rule>> {
    Json(s.store.rules())
}

async fn set_rules_h(
    State(s): State<WebState>,
    Json(rs): Json<Vec<RuleIn>>,
) -> Json<serde_json::Value> {
    let rules: Vec<Rule> = rs
        .into_iter()
        .enumerate()
        .map(|(i, r)| Rule {
            id: i as u64 + 1,
            enabled: r.enabled,
            part: r.part,
            pattern: r.pattern,
            replace: r.replace,
            regex: r.regex,
        })
        .collect();
    s.store.set_rules(rules.clone());
    Json(serde_json::json!({ "count": rules.len(), "rules": rules }))
}

// ---- Target: site map + content discovery ----

fn path_of(url: &str) -> String {
    if let Some(i) = url.find("://") {
        let rest = &url[i + 3..];
        match rest.find('/') {
            Some(j) => rest[j..].to_string(),
            None => "/".to_string(),
        }
    } else if url.starts_with('/') {
        url.to_string()
    } else {
        format!("/{url}")
    }
}

/// Site map: hosts -> paths (with methods, statuses, hit count) from history.
async fn sitemap(State(s): State<WebState>) -> Json<serde_json::Value> {
    use std::collections::{BTreeMap, BTreeSet};
    type PathInfo = (BTreeSet<String>, BTreeSet<u16>, u32);
    let mut hosts: BTreeMap<String, BTreeMap<String, PathInfo>> = BTreeMap::new();
    for e in s.store.all() {
        let host = if e.host.is_empty() {
            "(unknown)".to_string()
        } else {
            e.host.clone()
        };
        let info = hosts
            .entry(host)
            .or_default()
            .entry(path_of(&e.url))
            .or_insert_with(|| (BTreeSet::new(), BTreeSet::new(), 0));
        info.0.insert(e.method.clone());
        if e.status != 0 {
            info.1.insert(e.status);
        }
        info.2 += 1;
    }
    let hosts_json: Vec<_> = hosts
        .into_iter()
        .map(|(host, paths)| {
            let plist: Vec<_> = paths
                .into_iter()
                .map(|(path, (m, st, c))| {
                    serde_json::json!({
                        "path": path,
                        "methods": m.into_iter().collect::<Vec<_>>(),
                        "statuses": st.into_iter().collect::<Vec<_>>(),
                        "count": c,
                    })
                })
                .collect();
            serde_json::json!({ "host": host, "paths": plist })
        })
        .collect();
    Json(serde_json::json!({ "hosts": hosts_json }))
}

/// Built-in content-discovery wordlist (common paths; authored, not copied).
const DEFAULT_WORDLIST: &[&str] = &[
    "robots.txt",
    "sitemap.xml",
    ".git/HEAD",
    ".env",
    "admin",
    "administrator",
    "login",
    "api",
    "api/v1",
    "config",
    "config.json",
    "backup",
    "backup.zip",
    "db",
    "test",
    "debug",
    "status",
    "health",
    "metrics",
    "server-status",
    ".well-known/security.txt",
    "wp-admin",
    "wp-login.php",
    "phpinfo.php",
    "info.php",
    "console",
    "dashboard",
    "uploads",
    "static",
    "assets",
    "swagger",
    "swagger.json",
    "openapi.json",
    "graphql",
    "actuator",
    "actuator/health",
    ".svn/entries",
    "WEB-INF/web.xml",
    "old",
    "tmp",
];

#[derive(Deserialize)]
struct DiscoverReq {
    base: String,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    concurrency: usize,
}

/// Content discovery: probe a base URL for each wordlist path, report hits.
async fn discover(State(s): State<WebState>, Json(req): Json<DiscoverReq>) -> Response {
    let base = req.base.trim().trim_end_matches('/').to_string();
    if base.is_empty() {
        return (StatusCode::BAD_REQUEST, "base url required").into_response();
    }
    let words: Vec<String> = if req.paths.is_empty() {
        DEFAULT_WORDLIST.iter().map(|w| w.to_string()).collect()
    } else {
        req.paths
    };
    let concurrency = if req.concurrency == 0 {
        12
    } else {
        req.concurrency.clamp(1, 50)
    };
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut set = tokio::task::JoinSet::new();
    for (i, w) in words.into_iter().take(2000).enumerate() {
        let url = format!("{base}/{}", w.trim_start_matches('/'));
        let client = s.client.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _p = sem.acquire_owned().await.ok();
            let res = send_once(&client, "GET", &url, &[], "").await;
            (i, w, url, res)
        });
    }
    let mut rows: Vec<(usize, serde_json::Value)> = Vec::new();
    while let Some(j) = set.join_next().await {
        if let Ok((i, word, url, res)) = j {
            let row = match res {
                Ok((status, _h, body, ms)) => serde_json::json!({
                    "i": i, "path": word, "url": url, "status": status,
                    "len": body.len(), "ms": ms, "found": status != 404 && status != 0,
                }),
                Err(e) => serde_json::json!({
                    "i": i, "path": word, "url": url, "status": 0,
                    "len": 0, "ms": 0, "found": false, "error": e,
                }),
            };
            rows.push((i, row));
        }
    }
    rows.sort_by_key(|x| x.0);
    let results: Vec<_> = rows.into_iter().map(|x| x.1).collect();
    let found = results
        .iter()
        .filter(|r| r.get("found").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();
    s.store.push_log("discover", "GET", &base, 0, found, 0);
    Json(serde_json::json!({ "count": results.len(), "found": found, "results": results }))
        .into_response()
}

// ---- Comparer + Sequencer ----

#[derive(Deserialize)]
struct CompareReq {
    a: String,
    b: String,
    #[serde(default)]
    mode: String,
}

async fn compare(Json(r): Json<CompareReq>) -> Json<serde_json::Value> {
    let mode = if r.mode.is_empty() {
        "lines".to_string()
    } else {
        r.mode
    };
    let segs = crate::comparer::diff(&r.a, &r.b, &mode);
    let added = segs.iter().filter(|s| s.op == "add").count();
    let removed = segs.iter().filter(|s| s.op == "del").count();
    Json(serde_json::json!({ "mode": mode, "added": added, "removed": removed, "segments": segs }))
}

#[derive(Deserialize)]
struct SeqReq {
    tokens: Vec<String>,
}

async fn sequencer_h(Json(r): Json<SeqReq>) -> Json<serde_json::Value> {
    let report = crate::sequencer::analyze(&r.tokens);
    Json(serde_json::to_value(report).unwrap_or_default())
}

// ---- Active scanner (crawl is history-driven; this is the inject/audit side) ----

#[derive(Deserialize)]
struct ActiveScanReq {
    #[serde(default)]
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<[String; 2]>,
    #[serde(default)]
    body: String,
}

/// Inject SQLi + reflected-XSS probes into each parameter and audit responses.
async fn active_scan(
    State(s): State<WebState>,
    Json(r): Json<ActiveScanReq>,
) -> Json<serde_json::Value> {
    use crate::active;
    let method = if r.method.is_empty() {
        "GET".to_string()
    } else {
        r.method
    };
    let headers = r.headers;
    let is_form = headers.iter().any(|h| {
        h[0].eq_ignore_ascii_case("content-type")
            && h[1].to_ascii_lowercase().contains("x-www-form-urlencoded")
    });
    let host = r
        .url
        .split("://")
        .nth(1)
        .and_then(|x| x.split('/').next())
        .unwrap_or("")
        .to_string();
    let points = active::points(&r.url, &r.body, is_form);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut findings: Vec<serde_json::Value> = Vec::new();
    for (idx, p) in points.iter().enumerate() {
        // SQL injection (error-based): inject a single quote.
        let (u, b) = active::inject(&r.url, &r.body, p, "%27");
        if let Ok((st, _h, body, ms)) = send_once(&s.client, &method, &u, &headers, &b).await {
            s.store.push_log("scanner", &method, &u, st, body.len(), ms);
            if let Some(sig) = active::sql_error_signature(&body) {
                let detail = format!(
                    "parameter '{}' ({}) triggered a database error ('{}') when injected with a single quote",
                    p.name, p.loc, sig
                );
                s.store.add_issue(
                    "high",
                    "SQL Injection (error-based)",
                    detail.clone(),
                    &host,
                    &r.url,
                    &format!("sqli:{}:{}", p.loc, p.name),
                );
                findings.push(serde_json::json!({
                    "severity": "high", "type": "SQL Injection (error-based)",
                    "param": p.name, "loc": p.loc, "detail": detail,
                }));
            }
        }

        // Reflected XSS: inject unique raw markup, look for unescaped reflection.
        let token = format!("ssx{idx}{nonce:x}");
        let payload = active::xss_payload(&token);
        let (u, b) = active::inject(&r.url, &r.body, p, &active::encode_value(&payload));
        if let Ok((st, resp_headers, body, ms)) =
            send_once(&s.client, &method, &u, &headers, &b).await
        {
            s.store.push_log("scanner", &method, &u, st, body.len(), ms);
            // Only a real XSS risk if the reflection lands in an HTML response.
            let html = resp_headers.iter().any(|kv| {
                kv[0].eq_ignore_ascii_case("content-type")
                    && kv[1].to_ascii_lowercase().contains("html")
            });
            if html && active::xss_reflected_raw(&body, &token) {
                let detail = format!(
                    "parameter '{}' ({}) reflects injected markup unescaped (possible reflected XSS)",
                    p.name, p.loc
                );
                s.store.add_issue(
                    "high",
                    "Reflected XSS",
                    detail.clone(),
                    &host,
                    &r.url,
                    &format!("xss:{}:{}", p.loc, p.name),
                );
                findings.push(serde_json::json!({
                    "severity": "high", "type": "Reflected XSS",
                    "param": p.name, "loc": p.loc, "detail": detail,
                }));
            }
        }
    }

    Json(serde_json::json!({
        "points": points.len(),
        "findings_count": findings.len(),
        "findings": findings,
    }))
}

// ---- Extensions (HTTP webhooks) + OAST canary ----

async fn get_extensions(State(s): State<WebState>) -> Json<Vec<String>> {
    Json(s.store.extensions())
}

async fn set_extensions_h(
    State(s): State<WebState>,
    Json(urls): Json<Vec<String>>,
) -> Json<serde_json::Value> {
    s.store.set_extensions(urls);
    Json(serde_json::json!({ "extensions": s.store.extensions() }))
}

async fn oast_generate(State(s): State<WebState>) -> Json<serde_json::Value> {
    let token = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let url = format!("http://127.0.0.1:{}/{token}", s.oast_port);
    Json(serde_json::json!({ "token": token, "url": url }))
}

async fn oast_list(State(s): State<WebState>) -> Json<Vec<crate::model::Interaction>> {
    Json(s.store.oast_interactions())
}

async fn ws_log(State(s): State<WebState>) -> Json<Vec<crate::model::WsMessage>> {
    Json(s.store.ws_messages())
}

async fn ws_intercept_status(State(s): State<WebState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ws": s.store.ws_intercept() }))
}

#[derive(Deserialize)]
struct WsInterceptReq {
    #[serde(default)]
    ws: Option<bool>,
}

async fn set_ws_intercept_h(
    State(s): State<WebState>,
    Json(req): Json<WsInterceptReq>,
) -> Json<serde_json::Value> {
    if let Some(v) = req.ws {
        s.store.set_ws_intercept(v);
    }
    Json(serde_json::json!({ "ws": s.store.ws_intercept() }))
}

async fn ws_intercept_queue(State(s): State<WebState>) -> Json<Vec<crate::model::HeldWs>> {
    Json(s.store.ws_held())
}

#[derive(Deserialize)]
struct WsResolveReq {
    hold_id: u64,
    action: String,
    #[serde(default)]
    text: Option<String>,
}

async fn ws_resolve(
    State(s): State<WebState>,
    Json(r): Json<WsResolveReq>,
) -> Json<serde_json::Value> {
    let decision = if r.action == "drop" {
        crate::store::WsDecision::Drop
    } else {
        crate::store::WsDecision::Forward(r.text)
    };
    let ok = s.store.resolve_ws(r.hold_id, decision);
    Json(serde_json::json!({ "ok": ok }))
}

/// Separate HTTP listener: records every inbound request as an OAST interaction.
pub fn oast_router(store: Arc<Store>) -> Router {
    Router::new().fallback(oast_capture).with_state(store)
}

async fn oast_capture(
    State(store): State<Arc<Store>>,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    req: Request,
) -> &'static str {
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let method = req.method().to_string();
    let path = req.uri().to_string();
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    store.record_oast(crate::model::Interaction {
        ts_ms,
        method,
        path,
        remote: remote.to_string(),
        ua,
    });
    "SecureSuite OAST canary\n"
}

/// Background task: POST each captured exchange to registered extension
/// webhooks and ingest any issues they return.
pub fn spawn_extension_dispatcher(store: Arc<Store>, client: reqwest::Client) {
    tokio::spawn(async move {
        let mut rx = store.subscribe();
        loop {
            match rx.recv().await {
                Ok(ex) => {
                    let exts = store.extensions();
                    if exts.is_empty() {
                        continue;
                    }
                    let payload = serde_json::to_value(&ex).unwrap_or_default();
                    let host = ex.host.clone();
                    let url = ex.url.clone();
                    for ep in exts {
                        let client = client.clone();
                        let store = store.clone();
                        let payload = payload.clone();
                        let host = host.clone();
                        let url = url.clone();
                        tokio::spawn(async move {
                            let sent = client
                                .post(&ep)
                                .json(&payload)
                                .timeout(std::time::Duration::from_secs(5))
                                .send()
                                .await;
                            if let Ok(resp) = sent {
                                if let Ok(issues) = resp.json::<Vec<crate::model::ExtIssue>>().await
                                {
                                    for it in issues {
                                        store.add_issue(
                                            &it.severity,
                                            &it.name,
                                            it.detail,
                                            &host,
                                            &url,
                                            &format!("ext:{ep}:{}", it.name),
                                        );
                                    }
                                }
                            }
                        });
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });
}

/// Send one request built from a method/url/headers/body template.
/// Returns (status, headers, body-as-text, duration_ms) or an error string.
async fn send_once(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &[[String; 2]],
    body: &str,
) -> Result<(u16, Vec<[String; 2]>, String, u64), String> {
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut rb = client.request(m, url);
    for h in headers {
        if !h[0].is_empty() {
            rb = rb.header(h[0].as_str(), h[1].as_str());
        }
    }
    if !body.is_empty() {
        rb = rb.body(body.to_string());
    }
    let started = std::time::Instant::now();
    match rb.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let hdrs = resp
                .headers()
                .iter()
                .map(|(k, v)| {
                    [
                        k.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).to_string(),
                    ]
                })
                .collect();
            let body = resp.text().await.unwrap_or_default();
            Ok((status, hdrs, body, started.elapsed().as_millis() as u64))
        }
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Deserialize)]
struct RepeaterReq {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<[String; 2]>,
    #[serde(default)]
    body: String,
}

async fn repeater(State(s): State<WebState>, Json(req): Json<RepeaterReq>) -> Response {
    match send_once(&s.client, &req.method, &req.url, &req.headers, &req.body).await {
        Ok((status, headers, body, ms)) => {
            s.store
                .push_log("repeater", &req.method, &req.url, status, body.len(), ms);
            Json(serde_json::json!({
                "status": status, "headers": headers, "body": body, "duration_ms": ms,
            }))
            .into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("request failed: {e}")).into_response(),
    }
}

/// Count `§…§` injection positions across url + header values + body.
fn count_positions(url: &str, headers: &[[String; 2]], body: &str) -> usize {
    let c = |s: &str| s.matches('§').count() / 2;
    c(url) + headers.iter().map(|h| c(&h[1])).sum::<usize>() + c(body)
}

fn collect_bases(t: &str, out: &mut Vec<String>) {
    for (i, seg) in t.split('§').enumerate() {
        if i % 2 == 1 {
            out.push(seg.to_string());
        }
    }
}

/// The original text inside each `§…§` pair, in global order.
fn base_values(url: &str, headers: &[[String; 2]], body: &str) -> Vec<String> {
    let mut v = Vec::new();
    collect_bases(url, &mut v);
    for h in headers {
        collect_bases(&h[1], &mut v);
    }
    collect_bases(body, &mut v);
    v
}

fn render_field(t: &str, values: &[String], idx: &mut usize) -> String {
    let mut out = String::new();
    for (i, seg) in t.split('§').enumerate() {
        if i % 2 == 1 {
            let v = values.get(*idx).cloned().unwrap_or_else(|| seg.to_string());
            out.push_str(&v);
            *idx += 1;
        } else {
            out.push_str(seg);
        }
    }
    out
}

struct Rendered {
    url: String,
    headers: Vec<[String; 2]>,
    body: String,
}

fn render_all(url: &str, headers: &[[String; 2]], body: &str, values: &[String]) -> Rendered {
    let mut idx = 0usize;
    let url = render_field(url, values, &mut idx);
    let headers = headers
        .iter()
        .map(|h| [h[0].clone(), render_field(&h[1], values, &mut idx)])
        .collect();
    let body = render_field(body, values, &mut idx);
    Rendered { url, headers, body }
}

fn default_mode() -> String {
    "sniper".to_string()
}

#[derive(Deserialize)]
struct IntruderReq {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<[String; 2]>,
    #[serde(default)]
    body: String,
    #[serde(default = "default_mode")]
    mode: String,
    /// One payload set per entry (position-indexed for pitchfork/cluster-bomb).
    #[serde(default)]
    payloads: Vec<Vec<String>>,
    #[serde(default)]
    concurrency: usize,
}

/// Build the per-request value vectors (and a display label) for `mode`.
fn intruder_jobs(
    mode: &str,
    n: usize,
    bases: &[String],
    sets: &[Vec<String>],
) -> Vec<(Vec<String>, String)> {
    let empty = Vec::new();
    let set0 = sets.first().unwrap_or(&empty);
    let mut jobs: Vec<(Vec<String>, String)> = Vec::new();
    match mode {
        "batteringram" => {
            for p in set0 {
                jobs.push((vec![p.clone(); n], p.clone()));
            }
        }
        "pitchfork" => {
            let min_len = (0..n)
                .map(|p| sets.get(p).map(|s| s.len()).unwrap_or(0))
                .min()
                .unwrap_or(0);
            for i in 0..min_len {
                let mut vals = bases.to_vec();
                let mut label = Vec::new();
                for (p, slot) in vals.iter_mut().enumerate().take(n) {
                    if let Some(v) = sets.get(p).and_then(|s| s.get(i)) {
                        *slot = v.clone();
                        label.push(v.clone());
                    }
                }
                jobs.push((vals, label.join(", ")));
            }
        }
        "clusterbomb" => {
            let mut combos: Vec<Vec<String>> = vec![Vec::new()];
            for list in sets.iter().take(n) {
                let mut next = Vec::new();
                for combo in &combos {
                    for item in list {
                        let mut c = combo.clone();
                        c.push(item.clone());
                        next.push(c);
                        if next.len() > 5000 {
                            break;
                        }
                    }
                    if next.len() > 5000 {
                        break;
                    }
                }
                combos = next;
            }
            for combo in combos {
                if combo.len() != n {
                    continue;
                }
                let mut vals = bases.to_vec();
                for (p, v) in combo.iter().enumerate() {
                    vals[p] = v.clone();
                }
                jobs.push((vals, combo.join(", ")));
            }
        }
        _ => {
            // sniper: one position at a time, the rest left at their base value.
            for p in 0..n {
                for pl in set0 {
                    let mut vals = bases.to_vec();
                    vals[p] = pl.clone();
                    jobs.push((vals, format!("[{p}] {pl}")));
                }
            }
        }
    }
    jobs.truncate(2000);
    jobs
}

/// Automated attack (sniper / battering-ram / pitchfork / cluster-bomb) over the
/// `§`-marked positions, run with bounded concurrency.
async fn intruder(State(s): State<WebState>, Json(req): Json<IntruderReq>) -> Response {
    let n = count_positions(&req.url, &req.headers, &req.body);
    let bases = base_values(&req.url, &req.headers, &req.body);
    let jobs = intruder_jobs(&req.mode, n, &bases, &req.payloads);

    let concurrency = if req.concurrency == 0 {
        10
    } else {
        req.concurrency.clamp(1, 50)
    };
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut set = tokio::task::JoinSet::new();

    for (i, (vals, label)) in jobs.into_iter().enumerate() {
        let r = render_all(&req.url, &req.headers, &req.body, &vals);
        let client = s.client.clone();
        let method = req.method.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let res = send_once(&client, &method, &r.url, &r.headers, &r.body).await;
            (i, label, res)
        });
    }

    let mut rows: Vec<(usize, serde_json::Value)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, label, res)) = joined {
            let row = match res {
                Ok((status, _h, body, ms)) => serde_json::json!({
                    "i": i, "payload": label, "status": status, "len": body.len(), "ms": ms, "error": null,
                }),
                Err(e) => serde_json::json!({
                    "i": i, "payload": label, "status": 0, "len": 0, "ms": 0, "error": e,
                }),
            };
            rows.push((i, row));
        }
    }
    rows.sort_by_key(|x| x.0);
    let results: Vec<serde_json::Value> = rows.into_iter().map(|x| x.1).collect();
    s.store
        .push_log("intruder", &req.method, &req.url, 0, results.len(), 0);
    Json(serde_json::json!({
        "count": results.len(), "positions": n, "mode": req.mode, "results": results,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct DecodeReq {
    input: String,
    op: String,
}

/// Encode/decode/transform utility (Decoder tool).
async fn decode(Json(req): Json<DecodeReq>) -> Json<serde_json::Value> {
    let out = match req.op.as_str() {
        "base64-encode" => B64.encode(req.input.as_bytes()),
        "base64-decode" => match B64.decode(req.input.trim().as_bytes()) {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(e) => format!("<invalid base64: {e}>"),
        },
        "url-encode" => url_encode(&req.input),
        "url-decode" => url_decode(&req.input),
        "hex-encode" => req
            .input
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        "hex-decode" => hex_decode(&req.input),
        "html-encode" => html_encode(&req.input),
        other => format!("<unknown op: {other}>"),
    };
    Json(serde_json::json!({ "output": out }))
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_decode(s: &str) -> String {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return "<invalid hex: odd length>".to_string();
    }
    match (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
    {
        Ok(v) => String::from_utf8_lossy(&v).to_string(),
        Err(_) => "<invalid hex>".to_string(),
    }
}

fn html_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

async fn ws_handler(State(s): State<WebState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| ws_loop(socket, s))
}

async fn ws_loop(mut socket: WebSocket, s: WebState) {
    let mut rx = s.store.subscribe();
    while let Ok(ex) = rx.recv().await {
        match serde_json::to_string(&ex) {
            Ok(txt) => {
                if socket.send(Message::Text(txt.into())).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // M1.1 regression: /api/intercept/resolve must accept headers in BOTH the
    // `["name","value"]` pair form and the `{"name","value"}` object form that
    // /api/intercept/queue emits. Before the fix the object form returned 422.

    #[test]
    fn resolve_req_accepts_array_header_pairs() {
        let j = r#"{"hold_id":1,"action":"forward",
            "headers":[["Host","example.com"],["X-Test","1"]]}"#;
        let r: ResolveReq = serde_json::from_str(j).expect("array-pair headers must parse");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0].name, "Host");
        assert_eq!(r.headers[0].value, "example.com");
        assert_eq!(r.headers[1].name, "X-Test");
        assert_eq!(r.headers[1].value, "1");
    }

    #[test]
    fn resolve_req_accepts_object_headers() {
        // Exactly the shape that /api/intercept/queue returns for a held request.
        let j = r#"{"hold_id":2,"action":"forward",
            "headers":[{"name":"Host","value":"example.com"},{"name":"X-Test","value":"1"}]}"#;
        let r: ResolveReq = serde_json::from_str(j).expect("object headers must parse");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0].name, "Host");
        assert_eq!(r.headers[0].value, "example.com");
        assert_eq!(r.headers[1].value, "1");
    }

    #[test]
    fn resolve_req_mixed_and_missing_headers() {
        // Mixed shapes in one array are tolerated.
        let mixed = r#"{"hold_id":3,"action":"forward",
            "headers":[["A","1"],{"name":"B","value":"2"}]}"#;
        let r: ResolveReq = serde_json::from_str(mixed).expect("mixed headers must parse");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0].name, "A");
        assert_eq!(r.headers[1].name, "B");

        // No headers at all (e.g. a drop) still parses.
        let drop = r#"{"hold_id":4,"action":"drop"}"#;
        let r: ResolveReq = serde_json::from_str(drop).expect("header-less body must parse");
        assert!(r.headers.is_empty());
    }

    // Regression: the console API holds captured traffic, so it must answer only
    // callers that address it by a loopback name. Before the guard a foreign
    // `Host` (DNS rebinding) or `Origin` (any web page) was served like the console.

    async fn spawn_console() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(WebState {
            store: Arc::new(Store::new()),
            ca_pem: String::new(),
            client: reqwest::Client::new(),
            proxy_port: 0,
            oast_port: 0,
        });
        tokio::spawn(async move { axum::serve(listener, app.into_make_service()).await });
        addr
    }

    async fn status(url: String, headers: &[(&str, &str)]) -> u16 {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut req = client.get(url);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        req.send().await.unwrap().status().as_u16()
    }

    #[tokio::test]
    async fn console_api_rejects_foreign_host_and_origin() {
        let addr = spawn_console().await;
        let url = format!("http://{addr}/api/info");
        let own_origin = format!("http://{addr}");

        assert_eq!(status(url.clone(), &[]).await, 200, "local client");
        assert_eq!(
            status(url.clone(), &[("origin", own_origin.as_str())]).await,
            200,
            "the console itself"
        );
        assert_eq!(
            status(url.clone(), &[("host", "evil.example")]).await,
            403,
            "foreign Host"
        );
        assert_eq!(
            status(url.clone(), &[("origin", "http://evil.example")]).await,
            403,
            "foreign Origin"
        );
        assert_eq!(
            status(url, &[("origin", "null")]).await,
            403,
            "opaque Origin"
        );
    }

    #[tokio::test]
    async fn live_feed_websocket_rejects_cross_site_upgrade() {
        let addr = spawn_console().await;
        let url = format!("http://{addr}/api/ws");
        let own_origin = format!("http://{addr}");
        let mut upgrade = [
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("origin", own_origin.as_str()),
        ];
        assert_eq!(status(url.clone(), &upgrade).await, 101, "the console");
        upgrade[4] = ("origin", "http://evil.example");
        assert_eq!(status(url, &upgrade).await, 403, "another site");
    }
}
