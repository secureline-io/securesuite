//! Exchange store (in-memory + optional SQLite persistence), live broadcast,
//! request-intercept queue, scope rules, passive-scan issues, and Match &
//! Replace rules.
//!
//! History, scope, Match & Replace rules, and scanner issues are all persisted
//! to SQLite when a DB path is given, so a full session survives restarts.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use rusqlite::Connection;
use tokio::sync::{broadcast, oneshot};

use crate::model::{Exchange, HeldReq, HeldWs, Interaction, Issue, LogEntry, Rule, WsMessage};
use crate::scan::passive_scan;

/// What to do with an intercepted request.
pub enum Decision {
    /// Forward it, optionally replaced by the edited fields.
    Forward(Option<EditedReq>),
    /// Drop it (the client receives a 403 from SecureSuite).
    Drop,
}

/// Edited request fields supplied by the UI when resolving a held request.
pub struct EditedReq {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// What to do with an intercepted WebSocket frame.
pub enum WsDecision {
    /// Forward it; `Some(text)` replaces a text frame's payload, `None` forwards
    /// the frame unchanged.
    Forward(Option<String>),
    /// Drop the frame (it never reaches the far side).
    Drop,
}

/// Exchanges kept in memory (and reloaded at startup); older ones stay in the DB.
const MAX_HISTORY: usize = 10_000;

fn kv_get(c: &Connection, key: &str) -> Option<String> {
    c.query_row("SELECT json FROM kv WHERE key=?1", [key], |r| {
        r.get::<_, String>(0)
    })
    .ok()
}

/// Thread-safe history + live feed + intercept queue + scope + issues + rules.
pub struct Store {
    items: Mutex<Vec<Exchange>>,
    tx: broadcast::Sender<Exchange>,
    next_id: AtomicU64,
    intercept: AtomicBool,
    intercept_resp: AtomicBool,
    next_hold: AtomicU64,
    held: Mutex<Vec<HeldReq>>,
    responders: Mutex<HashMap<u64, oneshot::Sender<Decision>>>,
    scope: Mutex<Vec<String>>,
    issues: Mutex<Vec<Issue>>,
    issue_seen: Mutex<HashSet<String>>,
    next_issue: AtomicU64,
    rules: Mutex<Vec<Rule>>,
    extensions: Mutex<Vec<String>>,
    oast: Mutex<Vec<Interaction>>,
    ws: Mutex<Vec<WsMessage>>,
    next_ws: AtomicU64,
    ws_intercept: AtomicBool,
    ws_held: Mutex<Vec<HeldWs>>,
    ws_responders: Mutex<HashMap<u64, oneshot::Sender<WsDecision>>>,
    next_ws_hold: AtomicU64,
    log: Mutex<Vec<LogEntry>>,
    next_log: AtomicU64,
    db: Option<Mutex<Connection>>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// In-memory-only store (used by tests).
    pub fn new() -> Self {
        Self::with_db(None)
    }

    /// Store backed by a SQLite file at `path` (created if missing). History,
    /// scope, rules, and issues are loaded back into memory on open.
    pub fn with_db(path: Option<&Path>) -> Self {
        // Captured cookies and tokens live in this file: owner-only, like the CA
        // key, and set before SQLite opens it so its journal files match.
        #[cfg(unix)]
        if let Some(p) = path {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(p);
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }
        let db = path.and_then(|p| match Connection::open(p) {
            Ok(c) => {
                let _ = c.execute_batch(
                    "CREATE TABLE IF NOT EXISTS exchanges (id INTEGER PRIMARY KEY, json TEXT NOT NULL);
                     CREATE TABLE IF NOT EXISTS issues (id INTEGER PRIMARY KEY, json TEXT NOT NULL);
                     CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, json TEXT NOT NULL);",
                );
                Some(c)
            }
            Err(e) => {
                eprintln!("[store] could not open db {p:?}: {e}");
                None
            }
        });

        let mut items: Vec<Exchange> = Vec::new();
        let mut max_id = 0u64;
        let mut scope: Vec<String> = Vec::new();
        let mut rules: Vec<Rule> = Vec::new();
        let mut extensions: Vec<String> = Vec::new();
        let mut issues: Vec<Issue> = Vec::new();
        let mut issue_seen: HashSet<String> = HashSet::new();
        let mut max_issue = 0u64;

        if let Some(c) = &db {
            // Newest MAX_HISTORY only; the newest row also carries the max id.
            if let Ok(mut stmt) = c.prepare(
                "SELECT json FROM (SELECT id, json FROM exchanges ORDER BY id DESC LIMIT ?1) ORDER BY id",
            ) {
                if let Ok(rows) = stmt.query_map([MAX_HISTORY as i64], |r| r.get::<_, String>(0)) {
                    for json in rows.flatten() {
                        if let Ok(ex) = serde_json::from_str::<Exchange>(&json) {
                            max_id = max_id.max(ex.id);
                            items.push(ex);
                        }
                    }
                }
            }
            if let Ok(mut stmt) = c.prepare("SELECT json FROM issues ORDER BY id") {
                if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
                    for json in rows.flatten() {
                        if let Ok(it) = serde_json::from_str::<Issue>(&json) {
                            max_issue = max_issue.max(it.id);
                            issue_seen.insert(format!("{}|{}", it.name, it.host));
                            issues.push(it);
                        }
                    }
                }
            }
            scope = kv_get(c, "scope")
                .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
                .unwrap_or_default();
            rules = kv_get(c, "rules")
                .and_then(|j| serde_json::from_str::<Vec<Rule>>(&j).ok())
                .unwrap_or_default();
            extensions = kv_get(c, "extensions")
                .and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok())
                .unwrap_or_default();
        }

        let (tx, _) = broadcast::channel(4096);
        Self {
            items: Mutex::new(items),
            tx,
            next_id: AtomicU64::new(max_id + 1),
            intercept: AtomicBool::new(false),
            intercept_resp: AtomicBool::new(false),
            next_hold: AtomicU64::new(1),
            held: Mutex::new(Vec::new()),
            responders: Mutex::new(HashMap::new()),
            scope: Mutex::new(scope),
            issues: Mutex::new(issues),
            issue_seen: Mutex::new(issue_seen),
            next_issue: AtomicU64::new(max_issue + 1),
            rules: Mutex::new(rules),
            extensions: Mutex::new(extensions),
            oast: Mutex::new(Vec::new()),
            ws: Mutex::new(Vec::new()),
            next_ws: AtomicU64::new(1),
            ws_intercept: AtomicBool::new(false),
            ws_held: Mutex::new(Vec::new()),
            ws_responders: Mutex::new(HashMap::new()),
            next_ws_hold: AtomicU64::new(1),
            log: Mutex::new(Vec::new()),
            next_log: AtomicU64::new(1),
            db: db.map(Mutex::new),
        }
    }

    fn put_kv<T: serde::Serialize>(&self, key: &str, val: &T) {
        if let Some(db) = &self.db {
            if let Ok(json) = serde_json::to_string(val) {
                let _ = db.lock().expect("db poisoned").execute(
                    "INSERT OR REPLACE INTO kv (key, json) VALUES (?1, ?2)",
                    rusqlite::params![key, json],
                );
            }
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn push(&self, ex: Exchange) {
        if let Some(db) = &self.db {
            if let Ok(json) = serde_json::to_string(&ex) {
                let _ = db.lock().expect("db poisoned").execute(
                    "INSERT OR REPLACE INTO exchanges (id, json) VALUES (?1, ?2)",
                    rusqlite::params![ex.id as i64, json],
                );
            }
        }

        // Passive scan (scope-gated, deduped per issue+host); findings persisted.
        if self.in_scope(&ex.url) {
            for f in passive_scan(&ex) {
                let key = format!("{}|{}", f.name, ex.host);
                if self.issue_seen.lock().expect("store poisoned").insert(key) {
                    let id = self.next_issue.fetch_add(1, Ordering::SeqCst);
                    let issue = Issue {
                        id,
                        severity: f.severity.to_string(),
                        name: f.name,
                        detail: f.detail,
                        host: ex.host.clone(),
                        url: ex.url.clone(),
                        exchange_id: ex.id,
                    };
                    if let Some(db) = &self.db {
                        if let Ok(json) = serde_json::to_string(&issue) {
                            let _ = db.lock().expect("db poisoned").execute(
                                "INSERT OR REPLACE INTO issues (id, json) VALUES (?1, ?2)",
                                rusqlite::params![issue.id as i64, json],
                            );
                        }
                    }
                    self.issues.lock().expect("store poisoned").push(issue);
                }
            }
        }

        self.push_log(
            "proxy",
            &ex.method,
            &ex.url,
            ex.status,
            ex.resp_body_len,
            ex.duration_ms,
        );
        {
            let mut items = self.items.lock().expect("store poisoned");
            items.push(ex.clone());
            if items.len() > MAX_HISTORY {
                let drop = items.len() - MAX_HISTORY;
                items.drain(..drop);
            }
        }
        let _ = self.tx.send(ex); // ignore if no live subscribers
    }

    pub fn all(&self) -> Vec<Exchange> {
        self.items.lock().expect("store poisoned").clone()
    }

    pub fn get(&self, id: u64) -> Option<Exchange> {
        self.items
            .lock()
            .expect("store poisoned")
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Exchange> {
        self.tx.subscribe()
    }

    pub fn set_intercept(&self, v: bool) {
        self.intercept.store(v, Ordering::SeqCst);
        if !v {
            self.release("request");
        }
    }

    fn intercepting(&self, kind: &str) -> bool {
        if kind == "response" {
            self.intercept_resp()
        } else {
            self.intercept()
        }
    }

    /// Forward every held item of `kind` unchanged: once intercept is off,
    /// nothing in the console will ever resolve them.
    fn release(&self, kind: &str) {
        for h in self.held().into_iter().filter(|h| h.kind == kind) {
            self.resolve(h.hold_id, Decision::Forward(None));
        }
    }

    pub fn intercept(&self) -> bool {
        self.intercept.load(Ordering::SeqCst)
    }

    pub fn set_intercept_resp(&self, v: bool) {
        self.intercept_resp.store(v, Ordering::SeqCst);
        if !v {
            self.release("response");
        }
    }

    pub fn intercept_resp(&self) -> bool {
        self.intercept_resp.load(Ordering::SeqCst)
    }

    // ---- scope (persisted) ----

    pub fn set_scope(&self, patterns: Vec<String>) {
        let cleaned: Vec<String> = patterns
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        *self.scope.lock().expect("store poisoned") = cleaned.clone();
        self.put_kv("scope", &cleaned);
    }

    pub fn scope(&self) -> Vec<String> {
        self.scope.lock().expect("store poisoned").clone()
    }

    /// True if `url` is in scope. Empty scope means everything is in scope.
    pub fn in_scope(&self, url: &str) -> bool {
        let scope = self.scope.lock().expect("store poisoned");
        scope.is_empty() || scope.iter().any(|p| url.contains(p.as_str()))
    }

    // ---- issues ----

    pub fn issues(&self) -> Vec<Issue> {
        self.issues.lock().expect("store poisoned").clone()
    }

    /// Record an externally-generated issue (e.g. active scanner), deduped by
    /// (name, host, dedupe_key) and persisted like passive findings.
    pub fn add_issue(
        &self,
        severity: &str,
        name: &str,
        detail: String,
        host: &str,
        url: &str,
        dedupe_key: &str,
    ) {
        let key = format!("{name}|{host}|{dedupe_key}");
        if self.issue_seen.lock().expect("store poisoned").insert(key) {
            let id = self.next_issue.fetch_add(1, Ordering::SeqCst);
            let issue = Issue {
                id,
                severity: severity.to_string(),
                name: name.to_string(),
                detail,
                host: host.to_string(),
                url: url.to_string(),
                exchange_id: 0,
            };
            if let Some(db) = &self.db {
                if let Ok(json) = serde_json::to_string(&issue) {
                    let _ = db.lock().expect("db poisoned").execute(
                        "INSERT OR REPLACE INTO issues (id, json) VALUES (?1, ?2)",
                        rusqlite::params![issue.id as i64, json],
                    );
                }
            }
            self.issues.lock().expect("store poisoned").push(issue);
        }
    }

    // ---- match & replace rules (persisted) ----

    pub fn rules(&self) -> Vec<Rule> {
        self.rules.lock().expect("store poisoned").clone()
    }

    pub fn set_rules(&self, rules: Vec<Rule>) {
        *self.rules.lock().expect("store poisoned") = rules.clone();
        self.put_kv("rules", &rules);
    }

    // ---- extensions (HTTP webhooks, persisted) ----

    pub fn extensions(&self) -> Vec<String> {
        self.extensions.lock().expect("store poisoned").clone()
    }

    pub fn set_extensions(&self, urls: Vec<String>) {
        let cleaned: Vec<String> = urls
            .into_iter()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect();
        *self.extensions.lock().expect("store poisoned") = cleaned.clone();
        self.put_kv("extensions", &cleaned);
    }

    // ---- OAST interactions (in-memory ring, newest kept) ----

    pub fn record_oast(&self, i: Interaction) {
        let mut v = self.oast.lock().expect("store poisoned");
        v.push(i);
        if v.len() > 1000 {
            let drop = v.len() - 1000;
            v.drain(0..drop);
        }
    }

    pub fn oast_interactions(&self) -> Vec<Interaction> {
        self.oast.lock().expect("store poisoned").clone()
    }

    // ---- WebSocket frames (in-memory ring) ----

    pub fn push_ws(&self, dir: &str, host: &str, opcode: &str, len: usize, preview: String) {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let id = self.next_ws.fetch_add(1, Ordering::SeqCst);
        let mut v = self.ws.lock().expect("store poisoned");
        v.push(WsMessage {
            id,
            ts_ms,
            dir: dir.to_string(),
            host: host.to_string(),
            opcode: opcode.to_string(),
            len,
            preview,
        });
        if v.len() > 5000 {
            let drop = v.len() - 5000;
            v.drain(0..drop);
        }
    }

    pub fn ws_messages(&self) -> Vec<WsMessage> {
        self.ws.lock().expect("store poisoned").clone()
    }

    // ---- unified Logger (every tool-generated request, tagged by source) ----

    pub fn push_log(
        &self,
        source: &str,
        method: &str,
        url: &str,
        status: u16,
        len: usize,
        ms: u64,
    ) {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let id = self.next_log.fetch_add(1, Ordering::SeqCst);
        let mut v = self.log.lock().expect("store poisoned");
        v.push(LogEntry {
            id,
            ts_ms,
            source: source.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            status,
            len,
            ms,
        });
        if v.len() > 5000 {
            let drop = v.len() - 5000;
            v.drain(0..drop);
        }
    }

    pub fn log_entries(&self) -> Vec<LogEntry> {
        self.log.lock().expect("store poisoned").clone()
    }

    // ---- WebSocket frame interception ----

    pub fn set_ws_intercept(&self, v: bool) {
        self.ws_intercept.store(v, Ordering::SeqCst);
        if !v {
            for h in self.ws_held() {
                self.resolve_ws(h.hold_id, WsDecision::Forward(None));
            }
        }
    }

    pub fn ws_intercept(&self) -> bool {
        self.ws_intercept.load(Ordering::SeqCst)
    }

    /// Register a held WebSocket frame; returns its id and a receiver that
    /// resolves once the UI forwards/edits/drops it.
    pub fn hold_ws(&self, mut frame: HeldWs) -> (u64, oneshot::Receiver<WsDecision>) {
        let hold_id = self.next_ws_hold.fetch_add(1, Ordering::SeqCst);
        frame.hold_id = hold_id;
        let (tx, rx) = oneshot::channel();
        self.ws_responders
            .lock()
            .expect("store poisoned")
            .insert(hold_id, tx);
        self.ws_held.lock().expect("store poisoned").push(frame);
        if !self.ws_intercept() {
            self.resolve_ws(hold_id, WsDecision::Forward(None));
        }
        (hold_id, rx)
    }

    /// Currently held WebSocket frames, in arrival order.
    pub fn ws_held(&self) -> Vec<HeldWs> {
        self.ws_held.lock().expect("store poisoned").clone()
    }

    /// Resolve a held WebSocket frame; returns true if it was still pending.
    pub fn resolve_ws(&self, hold_id: u64, decision: WsDecision) -> bool {
        self.ws_held
            .lock()
            .expect("store poisoned")
            .retain(|h| h.hold_id != hold_id);
        if let Some(tx) = self
            .ws_responders
            .lock()
            .expect("store poisoned")
            .remove(&hold_id)
        {
            let _ = tx.send(decision);
            true
        } else {
            false
        }
    }

    // ---- intercept queue ----

    /// Register a held request; returns its id and a receiver that resolves
    /// once the UI forwards/edits/drops it.
    pub fn hold(&self, mut req: HeldReq) -> (u64, oneshot::Receiver<Decision>) {
        let hold_id = self.next_hold.fetch_add(1, Ordering::SeqCst);
        req.hold_id = hold_id;
        let (tx, rx) = oneshot::channel();
        self.responders
            .lock()
            .expect("store poisoned")
            .insert(hold_id, tx);
        let kind = req.kind.clone();
        self.held.lock().expect("store poisoned").push(req);
        // Intercept was switched off between the caller's check and this hold.
        if !self.intercepting(&kind) {
            self.resolve(hold_id, Decision::Forward(None));
        }
        (hold_id, rx)
    }

    /// Currently held requests, in arrival order.
    pub fn held(&self) -> Vec<HeldReq> {
        self.held.lock().expect("store poisoned").clone()
    }

    /// Resolve a held request; returns true if it was still pending.
    pub fn resolve(&self, hold_id: u64, decision: Decision) -> bool {
        self.held
            .lock()
            .expect("store poisoned")
            .retain(|h| h.hold_id != hold_id);
        if let Some(tx) = self
            .responders
            .lock()
            .expect("store poisoned")
            .remove(&hold_id)
        {
            let _ = tx.send(decision);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(kind: &str) -> HeldReq {
        HeldReq {
            hold_id: 0,
            kind: kind.into(),
            method: "GET".into(),
            url: "http://h/".into(),
            status: 0,
            headers: vec![],
            body: String::new(),
        }
    }

    // status 0 keeps the passive scanner out of these tests.
    fn ex(id: u64) -> Exchange {
        Exchange {
            id,
            ts_ms: 0,
            method: "GET".into(),
            url: format!("http://h/{id}"),
            host: "h".into(),
            scheme: "http".into(),
            status: 0,
            mime: String::new(),
            req_headers: vec![],
            req_body: String::new(),
            req_body_len: 0,
            resp_headers: vec![],
            resp_body: String::new(),
            resp_body_len: 0,
            duration_ms: 0,
        }
    }

    #[test]
    fn turning_intercept_off_releases_only_that_kind() {
        let s = Store::new();
        s.set_intercept(true);
        s.set_intercept_resp(true);
        let (_, mut req) = s.hold(held("request"));
        let (_, mut resp) = s.hold(held("response"));
        s.set_intercept(false);
        assert!(matches!(req.try_recv(), Ok(Decision::Forward(None))));
        assert!(resp.try_recv().is_err(), "responses stay held");
        assert_eq!(s.held().len(), 1);
        s.set_intercept_resp(false);
        assert!(matches!(resp.try_recv(), Ok(Decision::Forward(None))));
        assert!(s.held().is_empty());
    }

    #[test]
    fn a_hold_that_races_intercept_off_is_released() {
        let s = Store::new();
        let (_, mut req) = s.hold(held("request"));
        assert!(matches!(req.try_recv(), Ok(Decision::Forward(None))));
        assert!(s.held().is_empty());
    }

    #[test]
    fn turning_ws_intercept_off_releases_held_frames() {
        let s = Store::new();
        s.set_ws_intercept(true);
        let (_, mut rx) = s.hold_ws(HeldWs {
            hold_id: 0,
            dir: "c2s".into(),
            host: "h".into(),
            opcode: "text".into(),
            text: "x".into(),
            editable: true,
        });
        s.set_ws_intercept(false);
        assert!(matches!(rx.try_recv(), Ok(WsDecision::Forward(None))));
        assert!(s.ws_held().is_empty());
    }

    #[test]
    fn history_keeps_only_the_newest_exchanges() {
        let s = Store::new();
        for id in 1..=MAX_HISTORY as u64 + 1 {
            s.push(ex(id));
        }
        let all = s.all();
        assert_eq!(all.len(), MAX_HISTORY);
        assert_eq!(all[0].id, 2);
        assert!(s.get(1).is_none());
    }

    #[test]
    fn history_db_is_owner_only_and_reloads_only_the_newest() {
        let dir = std::env::temp_dir().join(format!("ss-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.db");
        {
            // An existing database, created with default permissions.
            let mut c = Connection::open(&path).unwrap();
            c.execute_batch("CREATE TABLE exchanges (id INTEGER PRIMARY KEY, json TEXT NOT NULL);")
                .unwrap();
            let t = c.transaction().unwrap();
            for id in 1..=MAX_HISTORY as u64 + 1 {
                t.execute(
                    "INSERT INTO exchanges (id, json) VALUES (?1, ?2)",
                    rusqlite::params![id as i64, serde_json::to_string(&ex(id)).unwrap()],
                )
                .unwrap();
            }
            t.commit().unwrap();
        }
        let s = Store::with_db(Some(&path));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let all = s.all();
        assert_eq!(all.len(), MAX_HISTORY);
        assert_eq!(all[0].id, 2);
        assert_eq!(
            s.next_id(),
            MAX_HISTORY as u64 + 2,
            "new ids never overwrite old rows"
        );
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
