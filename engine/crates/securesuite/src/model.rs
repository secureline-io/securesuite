//! Shared data model for captured HTTP exchanges.

use serde::{Deserialize, Serialize};

/// A single HTTP header (name/value), order-preserving.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// One captured request/response pair flowing through the proxy.
#[derive(Clone, Serialize, Deserialize)]
pub struct Exchange {
    pub id: u64,
    /// Capture time, Unix milliseconds (formatted client-side).
    pub ts_ms: u128,
    pub method: String,
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub status: u16,
    pub mime: String,
    pub req_headers: Vec<Header>,
    pub req_body: String,
    pub req_body_len: usize,
    pub resp_headers: Vec<Header>,
    pub resp_body: String,
    pub resp_body_len: usize,
    pub duration_ms: u64,
}

/// A request or response currently paused by the interceptor.
#[derive(Clone, Serialize)]
pub struct HeldReq {
    pub hold_id: u64,
    /// "request" or "response".
    pub kind: String,
    pub method: String,
    pub url: String,
    /// Response status (0 for held requests).
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: String,
}

/// A WebSocket frame currently paused by the interceptor.
#[derive(Clone, Serialize)]
pub struct HeldWs {
    pub hold_id: u64,
    /// "c2s" (client→server) or "s2c" (server→client).
    pub dir: String,
    pub host: String,
    pub opcode: String,
    /// Editable payload for text frames; a preview (e.g. "<N bytes>") otherwise.
    pub text: String,
    /// True for text frames (payload can be edited); false for binary/control.
    pub editable: bool,
}

/// A passive-scanner finding recorded against an exchange.
#[derive(Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: u64,
    pub severity: String,
    pub name: String,
    pub detail: String,
    pub host: String,
    pub url: String,
    pub exchange_id: u64,
}

/// A Match & Replace rule applied automatically to proxied traffic.
#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u64,
    pub enabled: bool,
    /// Which part to target: `url` | `req_header` | `req_body` | `resp_header` | `resp_body`.
    pub part: String,
    pub pattern: String,
    pub replace: String,
    /// If true, `pattern` is a Rust regex; otherwise a literal substring.
    pub regex: bool,
}

/// An out-of-band (OAST) interaction recorded by the canary HTTP listener.
#[derive(Clone, Serialize)]
pub struct Interaction {
    pub ts_ms: u128,
    pub method: String,
    pub path: String,
    pub remote: String,
    pub ua: String,
}

/// An issue returned by an HTTP extension (webhook) for ingestion.
#[derive(Deserialize)]
pub struct ExtIssue {
    pub severity: String,
    pub name: String,
    #[serde(default)]
    pub detail: String,
}

/// A captured WebSocket frame (either direction) flowing through the proxy.
#[derive(Clone, Serialize)]
pub struct WsMessage {
    pub id: u64,
    pub ts_ms: u128,
    /// "c2s" (client→server) or "s2c" (server→client).
    pub dir: String,
    pub host: String,
    pub opcode: String,
    pub len: usize,
    pub preview: String,
}

/// A unified Logger entry: one request produced by any tool.
#[derive(Clone, Serialize)]
pub struct LogEntry {
    pub id: u64,
    pub ts_ms: u128,
    /// Producing tool: "proxy" | "repeater" | "scanner" | "intruder" | "discover".
    pub source: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub len: usize,
    pub ms: u64,
}
