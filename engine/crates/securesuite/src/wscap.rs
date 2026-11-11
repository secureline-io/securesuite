//! WebSocket frame capture. Installs a hudsucker `WebSocketHandler` that records
//! every WebSocket message (both directions) flowing through the MITM proxy into
//! the store, then forwards it unchanged. This is what makes WS traffic visible
//! the same way HTTP exchanges are.

use std::sync::Arc;

use hudsucker::tokio_tungstenite::tungstenite::Message;
use hudsucker::{WebSocketContext, WebSocketHandler};

use crate::model::HeldWs;
use crate::store::{Store, WsDecision};

#[derive(Clone)]
pub struct WsRecorder {
    store: Arc<Store>,
}

impl WsRecorder {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl WebSocketHandler for WsRecorder {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let (dir, host) = match ctx {
            WebSocketContext::ClientToServer { dst, .. } => ("c2s", dst.to_string()),
            WebSocketContext::ServerToClient { src, .. } => ("s2c", src.to_string()),
        };

        // Classify the incoming frame and pull out an editable text payload.
        let (opcode, editable, held_text) = match &message {
            Message::Text(t) => ("text", true, t.as_str().to_string()),
            Message::Binary(b) => ("binary", false, format!("<{} bytes>", b.len())),
            Message::Ping(b) => ("ping", false, format!("<{} bytes>", b.len())),
            Message::Pong(b) => ("pong", false, format!("<{} bytes>", b.len())),
            Message::Close(_) => ("close", false, String::new()),
            _ => ("frame", false, String::new()),
        };

        // Only data frames are held for interception; control frames (ping/pong/
        // close) are always forwarded so the connection stays healthy.
        let is_data = matches!(opcode, "text" | "binary");
        let mut outgoing = Some(message);

        if self.store.ws_intercept() && is_data {
            let (_id, rx) = self.store.hold_ws(HeldWs {
                hold_id: 0,
                dir: dir.to_string(),
                host: host.clone(),
                opcode: opcode.to_string(),
                text: held_text,
                editable,
            });
            match rx.await {
                Ok(WsDecision::Drop) => {
                    self.store
                        .push_ws(dir, &host, opcode, 0, "[dropped]".to_string());
                    return None;
                }
                Ok(WsDecision::Forward(Some(new_text))) if editable => {
                    outgoing = Some(Message::Text(new_text.into()));
                }
                _ => {} // Forward(None), a non-editable edit, or a closed channel
            }
        }

        // Record what actually goes on the wire (post-edit), then forward it.
        let (rec_op, rec_len, rec_prev) = match outgoing.as_ref() {
            Some(Message::Text(t)) => (
                "text",
                t.len(),
                t.as_str().chars().take(4000).collect::<String>(),
            ),
            Some(Message::Binary(b)) => ("binary", b.len(), format!("<{} bytes>", b.len())),
            Some(Message::Ping(b)) => ("ping", b.len(), String::new()),
            Some(Message::Pong(b)) => ("pong", b.len(), String::new()),
            Some(Message::Close(_)) => ("close", 0, String::new()),
            _ => (opcode, 0, String::new()),
        };
        self.store.push_ws(dir, &host, rec_op, rec_len, rec_prev);
        outgoing
    }
}
