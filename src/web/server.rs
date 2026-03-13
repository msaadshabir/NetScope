//! Axum-based web server for the NetScope dashboard.
//!
//! Responsibilities:
//! - Serve the embedded static frontend (HTML/CSS/JS)
//! - Accept WebSocket connections and broadcast real-time data
//! - Handle client requests (e.g. packet detail lookup)
//!
//! The server runs on a dedicated tokio runtime in its own thread so that
//! the synchronous pcap capture loop on the main thread is undisturbed.

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::Embed;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast, mpsc};

use super::messages::{
    AlertMsg, CaptureEvent, Frame, PacketDetail, PacketSample, WsClientMsg, WsServerMsg,
};
use super::packet_store::PacketStore;

#[derive(Clone)]
struct BroadcastFrame {
    frame_seq: Option<u64>,
    json: Arc<str>,
}

// ---------------------------------------------------------------------------
// Embedded static assets
// ---------------------------------------------------------------------------

#[derive(Embed)]
#[folder = "web/static/"]
struct Assets;

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

/// State shared across all axum handlers.
pub struct AppState {
    /// Broadcast channel: every connected WS client subscribes here.
    broadcast_tx: broadcast::Sender<BroadcastFrame>,
    /// Latest merged frame for lag recovery / initial sync.
    latest_frame: Mutex<Option<BroadcastFrame>>,
    /// Packet ring buffer for on-demand detail retrieval.
    pub packet_store: Mutex<PacketStore>,
    /// Tick interval so we can tell the client in the hello message.
    pub tick_ms: u64,
}

// ---------------------------------------------------------------------------
// Public API: start the server
// ---------------------------------------------------------------------------

/// Configuration for the web server.
#[derive(Debug, Clone)]
pub struct WebServerConfig {
    pub bind: String,
    pub port: u16,
    pub tick_ms: u64,
    pub packet_buffer: usize,
}

/// Handle returned by `start()` so the capture thread can feed data in.
pub struct WebHandle {
    /// Send capture events into the web server.
    pub event_tx: mpsc::Sender<CaptureEvent>,
}

/// Start the web server in a background tokio runtime.
///
/// Returns a `WebHandle` the caller uses to push capture events.
pub fn start(config: WebServerConfig) -> Result<WebHandle, std::io::Error> {
    let (event_tx, event_rx) = mpsc::channel::<CaptureEvent>(4096);
    let (broadcast_tx, _) = broadcast::channel::<BroadcastFrame>(1024);

    let bind_addr = format!("{}:{}", config.bind, config.port);
    let listener = std::net::TcpListener::bind(&bind_addr)?;
    listener.set_nonblocking(true)?;

    let state = Arc::new(AppState {
        broadcast_tx: broadcast_tx.clone(),
        latest_frame: Mutex::new(None),
        packet_store: Mutex::new(PacketStore::new(config.packet_buffer)),
        tick_ms: config.tick_ms,
    });

    // Spawn a dedicated thread with its own tokio runtime
    let state_clone = state.clone();
    std::thread::Builder::new()
        .name("netscope-web".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("failed to build tokio runtime for web server");

            rt.block_on(async move {
                // Spawn the ingest task (reads from event_rx, broadcasts to clients)
                let ingest_state = state_clone.clone();
                tokio::spawn(ingest_task(event_rx, ingest_state));

                // Build the router
                let app = Router::new()
                    .route("/ws", get(ws_handler))
                    .route("/api/health", get(health_handler))
                    .fallback(get(static_handler))
                    .with_state(state_clone);

                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(err) => {
                        tracing::error!("failed to start web server on {}: {}", bind_addr, err);
                        return;
                    }
                };

                tracing::info!("web dashboard listening on http://{}", bind_addr);

                if let Err(err) = axum::serve(listener, app).await {
                    tracing::error!("web server stopped unexpectedly: {}", err);
                }
            });
        })
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    Ok(WebHandle { event_tx })
}

// ---------------------------------------------------------------------------
// Ingest task: capture events → broadcast + packet store
// ---------------------------------------------------------------------------

async fn ingest_task(mut rx: mpsc::Receiver<CaptureEvent>, state: Arc<AppState>) {
    let mut pending_packets: Vec<PacketSample> = Vec::new();
    let mut pending_alerts: Vec<AlertMsg> = Vec::new();

    while let Some(event) = rx.recv().await {
        match event {
            CaptureEvent::Tick(tick) => {
                let frame_seq = tick.frame_seq;
                let frame = Frame {
                    frame_seq,
                    tick,
                    packets: std::mem::take(&mut pending_packets),
                    alerts: std::mem::take(&mut pending_alerts),
                };
                let msg = WsServerMsg::Frame(frame);
                if let Ok(json) = serde_json::to_string(&msg) {
                    let frame = BroadcastFrame {
                        frame_seq: Some(frame_seq),
                        json: Arc::<str>::from(json),
                    };
                    {
                        let mut latest = state.latest_frame.lock().await;
                        *latest = Some(frame.clone());
                    }
                    let _ = state.broadcast_tx.send(frame);
                }
            }
            CaptureEvent::Packet(sample) => {
                pending_packets.push(sample);
            }
            CaptureEvent::PacketStored(stored) => {
                let mut store = state.packet_store.lock().await;
                store.push(stored);
            }
            CaptureEvent::Alert(alert) => {
                pending_alerts.push(alert);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> &'static str {
    "ok"
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    // Send hello
    let hello = WsServerMsg::Hello {
        version: env!("CARGO_PKG_VERSION").to_string(),
        tick_ms: state.tick_ms,
    };
    if let Ok(json) = serde_json::to_string(&hello) {
        if socket.send(Message::Text(json.into())).await.is_err() {
            return;
        }
    }

    // Subscribe to broadcast
    let mut broadcast_rx = state.broadcast_tx.subscribe();
    let mut last_sent_frame_seq: Option<u64> = None;

    // Send the latest frame so newly connected clients start from current state.
    if let Some(frame) = { state.latest_frame.lock().await.clone() } {
        last_sent_frame_seq = frame.frame_seq;
        if socket
            .send(Message::Text(frame.json.as_ref().to_owned().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    loop {
        tokio::select! {
            // Forward broadcasts to this client
            result = broadcast_rx.recv() => {
                match result {
                    Ok(msg) => {
                        if should_skip_frame(msg.frame_seq, last_sent_frame_seq) {
                            continue;
                        }
                        last_sent_frame_seq = msg.frame_seq.or(last_sent_frame_seq);
                        if socket
                            .send(Message::Text(msg.json.as_ref().to_owned().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("ws client lagged, skipped {} messages", n);
                        // Drop buffered backlog and resume from newest broadcast position.
                        broadcast_rx = state.broadcast_tx.subscribe();
                        // Resync by sending the newest merged frame instead of replaying history.
                        if let Some(frame) = { state.latest_frame.lock().await.clone() } {
                            if let Some(seq) = frame.frame_seq {
                                if last_sent_frame_seq == Some(seq) {
                                    continue;
                                }
                            }
                            last_sent_frame_seq = frame.frame_seq.or(last_sent_frame_seq);
                            if socket
                                .send(Message::Text(frame.json.as_ref().to_owned().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            // Handle messages from the client
            result = socket.recv() => {
                match result {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(client_msg) = serde_json::from_str::<WsClientMsg>(&text) {
                            match client_msg {
                                WsClientMsg::GetPacketDetail { id } => {
                                    let store = state.packet_store.lock().await;
                                    let response = match store.get(id) {
                                        Some(stored) => WsServerMsg::PacketDetail(PacketDetail {
                                            id: stored.id,
                                            ts: stored.ts,
                                            layers: stored.layers.clone(),
                                            hex_dump: stored.hex_dump.clone(),
                                        }),
                                        None => {
                                            // Packet no longer in buffer — ignore
                                            continue;
                                        }
                                    };
                                    drop(store);
                                    if let Ok(json) = serde_json::to_string(&response) {
                                        if socket.send(Message::Text(json.into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                WsClientMsg::PerfPing { client_ts } => {
                                    let server_ts = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64;
                                    let response = WsServerMsg::PerfPong {
                                        client_ts,
                                        server_ts,
                                    };
                                    if let Ok(json) = serde_json::to_string(&response) {
                                        if socket.send(Message::Text(json.into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

fn should_skip_frame(frame_seq: Option<u64>, last_sent_frame_seq: Option<u64>) -> bool {
    match (frame_seq, last_sent_frame_seq) {
        (Some(seq), Some(last_seq)) => seq <= last_seq,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Static file serving (embedded assets)
// ---------------------------------------------------------------------------

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // Try the exact path first, then fall back to index.html (SPA)
    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(axum::body::Body::from(content.data.to_vec()))
            .unwrap()
    } else if let Some(content) = Assets::get("index.html") {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(axum::body::Body::from(content.data.to_vec()))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("not found"))
            .unwrap()
    }
}
