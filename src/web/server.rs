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
        Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_embed::Embed;
use std::{path::PathBuf, sync::Arc};
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
    /// Optional HTTP Basic auth credentials.
    basic_auth: Option<BasicAuthCredentials>,
}

#[derive(Debug, Clone)]
struct BasicAuthCredentials {
    username: String,
    password: String,
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
    pub tls: Option<WebServerTlsConfig>,
    pub auth: Option<WebServerAuthConfig>,
}

#[derive(Debug, Clone)]
pub struct WebServerTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WebServerAuthConfig {
    pub username: String,
    pub password: String,
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
    let WebServerConfig {
        bind,
        port,
        tick_ms,
        packet_buffer,
        tls,
        auth,
    } = config;

    let rustls_config = if let Some(tls_config) = tls {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(std::io::Error::other)?;
        Some(rt.block_on(RustlsConfig::from_pem_file(
            &tls_config.cert_path,
            &tls_config.key_path,
        ))?)
    } else {
        None
    };

    let (event_tx, event_rx) = mpsc::channel::<CaptureEvent>(4096);
    let (broadcast_tx, _) = broadcast::channel::<BroadcastFrame>(1024);

    let bind_addr = format!("{}:{}", bind, port);
    let listener = std::net::TcpListener::bind(&bind_addr)?;
    listener.set_nonblocking(true)?;

    let state = Arc::new(AppState {
        broadcast_tx: broadcast_tx.clone(),
        latest_frame: Mutex::new(None),
        packet_store: Mutex::new(PacketStore::new(packet_buffer)),
        tick_ms,
        basic_auth: auth.map(|auth| BasicAuthCredentials {
            username: auth.username,
            password: auth.password,
        }),
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
                    .route("/metrics", get(metrics_handler))
                    .fallback(get(static_handler))
                    .with_state(state_clone.clone())
                    .layer(middleware::from_fn_with_state(state_clone, auth_middleware));

                if let Some(rustls_config) = rustls_config {
                    let server = match axum_server::from_tcp_rustls(listener, rustls_config) {
                        Ok(server) => server,
                        Err(err) => {
                            tracing::error!(
                                "failed to start HTTPS listener on {}: {}",
                                bind_addr,
                                err
                            );
                            return;
                        }
                    };

                    println!("Web dashboard: https://{}", bind_addr);
                    tracing::info!("web dashboard listening on https://{}", bind_addr);

                    if let Err(err) = server.serve(app.into_make_service()).await {
                        tracing::error!("web server stopped unexpectedly: {}", err);
                    }
                } else {
                    let server = match axum_server::from_tcp(listener) {
                        Ok(server) => server,
                        Err(err) => {
                            tracing::error!(
                                "failed to start HTTP listener on {}: {}",
                                bind_addr,
                                err
                            );
                            return;
                        }
                    };

                    println!("Web dashboard: http://{}", bind_addr);
                    tracing::info!("web dashboard listening on http://{}", bind_addr);

                    if let Err(err) = server.serve(app.into_make_service()).await {
                        tracing::error!("web server stopped unexpectedly: {}", err);
                    }
                }
            });
        })
        .map_err(std::io::Error::other)?;

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
                broadcast_frame(&state, frame_seq, frame).await;
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

    // Flush buffered live events on shutdown so the last partial interval isn't lost.
    for sample in pending_packets {
        broadcast_message(&state, WsServerMsg::PacketSample(sample)).await;
    }
    for alert in pending_alerts {
        broadcast_message(&state, WsServerMsg::Alert(alert)).await;
    }
}

async fn broadcast_frame(state: &Arc<AppState>, frame_seq: u64, frame: Frame) {
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

async fn broadcast_message(state: &Arc<AppState>, msg: WsServerMsg) {
    if let Ok(json) = serde_json::to_string(&msg) {
        let _ = state.broadcast_tx.send(BroadcastFrame {
            frame_seq: None,
            json: Arc::<str>::from(json),
        });
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> &'static str {
    "ok"
}

async fn metrics_handler() -> Response {
    let body = crate::metrics::render_prometheus_text();
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            crate::metrics::prometheus_content_type(),
        )
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(credentials) = &state.basic_auth else {
        return next.run(request).await;
    };

    let authorized =
        is_request_authorized(request.headers().get(header::AUTHORIZATION), credentials);
    if !authorized {
        return unauthorized_response();
    }

    next.run(request).await
}

fn is_request_authorized(
    authorization: Option<&axum::http::HeaderValue>,
    credentials: &BasicAuthCredentials,
) -> bool {
    let Some(value) = authorization else {
        return false;
    };

    let Ok(raw_header) = value.to_str() else {
        return false;
    };

    let Some((scheme, encoded)) = raw_header.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }

    let Ok(decoded) = BASE64_STANDARD.decode(encoded.as_bytes()) else {
        return false;
    };
    let Ok(decoded) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((username, password)) = decoded.split_once(':') else {
        return false;
    };

    let username_matches = constant_time_eq(username.as_bytes(), credentials.username.as_bytes());
    let password_matches = constant_time_eq(password.as_bytes(), credentials.password.as_bytes());

    username_matches & password_matches
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&l, &r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }

    diff == 0
}

fn unauthorized_response() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"NetScope\"")
        .body(axum::body::Body::from("unauthorized"))
        .unwrap()
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    // Send hello
    let hello = WsServerMsg::Hello {
        version: env!("CARGO_PKG_VERSION").to_string(),
        tick_ms: state.tick_ms,
    };
    if let Ok(json) = serde_json::to_string(&hello)
        && socket.send(Message::Text(json.into())).await.is_err()
    {
        return;
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
                            if let Some(seq) = frame.frame_seq
                                && last_sent_frame_seq == Some(seq) {
                                    continue;
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
                                    if let Ok(json) = serde_json::to_string(&response)
                                        && socket.send(Message::Text(json.into())).await.is_err() {
                                            break;
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
                                    if let Ok(json) = serde_json::to_string(&response)
                                        && socket.send(Message::Text(json.into())).await.is_err() {
                                            break;
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

    if path == "api" || path.starts_with("api/") {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("not found"))
            .unwrap();
    }

    // Try the exact path first, then fall back to index.html (SPA)
    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(axum::body::Body::from(content.data.to_vec()))
            .unwrap()
    } else if should_serve_spa(path) {
        let content = match Assets::get("index.html") {
            Some(content) => content,
            None => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(axum::body::Body::from("not found"))
                    .unwrap();
            }
        };
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

fn should_serve_spa(path: &str) -> bool {
    path.is_empty() || !path.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::util::ServiceExt;

    fn test_state(auth: Option<BasicAuthCredentials>) -> Arc<AppState> {
        let (broadcast_tx, _) = broadcast::channel::<BroadcastFrame>(16);
        Arc::new(AppState {
            broadcast_tx,
            latest_frame: Mutex::new(None),
            packet_store: Mutex::new(PacketStore::new(8)),
            tick_ms: 1000,
            basic_auth: auth,
        })
    }

    fn test_router(auth: Option<BasicAuthCredentials>) -> Router {
        let state = test_state(auth);
        Router::new()
            .route("/api/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .with_state(state.clone())
            .layer(middleware::from_fn_with_state(state, auth_middleware))
    }

    #[tokio::test]
    async fn health_without_auth_config_is_public() {
        let app = test_router(None);
        let request = Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_requires_auth_when_configured() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let request = Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .expect("WWW-Authenticate header should be present"),
            "Basic realm=\"NetScope\""
        );
    }

    #[tokio::test]
    async fn health_accepts_valid_basic_auth_header() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let token = BASE64_STANDARD.encode("netscope:secret");
        let request = Request::builder()
            .uri("/api/health")
            .header(header::AUTHORIZATION, format!("Basic {}", token))
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_without_auth_config_is_public() {
        let app = test_router(None);
        let request = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content type header should be present"),
            crate::metrics::prometheus_content_type()
        );
    }

    #[tokio::test]
    async fn metrics_requires_auth_when_configured() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let request = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_accepts_valid_basic_auth_header() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let token = BASE64_STANDARD.encode("netscope:secret");
        let request = Request::builder()
            .uri("/metrics")
            .header(header::AUTHORIZATION, format!("Basic {}", token))
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        let body = String::from_utf8(body.to_vec()).expect("response body should be valid utf8");
        assert!(body.contains("netscope_build_info"));
    }
}
