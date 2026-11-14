//! Shared helpers for the PhoneConnect server integration tests.

#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use phoneconnect_server::relay::RelayLimits;
use phoneconnect_server::store::{Clock, ManualClock, RevocationAudit, SqliteStore};
use phoneconnect_server::{AppState, build_router};
use serde_json::{Value, json};
use tower::ServiceExt;

pub const ADMIN_TOKEN: &str = "test-admin-token";
/// Base of the relay transport route. One session's transport lives at
/// [`relay_url`]`(session_id)`.
pub const RELAY_ENDPOINT: &str = "https://relay.test/api/sessions";
pub const NOW_MS: i64 = 1_760_000_000_000;

/// A revocation audit for a test that drives the store directly rather than a route. The
/// HTTP handlers always name the real actor and action.
pub fn store_device_revocation() -> RevocationAudit<'static> {
    RevocationAudit {
        actor: "store-test",
        action: phoneconnect_server::audit::ACTION_DEVICE_REVOKE,
    }
}

pub fn store_session_revocation() -> RevocationAudit<'static> {
    RevocationAudit {
        actor: "store-test",
        action: phoneconnect_server::audit::ACTION_SESSION_REVOKE,
    }
}

/// The live relay route for one session, as advertised in leases and candidates.
pub fn relay_url(session_id: &str) -> String {
    format!("{RELAY_ENDPOINT}/{session_id}/relay")
}

pub struct TestApp {
    pub state: Arc<AppState>,
    pub store: Arc<SqliteStore>,
    pub clock: Arc<ManualClock>,
    router: Router,
}

impl TestApp {
    pub fn new() -> Self {
        Self::with_relay(RelayLimits::default())
    }

    pub fn with_relay(limits: RelayLimits) -> Self {
        let store = Arc::new(SqliteStore::in_memory().expect("in-memory sqlite store"));
        Self::with_store_and_relay(store, limits)
    }

    /// The same app over a caller-supplied store, so a test can reach the same file from a
    /// second connection (a broken table, a query plan, a restart).
    pub fn with_store(store: Arc<SqliteStore>) -> Self {
        Self::with_store_and_relay(store, RelayLimits::default())
    }

    pub fn with_store_and_relay(store: Arc<SqliteStore>, limits: RelayLimits) -> Self {
        let clock = Arc::new(ManualClock::new(NOW_MS));
        let state = Arc::new(
            AppState::new(
                store.clone(),
                ADMIN_TOKEN,
                RELAY_ENDPOINT,
                limits,
                clock.clone(),
            )
            .expect("app state accepts a non-empty admin token"),
        );
        let router = build_router(state.clone());
        Self {
            state,
            store,
            clock,
            router,
        }
    }

    pub fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    pub async fn request(
        &self,
        method: Method,
        uri: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (status, _headers, value) = self.request_with_headers(method, uri, bearer, body).await;
        (status, value)
    }

    /// The same request, with the response headers a caller may have to act on
    /// (`Retry-After` on a throttled command).
    pub async fn request_with_headers(
        &self,
        method: Method,
        uri: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&value).expect("json body"))
            }
            None => Body::empty(),
        };
        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("router responds");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collected")
            .to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json response")
        };
        (status, headers, value)
    }

    pub async fn issue_token(&self, owner_id: &str) -> String {
        self.issue_token_with_ttl(owner_id, 900).await
    }

    pub async fn issue_token_with_ttl(&self, owner_id: &str, ttl_seconds: i64) -> String {
        let (status, body) = self
            .request(
                Method::POST,
                "/api/enrollment-tokens",
                Some(ADMIN_TOKEN),
                Some(json!({ "owner_id": owner_id, "expires_in_seconds": ttl_seconds })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "issue token failed: {body}");
        body["token"].as_str().expect("token").to_owned()
    }

    /// A fresh 32-byte X25519 identity public key in the wire form the server accepts.
    pub fn identity_key() -> String {
        phoneconnect_server::auth::generate_secret("").expect("identity key material")
    }

    pub async fn enroll_raw(&self, token: &str) -> (StatusCode, Value) {
        self.enroll_raw_with_identity(token, &Self::identity_key())
            .await
    }

    pub async fn enroll_raw_with_identity(
        &self,
        token: &str,
        identity_key: &str,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            "/api/devices/enroll",
            None,
            Some(json!({ "token": token, "identity_key": identity_key })),
        )
        .await
    }

    pub async fn enroll_new(&self, owner_id: &str) -> (String, String) {
        let (device_id, credential, _identity) = self.enroll_new_with_identity(owner_id).await;
        (device_id, credential)
    }

    /// Enrolls and returns the identity public key the device pinned, so a test can build
    /// the peer end of the AEAD tunnel.
    pub async fn enroll_new_with_identity(&self, owner_id: &str) -> (String, String, String) {
        let token = self.issue_token(owner_id).await;
        let identity_key = Self::identity_key();
        let (status, body) = self.enroll_raw_with_identity(&token, &identity_key).await;
        assert_eq!(status, StatusCode::CREATED, "enroll failed: {body}");
        (
            body["device_id"].as_str().expect("device_id").to_owned(),
            body["credential"].as_str().expect("credential").to_owned(),
            identity_key,
        )
    }

    pub async fn create_session_raw(
        &self,
        device_id: &str,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        self.create_session_with_identity(device_id, bearer, &Self::identity_key())
            .await
    }

    pub async fn create_session_with_identity(
        &self,
        device_id: &str,
        bearer: Option<&str>,
        client_identity_key: &str,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            "/api/sessions",
            bearer,
            Some(json!({
                "device_id": device_id,
                "client_identity_key": client_identity_key
            })),
        )
        .await
    }

    pub async fn create_session(&self, device_id: &str) -> Value {
        let (status, body) = self.create_session_raw(device_id, Some(ADMIN_TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "create session failed: {body}");
        body
    }

    pub async fn candidates(&self, session_id: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/api/sessions/{session_id}/candidates"),
            bearer,
            None,
        )
        .await
    }

    pub async fn ticket(&self, session_id: &str, bearer: &str) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/api/sessions/{session_id}/ticket"),
            Some(bearer),
            None,
        )
        .await
    }

    /// Redeems a ticket to publish a redemption nonce without advertising an endpoint.
    pub async fn register_nonce_only(
        &self,
        session_id: &str,
        bearer: &str,
        ticket: &Value,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/sessions/{session_id}/candidates"),
            Some(bearer),
            Some(json!({ "ticket": ticket })),
        )
        .await
    }

    pub async fn register_candidate(
        &self,
        session_id: &str,
        bearer: &str,
        ticket: &Value,
        endpoint: &str,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/sessions/{session_id}/candidates"),
            Some(bearer),
            Some(json!({ "ticket": ticket, "endpoint": endpoint })),
        )
        .await
    }

    pub async fn relay_upgrade(
        &self,
        session_id: &str,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/sessions/{session_id}/relay"),
            bearer,
            None,
        )
        .await
    }

    /// `POST /api/{kind}/{id}/revoke`, where `kind` is `devices`, `sessions`, or
    /// `enrollment-tokens`.
    pub async fn revoke(&self, kind: &str, id: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/{kind}/{id}/revoke"),
            bearer,
            None,
        )
        .await
    }

    /// `POST /api/devices/{id}/lease`: the owner (or a grantee) acquires control.
    pub async fn acquire_lease(
        &self,
        device_id: &str,
        actor_id: &str,
        expires_in_seconds: i64,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/devices/{device_id}/lease"),
            Some(ADMIN_TOKEN),
            Some(json!({ "actor_id": actor_id, "expires_in_seconds": expires_in_seconds })),
        )
        .await
    }

    /// `POST /api/devices/{id}/lease/handoff`: explicit transfer of control.
    pub async fn handoff_lease(
        &self,
        device_id: &str,
        actor_id: &str,
        to_user_id: &str,
        expires_in_seconds: i64,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/devices/{device_id}/lease/handoff"),
            Some(ADMIN_TOKEN),
            Some(json!({
                "actor_id": actor_id,
                "to_user_id": to_user_id,
                "expires_in_seconds": expires_in_seconds
            })),
        )
        .await
    }

    /// `POST /api/leases/{id}/revoke`: immediate revocation of one lease.
    pub async fn revoke_lease(&self, lease_id: &str, actor_id: &str) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/leases/{lease_id}/revoke"),
            Some(ADMIN_TOKEN),
            Some(json!({ "actor_id": actor_id })),
        )
        .await
    }

    /// `GET /api/devices/{id}/lease?user_id=...`: the active lease and one user's access.
    pub async fn lease_status(&self, device_id: &str, user_id: &str) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/api/devices/{device_id}/lease?user_id={user_id}"),
            Some(ADMIN_TOKEN),
            None,
        )
        .await
    }

    /// `POST /api/sessions` with `control: true`: a control stream needs a live lease.
    pub async fn create_control_session(
        &self,
        device_id: &str,
        user_id: &str,
        client_identity_key: &str,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            "/api/sessions",
            Some(ADMIN_TOKEN),
            Some(json!({
                "device_id": device_id,
                "client_identity_key": client_identity_key,
                "control": true,
                "user_id": user_id
            })),
        )
        .await
    }

    /// `GET /api/devices/{id}/sessions/next` as the device itself.
    pub async fn device_session(
        &self,
        device_id: &str,
        device_credential: &str,
    ) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/api/devices/{device_id}/sessions/next"),
            Some(device_credential),
            None,
        )
        .await
    }

    /// `POST /api/devices/{id}/telemetry` as the device itself.
    pub async fn ingest_telemetry(
        &self,
        device_id: &str,
        device_credential: &str,
        battery_percent: u8,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/devices/{device_id}/telemetry"),
            Some(device_credential),
            Some(json!({
                "sampled_at_ms": self.now(),
                "battery_percent": battery_percent,
                "cpu_percent": 12.5,
                "memory_used_bytes": 1_048_576,
                "memory_total_bytes": 8_388_608,
                "battery_charging": true,
                "connectivity": "wifi"
            })),
        )
        .await
    }

    /// `GET /api/devices/{id}/status?user_id=...`: the status surface the web UI renders.
    pub async fn device_status(&self, device_id: &str, user_id: &str) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/api/devices/{device_id}/status?user_id={user_id}"),
            Some(ADMIN_TOKEN),
            None,
        )
        .await
    }

    /// `POST /api/devices/{id}/commands?user_id=...`: dispatch one management command.
    pub async fn dispatch_command(
        &self,
        device_id: &str,
        user_id: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/devices/{device_id}/commands?user_id={user_id}"),
            Some(ADMIN_TOKEN),
            Some(body),
        )
        .await
    }

    /// `POST /api/devices/{id}/commands` exactly as given, so a test can vary the query.
    pub async fn dispatch_command_at(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        self.request(Method::POST, uri, Some(ADMIN_TOKEN), Some(body))
            .await
    }

    /// `GET /api/commands/{id}?user_id=...`: one command's current state.
    pub async fn command(&self, command_id: &str, user_id: &str) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/api/commands/{command_id}?user_id={user_id}"),
            Some(ADMIN_TOKEN),
            None,
        )
        .await
    }
}

/// A live management channel: the tests serve the real router on a loopback port, so the
/// WebSocket upgrade, the registry, and the device-facing frames are exercised end to end.
pub mod control {
    use std::time::Duration;

    use axum::http::{Method, StatusCode};
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio_tungstenite::MaybeTlsStream;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Error;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    use super::TestApp;

    pub type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    pub fn path(device_id: &str) -> String {
        format!("/api/devices/{device_id}/control")
    }

    /// Serves the router on a loopback port and returns the `ws://` base.
    pub async fn serve(app: &TestApp) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let router = phoneconnect_server::build_router(app.state.clone());
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        (format!("ws://{address}"), handle)
    }

    /// The HTTP answer a rejected WebSocket handshake receives: exactly what an agent sees
    /// when its credential is refused.
    pub async fn reject(base: &str, device_id: &str, bearer: &str) -> (u16, Value) {
        match connect(base, device_id, bearer).await {
            Err(Error::Http(response)) => {
                let status = response.status().as_u16();
                let body = response
                    .body()
                    .as_ref()
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .unwrap_or_default();
                let value = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_str(&body).unwrap_or(Value::String(body))
                };
                (status, value)
            }
            Err(other) => panic!("expected an HTTP rejection, got {other:?}"),
            Ok(_) => panic!("expected the handshake to be refused"),
        }
    }

    /// A plain GET without upgrade headers, for the transport refusal it earns.
    pub async fn plain_get(app: &TestApp, device_id: &str, bearer: &str) -> (StatusCode, String) {
        use tower::ServiceExt;

        let request = axum::http::Request::builder()
            .method(Method::GET)
            .uri(path(device_id))
            .header("authorization", format!("Bearer {bearer}"))
            .body(axum::body::Body::empty())
            .expect("request");
        let response = phoneconnect_server::build_router(app.state.clone())
            .oneshot(request)
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body collected")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    pub async fn connect(base: &str, device_id: &str, credential: &str) -> Result<Socket, Error> {
        let url = format!("{base}{}", path(device_id));
        let mut request = url.into_client_request().expect("websocket request");
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {credential}")
                .parse()
                .expect("bearer header"),
        );
        tokio_tungstenite::connect_async(request)
            .await
            .map(|(socket, _)| socket)
    }

    /// Connects and waits until the registry has registered the device, so a command sent
    /// immediately after cannot race the server's upgrade task.
    pub async fn connect_ok(
        app: &TestApp,
        device_id: &str,
        credential: &str,
    ) -> (Socket, String, tokio::task::JoinHandle<()>) {
        let (base, server) = serve(app).await;
        let socket = connect(&base, device_id, credential)
            .await
            .expect("authorized device attaches to the control channel");
        wait_online(app, device_id).await;
        (socket, base, server)
    }

    pub async fn wait_online(app: &TestApp, device_id: &str) {
        for _ in 0..200 {
            if app.state.management.is_online(device_id) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the device never became online on the management channel");
    }

    pub async fn wait_offline(app: &TestApp, device_id: &str) {
        for _ in 0..200 {
            if !app.state.management.is_online(device_id) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the device stayed online after its channel ended");
    }

    pub async fn send(socket: &mut Socket, value: Value) {
        socket
            .send(Message::Text(value.to_string().into()))
            .await
            .expect("frame sent");
    }

    /// Sends a frame and reports whether the socket accepted it, so a flood test can stop
    /// when the server has already closed the channel.
    pub async fn try_send(socket: &mut Socket, value: Value) -> bool {
        socket
            .send(Message::Text(value.to_string().into()))
            .await
            .is_ok()
    }

    /// Answers a real WebSocket upgrade request on a connection that cannot be upgraded.
    ///
    /// The extractor accepts the request, the handler runs and answers `101`, and the upgrade
    /// future then fails. That is exactly the "failed upgrade" an agent can hit, and it must
    /// not touch the device's registration.
    pub async fn failed_upgrade(app: &TestApp, device_id: &str, credential: &str) -> StatusCode {
        use tower::ServiceExt;

        let mut request = axum::http::Request::builder()
            .method(Method::GET)
            .uri(path(device_id))
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .header("authorization", format!("Bearer {credential}"))
            .body(axum::body::Body::empty())
            .expect("request");
        // `on` with no connection upgrade in place yields a future that fails at once; the
        // extractor removes it, so the handler's upgrade never completes.
        let not_upgradable = hyper::upgrade::on(&mut request);
        request.extensions_mut().insert(not_upgradable);

        phoneconnect_server::build_router(app.state.clone())
            .oneshot(request)
            .await
            .expect("router responds")
            .status()
    }

    pub async fn send_text(socket: &mut Socket, text: &str) {
        socket
            .send(Message::Text(text.to_owned().into()))
            .await
            .expect("frame sent");
    }

    pub async fn next_message(socket: &mut Socket) -> Message {
        tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("a message arrives within the deadline")
            .expect("the stream is open")
            .expect("a valid message")
    }

    pub async fn next_json(socket: &mut Socket) -> Value {
        match next_message(socket).await {
            Message::Text(text) => serde_json::from_str(&text).expect("a JSON text frame"),
            other => panic!("expected a JSON text frame, got {other:?}"),
        }
    }

    pub async fn next_close(socket: &mut Socket) -> (u16, String) {
        match next_message(socket).await {
            Message::Close(Some(frame)) => {
                (u16::from(frame.code), frame.reason.as_str().to_owned())
            }
            other => panic!("expected a close frame, got {other:?}"),
        }
    }

    /// A `result` frame for `request_id`.
    pub fn result(request_id: &str, status: &str, output: Value) -> Value {
        json!({
            "type": "result",
            "request_id": request_id,
            "status": status,
            "output": output,
            "error": null,
            "message": null
        })
    }

    /// A `result` error frame for `request_id`.
    pub fn error_result(request_id: &str, error: &str, message: &str) -> Value {
        json!({
            "type": "result",
            "request_id": request_id,
            "status": "error",
            "output": null,
            "error": error,
            "message": message
        })
    }
}
