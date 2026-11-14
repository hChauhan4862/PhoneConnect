//! The console routes: `POST /api/devices/{id}/console/{props,shell,logcat}`.
//!
//! `system.props` is the one console capability an ordinary installed app has: a documented
//! allowlist read through the platform's own property reader. The server forwards a
//! structurally valid key list and lets the device decide what its allowlist permits; a key
//! outside it is the device's `not_permitted`.
//!
//! `shell.exec` and `logcat.tail` are forwarded so a caller receives the device's constant
//! `not_permitted` with its reason instead of `unknown_command`. Neither can succeed for an
//! ordinary app (a shell needs the ADB/root UID; the system log needs the signature-level
//! `READ_LOGS`), and this route never fabricates output for them. There is no streaming
//! endpoint: one answer per accepted command.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::commands::{
    CommandAccepted, CommandError, CommandQuery, authorize_control, charge_attempt,
    dispatch_for_actor, record_refusal, required_user,
};
use crate::{ApiJson, AppState};

/// The most property names one request may select. The allowlist is six; this bound only
/// keeps an absurd list off the device.
pub const MAX_PROPERTY_KEYS: usize = 32;

/// The longest one property name may be. Allowlisted names are far shorter.
pub const MAX_PROPERTY_KEY_BYTES: usize = 64;

/// Why a console request was refused before it became a command.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleRequestError {
    #[error("invalid console request: {reason}")]
    InvalidRequest { reason: String },
    #[error(transparent)]
    Command(#[from] CommandError),
}

impl ConsoleRequestError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => "invalid_request",
            Self::Command(error) => error.code(),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Command(error) => error.status(),
        }
    }
}

impl IntoResponse for ConsoleRequestError {
    fn into_response(self) -> Response {
        match self {
            Self::Command(error) => error.into_response(),
            other => (other.status(), Json(json!({ "error": other.code() }))).into_response(),
        }
    }
}

/// `POST /api/devices/{id}/console/props`: the device's documented system properties.
pub async fn read_properties(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), ConsoleRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "system.props",
        props_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/console/shell`: forwarded so the device can refuse it honestly.
pub async fn run_shell(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), ConsoleRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "shell.exec",
        no_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/console/logcat`: forwarded so the device can refuse it honestly.
pub async fn tail_logcat(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), ConsoleRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "logcat.tail",
        no_args(&body),
    )
    .await
}

/// Authorizes the caller, records a refusal the server makes itself, and dispatches.
///
/// Nothing is dispatched (and no refusal is audited) until the caller holds the admin token
/// *and* control of this device, so a stranger cannot append a row naming a device it may not
/// touch.
async fn submit(
    state: &AppState,
    device_id: &str,
    headers: &HeaderMap,
    query: &CommandQuery,
    name: &str,
    args: Result<Value, ConsoleRequestError>,
) -> Result<(StatusCode, Json<CommandAccepted>), ConsoleRequestError> {
    state
        .auth
        .require_admin(headers)
        .map_err(CommandError::from)?;
    let actor = required_user(query)?;
    // Every attempt that can be traced charges the device's creation budget before an outcome
    // is decided, so a flood of refusals cannot append rows through the throttle.
    if let Some(error) = charge_attempt(state, device_id) {
        return Err(ConsoleRequestError::Command(error));
    }
    // The authorization decision comes before the request-shape check, so a refusal row is
    // only written for a caller that could act on the device it named, and an unauthorized
    // attempt is classified by the authorization failure.
    if let Err(error) = authorize_control(state, device_id, &actor).await {
        record_refusal(state, device_id, &actor, error.code()).await;
        return Err(ConsoleRequestError::Command(error));
    }
    let args = match args {
        Ok(args) => args,
        Err(error) => {
            record_refusal(state, device_id, &actor, error.code()).await;
            return Err(error);
        }
    };
    let dispatch = dispatch_for_actor(state, device_id, &actor, name, Some(args), None).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CommandAccepted {
            command_id: dispatch.command_id,
        }),
    ))
}

/// An optional `keys` list the device resolves against its own allowlist.
fn props_args(body: &Value) -> Result<Value, ConsoleRequestError> {
    if body.is_null() {
        return Ok(json!({}));
    }
    let object = body
        .as_object()
        .ok_or_else(|| invalid("the body must be an object"))?;
    let Some(raw) = object.get("keys") else {
        return Ok(json!({}));
    };
    let entries = raw
        .as_array()
        .ok_or_else(|| invalid("keys must be an array of property names"))?;
    if entries.is_empty() {
        return Err(invalid("keys must name at least one property"));
    }
    if entries.len() > MAX_PROPERTY_KEYS {
        return Err(invalid(
            "keys names more properties than the server forwards",
        ));
    }
    let mut keys = Vec::with_capacity(entries.len());
    for entry in entries {
        let value = entry
            .as_str()
            .ok_or_else(|| invalid("keys must contain strings"))?;
        let key = value.trim();
        if key.is_empty() {
            return Err(invalid("a property name must not be empty"));
        }
        if key.len() > MAX_PROPERTY_KEY_BYTES {
            return Err(invalid(
                "a property name is longer than the server forwards",
            ));
        }
        if key.contains('\u{0}') {
            return Err(invalid("a property name may not contain a NUL byte"));
        }
        keys.push(key);
    }
    Ok(json!({ "keys": keys }))
}

/// The two refusal commands take no arguments; only a body shape is checked.
fn no_args(body: &Value) -> Result<Value, ConsoleRequestError> {
    if body.is_object() || body.is_null() {
        return Ok(json!({}));
    }
    Err(invalid("the body must be an object"))
}

fn invalid(reason: impl Into<String>) -> ConsoleRequestError {
    ConsoleRequestError::InvalidRequest {
        reason: reason.into(),
    }
}
