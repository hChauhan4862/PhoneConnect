//! The control routes: `POST /api/devices/{id}/control/{get,set,reboot}`.
//!
//! Deliberately thin, like the app and screen routes. The device owns every capability
//! decision — which readings its platform produces, which changes a user grant gates, and
//! which setters Android removed or made signature-level — because only the device knows what
//! its platform permits. The server authorizes the caller, refuses a body that is not a control
//! request, and forwards through the one dispatch path that owns deadlines, capacity, the rate
//! limit, and the audit row.
//!
//! Nothing here stores a reading: the in-memory command record keeps the device's answer and
//! nothing is written to disk, the database, or the log.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::commands::{
    CommandAccepted, CommandError, CommandQuery, dispatch_for_actor, record_refusal, required_user,
};
use crate::{ApiJson, AppState};

/// The longest control key the server forwards. The device's own keys are far shorter; this
/// bound only keeps an absurd string off the device.
pub const MAX_CONTROL_KEY_BYTES: usize = 32;

/// Why a control request was refused before it became a command. The code is the same machine
/// code the UI already renders for a device refusal.
#[derive(Debug, thiserror::Error)]
pub enum ControlRequestError {
    #[error("invalid control request: {reason}")]
    InvalidRequest { reason: String },
    #[error(transparent)]
    Command(#[from] CommandError),
}

impl ControlRequestError {
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

impl IntoResponse for ControlRequestError {
    fn into_response(self) -> Response {
        match self {
            // A throttled caller keeps the `Retry-After` the command surface sets.
            Self::Command(error) => error.into_response(),
            other => (other.status(), Json(json!({ "error": other.code() }))).into_response(),
        }
    }
}

/// `POST /api/devices/{id}/control/get`: the device's readings and its refusals.
pub async fn read_controls(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), ControlRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "control.get",
        no_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/control/set`: one change, forwarded to the device that owns it.
pub async fn set_control(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), ControlRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "control.set",
        set_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/control/reboot`: forwarded so the device can refuse it honestly.
pub async fn reboot_device(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), ControlRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "control.reboot",
        no_args(&body),
    )
    .await
}

/// Authorizes the caller, records a refusal the server makes itself, and dispatches.
///
/// Arguments are built before this runs because they are pure; nothing is dispatched (and no
/// refusal is audited) until the caller is authorized, so a stranger learns nothing.
async fn submit(
    state: &AppState,
    device_id: &str,
    headers: &HeaderMap,
    query: &CommandQuery,
    name: &str,
    args: Result<Value, ControlRequestError>,
) -> Result<(StatusCode, Json<CommandAccepted>), ControlRequestError> {
    state
        .auth
        .require_admin(headers)
        .map_err(CommandError::from)?;
    let actor = required_user(query)?;
    let args = match args {
        Ok(args) => args,
        Err(error) => {
            // A refusal the server makes is as traceable as one the device makes.
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

fn no_args(body: &Value) -> Result<Value, ControlRequestError> {
    if !body.is_object() && !body.is_null() {
        return Err(invalid("the body must be an object"));
    }
    // `control.get` and `control.reboot` take no arguments; a caller cannot smuggle one to the
    // device.
    Ok(json!({}))
}

fn set_args(body: &Value) -> Result<Value, ControlRequestError> {
    if !body.is_object() {
        return Err(invalid("the body must be an object with a key and a value"));
    }
    let key = require_key(body)?;
    let value = require_value(body)?;
    // The device validates the range (brightness 0–255, volume 0–stream max) because only the
    // device knows the stream max; the server refuses only a value it could not forward.
    Ok(json!({ "key": key, "value": value }))
}

/// A key the server forwards is a name the device resolves against its own vocabulary. The
/// device answers `invalid_args` for a key it does not implement; this only refuses what is
/// not a name.
fn require_key(body: &Value) -> Result<String, ControlRequestError> {
    let value = body
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("key is required and must be a string"))?;
    let key = value.trim();
    if key.is_empty() {
        return Err(invalid("key must not be empty"));
    }
    if key.len() > MAX_CONTROL_KEY_BYTES {
        return Err(invalid("key is longer than the server forwards"));
    }
    if key.contains('\u{0}') {
        return Err(invalid("key may not contain a NUL byte"));
    }
    Ok(key.to_owned())
}

/// A value is a boolean (a radio) or an integer (brightness, volume, the interruption filter).
/// A string, an object, or a fraction never reaches the device.
fn require_value(body: &Value) -> Result<Value, ControlRequestError> {
    let value = body
        .get("value")
        .ok_or_else(|| invalid("value is required"))?;
    match value {
        Value::Bool(_) => Ok(value.clone()),
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => {
            Ok(value.clone())
        }
        _ => Err(invalid("value must be a boolean or an integer")),
    }
}

fn invalid(reason: impl Into<String>) -> ControlRequestError {
    ControlRequestError::InvalidRequest {
        reason: reason.into(),
    }
}
