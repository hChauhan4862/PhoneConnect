//! The app commands' HTTP surface: `POST /api/devices/{id}/apps/{operation}`.
//!
//! Deliberately thin, like the file routes. The device owns the app vocabulary and every
//! capability decision — `launch_blocked`, `no_launch_activity`, `not_permitted`,
//! `unknown_package` — because only the device knows what its platform permits. The server
//! authorizes the caller, refuses a body that is not a package name, and hands the command to
//! the same dispatch path, deadlines, rate limit, and audit row every other command uses.
//!
//! Nothing here stores an app list: the in-memory command record keeps the device's answer and
//! nothing is written to disk, the database, or the log.

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

/// The longest package name the server forwards. Android package names are far shorter; this
/// bound only keeps an absurd string off the device.
pub const MAX_PACKAGE_BYTES: usize = 255;

/// Why an app request was refused before it became a command. The code is the same machine
/// code the UI already renders for a device refusal.
#[derive(Debug, thiserror::Error)]
pub enum AppRequestError {
    #[error("invalid app request: {reason}")]
    InvalidRequest { reason: String },
    #[error(transparent)]
    Command(#[from] CommandError),
}

impl AppRequestError {
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

impl IntoResponse for AppRequestError {
    fn into_response(self) -> Response {
        match self {
            // A throttled caller keeps the `Retry-After` the command surface sets.
            Self::Command(error) => error.into_response(),
            other => (other.status(), Json(json!({ "error": other.code() }))).into_response(),
        }
    }
}

/// `POST /api/devices/{id}/apps/list`: the device's installed apps.
pub async fn list_apps(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), AppRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "apps.list",
        list_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/apps/launch`: start the app's launcher activity.
pub async fn launch_app(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), AppRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "apps.launch",
        package_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/apps/stop`: ask Android to kill the app's background processes.
pub async fn stop_app(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), AppRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "apps.stop",
        package_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/apps/clear`: forwarded so the device can refuse it honestly.
pub async fn clear_app(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), AppRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "apps.clear",
        package_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/apps/set_enabled`: forwarded so the device can refuse it honestly.
pub async fn set_app_enabled(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), AppRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "apps.set_enabled",
        set_enabled_args(&body),
    )
    .await
}

/// Authorizes the caller, records a refusal the server makes itself, and dispatches.
///
/// Arguments are built before this runs because they are pure; nothing is dispatched (and no
/// refusal is audited) until the caller holds the admin token *and* control of this device, so a
/// stranger cannot append a row naming a device it may not touch.
async fn submit(
    state: &AppState,
    device_id: &str,
    headers: &HeaderMap,
    query: &CommandQuery,
    name: &str,
    args: Result<Value, AppRequestError>,
) -> Result<(StatusCode, Json<CommandAccepted>), AppRequestError> {
    state
        .auth
        .require_admin(headers)
        .map_err(CommandError::from)?;
    let actor = required_user(query)?;
    // Every attempt that can be traced charges the device's creation budget before an outcome
    // is decided, so a flood of refusals cannot append rows through the throttle.
    if let Some(error) = charge_attempt(state, device_id) {
        return Err(AppRequestError::Command(error));
    }
    // The authorization decision comes before the request-shape check, so a refusal row is
    // only written for a caller that could act on the device it named, and an unauthorized
    // attempt is classified by the authorization failure.
    if let Err(error) = authorize_control(state, device_id, &actor).await {
        record_refusal(state, device_id, &actor, error.code()).await;
        return Err(AppRequestError::Command(error));
    }
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

fn list_args(body: &Value) -> Result<Value, AppRequestError> {
    if !body.is_object() && !body.is_null() {
        return Err(invalid("the body must be an object"));
    }
    // `apps.list` takes no arguments; a caller cannot smuggle one to the device.
    Ok(json!({}))
}

fn package_args(body: &Value) -> Result<Value, AppRequestError> {
    let package = require_package(body)?;
    Ok(json!({ "package": package }))
}

fn set_enabled_args(body: &Value) -> Result<Value, AppRequestError> {
    let package = require_package(body)?;
    let enabled = body
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("enabled is required and must be a boolean"))?;
    Ok(json!({ "package": package, "enabled": enabled }))
}

/// A package the server forwards is a name the device resolves against its own app list. The
/// device is the authority on whether it is installed; this only refuses what is not a name.
fn require_package(body: &Value) -> Result<String, AppRequestError> {
    let value = body
        .get("package")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("package is required and must be a string"))?;
    let package = value.trim();
    if package.is_empty() {
        return Err(invalid("package must not be empty"));
    }
    if package.len() > MAX_PACKAGE_BYTES {
        return Err(invalid("package is longer than the server forwards"));
    }
    if package.contains('\u{0}') {
        return Err(invalid("package may not contain a NUL byte"));
    }
    Ok(package.to_owned())
}

fn invalid(reason: impl Into<String>) -> AppRequestError {
    AppRequestError::InvalidRequest {
        reason: reason.into(),
    }
}
