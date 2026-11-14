//! The screen route: `POST /api/devices/{id}/screen/snapshot`.
//!
//! Deliberately thin, like the file and app routes. The device is the authority on whether it
//! can capture at all — without the projection consent the user granted on the setup screen
//! the answer is `consent_required` — and this route passes that through without prompting
//! anything or inventing a frame. It authorizes the caller, refuses a body that is not an
//! object, and dispatches through the one path that owns deadlines, capacity, and the audit
//! row.
//!
//! The frame itself is not stored: the command record keeps the device's answer in memory,
//! and an answer over the result cap is refused as `result_too_large` by the management
//! channel exactly like any other oversized result.

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

/// Why a snapshot request was refused before it became a command.
#[derive(Debug, thiserror::Error)]
pub enum ScreenRequestError {
    #[error("invalid screen request: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error(transparent)]
    Command(#[from] CommandError),
}

impl ScreenRequestError {
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

impl IntoResponse for ScreenRequestError {
    fn into_response(self) -> Response {
        match self {
            // A throttled caller keeps the `Retry-After` the command surface sets.
            Self::Command(error) => error.into_response(),
            other => (other.status(), Json(json!({ "error": other.code() }))).into_response(),
        }
    }
}

/// `POST /api/devices/{id}/screen/snapshot`: one frame through the device's own projection.
pub async fn snapshot_screen(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), ScreenRequestError> {
    state
        .auth
        .require_admin(&headers)
        .map_err(CommandError::from)?;
    let actor = required_user(&query)?;
    // Every attempt that can be traced charges the device's creation budget before an outcome
    // is decided, so a flood of refusals cannot append rows through the throttle.
    if let Some(error) = charge_attempt(&state, &device_id) {
        return Err(ScreenRequestError::Command(error));
    }
    // The authorization decision comes before the request-shape check, so a refusal row is
    // only written for a caller that could act on the device it named.
    if let Err(error) = authorize_control(&state, &device_id, &actor).await {
        record_refusal(&state, &device_id, &actor, error.code()).await;
        return Err(ScreenRequestError::Command(error));
    }
    if !body.is_object() && !body.is_null() {
        let error = ScreenRequestError::InvalidRequest {
            reason: "the body must be an object",
        };
        // A refusal the server makes is as traceable as one the device makes.
        record_refusal(&state, &device_id, &actor, error.code()).await;
        return Err(error);
    }
    // `screen.snapshot` takes no arguments; a caller cannot smuggle one to the device.
    let dispatch = dispatch_for_actor(
        &state,
        &device_id,
        &actor,
        "screen.snapshot",
        Some(json!({})),
        None,
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CommandAccepted {
            command_id: dispatch.command_id,
        }),
    ))
}
