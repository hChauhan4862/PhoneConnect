//! The file commands' HTTP surface: `POST /api/devices/{id}/files/{operation}`.
//!
//! These routes are deliberately thin. The device owns the file vocabulary and the path
//! safety ([`crate::commands`] forwards a name it does not interpret); the server's only jobs
//! are to authorize the caller, to refuse a write it knows is out of bounds, and to hand the
//! command to the same dispatch path — and the same audit row — every other command uses.
//!
//! Nothing here stores file content. An accepted write is forwarded as the caller's own
//! base64 string; the command record keeps the device's answer (`bytes_written`, entries, a
//! read chunk) in memory and nothing is written to disk or logged. The one size rule the
//! server *does* enforce is [`MAX_WRITE_BYTES`], because refusing a 100 MiB body after it has
//! crossed the network wastes the device's deadline: `413 too_large`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::commands::{
    CommandAccepted, CommandError, CommandQuery, authorize_control, dispatch_for_actor,
    record_refusal, required_user,
};
use crate::{ApiJson, AppState};

/// The longest path the server will forward. A path is a name inside the device's shared root,
/// not a payload.
pub const MAX_PATH_BYTES: usize = 4_096;

/// The most decoded bytes one write may carry. The device enforces the same cap; this one
/// exists so an oversized write is refused before it crosses the network.
pub const MAX_WRITE_BYTES: usize = 1024 * 1024;

/// The base64 form of [`MAX_WRITE_BYTES`]: anything longer decodes past the cap.
const MAX_ENCODED_BYTES: usize = 4 * MAX_WRITE_BYTES.div_ceil(3);

/// Why a file request was refused before it became a command. The codes are the same machine
/// codes the UI already renders for a device refusal.
#[derive(Debug, thiserror::Error)]
pub enum FileRequestError {
    #[error("invalid file request: {reason}")]
    InvalidRequest { reason: String },
    #[error("data_base64 is not valid base64")]
    InvalidBase64,
    #[error("a write may carry at most {MAX_WRITE_BYTES} decoded bytes")]
    TooLarge,
    #[error(transparent)]
    Command(#[from] CommandError),
}

impl FileRequestError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => "invalid_request",
            Self::InvalidBase64 => "invalid_base64",
            Self::TooLarge => "too_large",
            Self::Command(error) => error.code(),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest { .. } | Self::InvalidBase64 => StatusCode::BAD_REQUEST,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Command(error) => error.status(),
        }
    }
}

impl IntoResponse for FileRequestError {
    fn into_response(self) -> Response {
        match self {
            // A throttled caller keeps the `Retry-After` the command surface sets.
            Self::Command(error) => error.into_response(),
            other => (other.status(), Json(json!({ "error": other.code() }))).into_response(),
        }
    }
}

/// `POST /api/devices/{id}/files/list`: one directory's entries.
pub async fn list_files(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), FileRequestError> {
    let args = require_path(&body).map(|path| json!({ "path": path }));
    submit(&state, &device_id, &headers, &query, "files.list", args).await
}

/// `POST /api/devices/{id}/files/read`: one chunk of a file.
pub async fn read_file(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), FileRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "files.read",
        read_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/files/write`: a whole file, or an append.
pub async fn write_file(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), FileRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "files.write",
        write_args(&body),
    )
    .await
}

/// `POST /api/devices/{id}/files/mkdir`: one new directory.
pub async fn make_directory(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), FileRequestError> {
    let args = require_path(&body).map(|path| json!({ "path": path }));
    submit(&state, &device_id, &headers, &query, "files.mkdir", args).await
}

/// `POST /api/devices/{id}/files/delete`: a file or an empty directory.
pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), FileRequestError> {
    let args = require_path(&body).map(|path| json!({ "path": path }));
    submit(&state, &device_id, &headers, &query, "files.delete", args).await
}

/// `POST /api/devices/{id}/files/rename`: one move inside the shared root.
pub async fn rename_entry(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<CommandAccepted>), FileRequestError> {
    submit(
        &state,
        &device_id,
        &headers,
        &query,
        "files.rename",
        rename_args(&body),
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
    args: Result<Value, FileRequestError>,
) -> Result<(StatusCode, Json<CommandAccepted>), FileRequestError> {
    state
        .auth
        .require_admin(headers)
        .map_err(CommandError::from)?;
    let actor = required_user(query)?;
    // The authorization decision comes before the request-shape check, so a refusal row is
    // only written for a caller that could act on the device it named, and an unauthorized
    // attempt is classified by the authorization failure.
    if let Err(error) = authorize_control(state, device_id, &actor).await {
        record_refusal(state, device_id, &actor, error.code()).await;
        return Err(FileRequestError::Command(error));
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

fn require_path(body: &Value) -> Result<String, FileRequestError> {
    let value = body
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("path is required and must be a string"))?;
    check_path(value)?;
    Ok(value.to_owned())
}

/// A path the server forwards is a name inside the device's root. The device's own guard is
/// the authority on safety; this only refuses what is not a path at all.
fn check_path(value: &str) -> Result<(), FileRequestError> {
    if value.len() > MAX_PATH_BYTES {
        return Err(invalid("path is longer than the server forwards"));
    }
    if value.contains('\u{0}') {
        return Err(invalid("path may not contain a NUL byte"));
    }
    Ok(())
}

fn read_args(body: &Value) -> Result<Value, FileRequestError> {
    let path = require_path(body)?;
    let mut args = json!({ "path": path });
    for key in ["offset", "length"] {
        let Some(value) = body.get(key) else { continue };
        let number = value
            .as_u64()
            .ok_or_else(|| invalid(format!("{key} must be a non-negative integer")))?;
        args[key] = json!(number);
    }
    Ok(args)
}

fn write_args(body: &Value) -> Result<Value, FileRequestError> {
    let path = require_path(body)?;
    let encoded = body
        .get("data_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("data_base64 is required and must be a string"))?;
    // Refuse by length first: an oversized body is never decoded, so it costs only its own
    // bytes on the wire.
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err(FileRequestError::TooLarge);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| FileRequestError::InvalidBase64)?;
    if decoded.len() > MAX_WRITE_BYTES {
        return Err(FileRequestError::TooLarge);
    }
    let mut args = json!({ "path": path, "data_base64": encoded });
    if let Some(value) = body.get("append") {
        let append = value
            .as_bool()
            .ok_or_else(|| invalid("append must be a boolean"))?;
        args["append"] = json!(append);
    }
    Ok(args)
}

fn rename_args(body: &Value) -> Result<Value, FileRequestError> {
    let from = body
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("from is required and must be a string"))?;
    let to = body
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("to is required and must be a string"))?;
    check_path(from)?;
    check_path(to)?;
    Ok(json!({ "from": from, "to": to }))
}

fn invalid(reason: impl Into<String>) -> FileRequestError {
    FileRequestError::InvalidRequest {
        reason: reason.into(),
    }
}
