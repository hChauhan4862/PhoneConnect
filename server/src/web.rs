//! Server-served web UI: the one UI implementation both browsers and the native shell load.
//!
//! The app is served from `/` with an SPA fallback for its own routes, so a deep link and a
//! webview loading `<server>/` get the same document. An unknown `/api/...` path is always a
//! JSON 404, never the app shell. Every response carries a strict CSP and `nosniff`, and a
//! resolved file never escapes the web root.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::{AppState, build_router};

/// The document an SPA route and `/` both resolve to.
pub const INDEX_DOCUMENT: &str = "index.html";

/// Strict content policy: same-origin scripts and styles only, no framing, no object
/// embedding, no inline or evaluated script.
///
/// `connect-src` also allows the Tauri IPC scheme and host. The native shell embeds this same
/// document and installs its bridge before load; the bridge's `fetch("ipc://localhost/…")`
/// is governed by this page policy, so leaving it out would silently disable every native
/// capability. A browser has neither the scheme nor the host and is unaffected.
///
/// `frame-src 'self'` is explicit even though `default-src 'self'` already implies it:
/// WebView2 installs the shell's initialization scripts into subframes too, so a frame from
/// another origin would otherwise be a place the bridge globals could appear. The shell also
/// mints its IPC capability for the configured origin only; this header is the second half of
/// the same mitigation.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self'; img-src 'self' data:; font-src 'self'; \
     connect-src 'self' ipc: http://ipc.localhost; \
     manifest-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; \
     form-action 'self'; frame-ancestors 'none'";

/// Cache policy for a built asset: the build fingerprints file names, so an asset is
/// immutable while the app shell always revalidates.
const ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const SHELL_CACHE_CONTROL: &str = "no-cache";

#[derive(Debug, thiserror::Error)]
pub enum WebUiError {
    #[error("web root {root} has no {INDEX_DOCUMENT}")]
    MissingIndexDocument { root: String },
    #[error("failed to read {path}: {source}")]
    ReadFailure {
        path: String,
        source: std::io::Error,
    },
}

/// A built web app on disk. The index document is read once at startup so a missing build
/// fails loudly instead of serving an empty page.
#[derive(Debug)]
pub struct WebUi {
    root: PathBuf,
    index: String,
}

impl WebUi {
    pub fn load(root: impl AsRef<Path>) -> Result<Self, WebUiError> {
        let root = root.as_ref().to_path_buf();
        let index_path = root.join(INDEX_DOCUMENT);
        let index = std::fs::read_to_string(&index_path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                WebUiError::MissingIndexDocument {
                    root: root.display().to_string(),
                }
            } else {
                WebUiError::ReadFailure {
                    path: index_path.display().to_string(),
                    source,
                }
            }
        })?;
        Ok(Self { root, index })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Serves one request. The router's API routes are matched first, so this only sees the
    /// app's own routes, its assets, and unknown paths.
    pub async fn serve(&self, request: Request) -> Response {
        let path = request.uri().path().to_owned();

        // Classify on the decoded path: `/api%2Fnope` is an API path, not an app route.
        let decoded = match percent_decode(&path) {
            Ok(decoded) => decoded,
            Err(()) => return not_found(),
        };
        if is_api_path(&decoded) {
            return api_not_found();
        }
        if is_unsafe_path(&decoded) {
            return not_found();
        }
        if request.method() != Method::GET && request.method() != Method::HEAD {
            let mut response = (
                StatusCode::METHOD_NOT_ALLOWED,
                axum::Json(json!({ "error": "method_not_allowed" })),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return secure(response);
        }
        let relative = decoded.trim_start_matches('/');
        if !relative.is_empty() {
            let candidate = self.root.join(relative);
            if candidate.starts_with(&self.root) {
                match tokio::fs::read(&candidate).await {
                    Ok(bytes) => return secure(file_response(bytes, &candidate)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return not_found(),
                }
            }
            // A path that names a file but does not resolve is a real miss. Serving the app
            // shell here would hand a client HTML labelled as JavaScript.
            if Path::new(relative).extension().is_some() {
                return not_found();
            }
        }
        secure(shell_response(self.index.clone()))
    }
}

/// Serves the API and the built web app from one router, so the browser and the native
/// shell load the identical origin and URL.
pub fn router_with_web_ui(state: Arc<AppState>, ui: WebUi) -> Router {
    let ui = Arc::new(ui);
    build_router(state).fallback(move |request: Request| {
        let ui = Arc::clone(&ui);
        async move { ui.serve(request).await }
    })
}

fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

fn is_unsafe_path(decoded: &str) -> bool {
    decoded
        .split('/')
        .any(|segment| segment == ".." || segment == ".")
        || decoded.contains('\\')
        || decoded.contains('\0')
}

fn percent_decode(path: &str) -> Result<String, ()> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(());
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).map_err(|_| ())?;
            decoded.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn api_not_found() -> Response {
    secure(
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": "api_not_found" })),
        )
            .into_response(),
    )
}

fn not_found() -> Response {
    secure(
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": "not_found" })),
        )
            .into_response(),
    )
}

fn shell_response(index: String) -> Response {
    let mut response = Response::new(Body::from(index));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(SHELL_CACHE_CONTROL),
    );
    response
}

fn file_response(bytes: Vec<u8>, path: &Path) -> Response {
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type_for(path))
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(ASSET_CACHE_CONTROL),
    );
    response
}

fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
    {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Adds the headers every web response carries, including error responses: the CSP applies
/// to the JSON refusals too, so no response is served without it.
fn secure(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}
