//! Server-served web UI: one URL for browsers and the native shell, SPA fallback for the
//! app's own routes, explicit 404 for unknown API paths, and a strict CSP.

mod common;

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use common::TestApp;
use http_body_util::BodyExt;
use phoneconnect_server::web::WebUi;
use tower::ServiceExt;

/// A built web app laid out the way Vite emits it.
struct Dist {
    root: PathBuf,
}

impl Dist {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("web-ui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("assets")).expect("dist assets dir");
        std::fs::write(
            root.join("index.html"),
            "<!doctype html><html><head>\
             <link rel=\"stylesheet\" href=\"/assets/index-def456.css\"></head>\
             <body><div id=\"root\"></div>\
             <script type=\"module\" src=\"/assets/index-abc123.js\"></script></body></html>",
        )
        .expect("index document");
        std::fs::write(
            root.join("assets/index-abc123.js"),
            "document.getElementById('root').textContent='PhoneConnect';",
        )
        .expect("script asset");
        std::fs::write(root.join("assets/index-def456.css"), "#root{color:#111}")
            .expect("style asset");
        std::fs::write(
            root.join("favicon.svg"),
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
        )
        .expect("icon asset");
        let directory = Self { root };
        std::fs::write(directory.manifest(), "{\"name\":\"PhoneConnect\"}")
            .expect("manifest asset");
        directory
    }

    fn manifest(&self) -> PathBuf {
        self.root.join("manifest.webmanifest")
    }
}

impl Drop for Dist {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct WebApp {
    app: axum::Router,
    _dist: Dist,
}

impl WebApp {
    fn new(name: &str) -> Self {
        let dist = Dist::new(name);
        let test = TestApp::new();
        let ui = WebUi::load(&dist.root).expect("web ui loads");
        let app = phoneconnect_server::web::router_with_web_ui(test.state.clone(), ui);
        Self { app, _dist: dist }
    }

    async fn get(&self, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        self.request(Method::GET, uri).await
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router responds");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collected")
            .to_bytes()
            .to_vec();
        (status, headers, bytes)
    }
}

fn content_type(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn body_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn the_root_serves_the_spa_document_with_a_strict_csp() {
    let web = WebApp::new("root");

    let (status, headers, body) = web.get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type(&headers), "text/html; charset=utf-8");
    assert!(body_text(&body).contains("<div id=\"root\"></div>"));

    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("the document carries a CSP");
    for required in [
        "default-src 'self'",
        "script-src 'self'",
        // The native shell's bridge rides Tauri IPC from this same document.
        "connect-src 'self' ipc: http://ipc.localhost",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ] {
        assert!(csp.contains(required), "CSP is missing {required}: {csp}");
    }
    for forbidden in ["'unsafe-eval'", "'unsafe-inline'", "*"] {
        assert!(
            !csp.contains(forbidden),
            "CSP must not allow {forbidden}: {csp}"
        );
    }
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
}

#[tokio::test]
async fn deep_routes_return_the_spa_document() {
    let web = WebApp::new("deep");

    for uri in ["/devices", "/devices/dev_abc?user_id=owner-1"] {
        let (status, headers, body) = web.get(uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(content_type(&headers), "text/html; charset=utf-8", "{uri}");
        assert!(
            body_text(&body).contains("<div id=\"root\"></div>"),
            "{uri} must serve the app shell so the client router can render"
        );
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-cache"),
            "the app shell is revalidated, never cached stale"
        );
    }
}

#[tokio::test]
async fn an_unknown_api_path_is_a_404_not_the_spa_document() {
    let web = WebApp::new("api404");

    for (method, uri) in [
        (Method::GET, "/api/does-not-exist"),
        (Method::POST, "/api/devices/dev_abc/unknown"),
        (Method::GET, "/api/"),
        // The contract is about the decoded path: an encoded slash must not turn an API
        // path into the app shell.
        (Method::GET, "/api%2Fnope"),
        (Method::GET, "/api%2fdevices"),
        (Method::GET, "/ap%69/nope"),
    ] {
        let (status, headers, body) = web.request(method.clone(), uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
        assert_eq!(
            content_type(&headers),
            "application/json",
            "{method} {uri} must not answer with the app shell"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(parsed["error"], "api_not_found", "{method} {uri}");
        assert!(!body_text(&body).contains("<div id=\"root\">"));
    }
}

#[tokio::test]
async fn assets_are_served_with_the_right_content_type_and_cache_policy() {
    let web = WebApp::new("assets");

    for (uri, expected_type) in [
        ("/assets/index-abc123.js", "text/javascript; charset=utf-8"),
        ("/assets/index-def456.css", "text/css; charset=utf-8"),
        ("/favicon.svg", "image/svg+xml"),
        ("/manifest.webmanifest", "application/manifest+json"),
    ] {
        let (status, headers, body) = web.get(uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(content_type(&headers), expected_type, "{uri}");
        assert!(!body.is_empty(), "{uri}");
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=31536000, immutable"),
            "{uri}"
        );
    }

    let (_, headers, body) = web.get("/assets/index-abc123.js").await;
    assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
    assert!(body_text(&body).contains("PhoneConnect"));
}

#[tokio::test]
async fn a_missing_asset_is_not_replaced_by_the_spa_document() {
    let web = WebApp::new("missing-asset");

    for uri in ["/assets/missing.js", "/missing.css", "/assets/app.js.map"] {
        let (status, headers, _) = web.get(uri).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} must be a real miss, not an HTML page"
        );
        assert_ne!(content_type(&headers), "text/html; charset=utf-8", "{uri}");
    }
}

#[tokio::test]
async fn traversal_requests_never_escape_the_web_root() {
    let web = WebApp::new("traversal");

    for uri in [
        "/../Cargo.toml",
        "/%2e%2e/Cargo.toml",
        "/assets/%2e%2e/%2e%2e/Cargo.toml",
        "/..%2fCargo.toml",
    ] {
        let (status, headers, body) = web.get(uri).await;
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
            "{uri} must not be served: {status}"
        );
        assert!(
            !body_text(&body).contains("[package]"),
            "{uri} escaped the web root"
        );
        assert_ne!(
            content_type(&headers),
            "text/javascript; charset=utf-8",
            "{uri}"
        );
    }
}

#[tokio::test]
async fn the_api_keeps_working_with_the_web_ui_mounted() {
    let web = WebApp::new("api");

    let (status, headers, body) = web.get("/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type(&headers), "application/json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")["status"],
        "ok"
    );

    // A real API route still answers with its own JSON error, not the app shell.
    let (status, headers, _) = web.get("/api/devices/dev_missing/status").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(content_type(&headers), "application/json");
}

#[tokio::test]
async fn the_native_shell_loads_the_server_root_unchanged() {
    let web = WebApp::new("native");

    // A webview that loads `<server>/` gets the document at that exact URL: no redirect
    // and no second UI bundle.
    let (status, headers, body) = web.get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "the root URL must not redirect the shell elsewhere"
    );
    assert_eq!(content_type(&headers), "text/html; charset=utf-8");
    let document = body_text(&body);
    assert!(document.contains("/assets/index-abc123.js"));
    assert!(
        document.contains(".css"),
        "styles are served by the same origin"
    );
}

#[tokio::test]
async fn a_web_ui_that_is_not_built_is_an_explicit_error() {
    let root =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("web-ui-empty-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("empty dir");
    let error = WebUi::load(&root).expect_err("an empty web root cannot serve the app");
    assert!(
        error.to_string().contains("index.html"),
        "the error names the missing document: {error}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
