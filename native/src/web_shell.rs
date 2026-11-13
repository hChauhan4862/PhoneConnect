//! Shell-side decisions that do not need a webview.
//!
//! The native client is a thin shell: the webview loads the server-served app at exactly the
//! configured URL, and the only native additions are the host context below, detached OS
//! windows, the tray, notifications, and loopback proxy endpoints. Everything here is a pure
//! function or plain data so it is testable without a display.

use std::ffi::OsString;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::proxy::LocalEndpoint;

/// The global the page reads to select its native behavior.
pub const HOST_CONTEXT_GLOBAL: &str = "__PHONECONNECT_HOST__";
/// The global the page reads for the capabilities the shell actually provides.
pub const HOST_BRIDGE_GLOBAL: &str = "__PHONECONNECT_BRIDGE__";
/// Environment variable naming the server origin the shell loads.
pub const SERVER_URL_ENV: &str = "PHONECONNECT_SERVER_URL";
/// Development default: a server on this machine, never a remote plain-HTTP origin.
pub const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

/// Explicit URL-policy failures. A rejected configuration names what is wrong; the shell
/// never silently corrects a URL it was told to load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlPolicyError {
    #[error("no server URL is configured; set {SERVER_URL_ENV}")]
    NotConfigured,
    #[error("{value:?} is not an absolute URL")]
    NotAbsolute { value: String },
    #[error("{value:?} uses {scheme:?}; use https, or http on loopback")]
    UnsupportedScheme { value: String, scheme: String },
    #[error("{value:?} has no host")]
    MissingHost { value: String },
    #[error("{value:?} carries credentials; the shell must not embed privileged credentials")]
    UserInfo { value: String },
    #[error("{value:?} has a fragment; the app is loaded at the origin root")]
    Fragment { value: String },
    #[error("{value:?} has a query; the app is loaded at the origin root")]
    Query { value: String },
    #[error(
        "{value:?} names path {path:?}; the server serves the UI at / and the shell never \
         rewrites paths"
    )]
    NotRootPath { value: String, path: String },
    #[error("plain HTTP is only accepted on 127.0.0.1 or localhost, not {host:?}")]
    InsecureRemoteHost { value: String, host: String },
    #[error("{route:?} is not a same-origin route; only paths starting with one / are opened")]
    RouteNotRelative { route: String },
    #[error("{route:?} resolves outside the configured server origin")]
    RouteEscapesOrigin { route: String },
    #[error("the configured server URL is not valid Unicode")]
    NotUnicode,
}

/// The object the shell injects as `window.__PHONECONNECT_HOST__`.
///
/// The field names and JSON shape are the contract in `web/src/host/hostContext.ts`; a page
/// that cannot read this object stays a browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeHostContext {
    pub kind: &'static str,
    pub server_url: String,
    pub proxy_capabilities: Vec<LocalEndpoint>,
}

/// Health the page reports for the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrayHealth {
    Connected,
    Degraded,
    Disconnected,
    Unknown,
}

impl TrayHealth {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Degraded => "degraded",
            Self::Disconnected => "disconnected",
            Self::Unknown => "unknown",
        }
    }
}

/// Tray state the page sends through the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrayStatus {
    pub label: String,
    pub health: TrayHealth,
    #[serde(default)]
    pub detail: Option<String>,
}

/// One OS notification the page asks the shell to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationInput {
    pub title: String,
    pub body: String,
}

/// Largest tray label and notification text the shell accepts from the page. A remote page
/// drives these commands, so unbounded text never reaches the OS UI.
pub const MAX_TRAY_LABEL_LEN: usize = 128;
pub const MAX_TRAY_DETAIL_LEN: usize = 256;
pub const MAX_NOTIFICATION_TITLE_LEN: usize = 200;
pub const MAX_NOTIFICATION_BODY_LEN: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShellInputError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} is {length} bytes; the limit is {limit}")]
    TooLong {
        field: &'static str,
        length: usize,
        limit: usize,
    },
}

fn bounded(field: &'static str, value: &str, limit: usize) -> Result<(), ShellInputError> {
    if value.trim().is_empty() {
        return Err(ShellInputError::Empty { field });
    }
    if value.len() > limit {
        return Err(ShellInputError::TooLong {
            field,
            length: value.len(),
            limit,
        });
    }
    Ok(())
}

impl TrayStatus {
    pub fn validate(&self) -> Result<(), ShellInputError> {
        bounded("tray label", &self.label, MAX_TRAY_LABEL_LEN)?;
        match &self.detail {
            Some(detail) if !detail.is_empty() => {
                bounded("tray detail", detail, MAX_TRAY_DETAIL_LEN)
            }
            _ => Ok(()),
        }
    }
}

impl NotificationInput {
    pub fn validate(&self) -> Result<(), ShellInputError> {
        bounded(
            "notification title",
            &self.title,
            MAX_NOTIFICATION_TITLE_LEN,
        )?;
        if self.body.is_empty() {
            return Ok(());
        }
        if self.body.len() > MAX_NOTIFICATION_BODY_LEN {
            return Err(ShellInputError::TooLong {
                field: "notification body",
                length: self.body.len(),
                limit: MAX_NOTIFICATION_BODY_LEN,
            });
        }
        Ok(())
    }
}

/// The host the development exception in [`resolve_url`] names, and nothing else.
fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost")
}

/// Validates the server URL from configuration.
///
/// Accepted: `https://` on any host, and `http://` only on `127.0.0.1` or `localhost` for
/// development. The URL must be an origin: no userinfo, no fragment, no query, and no path
/// other than `/`. Nothing is rewritten, so the webview loads exactly this URL.
pub fn resolve_url(configured: &str) -> Result<Url, UrlPolicyError> {
    let value = configured.trim();
    if value.is_empty() {
        return Err(UrlPolicyError::NotConfigured);
    }
    let url = Url::parse(value).map_err(|_| UrlPolicyError::NotAbsolute {
        value: value.to_owned(),
    })?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(UrlPolicyError::UnsupportedScheme {
                value: value.to_owned(),
                scheme: scheme.to_owned(),
            });
        }
    }
    // A credential in the URL would either be embedded in the page or silently ignored;
    // the shell uses the server's normal session cookies and nothing else.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlPolicyError::UserInfo {
            value: value.to_owned(),
        });
    }
    let host = url.host_str().ok_or_else(|| UrlPolicyError::MissingHost {
        value: value.to_owned(),
    })?;
    if url.fragment().is_some() {
        return Err(UrlPolicyError::Fragment {
            value: value.to_owned(),
        });
    }
    if url.query().is_some() {
        return Err(UrlPolicyError::Query {
            value: value.to_owned(),
        });
    }
    if url.scheme() == "http" && !is_loopback_host(host) {
        return Err(UrlPolicyError::InsecureRemoteHost {
            value: value.to_owned(),
            host: host.to_owned(),
        });
    }
    if url.path() != "/" {
        return Err(UrlPolicyError::NotRootPath {
            value: value.to_owned(),
            path: url.path().to_owned(),
        });
    }
    Ok(url)
}

/// Resolves a route the page asked for to a same-origin URL.
///
/// Only an absolute path (`/devices/...`) is accepted. A protocol-relative path, a full URL,
/// or a path that resolves to another origin is refused, so a compromised page cannot use
/// the shell to open an arbitrary site.
pub fn resolve_route(server: &Url, route: &str) -> Result<Url, UrlPolicyError> {
    // A single leading slash only: `//host` is protocol-relative and a scheme makes the
    // route absolute. A backslash is normalized into a slash by URL parsers.
    if !route.starts_with('/')
        || route.starts_with("//")
        || route.contains("://")
        || route.contains('\\')
    {
        return Err(UrlPolicyError::RouteNotRelative {
            route: route.to_owned(),
        });
    }
    let url = server
        .join(route)
        .map_err(|_| UrlPolicyError::RouteNotRelative {
            route: route.to_owned(),
        })?;
    if url.origin() != server.origin() || url.fragment().is_some() {
        return Err(UrlPolicyError::RouteEscapesOrigin {
            route: route.to_owned(),
        });
    }
    Ok(url)
}

/// Builds the injected host context.
pub fn host_context(server: &Url, proxy_capabilities: Vec<LocalEndpoint>) -> NativeHostContext {
    NativeHostContext {
        kind: "native",
        server_url: server.as_str().to_owned(),
        proxy_capabilities,
    }
}

/// One value as a JavaScript literal. `<`, `>`, `&`, and the two Unicode line separators are
/// escaped so no page-supplied string can end the script or start a new statement.
fn script_literal(value: &impl Serialize) -> String {
    serde_json::to_string(value)
        .expect("host contexts and capabilities are JSON-serializable")
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// The initialization script that installs `window.__PHONECONNECT_HOST__` before the app
/// loads.
pub fn host_context_script(context: &NativeHostContext) -> String {
    format!(
        "Object.defineProperty(window, {HOST_CONTEXT_GLOBAL:?}, \
         {{ value: Object.freeze({}), configurable: true }});",
        script_literal(context)
    )
}

/// The initialization script that installs `window.__PHONECONNECT_BRIDGE__`.
///
/// Every method is optional to the page: if the shell does not install this script, or IPC
/// fails, the page falls back to its in-page behavior for that one operation.
pub fn bridge_script() -> String {
    let global = HOST_BRIDGE_GLOBAL;
    format!(
        r#"(function () {{
  var tauri = window.__TAURI__;
  var invoke = function (command, args) {{
    if (tauri && tauri.core && typeof tauri.core.invoke === "function") {{
      return tauri.core.invoke(command, args);
    }}
    var internals = window.__TAURI_INTERNALS__;
    if (internals && typeof internals.invoke === "function") {{
      return internals.invoke(command, args);
    }}
    return Promise.reject(new Error("PhoneConnect shell IPC is unavailable"));
  }};
  Object.defineProperty(window, "{global}", {{
    configurable: true,
    value: Object.freeze({{
      openWindow: function (route) {{ return invoke("open_window", {{ route: route }}); }},
      setTrayStatus: function (status) {{ return invoke("set_tray_status", {{ status: status }}); }},
      localEndpoints: function () {{ return invoke("local_endpoints"); }},
      notify: function (input) {{ return invoke("notify", {{ input: input }}); }}
    }})
  }});
}})();"#
    )
}

/// A stable, bounded window label for a detached view.
pub fn route_window_label(route: &str) -> String {
    // FNV-1a keeps two routes that sanitize to the same text (`/a-b` and `/a_b`) in two
    // different windows instead of silently sharing one.
    let mut hash: u32 = 0x811c_9dc5;
    for byte in route.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let sanitized: String = route
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    let prefix: String = trimmed.chars().take(40).collect();
    let label = format!("view-{}-{hash:08x}", prefix.trim_end_matches('-'));
    debug_assert!(label.len() <= 64);
    label
}

/// The tray tooltip for a status the page reported.
pub fn tray_tooltip(status: &TrayStatus) -> String {
    let mut tooltip = format!("{} \u{2014} {}", status.label, status.health.label());
    if let Some(detail) = &status.detail
        && !detail.is_empty()
    {
        tooltip.push_str(": ");
        tooltip.push_str(detail);
    }
    tooltip
}

/// True when `url` is on the configured server's origin. Every navigation the shell allows
/// must pass this: a remote page that reached another origin would inherit the four bridge
/// capabilities from the Tauri capability, so the webview must not leave the server.
pub fn is_same_origin(server: &Url, url: &Url) -> bool {
    server.origin() == url.origin()
}

/// Reads the configured server URL, falling back to the local development server.
pub fn configured_server_url() -> Result<Url, UrlPolicyError> {
    resolve_configured(std::env::var_os(SERVER_URL_ENV))
}

fn resolve_configured(value: Option<OsString>) -> Result<Url, UrlPolicyError> {
    match value {
        Some(value) => match value.into_string() {
            Ok(configured) => resolve_url(&configured),
            Err(_) => Err(UrlPolicyError::NotUnicode),
        },
        None => resolve_url(DEFAULT_SERVER_URL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> LocalEndpoint {
        LocalEndpoint {
            device_id: "dev_1".to_owned(),
            stream: "adb".to_owned(),
            url: "http://127.0.0.1:49152".to_owned(),
        }
    }

    fn context() -> NativeHostContext {
        host_context(
            &resolve_url("https://phoneconnect.example").expect("valid URL"),
            vec![endpoint()],
        )
    }

    #[test]
    fn accepts_an_https_origin() {
        let url = resolve_url("https://phoneconnect.example").expect("https origin");
        assert_eq!(url.as_str(), "https://phoneconnect.example/");
    }

    #[test]
    fn accepts_loopback_http_for_development() {
        for configured in ["http://127.0.0.1:8080", "http://localhost:3000/"] {
            let url = resolve_url(configured).expect(configured);
            assert_eq!(url.scheme(), "http");
            assert!(url.path() == "/");
        }
    }

    #[test]
    fn rejects_plain_http_on_a_remote_host() {
        let error = resolve_url("http://phoneconnect.example").expect_err("remote http");
        assert!(
            matches!(error, UrlPolicyError::InsecureRemoteHost { .. }),
            "{error:?}"
        );
        let error = resolve_url("http://127.0.0.1.evil.example").expect_err("lookalike host");
        assert!(
            matches!(error, UrlPolicyError::InsecureRemoteHost { .. }),
            "{error:?}"
        );
        let error = resolve_url("http://[::1]:8080").expect_err("IPv6 is not the ruled loopback");
        assert!(
            matches!(error, UrlPolicyError::InsecureRemoteHost { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn rejects_userinfo_and_a_fragment() {
        let error = resolve_url("https://user:secret@phoneconnect.example").expect_err("userinfo");
        assert!(
            matches!(error, UrlPolicyError::UserInfo { .. }),
            "{error:?}"
        );

        let error = resolve_url("https://phoneconnect.example/#/devices").expect_err("fragment");
        assert!(
            matches!(error, UrlPolicyError::Fragment { .. }),
            "{error:?}"
        );

        let error =
            resolve_url("http://localhost@evil.example").expect_err("userinfo on loopback shape");
        assert!(
            matches!(error, UrlPolicyError::UserInfo { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn rejects_a_path_or_query_it_would_have_to_rewrite() {
        let error = resolve_url("https://phoneconnect.example/phoneconnect").expect_err("path");
        assert!(
            matches!(error, UrlPolicyError::NotRootPath { .. }),
            "{error:?}"
        );

        let error = resolve_url("https://phoneconnect.example/?next=/devices").expect_err("query");
        assert!(matches!(error, UrlPolicyError::Query { .. }), "{error:?}");
    }

    #[test]
    fn rejects_a_scheme_that_is_not_http() {
        for configured in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ws://localhost:8080",
        ] {
            let error = resolve_url(configured).expect_err(configured);
            assert!(
                matches!(error, UrlPolicyError::UnsupportedScheme { .. }),
                "{configured}: {error:?}"
            );
        }
        let error = resolve_url("phoneconnect.example").expect_err("relative");
        assert!(
            matches!(error, UrlPolicyError::NotAbsolute { .. }),
            "{error:?}"
        );
        let error = resolve_url("   ").expect_err("empty");
        assert!(matches!(error, UrlPolicyError::NotConfigured), "{error:?}");
    }

    #[test]
    fn the_host_context_matches_the_page_contract_field_for_field() {
        let value = serde_json::to_value(context()).expect("JSON");
        assert_eq!(
            value,
            serde_json::json!({
                "kind": "native",
                "serverUrl": "https://phoneconnect.example/",
                "proxyCapabilities": [
                    {"deviceId": "dev_1", "stream": "adb", "url": "http://127.0.0.1:49152"}
                ]
            })
        );
    }

    #[test]
    fn the_context_script_installs_the_documented_global_before_load() {
        let script = host_context_script(&context());
        assert!(
            script.contains(&format!(
                "Object.defineProperty(window, \"{HOST_CONTEXT_GLOBAL}\""
            )),
            "{script}"
        );
        let frozen = "Object.freeze(";
        let start = script.find(frozen).expect("the context is frozen") + frozen.len();
        let end = script
            .find("), configurable")
            .expect("the context is the frozen value");
        let value: serde_json::Value =
            serde_json::from_str(&script[start..end]).expect("valid embedded JSON");
        assert_eq!(value, serde_json::to_value(context()).unwrap());
    }

    #[test]
    fn injected_strings_cannot_break_out_of_the_script() {
        let hostile = NativeHostContext {
            kind: "native",
            server_url: "https://phoneconnect.example/".to_owned(),
            proxy_capabilities: vec![LocalEndpoint {
                device_id: "dev_1".to_owned(),
                stream: "</script><script>alert(1)</script>".to_owned(),
                url: "http://127.0.0.1:1".to_owned(),
            }],
        };
        let script = host_context_script(&hostile);
        assert!(!script.contains("</script>"), "{script}");
        assert!(!script.contains("<script>"), "{script}");
    }

    #[test]
    fn the_bridge_script_exposes_every_optional_capability() {
        let script = bridge_script();
        for command in [
            "open_window",
            "set_tray_status",
            "local_endpoints",
            "notify",
        ] {
            assert!(script.contains(command), "{command} missing from {script}");
        }
        assert!(script.contains(HOST_BRIDGE_GLOBAL));
    }

    #[test]
    fn routes_stay_on_the_configured_origin() {
        let server = resolve_url("https://phoneconnect.example").expect("server");
        let url = resolve_route(&server, "/devices/dev_1/telemetry").expect("route");
        assert_eq!(
            url.as_str(),
            "https://phoneconnect.example/devices/dev_1/telemetry"
        );

        for route in [
            "https://evil.example/",
            "//evil.example/devices",
            "/\\evil.example",
        ] {
            let error = resolve_route(&server, route).expect_err(route);
            assert!(
                matches!(error, UrlPolicyError::RouteNotRelative { .. }),
                "{route}: {error:?}"
            );
        }
        let error = resolve_route(&server, "devices/dev_1").expect_err("relative path");
        assert!(
            matches!(error, UrlPolicyError::RouteNotRelative { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn window_labels_are_stable_bounded_and_distinct() {
        let one = route_window_label("/devices/dev_1");
        assert_eq!(one, route_window_label("/devices/dev_1"));
        assert_ne!(one, route_window_label("/devices/dev_2"));
        assert_ne!(
            route_window_label("/devices/a-b"),
            route_window_label("/devices/a_b")
        );
        assert!(one.len() <= 64, "{one}");
        assert!(
            one.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "{one}"
        );
        let long = route_window_label(&format!("/devices/{}", "x".repeat(500)));
        assert!(long.len() <= 64, "{long}");
    }

    #[test]
    fn tray_text_names_the_device_health_and_detail() {
        let status = TrayStatus {
            label: "dev_1".to_owned(),
            health: TrayHealth::Degraded,
            detail: Some("relay".to_owned()),
        };
        assert_eq!(tray_tooltip(&status), "dev_1 — degraded: relay");

        let status = TrayStatus {
            label: "dev_1".to_owned(),
            health: TrayHealth::Connected,
            detail: None,
        };
        assert_eq!(tray_tooltip(&status), "dev_1 — connected");
    }

    #[test]
    fn page_input_is_bounded() {
        let empty = TrayStatus {
            label: String::new(),
            health: TrayHealth::Unknown,
            detail: None,
        };
        assert!(matches!(
            empty.validate(),
            Err(ShellInputError::Empty {
                field: "tray label"
            })
        ));

        let long = TrayStatus {
            label: "x".repeat(MAX_TRAY_LABEL_LEN + 1),
            health: TrayHealth::Unknown,
            detail: None,
        };
        assert!(matches!(
            long.validate(),
            Err(ShellInputError::TooLong {
                field: "tray label",
                ..
            })
        ));

        let notification = NotificationInput {
            title: "Lease revoked".to_owned(),
            body: "x".repeat(MAX_NOTIFICATION_BODY_LEN + 1),
        };
        assert!(matches!(
            notification.validate(),
            Err(ShellInputError::TooLong {
                field: "notification body",
                ..
            })
        ));
        assert!(
            NotificationInput {
                title: "Lease revoked".to_owned(),
                body: "Control returned to the owner".to_owned(),
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn navigation_stays_on_the_configured_origin() {
        let server = resolve_url("https://phoneconnect.example").expect("server");
        let route = resolve_route(&server, "/devices/dev_1").expect("route");
        assert!(is_same_origin(&server, &route));
        for other in ["https://evil.example/", "http://phoneconnect.example/"] {
            let url = Url::parse(other).expect("URL");
            assert!(!is_same_origin(&server, &url), "{other}");
        }
    }

    #[test]
    fn a_missing_server_url_uses_the_loopback_default_and_bad_unicode_is_refused() {
        assert_eq!(
            resolve_configured(None).expect("default").as_str(),
            "http://127.0.0.1:8080/"
        );
        assert_eq!(
            resolve_configured(Some(OsString::from("https://phoneconnect.example")))
                .expect("configured")
                .as_str(),
            "https://phoneconnect.example/"
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let invalid = OsString::from_vec(vec![0xff, 0xfe]);
            assert!(matches!(
                resolve_configured(Some(invalid)),
                Err(UrlPolicyError::NotUnicode)
            ));
        }
    }

    #[test]
    fn tray_health_deserializes_from_the_page_values() {
        let status: TrayStatus = serde_json::from_value(serde_json::json!({
            "label": "dev_1",
            "health": "degraded",
            "detail": "relay",
        }))
        .expect("the page shape");
        assert_eq!(status.health, TrayHealth::Degraded);
    }
}
