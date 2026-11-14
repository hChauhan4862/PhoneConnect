//! Deployment configuration shared by the binary and its tests.
//!
//! The server advertises one origin: the URL clients use to reach it. The relay base is
//! derived from that origin instead of being a second setting that must agree with it by
//! hand, because a native client only dials a relay on the origin it loaded.

/// Environment variable naming the public origin clients use.
pub const PUBLIC_URL_ENV: &str = "PHONECONNECT_PUBLIC_URL";

/// Default public origin. Shared with the native shell's default server URL.
pub const DEFAULT_PUBLIC_URL: &str = phoneconnect::DEFAULT_SERVER_ORIGIN;

/// The relay base peers receive for a public origin: `<origin>/api/sessions`.
///
/// One session's transport appends `/<session_id>/relay` to this.
pub fn relay_endpoint_for(public_url: &str) -> String {
    format!("{}/api/sessions", public_url.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_public_origin_advertises_a_relay_on_that_same_origin() {
        let public = DEFAULT_PUBLIC_URL;
        let relay = relay_endpoint_for(public);

        assert_eq!(
            relay, "http://127.0.0.1:8080/api/sessions",
            "the default is the origin the native shell loads by default"
        );
        assert_eq!(relay.strip_suffix("/api/sessions"), Some(public));
    }

    #[test]
    fn a_trailing_slash_and_a_public_https_origin_are_handled() {
        assert_eq!(
            relay_endpoint_for("https://phoneconnect.example/"),
            "https://phoneconnect.example/api/sessions"
        );
    }
}
