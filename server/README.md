# PhoneConnect server

Placeholder: this directory will hold the Rust server binary that is PhoneConnect's
control plane.

Its intended responsibility is user authentication and sessions, one-time enrollment
tokens, device ownership/sharing, audit events, device rendezvous and capability
negotiation, an optional end-to-end encrypted relay for control/file/media/proxy streams,
bounded telemetry aggregation, and update manifests. It also serves the single React web
UI, so browsers and native shells load the same origin and URL.

The server authorizes every session before issuing a short-lived capability and never
trusts a client-provided device identity by itself. It consumes the shared protocol crate
`phoneconnect-protocol` for framing rather than defining its own.
