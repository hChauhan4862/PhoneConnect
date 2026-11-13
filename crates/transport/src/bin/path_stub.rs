//! Container stub for the transport end-to-end test.
//!
//! Two instances run in Docker against one server: a client stub and a device stub. Each
//! verifies its server-signed ticket, tries a deliberately dead direct candidate, and then
//! connects through the relay because direct negotiation cannot succeed. The frames they
//! exchange prove the fallback is transparent to the session.
//!
//! All inputs arrive as environment variables so the driver can mint them once and start
//! both containers with the same round:
//! `STUB_ROLE`, `STUB_TICKET`, `STUB_CANDIDATES`, `STUB_RELAY_URL`, `STUB_BEARER`,
//! `STUB_PAYLOAD`, `STUB_TARGET`.

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use phoneconnect::v1::{DeviceId, Envelope, FrameLimits, RequestId, SessionId, StreamKind};
use phoneconnect_transport::{
    CandidateSet, IdentityKey, PathConfig, PathController, PathKind, PathSetup, ProbeConfig,
    RendezvousCandidates, SwitchConfig, Ticket, WebSocketRelay,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const RECEIVE_DEADLINE: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--generate-identity") {
        // The driver asks for a fresh pinned identity per stub; the private half is handed
        // to exactly one container and never to the server.
        let identity = IdentityKey::generate()?;
        println!("{}", identity.to_secret_string());
        println!("{}", identity.public_key().as_str());
        return Ok(());
    }

    let role = required("STUB_ROLE")?;
    let identity = IdentityKey::parse(&required("STUB_IDENTITY_KEY")?)?;
    let ticket: Ticket = serde_json::from_str(&required("STUB_TICKET")?)?;
    let rendezvous: RendezvousCandidates = serde_json::from_str(&required("STUB_CANDIDATES")?)?;
    let relay_url = required("STUB_RELAY_URL")?;
    let bearer = required("STUB_BEARER")?;
    let payload = required("STUB_PAYLOAD")?;
    let target = required("STUB_TARGET")?;

    let device_id = DeviceId::new(ticket.device_id.clone())?;
    let session_id = SessionId::new(ticket.session_id.clone())?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let candidates = CandidateSet::discover(rendezvous, vec![])?;
    let relay = WebSocketRelay::connect(&relay_url, &bearer, 1024 * 1024).await?;
    let config = PathConfig {
        frame_limits: FrameLimits::control_only(),
        probe: ProbeConfig {
            attempt_timeout: Duration::from_millis(50),
            max_attempts: 2,
        },
        switch: SwitchConfig {
            retries: 3,
            timeout: Duration::from_millis(100),
            ..SwitchConfig::default()
        },
        ..PathConfig::default()
    };
    let path = PathController::connect(
        ticket,
        candidates,
        PathSetup::new(socket, identity)
            .with_relay(relay)
            .with_config(config)
            .at(unix_ms()),
    )
    .await?;
    println!("PATH={} ROLE={role}", path.path_kind());
    if path.path_kind() != PathKind::Relay {
        eprintln!("direct negotiation was expected to fail in the stub");
        std::process::exit(3);
    }

    if role == "client" {
        let request = RequestId::new("req-docker-e2e")?;
        let mut envelope = Envelope::new(StreamKind::Control, &device_id, &session_id, &request);
        envelope.payload = format!("{target}:{payload}").into_bytes();
        path.send_frame(&envelope).await?;
        println!("SENT={}", envelope.request_id);
    }

    let received = timeout(RECEIVE_DEADLINE, path.recv_frame()).await??;
    println!(
        "RECEIVED={} PAYLOAD={}",
        received.request_id,
        String::from_utf8_lossy(&received.payload)
    );

    if role == "device" {
        let reply = RequestId::new("req-docker-e2e-reply")?;
        let mut envelope = Envelope::new(StreamKind::Control, &device_id, &session_id, &reply);
        envelope.payload = format!("{target}:echo").into_bytes();
        path.send_frame(&envelope).await?;
        println!("REPLIED={}", envelope.request_id);
    }

    path.shutdown().await?;
    Ok(())
}

fn required(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("{key} must be set"))
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}
