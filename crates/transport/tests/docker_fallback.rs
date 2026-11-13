//! Docker end-to-end fallback test.
//!
//! The in-process tests in `path_upgrade.rs` prove the path state machine against the
//! server's relay type. This test proves the same behaviour across process boundaries with
//! the components the plan names: one server container, one Android-side transport stub,
//! and one native-side transport stub, all forcing direct negotiation to fail so the
//! session must fall back to the relay transparently.
//!
//! It needs a Docker daemon, so it is ignored by default. Run it with:
//!
//! ```text
//! PHONECONNECT_DOCKER_E2E=1 cargo test -p phoneconnect-transport --test docker_fallback -- --ignored --nocapture
//! ```

use std::process::Command;

#[test]
#[ignore = "requires a Docker daemon; see the module docs for the command"]
fn relay_fallback_survives_a_cross_process_docker_run() {
    assert_eq!(
        std::env::var("PHONECONNECT_DOCKER_E2E").as_deref(),
        Ok("1"),
        "set PHONECONNECT_DOCKER_E2E=1 to run the Docker transport end-to-end test"
    );

    let output = Command::new("bash")
        .arg("../../docker/transport-e2e/run.sh")
        .output()
        .expect("the Docker driver runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("{stdout}");
    eprintln!("{stderr}");

    assert!(
        output.status.success(),
        "transport end-to-end fallback failed: {stderr}"
    );
    assert!(
        stdout.contains("transport end-to-end fallback test passed"),
        "the driver never reported success: {stdout}"
    );
}
