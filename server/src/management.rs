//! The management channel: the authenticated device WebSocket that carries telemetry and
//! commands, plus the in-memory registry that dispatches them.
//!
//! This is the server-mediated half of the design's "two channels, two confidentiality
//! rules". Payloads are JSON and the server reads them, because a management console must;
//! the sealed peer relay is untouched and stays unreadable.
//!
//! Bounded by construction:
//! - one connection per device — a new one replaces the old with an explicit `replaced`
//!   close, and the replaced connection's in-flight commands complete as `device_offline`;
//! - at most [`MAX_IN_FLIGHT_PER_DEVICE`] pending commands per device;
//! - a result may not exceed [`MAX_RESULT_BYTES`], and an oversized one refuses the command
//!   with `result_too_large` instead of being held;
//! - the retained answers together may not exceed [`MAX_RETAINED_ANSWER_BYTES`]: `output` plus
//!   its message and error text, with each text field itself capped by
//!   `MAX_RETAINED_TEXT_BYTES`; the oldest completed records are dropped (as past the count
//!   cap) so a device answering large file chunks — or large prose — cannot grow the table
//!   without bound;
//! - commands live in memory only; the audit rows written by the HTTP surface and by this
//!   registry (`command.dispatch`, then `command.outcome` when no device answer arrives) are the
//!   durable trace, so there is no commands table;
//! - one device cannot degrade ingest for the others: its inbound frames and bytes are
//!   rate-limited (see [`limits`]) and an over-budget channel is closed with
//!   [`CLOSE_RATE_LIMITED`]; command creation is throttled per device and answers
//!   `429 rate_limited`.
//!
//! Frame shapes are fixed by the design:
//! - device → server `{"type":"hello"|"telemetry"|"result", ...}`,
//! - server → device `{"type":"command","request_id","name","args","deadline_ms"}`.
//!
//! `deadline_ms` is a duration the device may spend, not an absolute timestamp: a device
//! clock is not trusted to agree with the server's.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};

use crate::AppState;
use crate::auth::{AuthError, generate_secret};
use crate::commands::AUDIT_ACTION_OUTCOME;
use crate::store::{AuditEntry, Clock, DeviceStore, UnixMs};
use crate::telemetry::TelemetrySample;

/// Default time a device has to answer a command.
pub const DEFAULT_COMMAND_TIMEOUT_MS: i64 = 10_000;

/// Longest deadline an operator may request. The bound protects the in-memory command table
/// and the caller's wait, not the control lease: a lease may last as little as a second, so a
/// command can outlive the authority that authorized it, and there is no cancel channel that
/// revocation could use to withdraw an already-delivered frame. The device is the one that
/// refuses to start a command whose absolute deadline passed; a revocation mid-command
/// therefore bounds *new* commands, not one already in a device's hands.
pub const MAX_COMMAND_TIMEOUT_MS: i64 = 60_000;

/// Pending commands one device may hold. The channel queues exactly this many frames, so a
/// slow device applies backpressure instead of growing a buffer.
pub const MAX_IN_FLIGHT_PER_DEVICE: usize = 64;

/// Largest accepted result payload. A result above this is refused, never stored.
pub const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;

/// Retained command records. Completed records are dropped oldest-first past this; pending
/// ones are bounded by [`MAX_IN_FLIGHT_PER_DEVICE`] per connected device.
const MAX_RETAINED_COMMANDS: usize = 4 * 1024;

/// Aggregate answer bytes retained by completed commands: the serialized `output` plus the
/// stored `message` and `error` text, charged as one answer.
///
/// Count alone is not a memory bound: `files.read` answers ~350 KiB of base64 each, so 4 096
/// records could hold ~1.4 GiB, and command creation is fast enough to reach that in minutes.
/// This is one budget for the whole table — not per device, so a busy fleet cannot multiply it.
/// Once it is crossed the oldest completed records are dropped whole, exactly as past the count
/// cap, and `GET /api/commands/{id}` answers `command_unknown` for a trimmed record. Pending
/// commands retain no answer and are never dropped.
pub const MAX_RETAINED_ANSWER_BYTES: usize = 32 * 1024 * 1024;

/// Longest retained `message` or `error` text.
///
/// A frame may carry far more, but an explanation is useful at paragraph length, and without
/// this one successful result could spend the whole retained-answer budget on prose. A longer
/// value is stored as its beginning plus an ellipsis, so the text stays useful and still fits
/// inside [`MAX_RETAINED_ANSWER_BYTES`].
const MAX_RETAINED_TEXT_BYTES: usize = 4 * 1024;

/// Longest accepted command name. Names belong to the device; the server only bounds them.
const MAX_COMMAND_NAME_BYTES: usize = 128;

/// Command-creation budget entries. A bucket is created for every asserted device id an attempt
/// names, including an id that matches no device — such an attempt is refused and traced, and the
/// rejection happens before the store is consulted. The table is therefore capped, and full means
/// **evict the least recently used**, never refuse an unseen id: a rotating id costs a reset
/// bucket, and a device that enrolls after churn is still admitted. Four thousand is far above any
/// real fleet, so eviction only happens under deliberate churn.
const MAX_CREATION_BUCKETS: usize = 4 * 1024;

/// Inbound WebSocket message ceiling: the largest acceptable result plus frame overhead. A
/// result larger than [`MAX_RESULT_BYTES`] still arrives and is refused by name.
const MAX_CLIENT_MESSAGE_BYTES: usize = MAX_RESULT_BYTES + 64 * 1024;

/// WebSocket policy close, matching the relay's convention.
const POLICY_CLOSE_CODE: u16 = 1008;

/// Close reasons the device reads. Each names why the channel ended.
pub const CLOSE_REPLACED: &str = "replaced";
pub const CLOSE_MALFORMED_FRAME: &str = "malformed_frame";
pub const CLOSE_RATE_LIMITED: &str = "rate_limited";
/// A revoked device's open channel is closed with this, so status stops claiming freshness.
pub const CLOSE_DEVICE_REVOKED: &str = "device_revoked";

/// The `command.outcome` label for a command whose deadline passed unanswered.
const OUTCOME_TIMEOUT: &str = "timeout";
/// The `command.outcome` label for a command whose device channel ended first.
const OUTCOME_DEVICE_OFFLINE: &str = "device_offline";

/// The management channel's rate limits, in one place.
///
/// The design calls this channel "rate-limited and bounded": size alone is not enough, because
/// one device could otherwise flood telemetry (every sample takes the single global ingest
/// mutex) or a `hello` loop, degrading every other device, and one operator could append audit
/// rows without bound. Every bucket starts full, refills continuously, and is charged per
/// device, so reconnecting does not reset a limit.
pub mod limits {
    /// Inbound frames per second from one device.
    pub const FRAMES_PER_SECOND: f64 = 20.0;

    /// Burst of inbound frames. **Invariant:** it must fit everything a device can
    /// legitimately owe in one flush — one result per in-flight command — plus the hello and
    /// telemetry around them. A smaller burst would cut a device off mid-flush and report
    /// commands it did execute as `device_offline`.
    pub const FRAME_BURST: f64 = super::MAX_IN_FLIGHT_PER_DEVICE as f64 + 32.0;

    /// Inbound bytes per second from one device.
    pub const BYTES_PER_SECOND: f64 = 4.0 * 1024.0 * 1024.0;

    /// Burst of inbound bytes. **Invariant:** every in-flight command may owe a full-size
    /// result, so the burst covers [`MAX_RESULT_BYTES`] × [`MAX_IN_FLIGHT_PER_DEVICE`] plus a
    /// little telemetry headroom. Larger results are refused by name, not by the bucket.
    pub const BYTE_BURST: f64 =
        (super::MAX_RESULT_BYTES * super::MAX_IN_FLIGHT_PER_DEVICE + 1024 * 1024) as f64;

    /// Command creations per device per second on the HTTP path.
    pub const COMMAND_CREATES_PER_SECOND: f64 = 10.0;
    pub const COMMAND_BURST: f64 = 20.0;

    /// Command creations per second across every asserted device id.
    ///
    /// The per-device allowance multiplies with the number of ids a caller names, so it cannot
    /// bound the total; this does. Every traced attempt — accepted, refused for want of access,
    /// or refused for its shape — charges it, which makes it the real ceiling on audit growth.
    pub const GLOBAL_CREATES_PER_SECOND: f64 = 200.0;
    pub const GLOBAL_CREATE_BURST: f64 = 200.0;
}

/// The one shape a throttled caller sees: `429 rate_limited` with `Retry-After`. Both the
/// management channel's command path and the HTTP telemetry route use it.
pub fn rate_limited_response(retry_after_ms: i64) -> Response {
    let seconds = ((retry_after_ms + 999) / 1_000).max(1);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(json!({ "error": "rate_limited" })),
    )
        .into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&seconds.to_string()) {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, value);
    }
    response
}

/// The description a device sends in its `hello` frame, before any command is dispatched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHello {
    pub model: String,
    pub android_version: String,
    pub sdk: i64,
}

/// A command's terminal or current state. `Pending` is the only non-terminal one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Pending,
    Ok,
    Error,
    Timeout,
}

/// One dispatched command. In memory only: the audit rows are the durable trace.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CommandRecord {
    pub command_id: String,
    pub device_id: String,
    pub name: String,
    pub status: CommandStatus,
    pub output: Option<Value>,
    pub error: Option<String>,
    pub message: Option<String>,
    pub created_at_ms: UnixMs,
    pub completed_at_ms: Option<UnixMs>,
    /// The asserted actor that dispatched it, so a command that ends without an answer writes
    /// an outcome row attributed as its dispatch row was. Not part of the wire record.
    #[serde(skip)]
    pub actor: String,
    /// When the command becomes `timeout`. Not part of the wire record.
    #[serde(skip)]
    pub deadline_at_ms: UnixMs,
    /// Answer bytes this record retains, charged against [`MAX_RETAINED_ANSWER_BYTES`]. Not
    /// part of the wire record.
    #[serde(skip)]
    retained_answer_bytes: usize,
}

/// A command that was handed to the device's channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    pub command_id: String,
    pub deadline_ms: i64,
}

/// Why a dispatch never reached the device. Every variant is an explicit refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DispatchError {
    #[error("device {device_id} has no management channel")]
    Offline { device_id: String },
    #[error("device {device_id} already has {limit} commands in flight")]
    Capacity { device_id: String, limit: usize },
    #[error("timeout_ms must be between 1 and {MAX_COMMAND_TIMEOUT_MS}")]
    InvalidTimeout,
    #[error("command name must be 1 to {MAX_COMMAND_NAME_BYTES} bytes")]
    InvalidName,
    #[error("command state is unavailable")]
    Internal,
}

/// Why a result frame did not complete a command. The channel keeps running: a stale or
/// duplicated result is ignored, never turned into a second outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResultError {
    #[error("request {request_id} is unknown")]
    UnknownRequest { request_id: String },
    #[error("request {request_id} belongs to another device")]
    RequestScopeMismatch { request_id: String },
    #[error("request {request_id} already completed")]
    AlreadyCompleted { request_id: String },
}

/// The handle the socket task holds for its own registration. It carries the connection id,
/// so a replaced connection's cleanup cannot unregister its successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementConnection {
    device_id: String,
    connection_id: u64,
}

impl ManagementConnection {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

struct Connection {
    id: u64,
    commands: mpsc::Sender<Value>,
    close: watch::Sender<Option<&'static str>>,
    hello: Option<DeviceHello>,
}

/// A continuously refilling token bucket. `take` is the only operation that changes it, and
/// it reports how long until enough tokens exist so the caller can say `Retry-After`.
#[derive(Debug, Clone)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_ms: f64,
    last_refill_ms: UnixMs,
}

impl TokenBucket {
    fn new(capacity: f64, per_second: f64, now_ms: UnixMs) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_ms: per_second / 1_000.0,
            last_refill_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: UnixMs) {
        let elapsed_ms = (now_ms - self.last_refill_ms).max(0) as f64;
        if elapsed_ms > 0.0 {
            self.tokens = (self.tokens + elapsed_ms * self.refill_per_ms).min(self.capacity);
            self.last_refill_ms = now_ms;
        }
    }

    /// Charges `cost`. `Err(retry_after_ms)` means the budget is exhausted; a cost larger
    /// than the whole bucket can never fit and is refused rather than wedging the caller.
    fn take(&mut self, cost: f64, now_ms: UnixMs) -> Result<(), i64> {
        self.refill(now_ms);
        if cost > self.capacity {
            return Err(1_000);
        }
        if self.tokens >= cost {
            self.tokens -= cost;
            Ok(())
        } else {
            Err((((cost - self.tokens) / self.refill_per_ms).ceil() as i64).max(1))
        }
    }
}

/// One device's inbound budget: a frame rate and a byte rate.
#[derive(Debug, Clone)]
struct IngestBudget {
    frames: TokenBucket,
    bytes: TokenBucket,
}

impl IngestBudget {
    fn new(now_ms: UnixMs) -> Self {
        Self {
            frames: TokenBucket::new(limits::FRAME_BURST, limits::FRAMES_PER_SECOND, now_ms),
            bytes: TokenBucket::new(limits::BYTE_BURST, limits::BYTES_PER_SECOND, now_ms),
        }
    }
}

/// Command-creation budgets: one bucket per asserted device id, plus one global bucket.
///
/// The per-device table is capped and **self-healing**: each bucket remembers when it was last
/// charged, and an id it has never seen evicts the least recently used bucket instead of being
/// refused. Rotating ids therefore cannot fill the table permanently, and a device that enrolls
/// after the table has been churned is always admitted — at the cost of the evicted device
/// starting a fresh, full budget when it returns.
///
/// The global bucket is the ceiling that matters: the per-device allowance multiplies with the
/// number of asserted ids, so only a fleet-wide budget bounds the total attempt — and therefore
/// audit — rate.
#[derive(Default)]
struct CreationBudgets {
    per_device: HashMap<String, CreationBucket>,
    /// Created on first use so it starts full at the current clock, not at zero.
    global: Option<TokenBucket>,
}

struct CreationBucket {
    bucket: TokenBucket,
    last_seen_ms: UnixMs,
}

impl CreationBudgets {
    /// Charges one creation. `Some(retry_after_ms)` means the attempt is throttled and must answer
    /// `429` without being traced; the wait is the time until a token actually exists.
    fn charge(&mut self, device_id: &str, now_ms: UnixMs) -> Option<i64> {
        let global = self.global.get_or_insert_with(|| {
            TokenBucket::new(
                limits::GLOBAL_CREATE_BURST,
                limits::GLOBAL_CREATES_PER_SECOND,
                now_ms,
            )
        });
        if let Err(retry_after_ms) = global.take(1.0, now_ms) {
            return Some(retry_after_ms);
        }
        if !self.per_device.contains_key(device_id) && self.per_device.len() >= MAX_CREATION_BUCKETS
        {
            self.evict_least_recently_used();
        }
        let entry = self
            .per_device
            .entry(device_id.to_owned())
            .or_insert_with(|| CreationBucket {
                bucket: TokenBucket::new(
                    limits::COMMAND_BURST,
                    limits::COMMAND_CREATES_PER_SECOND,
                    now_ms,
                ),
                last_seen_ms: now_ms,
            });
        entry.last_seen_ms = now_ms;
        entry.bucket.take(1.0, now_ms).err()
    }

    /// Drops the bucket charged least recently. Called only when the table is full and an unseen
    /// id arrives, so the table never refuses an id for lack of space.
    fn evict_least_recently_used(&mut self) {
        let Some(oldest) = self
            .per_device
            .iter()
            .min_by_key(|(_, bucket)| bucket.last_seen_ms)
            .map(|(device_id, _)| device_id.clone())
        else {
            return;
        };
        self.per_device.remove(&oldest);
    }
}

#[derive(Default)]
struct RegistryInner {
    next_connection_id: u64,
    connections: HashMap<String, Connection>,
    commands: HashMap<String, CommandRecord>,
    /// Devices revoked in this process. A revoked device never authorizes again, but its
    /// channel may still have a frame in flight when revocation lands; this refuses those.
    /// One entry per revoked device, and device records are never deleted, so it is bounded by
    /// the number of revocations the store itself holds.
    revoked: HashSet<String>,
    /// Sum of every retained record's `retained_answer_bytes`.
    retained_answer_bytes: usize,
    completed: VecDeque<String>,
    /// Per-device inbound budgets, keyed by device so a reconnect does not reset them.
    ingest: HashMap<String, IngestBudget>,
    /// Command-creation budgets: one bucket per asserted id plus the global budget.
    creates: CreationBudgets,
}

/// A command that reached a terminal state without a device answer. Its fields are copied out
/// of the registry so the `command.outcome` row is written after the registry mutex is
/// released — a database call never stalls a device's channel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandOutcome {
    at_ms: UnixMs,
    actor: String,
    device_id: String,
    outcome: &'static str,
}

impl RegistryInner {
    /// A pending command whose deadline passed is `timeout`; nothing may still be pending
    /// after its deadline reads as success, and no caller has to poll for it. Each one yields
    /// the outcome fact its audit row records.
    fn expire(&mut self, now_ms: UnixMs) -> Vec<CommandOutcome> {
        let mut expired = Vec::new();
        let mut outcomes = Vec::new();
        for (command_id, record) in self.commands.iter_mut() {
            if record.status == CommandStatus::Pending && record.deadline_at_ms <= now_ms {
                record.status = CommandStatus::Timeout;
                record.completed_at_ms = Some(now_ms);
                expired.push(command_id.clone());
                outcomes.push(CommandOutcome {
                    at_ms: now_ms,
                    actor: record.actor.clone(),
                    device_id: record.device_id.clone(),
                    outcome: OUTCOME_TIMEOUT,
                });
            }
        }
        self.completed.extend(expired);
        self.trim();
        outcomes
    }

    /// Completes every pending command for `device_id` with one terminal `error`.
    fn fail_pending(
        &mut self,
        device_id: &str,
        error: &str,
        now_ms: UnixMs,
    ) -> Vec<CommandOutcome> {
        let mut failed = Vec::new();
        let mut outcomes = Vec::new();
        for (command_id, record) in self.commands.iter_mut() {
            if record.device_id == device_id && record.status == CommandStatus::Pending {
                record.status = CommandStatus::Error;
                record.error = Some(error.to_owned());
                record.message = Some(format!(
                    "the device's management channel ended before it answered ({error})"
                ));
                record.completed_at_ms = Some(now_ms);
                failed.push(command_id.clone());
                outcomes.push(CommandOutcome {
                    at_ms: now_ms,
                    actor: record.actor.clone(),
                    device_id: record.device_id.clone(),
                    outcome: OUTCOME_DEVICE_OFFLINE,
                });
            }
        }
        self.completed.extend(failed);
        self.trim();
        outcomes
    }

    /// Settles one device's table before its channel changes: a command whose deadline passed
    /// is `timeout` — the deadline happened first — and only what is still pending when the
    /// channel ends becomes `device_offline`. The outcomes are returned in that order so the
    /// durable rows record the same sequence.
    fn settle_device(&mut self, device_id: &str, now_ms: UnixMs) -> Vec<CommandOutcome> {
        let mut outcomes = self.expire(now_ms);
        outcomes.extend(self.fail_pending(device_id, "device_offline", now_ms));
        outcomes
    }

    fn in_flight(&self, device_id: &str) -> usize {
        self.commands
            .values()
            .filter(|record| {
                record.device_id == device_id && record.status == CommandStatus::Pending
            })
            .count()
    }

    /// Drops the oldest completed records past the count cap or the retained-output budget.
    /// Pending records are never dropped; their answers do not exist yet.
    fn trim(&mut self) {
        while self.commands.len() > MAX_RETAINED_COMMANDS
            || self.retained_answer_bytes > MAX_RETAINED_ANSWER_BYTES
        {
            let Some(command_id) = self.completed.pop_front() else {
                break;
            };
            let Some(retained) = self
                .commands
                .get(&command_id)
                .filter(|record| record.status != CommandStatus::Pending)
                .map(|record| record.retained_answer_bytes)
            else {
                continue;
            };
            self.commands.remove(&command_id);
            self.retained_answer_bytes = self.retained_answer_bytes.saturating_sub(retained);
        }
    }
}

/// The device registry and in-flight command table.
pub struct DeviceRegistry {
    clock: Arc<dyn Clock>,
    /// Durable audit path, shared with the HTTP command surface: a command that ends without
    /// a device answer appends its `command.outcome` row through the same store.
    store: Arc<dyn DeviceStore>,
    /// Shared with `AppState`, so a failed outcome write is visible in `/health`.
    audit_write_failures: Arc<AtomicU64>,
    inner: Mutex<RegistryInner>,
}

impl DeviceRegistry {
    pub fn new(
        clock: Arc<dyn Clock>,
        store: Arc<dyn DeviceStore>,
        audit_write_failures: Arc<AtomicU64>,
    ) -> Self {
        Self {
            clock,
            store,
            audit_write_failures,
            inner: Mutex::new(RegistryInner::default()),
        }
    }

    pub fn now_ms(&self) -> UnixMs {
        self.clock.now_ms()
    }

    pub fn is_online(&self, device_id: &str) -> bool {
        self.inner().connections.contains_key(device_id)
    }

    /// Whether this process revoked the device. A revoked device's frames are dropped even if
    /// its socket has not observed the close yet.
    pub fn is_revoked(&self, device_id: &str) -> bool {
        self.inner().revoked.contains(device_id)
    }

    /// Writes one `command.outcome` row per terminal fact. Called only after the fact has been
    /// copied out and the registry mutex released: best-effort, like the dispatch row, so a
    /// store failure counts in `/health` and never changes a command's state.
    async fn record_outcomes(&self, outcomes: Vec<CommandOutcome>) {
        for outcome in outcomes {
            let entry = AuditEntry {
                at_ms: outcome.at_ms,
                actor: outcome.actor,
                action: AUDIT_ACTION_OUTCOME.to_owned(),
                device_id: outcome.device_id,
                outcome: outcome.outcome.to_owned(),
                error: None,
            };
            if let Err(error) = self.store.insert_audit(entry).await {
                let failures = self.audit_write_failures.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!(
                    "phoneconnect: error: command outcome audit write failed ({failures} total): {error}"
                );
            }
        }
    }

    /// The description the device sent in its `hello`. `None` until it sends one.
    pub fn hello(&self, device_id: &str) -> Option<DeviceHello> {
        self.inner()
            .connections
            .get(device_id)
            .and_then(|connection| connection.hello.clone())
    }

    /// Registers a device channel. A previous channel for the same device is told to close
    /// with [`CLOSE_REPLACED`], and its pending commands complete as `device_offline`.
    ///
    /// A device revoked between the handshake's `require_device` and this call is refused
    /// here: the channel is closed with [`CLOSE_DEVICE_REVOKED`] and never registered, so the
    /// device learns why instead of holding a channel that silently drops everything.
    pub async fn connect(
        &self,
        device_id: &str,
        commands: mpsc::Sender<Value>,
        close: watch::Sender<Option<&'static str>>,
    ) -> ManagementConnection {
        let (connection, outcomes) = {
            let mut inner = self.inner();
            let now = self.now_ms();
            inner.next_connection_id += 1;
            let connection_id = inner.next_connection_id;
            let connection = ManagementConnection {
                device_id: device_id.to_owned(),
                connection_id,
            };
            if inner.revoked.contains(device_id) {
                // The handler authenticated before revocation committed; this is the last place
                // that can refuse the registration. `commands` and `close` are dropped after the
                // close signal, so the task writes the close frame and stops.
                let _ = close.send(Some(CLOSE_DEVICE_REVOKED));
                (connection, Vec::new())
            } else {
                let previous = inner.connections.insert(
                    device_id.to_owned(),
                    Connection {
                        id: connection_id,
                        commands,
                        close,
                        hello: None,
                    },
                );
                let mut outcomes = inner.expire(now);
                if let Some(previous) = previous {
                    // The replacement is live before the old one is told to go: a device never
                    // observes a window with no management channel.
                    let _ = previous.close.send(Some(CLOSE_REPLACED));
                }
                outcomes.extend(inner.fail_pending(device_id, "device_offline", now));
                (connection, outcomes)
            }
        };
        self.record_outcomes(outcomes).await;
        connection
    }

    /// Removes the registration only if it is still the current one. A replaced connection
    /// finishing its cleanup must not unregister its successor.
    pub async fn disconnect(&self, connection: &ManagementConnection) {
        let outcomes = {
            let mut inner = self.inner();
            let now = self.now_ms();
            let is_current = inner
                .connections
                .get(&connection.device_id)
                .is_some_and(|current| current.id == connection.connection_id);
            if !is_current {
                Vec::new()
            } else {
                inner.connections.remove(&connection.device_id);
                inner.settle_device(&connection.device_id, now)
            }
        };
        self.record_outcomes(outcomes).await;
    }

    /// Revocation's effect on the live channel: the device is marked revoked (so a frame
    /// already in flight is dropped even before its socket observes the close, and a channel
    /// that registers afterwards is refused), its pending commands complete — a passed deadline
    /// as `timeout`, the rest as `device_offline` — and the channel is closed with
    /// [`CLOSE_DEVICE_REVOKED`]. Returns whether a channel was open.
    pub async fn revoke(&self, device_id: &str) -> bool {
        let (was_online, outcomes) = {
            let mut inner = self.inner();
            let now = self.now_ms();
            inner.revoked.insert(device_id.to_owned());
            let closed = inner.connections.remove(device_id);
            let was_online = closed.is_some();
            if let Some(connection) = closed {
                // The close signal is sent before the command sender is dropped, so the
                // channel task reports the reason rather than a generic end.
                let _ = connection.close.send(Some(CLOSE_DEVICE_REVOKED));
            }
            (was_online, inner.settle_device(device_id, now))
        };
        self.record_outcomes(outcomes).await;
        was_online
    }

    /// Charges one command creation against `device_id`'s budget. `Some(retry_after_ms)` means
    /// the attempt is throttled and must answer `429` **without** appending an audit row: the
    /// throttle is what bounds the log's growth, so a flood must not write through it.
    ///
    /// Every attempt whose outcome can be traced — accepted, refused for want of access, refused
    /// for its shape, or refused because the id matches no device — charges it, which is why it is
    /// keyed by the asserted id. The global bucket is what actually bounds the total, because the
    /// per-device allowance multiplies with the number of ids named; the per-device table is
    /// capped ([`MAX_CREATION_BUCKETS`]) and evicts its least recently used bucket rather than
    /// refusing an unseen id. Attempts stopped before any row could exist (a missing actor, a bad
    /// token) do not charge.
    pub fn charge_command(&self, device_id: &str) -> Option<i64> {
        let now = self.now_ms();
        self.inner().creates.charge(device_id, now)
    }

    /// Records the `hello` a connection sent. A replaced connection's late hello is ignored:
    /// only the current connection describes the device.
    pub fn record_hello(&self, connection: &ManagementConnection, hello: DeviceHello) {
        let mut inner = self.inner();
        if let Some(current) = inner.connections.get_mut(&connection.device_id) {
            if current.id == connection.connection_id {
                current.hello = Some(hello);
            }
        }
    }

    /// Charges one inbound frame against the device's budget. `None` means it fits;
    /// `Some(retry_after_ms)` means the channel is over budget and must be closed with
    /// [`CLOSE_RATE_LIMITED`].
    pub fn charge_ingest(&self, device_id: &str, frame_bytes: usize) -> Option<i64> {
        let now = self.now_ms();
        let mut inner = self.inner();
        let budget = inner
            .ingest
            .entry(device_id.to_owned())
            .or_insert_with(|| IngestBudget::new(now));
        budget
            .frames
            .take(1.0, now)
            .and(budget.bytes.take(frame_bytes as f64, now))
            .err()
    }

    /// Hands one command to the device's channel.
    ///
    /// The caller charges the device's creation budget first ([`Self::charge_command`]) and
    /// answers `429` itself when it is exhausted: the throttle sits at the audit boundary, where
    /// every traced attempt — accepted or refused — is charged exactly once.
    /// [`crate::commands::dispatch_for_actor`] is the one caller and owns that ordering.
    pub async fn dispatch(
        &self,
        device_id: &str,
        actor: &str,
        name: &str,
        args: Option<Value>,
        timeout_ms: Option<i64>,
    ) -> Result<Dispatch, DispatchError> {
        let (result, outcomes) = self.dispatch_locked(device_id, actor, name, args, timeout_ms);
        self.record_outcomes(outcomes).await;
        result
    }

    /// The locked half of [`Self::dispatch`]. It returns the terminal facts it observed along
    /// with the result so the guard is released before any audit row is written.
    fn dispatch_locked(
        &self,
        device_id: &str,
        actor: &str,
        name: &str,
        args: Option<Value>,
        timeout_ms: Option<i64>,
    ) -> (Result<Dispatch, DispatchError>, Vec<CommandOutcome>) {
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_COMMAND_NAME_BYTES {
            return (Err(DispatchError::InvalidName), Vec::new());
        }
        let deadline_ms = match timeout_ms {
            None => DEFAULT_COMMAND_TIMEOUT_MS,
            Some(value) if (1..=MAX_COMMAND_TIMEOUT_MS).contains(&value) => value,
            Some(_) => return (Err(DispatchError::InvalidTimeout), Vec::new()),
        };
        let now = self.now_ms();
        let mut inner = self.inner();
        let mut outcomes = Vec::new();
        let result = (|| -> Result<Dispatch, DispatchError> {
            outcomes = inner.expire(now);
            // Clone the sender out of the map: the guard borrows the whole registry, so one
            // borrow cannot stay alive while the command table is updated.
            let Some(sender) = inner
                .connections
                .get(device_id)
                .map(|connection| connection.commands.clone())
            else {
                return Err(DispatchError::Offline {
                    device_id: device_id.to_owned(),
                });
            };
            if inner.in_flight(device_id) >= MAX_IN_FLIGHT_PER_DEVICE {
                return Err(DispatchError::Capacity {
                    device_id: device_id.to_owned(),
                    limit: MAX_IN_FLIGHT_PER_DEVICE,
                });
            }
            let command_id = format!(
                "cmd_{}",
                generate_secret("").map_err(|_| DispatchError::Internal)?
            );
            let frame = json!({
                "type": "command",
                "request_id": command_id,
                "name": name,
                "args": args.unwrap_or(Value::Null),
                "deadline_ms": deadline_ms,
                // The absolute server deadline. A device that dequeues the frame after it passed
                // must refuse to start the command: a duration alone would let a queued command
                // run long after the server already reported `timeout`.
                "expires_at_ms": now + deadline_ms,
            });
            // The record exists before the frame can be answered, so an immediate result is never
            // dropped as unknown. A full or closed channel means the writer is gone or cannot keep
            // up: the command never reached the device, so it is refused rather than left pending.
            inner.commands.insert(
                command_id.clone(),
                CommandRecord {
                    command_id: command_id.clone(),
                    device_id: device_id.to_owned(),
                    name: name.to_owned(),
                    status: CommandStatus::Pending,
                    output: None,
                    error: None,
                    message: None,
                    created_at_ms: now,
                    completed_at_ms: None,
                    actor: actor.to_owned(),
                    deadline_at_ms: now + deadline_ms,
                    retained_answer_bytes: 0,
                },
            );
            if sender.try_send(frame).is_err() {
                inner.commands.remove(&command_id);
                return Err(DispatchError::Offline {
                    device_id: device_id.to_owned(),
                });
            }
            inner.trim();
            Ok(Dispatch {
                command_id,
                deadline_ms,
            })
        })();
        (result, outcomes)
    }

    /// Completes one command from the device's `result` frame. Only a pending command of the
    /// same device can complete it, and only once.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete(
        &self,
        device_id: &str,
        request_id: &str,
        status: ResultStatus,
        output: Option<Value>,
        error: Option<String>,
        message: Option<String>,
    ) -> Result<(), ResultError> {
        let (result, outcomes) =
            self.complete_locked(device_id, request_id, status, output, error, message);
        self.record_outcomes(outcomes).await;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_locked(
        &self,
        device_id: &str,
        request_id: &str,
        status: ResultStatus,
        output: Option<Value>,
        error: Option<String>,
        message: Option<String>,
    ) -> (Result<(), ResultError>, Vec<CommandOutcome>) {
        let now = self.now_ms();
        let mut inner = self.inner();
        let outcomes = inner.expire(now);
        let result = (|| -> Result<(), ResultError> {
            let Some(record) = inner.commands.get_mut(request_id) else {
                return Err(ResultError::UnknownRequest {
                    request_id: request_id.to_owned(),
                });
            };
            if record.device_id != device_id {
                return Err(ResultError::RequestScopeMismatch {
                    request_id: request_id.to_owned(),
                });
            }
            if record.status != CommandStatus::Pending {
                return Err(ResultError::AlreadyCompleted {
                    request_id: request_id.to_owned(),
                });
            }
            let mut answer_bytes = 0;
            match status {
                ResultStatus::Ok => {
                    let bytes = match output.as_ref() {
                        None => 0,
                        // An unserializable result is refused rather than accepted unknown.
                        Some(value) => serde_json::to_vec(value)
                            .map(|bytes| bytes.len())
                            .unwrap_or(usize::MAX),
                    };
                    if bytes > MAX_RESULT_BYTES {
                        record.status = CommandStatus::Error;
                        record.error = Some("result_too_large".to_owned());
                        record.message =
                            Some(format!("a result may not exceed {MAX_RESULT_BYTES} bytes"));
                    } else {
                        record.status = CommandStatus::Ok;
                        record.output = output;
                        record.message = message.map(bounded_text);
                        answer_bytes = bytes;
                    }
                }
                ResultStatus::Error => {
                    record.status = CommandStatus::Error;
                    record.error = Some(match error {
                        Some(error) => bounded_text(error),
                        None => "device_error".to_owned(),
                    });
                    record.message = message.map(bounded_text);
                }
            }
            record.completed_at_ms = Some(now);
            // The whole retained answer is charged, not only `output`: a `message` or an `error`
            // is just as able to grow the table as a result payload.
            answer_bytes = answer_bytes
                .saturating_add(record.message.as_deref().map_or(0, str::len))
                .saturating_add(record.error.as_deref().map_or(0, str::len));
            record.retained_answer_bytes = answer_bytes;
            let command_id = request_id.to_owned();
            // The mutable borrow of the record ends here, so the aggregate can be charged.
            inner.retained_answer_bytes = inner.retained_answer_bytes.saturating_add(answer_bytes);
            inner.completed.push_back(command_id);
            inner.trim();
            Ok(())
        })();
        (result, outcomes)
    }

    /// One command's current state, with a passed deadline already reflected as `timeout`.
    pub async fn command(&self, command_id: &str) -> Option<CommandRecord> {
        let (record, outcomes) = {
            let now = self.now_ms();
            let mut inner = self.inner();
            let outcomes = inner.expire(now);
            (inner.commands.get(command_id).cloned(), outcomes)
        };
        self.record_outcomes(outcomes).await;
        record
    }

    fn inner(&self) -> MutexGuard<'_, RegistryInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A retained `message` or `error`, bounded so one result cannot spend the whole
/// [`MAX_RETAINED_ANSWER_BYTES`] budget on prose. The beginning is what a reader needs.
fn bounded_text(text: String) -> String {
    if text.len() <= MAX_RETAINED_TEXT_BYTES {
        return text;
    }
    let mut end = MAX_RETAINED_TEXT_BYTES - '…'.len_utf8();
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = String::with_capacity(MAX_RETAINED_TEXT_BYTES);
    bounded.push_str(&text[..end]);
    bounded.push('…');
    bounded
}

/// The `status` a device reports in a `result` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Ok,
    Error,
}

/// One frame the device may send. Anything else is a framing fault and closes the channel.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DeviceFrame {
    Hello {
        model: String,
        android_version: String,
        sdk: i64,
    },
    Telemetry {
        sample: TelemetrySample,
    },
    Result {
        request_id: String,
        status: ResultStatus,
        #[serde(default)]
        output: Option<Value>,
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        message: Option<String>,
    },
}

/// Refusals before the WebSocket handshake. A revoked device and a bad credential never
/// reach the channel at all.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("credential does not authorize device {device_id}")]
    DeviceScopeMismatch { device_id: String },
}

impl IntoResponse for ControlError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            Self::DeviceScopeMismatch { .. } => (
                StatusCode::FORBIDDEN,
                axum::Json(json!({ "error": "device_scope_mismatch" })),
            )
                .into_response(),
        }
    }
}

/// `GET /api/devices/{id}/control`: the device's management channel.
///
/// The device credential is required in the `Authorization` header and authorizes only its
/// own device. The handler authenticates before it calls `on_upgrade`, so an unauthorized
/// device receives an ordinary `401`/`403` and never reaches a WebSocket.
pub async fn control_socket(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ControlError> {
    let device = state.auth.require_device(&headers).await?;
    if device.device_id != device_id {
        return Err(ControlError::DeviceScopeMismatch { device_id });
    }
    let device_id = device.device_id;
    Ok(upgrade
        .max_message_size(MAX_CLIENT_MESSAGE_BYTES)
        .max_frame_size(MAX_CLIENT_MESSAGE_BYTES)
        // Registration happens inside the upgrade future, not before it: an upgrade that
        // fails after the `101` must not displace the device's live channel or leave a
        // registration whose receiver no longer exists.
        .on_upgrade(move |socket| async move {
            let (commands_tx, commands_rx) = mpsc::channel(MAX_IN_FLIGHT_PER_DEVICE);
            let (close_tx, close_rx) = watch::channel(None);
            let connection = state
                .management
                .connect(&device_id, commands_tx, close_tx)
                .await;
            run_channel(socket, state, device_id, connection, commands_rx, close_rx).await;
        })
        .into_response())
}

/// Serves one management connection until it closes for any reason. The registration is
/// removed on the way out, so a command is never dispatched into a dead channel.
async fn run_channel(
    socket: WebSocket,
    state: Arc<AppState>,
    device_id: String,
    connection: ManagementConnection,
    mut commands: mpsc::Receiver<Value>,
    mut close: watch::Receiver<Option<&'static str>>,
) {
    let (mut sink, mut stream) = socket.split();
    loop {
        // A replacement signals close and drops the command sender in the same step, so the
        // close is checked first: the device must learn *why* it was replaced.
        tokio::select! {
            biased;
            changed = close.changed() => {
                if changed.is_err() {
                    break;
                }
                // Copy the reason out before awaiting: the watch guard is not `Send`.
                let reason = *close.borrow();
                if let Some(reason) = reason {
                    let _ = sink.send(Message::Close(Some(policy_close(reason)))).await;
                    break;
                }
            },
            outbound = commands.recv() => match outbound {
                Some(frame) => {
                    if sink.send(Message::Text(frame.to_string().into())).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            inbound = stream.next() => match inbound {
                Some(Ok(Message::Text(text))) => {
                    if state
                        .management
                        .charge_ingest(&device_id, text.len())
                        .is_some()
                    {
                        let _ = sink
                            .send(Message::Close(Some(policy_close(CLOSE_RATE_LIMITED))))
                            .await;
                        break;
                    }
                    if handle_frame(&state, &device_id, &connection, text.as_str())
                        .await
                        .is_err()
                    {
                        let _ = sink
                            .send(Message::Close(Some(policy_close(CLOSE_MALFORMED_FRAME))))
                            .await;
                        break;
                    }
                }
                // A binary message is not a management frame. Telling the device why is
                // better than a silent drop it would have to infer.
                Some(Ok(Message::Binary(_))) => {
                    let _ = sink
                        .send(Message::Close(Some(policy_close(CLOSE_MALFORMED_FRAME))))
                        .await;
                    break;
                }
                Some(Ok(Message::Ping(payload))) => {
                    if sink.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
            },
        }
    }
    state.management.disconnect(&connection).await;
}

/// Applies one device frame. Only a frame that is not valid JSON closes the channel: a bad
/// telemetry *value* is dropped and stays visible as stale telemetry, and a stale result is
/// ignored, because neither is a framing fault.
async fn handle_frame(
    state: &AppState,
    device_id: &str,
    connection: &ManagementConnection,
    text: &str,
) -> Result<(), ()> {
    // Defence in depth: a revoked device's channel is closed in the same request, but a frame
    // already read from the socket must not refresh telemetry or describe the device.
    if state.management.is_revoked(device_id) {
        return Ok(());
    }
    let frame: DeviceFrame = serde_json::from_str(text).map_err(|_| ())?;
    match frame {
        DeviceFrame::Hello {
            model,
            android_version,
            sdk,
        } => state.management.record_hello(
            connection,
            DeviceHello {
                model,
                android_version,
                sdk,
            },
        ),
        DeviceFrame::Telemetry { sample } => {
            let _ = state.telemetry.ingest(device_id, sample);
        }
        DeviceFrame::Result {
            request_id,
            status,
            output,
            error,
            message,
        } => {
            let _ = state
                .management
                .complete(device_id, &request_id, status, output, error, message)
                .await;
        }
    }
    Ok(())
}

fn policy_close(reason: &'static str) -> CloseFrame {
    CloseFrame {
        code: POLICY_CLOSE_CODE,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::relay::RelayLimits;
    use crate::store::{ManualClock, SqliteStore};

    /// The defence-in-depth half of revocation: a frame read from a socket that has not yet
    /// observed the close is dropped, so it cannot refresh telemetry after the device is revoked.
    #[tokio::test]
    async fn a_revoked_devices_telemetry_frame_is_dropped() {
        let store = Arc::new(SqliteStore::in_memory().expect("in-memory store"));
        let clock = Arc::new(ManualClock::new(1_760_000_000_000));
        let state = AppState::new(
            store,
            "test-admin-token",
            "https://relay.test/api/sessions",
            RelayLimits::default(),
            clock,
        )
        .expect("app state with a non-empty admin token");
        state.management.revoke("dev_a").await;
        assert!(state.management.is_revoked("dev_a"));

        let connection = ManagementConnection {
            device_id: "dev_a".to_owned(),
            connection_id: 1,
        };
        let frame = json!({
            "type": "telemetry",
            "sample": { "sampled_at_ms": 1_760_000_000_000i64, "battery_percent": 99 }
        })
        .to_string();
        handle_frame(&state, "dev_a", &connection, &frame)
            .await
            .expect("a revoked frame is dropped, not a framing fault");

        assert!(
            state.telemetry.aggregate("dev_a").is_none(),
            "no sample may be ingested from a revoked device"
        );
    }

    fn state_with_clock() -> (AppState, Arc<ManualClock>) {
        let store = Arc::new(SqliteStore::in_memory().expect("in-memory store"));
        let clock = Arc::new(ManualClock::new(1_760_000_000_000));
        let state = AppState::new(
            store,
            "test-admin-token",
            "https://relay.test/api/sessions",
            RelayLimits::default(),
            clock.clone(),
        )
        .expect("app state with a non-empty admin token");
        (state, clock)
    }

    /// The global budget is the real ceiling: rotating the asserted id gives every attempt a full
    /// per-device bucket, so only the fleet-wide bucket can stop it. The wait it reports is the
    /// time until a token exists, not a permanent refusal.
    #[tokio::test]
    async fn the_global_budget_throttles_a_flood_across_many_ids() {
        let (state, clock) = state_with_clock();

        let mut admitted = 0;
        let retry_after_ms = loop {
            assert!(admitted <= 10_000, "the global budget never fired");
            let device_id = format!("dev_rotating_{admitted}");
            if let Some(retry_after_ms) = state.management.charge_command(&device_id) {
                break retry_after_ms;
            }
            admitted += 1;
        };
        assert_eq!(
            admitted as f64,
            limits::GLOBAL_CREATE_BURST,
            "every new id has a full per-device bucket, so only the global burst can stop it"
        );
        assert!(
            (1..=10).contains(&retry_after_ms),
            "the wait is the ~5ms until a token refills, not a permanent refusal: {retry_after_ms}"
        );

        // The reported wait is real: one refill interval later an attempt is admitted again.
        clock.advance_ms(5);
        assert!(
            state
                .management
                .charge_command("dev_after_the_wait")
                .is_none(),
            "the global budget refills"
        );
    }

    /// A full table evicts the least recently used bucket, so an unseen id — a device that enrolls
    /// after churn included — is admitted and the evicted device starts fresh when it returns.
    #[tokio::test]
    async fn a_full_table_evicts_the_least_recently_used_bucket_instead_of_refusing() {
        let (state, clock) = state_with_clock();

        // Charge 4096 distinct ids, giving the global bucket its 200/s back between attempts.
        for index in 0..MAX_CREATION_BUCKETS {
            assert!(
                state
                    .management
                    .charge_command(&format!("dev_spoofed_{index}"))
                    .is_none(),
                "a fresh id is admitted"
            );
            clock.advance_ms(5);
        }

        // The table is full. An id it has never seen is admitted, at the cost of the oldest bucket.
        assert!(
            state
                .management
                .charge_command("dev_newly_enrolled")
                .is_none(),
            "a full table never refuses an unseen id"
        );
        clock.advance_ms(5);
        assert!(
            state
                .management
                .charge_command("dev_another_new_one")
                .is_none(),
            "the table keeps admitting unseen ids"
        );

        // The evicted device returns with a full bucket: its old state did not survive eviction.
        // The clock is frozen here so the bucket cannot refill between charges.
        for charge in 0..(limits::COMMAND_BURST as usize) {
            assert!(
                state.management.charge_command("dev_spoofed_0").is_none(),
                "charge {charge} of a fresh bucket succeeds"
            );
        }
        assert!(
            state.management.charge_command("dev_spoofed_0").is_some(),
            "a bucket starts fresh after eviction, so the burst is exactly full again"
        );
    }
}
