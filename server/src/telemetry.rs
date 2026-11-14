//! Bounded telemetry aggregation.
//!
//! Two hundred background devices must not create an unbounded event log. Each device keeps
//! a fixed-size window of recent samples plus a small aggregate, keyed by device id; nothing
//! here persists a raw sample stream, a file, or media bytes. Staleness is explicit, and
//! aggregates older than the retention window are deleted by [`TelemetryAggregator::purge_older_than`].

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::AuthError;
use crate::store::{Clock, UnixMs};
use crate::{ApiJson, AppState};

/// A reading older than this is stale: three missed reports at the default 30 s interval.
pub const STALE_AFTER_MS: UnixMs = 90_000;

/// Samples retained per device. Older samples are dropped, never appended to a log.
pub const MAX_RECENT_SAMPLES: usize = 16;

/// Devices tracked at once. The deployment ceiling is 200 background-connected devices.
pub const MAX_TRACKED_DEVICES: usize = 200;

/// Longest accepted `connectivity` label. A report names a transport (`wifi`, `cellular`), not
/// prose: 16 samples retained per device means an unbounded string would let one agent pin
/// megabytes. Printable ASCII only, so a captured value cannot smuggle control characters into
/// a console or a log.
pub const MAX_CONNECTIVITY_BYTES: usize = 64;

/// Default retention for aggregates: 30 days, matching session and audit retention.
pub const RETENTION_MS: UnixMs = 30 * 24 * 60 * 60 * 1_000;

/// One device report. Every metric is optional because an agent reports what the platform
/// exposes; a missing metric is absent, never a fabricated zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySample {
    #[serde(default)]
    pub sampled_at_ms: UnixMs,
    #[serde(default)]
    pub cpu_percent: Option<f64>,
    #[serde(default)]
    pub memory_used_bytes: Option<u64>,
    #[serde(default)]
    pub memory_total_bytes: Option<u64>,
    #[serde(default)]
    pub battery_percent: Option<u8>,
    #[serde(default)]
    pub battery_charging: Option<bool>,
    #[serde(default)]
    pub connectivity: Option<String>,
}

impl TelemetrySample {
    fn validate(&self) -> Result<(), TelemetryError> {
        if self.sampled_at_ms <= 0 {
            return Err(TelemetryError::InvalidSample {
                reason: "sampled_at_ms is required",
            });
        }
        if let Some(cpu) = self.cpu_percent {
            if !cpu.is_finite() || !(0.0..=1000.0).contains(&cpu) {
                return Err(TelemetryError::InvalidSample {
                    reason: "cpu_percent must be a finite percentage",
                });
            }
        }
        if let Some(battery) = self.battery_percent {
            if battery > 100 {
                return Err(TelemetryError::InvalidSample {
                    reason: "battery_percent must be between 0 and 100",
                });
            }
        }
        if let (Some(used), Some(total)) = (self.memory_used_bytes, self.memory_total_bytes) {
            if total == 0 || used > total {
                return Err(TelemetryError::InvalidSample {
                    reason: "memory usage must fit within the reported total",
                });
            }
        }
        if let Some(connectivity) = self.connectivity.as_deref() {
            if connectivity.len() > MAX_CONNECTIVITY_BYTES {
                return Err(TelemetryError::InvalidSample {
                    reason: "connectivity must be at most 64 bytes",
                });
            }
            if !connectivity
                .chars()
                .all(|value| value.is_ascii_graphic() || value == ' ')
            {
                return Err(TelemetryError::InvalidSample {
                    reason: "connectivity must be printable ASCII",
                });
            }
        }
        Ok(())
    }

    fn memory_percent(&self) -> Option<f64> {
        match (self.memory_used_bytes, self.memory_total_bytes) {
            (Some(used), Some(total)) if total > 0 => Some(used as f64 / total as f64 * 100.0),
            _ => None,
        }
    }
}

/// Min/max/mean over the retained window, with the newest reading kept verbatim.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetricAggregate {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub latest: f64,
}

impl MetricAggregate {
    fn from_values(values: &[f64]) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        let min = values.iter().copied().fold(f64::INFINITY, f64::min);
        let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        Some(Self {
            min,
            max,
            mean,
            latest: *values.last().expect("non-empty window"),
        })
    }
}

/// What the status surface and the UI render for one device.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TelemetryAggregate {
    pub device_id: String,
    /// Reports accepted since tracking began. A counter, not a retained sample list.
    pub samples_received: u64,
    /// Samples actually retained: never more than [`MAX_RECENT_SAMPLES`].
    pub window_samples: usize,
    /// Span of the retained window, from the oldest retained sample to the newest.
    pub window_ms: UnixMs,
    pub first_received_ms: UnixMs,
    pub last_received_ms: UnixMs,
    pub latest: TelemetrySample,
    pub window_cpu_percent: Option<MetricAggregate>,
    pub window_memory_percent: Option<MetricAggregate>,
    pub window_battery_percent: Option<MetricAggregate>,
}

/// Explicit freshness. Missing and stale are reported as such; neither reads as fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryFreshness {
    Fresh,
    Stale,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TelemetryStatus {
    pub state: TelemetryFreshness,
    pub age_ms: Option<UnixMs>,
    pub last_received_ms: Option<UnixMs>,
    pub sampled_at_ms: Option<UnixMs>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryError {
    #[error("device id must not be empty")]
    InvalidDevice,
    #[error("invalid telemetry sample: {reason}")]
    InvalidSample { reason: &'static str },
    #[error("telemetry tracks at most {limit} devices")]
    Capacity { limit: usize },
    #[error("telemetry is throttled; retry in {retry_after_ms}ms")]
    RateLimited { retry_after_ms: i64 },
}

struct DeviceTelemetry {
    recent: VecDeque<TelemetrySample>,
    samples_received: u64,
    first_received_ms: UnixMs,
    last_received_ms: UnixMs,
    sampled_at_ms: UnixMs,
    latest: TelemetrySample,
}

impl DeviceTelemetry {
    fn new(now_ms: UnixMs, sample: TelemetrySample) -> Self {
        let mut recent = VecDeque::with_capacity(MAX_RECENT_SAMPLES);
        recent.push_back(sample.clone());
        Self {
            recent,
            samples_received: 1,
            first_received_ms: now_ms,
            last_received_ms: now_ms,
            sampled_at_ms: sample.sampled_at_ms,
            latest: sample,
        }
    }

    fn push(&mut self, sample: TelemetrySample, now_ms: UnixMs) {
        self.samples_received = self.samples_received.saturating_add(1);
        self.last_received_ms = now_ms;
        // "Latest" follows the device clock, so a late-arriving older reading never
        // replaces a newer one in the status surface.
        if sample.sampled_at_ms >= self.latest.sampled_at_ms {
            self.sampled_at_ms = sample.sampled_at_ms;
            self.latest = sample.clone();
        }
        self.recent.push_back(sample);
        while self.recent.len() > MAX_RECENT_SAMPLES {
            self.recent.pop_front();
        }
    }

    fn aggregate(&self, device_id: &str) -> TelemetryAggregate {
        let cpu = self
            .recent
            .iter()
            .filter_map(|sample| sample.cpu_percent)
            .collect::<Vec<_>>();
        let memory = self
            .recent
            .iter()
            .filter_map(TelemetrySample::memory_percent)
            .collect::<Vec<_>>();
        let battery = self
            .recent
            .iter()
            .filter_map(|sample| sample.battery_percent.map(f64::from))
            .collect::<Vec<_>>();
        let oldest = self
            .recent
            .front()
            .map(|sample| sample.sampled_at_ms)
            .unwrap_or(self.latest.sampled_at_ms);
        TelemetryAggregate {
            device_id: device_id.to_owned(),
            samples_received: self.samples_received,
            window_samples: self.recent.len(),
            window_ms: (self.latest.sampled_at_ms - oldest).max(0),
            first_received_ms: self.first_received_ms,
            last_received_ms: self.last_received_ms,
            latest: self.latest.clone(),
            window_cpu_percent: MetricAggregate::from_values(&cpu),
            window_memory_percent: MetricAggregate::from_values(&memory),
            window_battery_percent: MetricAggregate::from_values(&battery),
        }
    }
}

/// Bounded in-memory telemetry state. Aggregates survive as long as the process; the
/// retention job deletes the ones no report has refreshed for 30 days.
pub struct TelemetryAggregator {
    clock: Arc<dyn Clock>,
    devices: Mutex<HashMap<String, DeviceTelemetry>>,
}

impl TelemetryAggregator {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            devices: Mutex::new(HashMap::new()),
        }
    }

    pub fn now_ms(&self) -> UnixMs {
        self.clock.now_ms()
    }

    /// Accepts one report and keeps only a bounded window of it.
    pub fn ingest(
        &self,
        device_id: &str,
        sample: TelemetrySample,
    ) -> Result<TelemetryAggregate, TelemetryError> {
        let device_id = device_id.trim();
        if device_id.is_empty() {
            return Err(TelemetryError::InvalidDevice);
        }
        sample.validate()?;
        let now = self.now_ms();
        let mut devices = self.devices();
        if !devices.contains_key(device_id) && devices.len() >= MAX_TRACKED_DEVICES {
            return Err(TelemetryError::Capacity {
                limit: MAX_TRACKED_DEVICES,
            });
        }
        match devices.get_mut(device_id) {
            Some(entry) => entry.push(sample, now),
            None => {
                devices.insert(device_id.to_owned(), DeviceTelemetry::new(now, sample));
            }
        }
        let aggregate = devices
            .get(device_id)
            .expect("the device was just inserted or updated")
            .aggregate(device_id);
        Ok(aggregate)
    }

    pub fn aggregate(&self, device_id: &str) -> Option<TelemetryAggregate> {
        self.devices()
            .get(device_id)
            .map(|entry| entry.aggregate(device_id))
    }

    pub fn freshness(&self, device_id: &str, now_ms: UnixMs) -> TelemetryStatus {
        let devices = self.devices();
        let Some(entry) = devices.get(device_id) else {
            return TelemetryStatus {
                state: TelemetryFreshness::Missing,
                age_ms: None,
                last_received_ms: None,
                sampled_at_ms: None,
            };
        };
        let age = (now_ms - entry.last_received_ms).max(0);
        TelemetryStatus {
            state: if age > STALE_AFTER_MS {
                TelemetryFreshness::Stale
            } else {
                TelemetryFreshness::Fresh
            },
            age_ms: Some(age),
            last_received_ms: Some(entry.last_received_ms),
            sampled_at_ms: Some(entry.sampled_at_ms),
        }
    }

    pub fn tracked_devices(&self) -> usize {
        self.devices().len()
    }

    /// Deletes aggregates whose last report is older than `cutoff_ms`, returning their ids.
    pub fn purge_older_than(&self, cutoff_ms: UnixMs) -> Vec<String> {
        let mut devices = self.devices();
        let mut deleted = Vec::new();
        devices.retain(|device_id, entry| {
            let keep = entry.last_received_ms >= cutoff_ms;
            if !keep {
                deleted.push(device_id.clone());
            }
            keep
        });
        deleted.sort();
        deleted
    }

    fn devices(&self) -> MutexGuard<'_, HashMap<String, DeviceTelemetry>> {
        self.devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Telemetry is reported by the device itself; the device credential proves which device.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryIngestError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("credential is not for device {device_id}")]
    DeviceScopeMismatch { device_id: String },
    #[error(transparent)]
    Invalid(#[from] TelemetryError),
}

impl IntoResponse for TelemetryIngestError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            Self::DeviceScopeMismatch { .. } => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "device_scope_mismatch" })),
            )
                .into_response(),
            Self::Invalid(TelemetryError::RateLimited { retry_after_ms }) => {
                crate::management::rate_limited_response(retry_after_ms)
            }
            Self::Invalid(error) => {
                let (status, code) = match error {
                    TelemetryError::InvalidDevice => (StatusCode::BAD_REQUEST, "invalid_device"),
                    TelemetryError::InvalidSample { .. } => {
                        (StatusCode::BAD_REQUEST, "invalid_sample")
                    }
                    TelemetryError::Capacity { .. } => {
                        (StatusCode::TOO_MANY_REQUESTS, "telemetry_capacity")
                    }
                    // Handled above: it carries a `Retry-After` header.
                    TelemetryError::RateLimited { .. } => {
                        (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
                    }
                };
                (status, Json(json!({ "error": code }))).into_response()
            }
        }
    }
}

/// `POST /api/devices/{id}/telemetry`: one bounded report from the device itself.
///
/// This route feeds the same global ingest mutex as the management channel, so it is charged
/// from the same per-device ingress budget: a flood here is refused exactly as a flood on the
/// channel is.
pub async fn ingest_telemetry(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    ApiJson(sample): ApiJson<TelemetrySample>,
) -> Result<Json<TelemetryAggregate>, TelemetryIngestError> {
    let device = state.auth.require_device(&headers).await?;
    if device.device_id != device_id {
        return Err(TelemetryIngestError::DeviceScopeMismatch { device_id });
    }
    let reported_bytes = serde_json::to_vec(&sample)
        .map(|body| body.len())
        .unwrap_or(0);
    if let Some(retry_after_ms) = state
        .management
        .charge_ingest(&device.device_id, reported_bytes)
    {
        return Err(TelemetryIngestError::Invalid(TelemetryError::RateLimited {
            retry_after_ms,
        }));
    }
    Ok(Json(state.telemetry.ingest(&device.device_id, sample)?))
}
