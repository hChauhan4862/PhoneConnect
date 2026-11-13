//! 30-day retention. One callable job deletes session records, control leases, and
//! telemetry aggregates older than the window.
//!
//! There is no scheduler daemon: [`RetentionJob::run`] is deterministic and takes the
//! clock reading as an argument, and [`RetentionJob::spawn_interval`] is the startup hook a
//! deployment uses to call it periodically.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::store::{Clock, DeviceStore, RetentionCounts, StoreError, UnixMs};
use crate::telemetry::{RETENTION_MS, TelemetryAggregator};

/// How often a long-running server runs retention unless configured otherwise.
pub const DEFAULT_RETENTION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// What one run deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RetentionReport {
    pub cutoff_ms: UnixMs,
    #[serde(flatten)]
    pub records: RetentionCounts,
    pub telemetry_devices_deleted: Vec<String>,
}

pub struct RetentionJob {
    store: Arc<dyn DeviceStore>,
    telemetry: Arc<TelemetryAggregator>,
    clock: Arc<dyn Clock>,
}

impl RetentionJob {
    pub fn new(
        store: Arc<dyn DeviceStore>,
        telemetry: Arc<TelemetryAggregator>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            telemetry,
            clock,
        }
    }

    /// Runs retention as of `now_ms`. Callers in tests pass a fixed reading; the interval
    /// hook reads the injected clock.
    pub async fn run(&self, now_ms: UnixMs) -> Result<RetentionReport, StoreError> {
        let cutoff_ms = now_ms - RETENTION_MS;
        let records = self.store.delete_records_older_than(cutoff_ms).await?;
        let telemetry_devices_deleted = self.telemetry.purge_older_than(cutoff_ms);
        Ok(RetentionReport {
            cutoff_ms,
            records,
            telemetry_devices_deleted,
        })
    }

    /// Runs retention against the injected clock.
    pub async fn run_due(&self) -> Result<RetentionReport, StoreError> {
        self.run(self.clock.now_ms()).await
    }

    /// Runs retention once soon after startup and then on an interval. A failed run is
    /// reported and retried on the next tick; it never panics the server.
    pub fn spawn_interval(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(error) = self.run_due().await {
                    eprintln!("phoneconnect: retention run failed: {error}");
                }
            }
        })
    }
}
