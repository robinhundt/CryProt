//! [`tracing_subscriber::Layer`] for structured communication metrics
//!
//! The [`CommLayer`] is a [`tracing_subscriber::Layer`] which records numbers of bytes read and
//! written. Metrics are collected by [`instrumenting`](`tracing::instrument`) spans with the
//! `seec_metrics` target and a phase. From within these spans, events with the same target can be emitted
//! to track the number of bytes read/written.
//!
//! ```
//! use tracing::{event, instrument, Level};
//!
//! #[instrument(target = "seec_metrics", fields(phase = "Online"))]
//! async fn online() {
//!     event!(target: "seec_metrics", Level::TRACE, bytes_written = 5);
//!     interleaved_setup().await
//! }
//!
//! #[instrument(target = "seec_metrics", fields(phase = "Setup"))]
//! async fn interleaved_setup() {
//!     // Will be recorded in the sub phase "Setup" of the online phase
//!     event!(target: "seec_metrics", Level::TRACE, bytes_written = 10);
//! }
//!
//! ```
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::mem;
use std::ops::AddAssign;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{warn, Level};
use tracing_subscriber::filter::{Filtered, Targets};
use tracing_subscriber::layer::{Context, Layer};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
/// Communication metrics for a phase and its sub phases.
pub struct CommData {
    pub phase: String,
    pub read: Counter,
    pub write: Counter,
    pub sub_comm_data: SubCommData,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct Counter {
    /// Number of written/read directly in this phase.
    pub bytes: u64,
    /// Total number of bytes written/read in this phase an all sub phases.
    pub bytes_with_sub_comm: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
/// Sub communication data for different phases
pub struct SubCommData(BTreeMap<String, CommData>);

/// Convenience type alias for a filtered `CommLayerData` which only handles
/// spans and events with `target = "seec_metrics"`.
pub type CommLayer<S> = Filtered<CommLayerData, Targets, S>;

#[derive(Clone, Debug, Default)]
/// The `CommLayerData` has shared ownership of the root [`SubCommData`].
pub struct CommLayerData {
    // TOOD use Atomics in SubCommData to not need lock, maybe?
    comm_data: Arc<Mutex<SubCommData>>,
}

/// Instantiate a new [`CommLayer`] and corresponding [`CommLayerData`].
pub fn new_comm_layer<S>() -> (CommLayer<S>, CommLayerData)
where
    S: tracing::Subscriber,
    S: for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    let inner = CommLayerData::default();
    let target_filter = Targets::new().with_target("seec_metrics", Level::TRACE);
    (inner.clone().with_filter(target_filter), inner)
}

impl CommLayerData {
    /// Returns a clone of the root `SubCommData` at this moment.
    pub fn comm_data(&self) -> SubCommData {
        self.comm_data.lock().expect("lock poisoned").clone()
    }

    /// Resets the root `SubCommData` and returns it.
    ///
    /// Do not use this method while an instrumented `target = seec_metrics` span is active,
    /// as this will result in inconsistent data.
    pub fn reset(&self) -> SubCommData {
        let mut comm_data = self.comm_data.lock().expect("lock poisoned");
        mem::take(&mut *comm_data)
    }
}

impl<S> Layer<S> for CommLayerData
where
    S: tracing::Subscriber,
    S: for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Id is valid");
        let mut visitor = PhaseVisitor(None);
        attrs.record(&mut visitor);
        if let Some(phase) = visitor.0 {
            let data = CommData::new(phase);
            span.extensions_mut().insert(data);
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.event_span(event) else {
            warn!(
                "Received seec_metrics event outside of seec_metrics span. \
                Communication is not tracked"
            );
            return;
        };
        // Check that we only have one field per event, otherwise the CommEventVisitor will
        // only record on of them
        let field_cnt = event
            .fields()
            .filter(|field| field.name() == "bytes_read" || field.name() == "bytes_written")
            .count();
        if field_cnt >= 2 {
            warn!("Use individual events to record bytes_read and bytes_written");
            return;
        }
        let mut vis = CommEventVisitor(None);
        event.record(&mut vis);
        if let Some(event) = vis.0 {
            let mut extensions = span.extensions_mut();
            let Some(comm_data) = extensions.get_mut::<CommData>() else {
                warn!(
                    "Received seec_metrics event inside seec_metrics span with no phase. \
                    Communication is not tracked"
                );
                return;
            };
            match event {
                CommEvent::Read(read) => {
                    comm_data.read += read;
                }
                CommEvent::Write(written) => {
                    comm_data.write += written;
                }
            }
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("Id is valid");
        let mut extensions = span.extensions_mut();
        let Some(comm_data) = extensions.get_mut::<CommData>().map(mem::take) else {
            // nothing to do
            return;
        };

        if let Some(parent) = span.parent() {
            if let Some(parent_comm_data) = parent.extensions_mut().get_mut::<CommData>() {
                let entry = parent_comm_data
                    .sub_comm_data
                    .0
                    .entry(comm_data.phase.clone())
                    .or_insert_with(|| CommData::new(comm_data.phase.clone()));
                parent_comm_data.read.bytes_with_sub_comm += comm_data.read.bytes_with_sub_comm;
                parent_comm_data.write.bytes_with_sub_comm += comm_data.write.bytes_with_sub_comm;
                merge(comm_data, entry)
            }
        } else {
            let mut root_comm_data = self.comm_data.lock().expect("lock poisoned");
            let phase_comm_data = root_comm_data
                .0
                .entry(comm_data.phase.clone())
                .or_insert_with(|| CommData::new(comm_data.phase.clone()));
            merge(comm_data, phase_comm_data);
        }
    }
}

fn merge(from: CommData, into: &mut CommData) {
    into.read += from.read;
    into.write += from.write;
    for (phase, from_sub_comm) in from.sub_comm_data.0.into_iter() {
        match into.sub_comm_data.0.entry(phase) {
            Entry::Vacant(entry) => {
                entry.insert(from_sub_comm);
            }
            Entry::Occupied(mut entry) => {
                merge(from_sub_comm, entry.get_mut());
            }
        }
    }
}

impl SubCommData {
    /// Get the [`CommData`] for a phase.
    pub fn get(&self, phase: &str) -> Option<&CommData> {
        self.0.get(phase)
    }

    /// Iterate over all [`CommData`].
    pub fn iter(&self) -> impl Iterator<Item = &CommData> {
        self.0.values()
    }
}

impl AddAssign for Counter {
    fn add_assign(&mut self, rhs: Self) {
        self.bytes += dbg!(rhs.bytes);
        self.bytes_with_sub_comm += dbg!(rhs.bytes_with_sub_comm);
    }
}

impl AddAssign<u64> for Counter {
    fn add_assign(&mut self, rhs: u64) {
        self.bytes += rhs;
        self.bytes_with_sub_comm += rhs;
    }
}

impl CommData {
    fn new(phase: String) -> Self {
        Self {
            phase,
            ..Default::default()
        }
    }
}

struct PhaseVisitor(Option<String>);

impl Visit for PhaseVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "phase" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "phase" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

enum CommEvent {
    Read(u64),
    Write(u64),
}

struct CommEventVisitor(Option<CommEvent>);

impl CommEventVisitor {
    fn record<T>(&mut self, field: &Field, value: T)
    where
        T: TryInto<u64>,
        T::Error: Debug,
    {
        let name = dbg!(field.name());
        if name != "bytes_written" && name != "bytes_read" {
            return;
        }
        let value = value
            .try_into()
            .expect("recorded bytes must be convertible to u64");
        if name == "bytes_written" {
            self.0 = Some(CommEvent::Write(value))
        } else if name == "bytes_read" {
            self.0 = Some(CommEvent::Read(value))
        }
    }
}

impl Visit for CommEventVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field, value);
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field, value)
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record(field, value)
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record(field, value)
    }
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        warn!(
            "seec_metrics event with field which is not an integer. {}: {:?}",
            field.name(),
            value
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::sleep;
    use tokio::{self, join};
    use tracing::{event, instrument, Instrument, Level};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    use crate::metrics::new_comm_layer;

    #[tokio::test]
    async fn test_communication_metrics() {
        #[instrument(target = "seec_metrics", fields(phase = "TopLevel"))]
        async fn top_level_operation() {
            // Simulate some direct communication
            event!(target: "seec_metrics", Level::TRACE, bytes_read = 100);
            event!(target: "seec_metrics", Level::TRACE, bytes_written = 200);

            // Call sub-operation
            sub_operation().await;
        }

        #[instrument(target = "seec_metrics", fields(phase = "SubOperation"))]
        async fn sub_operation() {
            // Simulate some communication in the sub-operation
            event!(target: "seec_metrics", Level::TRACE, bytes_read = 50);
            event!(target: "seec_metrics", Level::TRACE, bytes_written = 100);
        }

        // Set up the metrics layer
        let (comm_layer, comm_data) = new_comm_layer();
        let subscriber = Registry::default().with(comm_layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Run instrumented functions
        top_level_operation().await;

        // Verify metrics
        let metrics = comm_data.comm_data();

        // Check top level metrics
        let top_phase = metrics
            .get("TopLevel")
            .expect("TopLevel phase should exist");
        assert_eq!(top_phase.phase, "TopLevel");
        assert_eq!(top_phase.read.bytes, 100);
        assert_eq!(top_phase.write.bytes, 200);
        assert_eq!(top_phase.read.bytes_with_sub_comm, 150); // 100 (direct) + 50 (from sub)
        assert_eq!(top_phase.write.bytes_with_sub_comm, 300); // 200 (direct) + 100 (from sub)

        // Check sub-phase metrics
        let sub_phase = top_phase
            .sub_comm_data
            .get("SubOperation")
            .expect("SubOperation phase should exist");
        assert_eq!(sub_phase.phase, "SubOperation");
        assert_eq!(sub_phase.read.bytes, 50);
        assert_eq!(sub_phase.write.bytes, 100);
        assert_eq!(sub_phase.read.bytes_with_sub_comm, 50);
        assert_eq!(sub_phase.write.bytes_with_sub_comm, 100);

        // Reset metrics and verify they're cleared
        let reset_metrics = comm_data.reset();
        assert!(reset_metrics.get("TopLevel").is_some());
        let new_metrics = comm_data.comm_data();
        assert!(new_metrics.get("TopLevel").is_none());
    }

    #[tokio::test]
    async fn test_parallel_span_accumulation() {
        #[instrument(target = "seec_metrics", fields(phase = "ParentPhase"))]
        async fn parallel_operation(id: u32) {
            // If communication of a sub-phase happens in a spawned task, the future needs
            // to be instrumented with the current span to preserve hierarchy
            tokio::spawn(sub_operation(id).in_current_span()).await.unwrap();
        }

        #[instrument(target = "seec_metrics", fields(phase = "SubPhase"))]
        async fn sub_operation(id: u32) {
            // Each sub-operation does some communication
            event!(
                target: "seec_metrics",
                Level::TRACE,
                bytes_written = 100,
            );
            event!(
                target: "seec_metrics",
                Level::TRACE,
                bytes_read = 50
            );
            // Simulate some work to increase chance of overlap
            sleep(Duration::from_millis(10)).await;
        }

        // Set up the metrics layer
        let (comm_layer, comm_data) = new_comm_layer();
        let subscriber = Registry::default().with(comm_layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Run parallel operations
        join!(parallel_operation(1), parallel_operation(2));

        // Verify metrics
        let metrics = comm_data.comm_data();
        let phase = metrics
            .get("ParentPhase")
            .expect("ParentPhase should exist");

        // The sub-phase metrics should accumulate from both parallel operations
        let sub_phase = phase
            .sub_comm_data
            .get("SubPhase")
            .expect("SubPhase should exist");

        // Each parallel operation writes 100 bytes in the sub-phase
        // So we expect 200 total bytes written in the sub-phase
        assert_eq!(
            sub_phase.write.bytes, 200,
            "Expected accumulated writes from both parallel operations"
        );

        // Each parallel operation reads 50 bytes in the sub-phase
        // So we expect 100 total bytes read in the sub-phase
        assert_eq!(
            sub_phase.read.bytes, 100,
            "Expected accumulated reads from both parallel operations"
        );

        // Parent phase should accumulate all sub-phase metrics
        assert_eq!(
            phase.write.bytes_with_sub_comm, 200,
            "Parent should include all sub-phase writes"
        );
        assert_eq!(
            phase.read.bytes_with_sub_comm, 100,
            "Parent should include all sub-phase reads"
        );
    }
}