//! [`tracing_subscriber::Layer`] for structured communication metrics
//!
//! The [`CommLayer`] is a [`tracing_subscriber::Layer`] which records numbers of bytes read and
//! written. Metrics are collected by [`instrumenting`](`tracing::instrument`) spans with the
//! `seec_metrics` and a phase. From within these spans, events with the same target can be emitted
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
        if let Some(into_sub_comm) = into.sub_comm_data.0.get_mut(&phase) {
            merge(from_sub_comm, into_sub_comm);
        } else {
            into.sub_comm_data.0.insert(phase.clone(), from_sub_comm);
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
        self.bytes += rhs.bytes;
        self.bytes_with_sub_comm += rhs.bytes_with_sub_comm;
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
        let name = field.name();
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

    fn record_debug(&mut self, _field: &Field, _value: &dyn Debug) {}
}
