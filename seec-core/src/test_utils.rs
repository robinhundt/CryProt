use tracing_subscriber::{fmt::format::FmtSpan, util::SubscriberInitExt, EnvFilter};

/// Initializes tracing subscriber with EnvFilter for usage in tests. This
/// should be the first call in each test, with the returned value being
/// assigned to a variable to prevent dropping. Output can be configured via
/// RUST_LOG env variable as explained [here](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/struct.EnvFilter.html)
///
/// ```ignore
/// use seec::private_test_utils::init_tracing;
/// fn some_test() {
///     let _guard = init_tracing();
/// }
/// ```
pub fn init_tracing() -> tracing::dispatcher::DefaultGuard {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::ACTIVE | FmtSpan::CLOSE)
        .with_test_writer()
        .set_default()
}

pub fn init_bench_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::ACTIVE | FmtSpan::CLOSE)
        .init();
}
