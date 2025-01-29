use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Context;
use s2n_quic::{client::Connect, provider::limits::Limits, Client, Server};
use tokio::join;

use crate::{
    metrics::{new_comm_layer, CommLayerData},
    Connection,
};

/// NOTE: this certificate is to be used for demonstration purposes only!
static CERT_PEM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/cert.pem"));
/// NOTE: this certificate is to be used for demonstration purposes only!
static KEY_PEM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/key.pem"));

#[tracing::instrument]
pub async fn local_conn() -> anyhow::Result<(Connection, Connection)> {
    // TODO sensible send buffer sizes and limits
    #[allow(non_upper_case_globals)]
    const MiB: usize = 1024 * 1024;
    let max_streams = 1 << 59;
    let limits = Limits::new()
        .with_max_send_buffer_size(12 * MiB as u32)?
        .with_max_open_local_unidirectional_streams(max_streams)?
        .with_max_open_remote_unidirectional_streams(max_streams)?;

    let addr = "127.0.0.1:0".parse()?;
    let io = || {
        s2n_quic::provider::io::Default::builder()
            .with_receive_address(addr)?
            .with_max_mtu(9000)?
            .build()
    };

    let mut server: Server = Server::builder()
        .with_tls((CERT_PEM, KEY_PEM))?
        .with_io(io()?)?
        .with_limits(limits)?
        .start()?;
    let server_port = server.local_addr()?.port();
    let client = Client::builder()
        .with_tls(CERT_PEM)?
        .with_io(io()?)?
        .with_limits(limits)?
        .start()?;

    let addr: SocketAddr = (Ipv4Addr::LOCALHOST, server_port).into();
    let connect = Connect::new(addr).with_server_name("localhost");
    let (server_conn, client_conn) = join!(server.accept(), client.connect(connect));
    let server_conn = server_conn.context("server_conn")?;
    let client_conn = client_conn?;

    let (server_conn, stream_manager) = Connection::new(server_conn);
    tokio::spawn(stream_manager.start());
    let (client_conn, stream_manager) = Connection::new(client_conn);
    tokio::spawn(stream_manager.start());
    Ok((server_conn, client_conn))
}

use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    EnvFilter, Layer, Registry,
};

pub struct TestCommLayerDataGuard(pub CommLayerData);

impl Drop for TestCommLayerDataGuard {
    fn drop(&mut self) {
        let comm_data = self.0.comm_data();
        tracing::info!(?comm_data);
    }
}

/// Initializes tracing subscriber with EnvFilter for usage in tests. This
/// should be the first call in each test, with the returned value being
/// assigned to a variable to prevent dropping. Output can be configured via
/// RUST_LOG env variable as explained [here](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/struct.EnvFilter.html).
///
/// When the [`TestCommLayerDataGuard`] is dropped, it logs the metrics data
/// with `Level::INFO`.
///
/// ```ignore
/// use seec::private_test_utils::init_tracing;
/// fn some_test() {
///     let _guards = init_tracing();
/// }
/// ```
pub fn init_tracing() -> (TestCommLayerDataGuard, tracing::dispatcher::DefaultGuard) {
    let fmt_layer = fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_test_writer()
        .with_filter(EnvFilter::from_default_env()); // Use the environment filter here

    let (comm_layer, comm_data) = new_comm_layer();
    let subscriber = Registry::default()
        .with(fmt_layer) // Layer terminal logging
        .with(comm_layer); // Layer your custom comm_layer

    // order of returns is important, wrapped comm_data needs to be dropped before
    // tracing guard to actually log comm data
    (
        TestCommLayerDataGuard(comm_data),
        tracing::subscriber::set_default(subscriber),
    )
}

pub fn init_bench_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();
}
