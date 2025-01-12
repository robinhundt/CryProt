use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Context;
use s2n_quic::{client::Connect, provider::limits::Limits, Client, Server};
use tokio::join;

use crate::Connection;

/// NOTE: this certificate is to be used for demonstration purposes only!
static CERT_PEM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/cert.pem"));
/// NOTE: this certificate is to be used for demonstration purposes only!
static KEY_PEM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/key.pem"));

#[tracing::instrument]
pub async fn local_conn() -> anyhow::Result<(Connection, Connection)> {
    // TODO sensible send buffer sizes and limits
    const MiB: usize = 1024 * 1024;
    let max_streams = 1 << 59;
    let limits = Limits::new()
        .with_max_send_buffer_size(300 * MiB as u32)?
        .with_max_open_local_unidirectional_streams(max_streams)?
        .with_max_open_remote_unidirectional_streams(max_streams)?;

    let addr = "127.0.0.1:0".parse()?;
    let io = || {
        s2n_quic::provider::io::Default::builder()
            .with_receive_address(addr)?
            .with_max_mtu(9000)?
            .with_recv_buffer_size(200 * MiB)?
            .with_send_buffer_size(200 * MiB)?
            .with_internal_recv_buffer_size(200 * MiB)?
            .with_internal_send_buffer_size(200 * MiB)?
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
