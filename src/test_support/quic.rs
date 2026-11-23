// A live loopback QUIC connection under mutual TLS, shared by the tunnel and raw-relay tests. Its own tests
// live in `transport::quic`, since a test-only file holds no tests.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connecting, Connection, ConnectionError, Endpoint, ServerConfig};
use rcgen::SanType;
use tempfile::NamedTempFile;
use tokio::join;

use super::{LOOPBACK_ANY, LeafFiles, generate_ca, generate_signed_cert, leaf_files, write_pem};
use crate::tls::certs::{build_client_config, build_server_config};

/// Both ends of the connection. The endpoints stay alive with it, so the server-side Connection stays
/// usable (open_bi, close_reason); `client_conn` is the device side and `client_tls` its config.
pub struct QuicPair {
	pub server_conn: Connection,
	pub client_conn: Connection,
	pub client_tls: Arc<rustls::ClientConfig>,
	// The server leaf (SAN 127.0.0.1) under the same CA: serves a backend the client config trusts.
	pub server_tls: Arc<rustls::ServerConfig>,
	_server_ep: Endpoint,
	_client_ep: Endpoint,
}

// mTLS configs under a fresh CA: the server leaf (CN reduction-server) has SAN 127.0.0.1, the client
// leaf is CN "device-1".
pub fn mtls_configs() -> Result<(rustls::ServerConfig, rustls::ClientConfig), String> {
	let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	let ca = generate_ca()?;
	let server_sans: Vec<SanType> = vec![SanType::IpAddress(IpAddr::from([127, 0, 0, 1]))];
	let server: LeafFiles = generate_signed_cert(&ca, "reduction-server", server_sans).and_then(leaf_files)?;
	let client: LeafFiles = generate_signed_cert(&ca, "device-1", vec![]).and_then(leaf_files)?;
	let ca_file: NamedTempFile = write_pem(&ca.cert.pem())?;
	return build_server_config(server.cert.path(), server.key.path(), ca_file.path())
		.and_then(|(server_tls, _r1)| {
			let (client_tls, _r2, _v2) = build_client_config(client.cert.path(), client.key.path(), ca_file.path())?;
			return Ok((server_tls, client_tls));
		})
		.map_err(|err| format!("build mTLS configs: {err:?}"));
}

pub fn server_endpoint(server_tls: Arc<rustls::ServerConfig>) -> Result<(Endpoint, SocketAddr), String> {
	let quic_crypto = QuicServerConfig::try_from(server_tls)
		.map_err(|err| format!("QuicServerConfig::try_from: {err:?}"))?;
	return Endpoint::server(ServerConfig::with_crypto(Arc::new(quic_crypto)), LOOPBACK_ANY)
		.and_then(|server_ep: Endpoint| {
			let addr: SocketAddr = server_ep.local_addr()?;
			return Ok((server_ep, addr));
		})
		.map_err(|err| format!("bind the QUIC server endpoint: {err:?}"));
}

pub fn client_endpoint(client_tls: &Arc<rustls::ClientConfig>) -> Result<Endpoint, String> {
	let quic_client_crypto = QuicClientConfig::try_from(Arc::clone(client_tls))
		.map_err(|err| format!("QuicClientConfig::try_from: {err:?}"))?;
	let mut client_ep = Endpoint::client(LOOPBACK_ANY).map_err(|err| format!("Endpoint::client: {err:?}"))?;
	client_ep.set_default_client_config(ClientConfig::new(Arc::new(quic_client_crypto)));
	return Ok(client_ep);
}

// The next connection `endpoint` accepts, once its handshake completes.
pub async fn accept_one(endpoint: &Endpoint) -> Result<Connection, String> {
	let Some(incoming) = endpoint.accept().await else {
		return Err(String::from("endpoint closed before a connection arrived"));
	};
	return match incoming.await {
		Ok(conn) => Ok(conn),
		Err(err) => Err(format!("incoming.await: {err:?}")),
	};
}

/// Dial a loopback QUIC connection between a fresh mTLS server and client.
pub async fn mtls_quic_pair() -> Result<QuicPair, String> {
	let (server_tls, client_tls) = mtls_configs()?;
	let (server_tls, client_tls) = (Arc::new(server_tls), Arc::new(client_tls));
	let (server_ep, addr) = server_endpoint(Arc::clone(&server_tls))?;
	let client_ep: Endpoint = client_endpoint(&client_tls)?;
	let connecting: Connecting =
		client_ep.connect(addr, "127.0.0.1").map_err(|err| format!("client_ep.connect: {err:?}"))?;
	let (accepted, dialed): (Result<Connection, String>, Result<Connection, ConnectionError>) =
		join!(accept_one(&server_ep), connecting);
	let client_conn: Connection = dialed.map_err(|err| format!("client handshake: {err:?}"))?;
	let server_conn: Connection = accepted?;
	return Ok(QuicPair {
		server_conn,
		client_conn,
		client_tls,
		server_tls,
		_server_ep: server_ep,
		_client_ep: client_ep,
	});
}
