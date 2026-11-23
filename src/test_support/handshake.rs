// Socketless TLS handshakes over real rustls configs: shows exactly what a live listener would serve or accept.

use std::sync::Arc;

use rcgen::{CertifiedKey, KeyPair};
use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
	ClientConfig, ClientConnection, ConnectionCommon, Error as TlsError, HandshakeKind, RootCertStore, ServerConfig,
	ServerConnection,
};
use core_utils::ctx::Ctx;

// A TLS 1.3 handshake settles in a few flights. The cap only stops a wedged pair from an endless loop.
const HANDSHAKE_MAX_FLIGHTS: u32 = 16;

// Which side of a rotation a handshake observed, so swap-off and swap-on runs compare directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
	Old,
	New,
}

// The store trusts exactly one CA at a time. Both or neither means a broken store, not a rotation.
pub fn trust_epoch(old_accepted: bool, new_accepted: bool) -> Observed {
	assert_ne!(
		old_accepted, new_accepted,
		"exactly one CA must be trusted (old={old_accepted}, new={new_accepted})"
	);
	return if new_accepted { Observed::New } else { Observed::Old };
}

// The served leaf must be exactly one of the two. Anything else means the handshake hit a third cert.
pub fn served_epoch(
	served: &CertificateDer<'static>,
	old_leaf: &CertifiedKey<KeyPair>,
	new_leaf: &CertifiedKey<KeyPair>,
) -> Observed {
	let is_old: bool = served == old_leaf.cert.der();
	let is_new: bool = served == new_leaf.cert.der();
	assert!(is_old != is_new, "served cert must be exactly one of the two leaves");
	return if is_new { Observed::New } else { Observed::Old };
}

pub fn pkcs8(key: &KeyPair) -> PrivateKeyDer<'static> {
	return PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
}

pub fn roots_of(ca: &CertifiedKey<KeyPair>) -> Result<RootCertStore, String> {
	let mut roots: RootCertStore = RootCertStore::empty();
	roots.add(CertificateDer::from(ca.cert.der().as_ref())).ctx("roots.add(ca cert)")?;
	return Ok(roots);
}

// Resumption off: a resumed session skips cert verification and replays the old chain. That hides a swap.
pub fn no_resumption(mut config: ClientConfig) -> Arc<ClientConfig> {
	config.resumption = Resumption::disabled();
	return Arc::new(config);
}

// Server that presents `leaf`, no client auth. Takes the leaf so its DER moves into the config.
pub fn serving(leaf: CertifiedKey<KeyPair>) -> Result<Arc<ServerConfig>, String> {
	let config: ServerConfig = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![CertificateDer::from(leaf.cert)], pkcs8(&leaf.signing_key))
	.map_err(|err| format!("ServerConfig::builder().with_no_client_auth().wi...: {err:?}"))?;
	return Ok(Arc::new(config));
}

// Client that trusts `server_ca` and presents no client cert.
pub fn trusting(server_ca: &CertifiedKey<KeyPair>) -> Result<Arc<ClientConfig>, String> {
	return Ok(no_resumption(
		ClientConfig::builder()
			.with_root_certificates(roots_of(server_ca)?)
			.with_no_client_auth(),
	));
}

// Client that trusts `server_ca` and presents `leaf` as its client cert. The leaf's DER moves into the config.
pub fn presenting(
	server_ca: &CertifiedKey<KeyPair>,
	leaf: CertifiedKey<KeyPair>,
) -> Result<Arc<ClientConfig>, String> {
	return Ok(no_resumption(
		ClientConfig::builder()
			.with_root_certificates(roots_of(server_ca)?)
			.with_client_auth_cert(vec![CertificateDer::from(leaf.cert)], pkcs8(&leaf.signing_key))
		.map_err(|err| format!("ClientConfig::builder().with_root_certificates(r...: {err:?}"))?,
	));
}

// Moves every queued record from one in-memory endpoint to the other and lets the receiver process it.
// Outer Err: the in-memory harness broke. Inner Err: TLS refused the flight.
fn flight<A, B>(from: &mut ConnectionCommon<A>, to: &mut ConnectionCommon<B>) -> Result<Result<(), TlsError>, String> {
	let mut wire: Vec<u8> = Vec::new();
	while from.wants_write() {
		from.write_tls(&mut wire).ctx("from.write_tls(&mut wire)")?;
	}
	let mut rd: &[u8] = &wire;
	while !rd.is_empty() {
		to.read_tls(&mut rd).ctx("to.read_tls(&mut rd)")?;
		match to.process_new_packets() {
			Ok(_) => {}
			Err(err) => return Ok(Err(err)),
		}
	}
	return Ok(Ok(()));
}

// Both ends of one in-memory connection after its handshake.
struct Settled {
	client: ClientConnection,
	server: ServerConnection,
}

// Runs the handshake to its end. Outer Err: the in-memory harness broke, which is never a TLS verdict.
fn settle(server: Arc<ServerConfig>, client: Arc<ClientConfig>) -> Result<Result<Settled, TlsError>, String> {
	let name: ServerName<'static> = ServerName::try_from("localhost")
		.map_err(|err| format!("ServerName::try_from(\"localhost\"): {err:?}"))?;
	let mut client_conn: ClientConnection = match ClientConnection::new(client, name) {
		Ok(value) => value,
		Err(err) => return Ok(Err(err)),
	};
	let mut server_conn: ServerConnection = match ServerConnection::new(server) {
		Ok(value) => value,
		Err(err) => return Ok(Err(err)),
	};
	for _ in 0..HANDSHAKE_MAX_FLIGHTS {
		if !client_conn.is_handshaking() && !server_conn.is_handshaking() {
			return Ok(Ok(Settled { client: client_conn, server: server_conn }));
		}
		if let Err(err) = flight(&mut *client_conn, &mut *server_conn)? {
			return Ok(Err(err));
		}
		if let Err(err) = flight(&mut *server_conn, &mut *client_conn)? {
			return Ok(Err(err));
		}
	}
	return Ok(Err(TlsError::General(format!(
		"handshake did not settle within {HANDSHAKE_MAX_FLIGHTS} flights"
	))));
}

// Fresh in-memory handshake through rustls's own configs. Returns the served leaf or the first rejection.
pub fn handshake(
	server: Arc<ServerConfig>,
	client: Arc<ClientConfig>,
) -> Result<Result<CertificateDer<'static>, TlsError>, String> {
	let settled: Settled = match settle(server, client)? {
		Ok(settled) => settled,
		Err(err) => return Ok(Err(err)),
	};
	return Ok(settled
		.client
		.peer_certificates()
		.and_then(|chain| chain.first())
		.cloned()
		.ok_or(TlsError::NoCertificatesPresented));
}

// A handshake that then gives the server's session tickets to the client, so the next one can resume.
// Returns if this handshake was full or resumed, or the first rejection.
pub fn resumable_handshake(
	server: Arc<ServerConfig>,
	client: Arc<ClientConfig>,
) -> Result<Result<HandshakeKind, TlsError>, String> {
	let mut settled: Settled = match settle(server, client)? {
		Ok(settled) => settled,
		Err(err) => return Ok(Err(err)),
	};
	if let Err(err) = flight(&mut *settled.server, &mut *settled.client)? {
		return Ok(Err(err));
	}
	return Ok(settled.client.handshake_kind().ok_or(TlsError::HandshakeNotComplete));
}
