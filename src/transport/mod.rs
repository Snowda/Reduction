pub mod quic;
pub mod tcp;

#[derive(Debug, Clone, Copy)]
pub struct ConnectAddr(pub std::net::SocketAddr);

impl std::ops::Deref for ConnectAddr {
    type Target = std::net::SocketAddr;
    fn deref(&self) -> &Self::Target {
        return &self.0;
    }
}
