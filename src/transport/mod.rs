pub mod quic;
pub mod tcp;

use std::net::SocketAddr;
use std::ops::Deref;

#[derive(Debug, Clone, Copy)]
pub struct ConnectAddr(pub SocketAddr);

impl Deref for ConnectAddr {
    type Target = SocketAddr;
    fn deref(&self) -> &Self::Target {
        return &self.0;
    }
}
