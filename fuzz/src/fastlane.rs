//! Direct harnesses for fastlane's handwritten HTTP/1.1 wire parsers, each checked against hyper (src/oracle.rs).
//! The proxy_request and upstream_send targets enter after hyper has parsed, so they never reach this code.

pub mod chunked;
pub mod classify;
pub mod response;
