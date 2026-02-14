pub mod connection;
pub mod dest;
pub mod frame;
pub mod handshake;
pub mod resilience;
pub mod source;

pub use connection::{ConnectionError, ConnectionManager, ConnectionState};
pub use dest::DestContainer;
pub use frame::{Frame, FrameCodec, FrameError, FrameType, Protocol, WireFrame, PROTOCOL_VERSION};
pub use handshake::{HandshakeContext, HandshakeError};
// Re-export resilience types for use in tests and external modules
#[allow(unused_imports)]
pub use resilience::{CircuitBreaker, DemuxWatchdog, TunnelMetrics};
pub use source::SourceContainer;
