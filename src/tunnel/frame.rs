use crate::crypto::SessionCrypto;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

// Constants
pub const PROTOCOL_VERSION: u8 = 1;
pub const FRAME_HEADER_SIZE: usize = 13; // version(1) + type(1) + flags(1) + seq(4) + conn_id(4) + len(2)
pub const MAX_PAYLOAD_SIZE: usize = 65535;
pub const MAC_SIZE: usize = 16;
pub const MIN_FRAME_SIZE: usize = FRAME_HEADER_SIZE + MAC_SIZE;
pub const MAX_FRAME_SIZE: usize = FRAME_HEADER_SIZE + MAX_PAYLOAD_SIZE + MAC_SIZE;

// Protocol enum for TCP/UDP differentiation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 0x01,
    Udp = 0x02,
}

impl Protocol {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Protocol::Tcp),
            0x02 => Some(Protocol::Udp),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

// Frame Type Enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x01,
    Control = 0x02,
    KeyRotation = 0x03,
    Ack = 0x04,
    Ping = 0x05,
    Pong = 0x06,
    Close = 0x07,
    Handshake = 0x08,
    HandshakeAck = 0x09,
    Connect = 0x0A,
    ConnectAck = 0x0B,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(FrameType::Data),
            0x02 => Some(FrameType::Control),
            0x03 => Some(FrameType::KeyRotation),
            0x04 => Some(FrameType::Ack),
            0x05 => Some(FrameType::Ping),
            0x06 => Some(FrameType::Pong),
            0x07 => Some(FrameType::Close),
            0x08 => Some(FrameType::Handshake),
            0x09 => Some(FrameType::HandshakeAck),
            0x0A => Some(FrameType::Connect),
            0x0B => Some(FrameType::ConnectAck),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

// Frame Flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const FIN: Self = Self(0x01); // End of stream
    pub const RST: Self = Self(0x02); // Reset connection
    pub const ACK: Self = Self(0x04); // Acknowledge requested
    pub const COMPRESS: Self = Self(0x08); // Payload is compressed
    pub const PRIORITY: Self = Self(0x10); // High priority frame
    pub const UDP: Self = Self(0x20); // UDP traffic (vs TCP)

    pub fn new() -> Self {
        Self(0)
    }

    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    pub fn has(&self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    pub fn bits(&self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

// Frame Struct
#[derive(Debug, Clone)]
pub struct Frame {
    version: u8,
    frame_type: FrameType,
    flags: FrameFlags,
    sequence: u32,
    connection_id: u32,
    length: u16,
    payload: Vec<u8>,
}

impl Frame {
    // Constructors
    pub fn new_data(connection_id: u32, sequence: u32, payload: &[u8]) -> Result<Self, FrameError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        Ok(Self {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::Data,
            flags: FrameFlags::new(),
            sequence,
            connection_id,
            length: payload.len() as u16,
            payload: payload.to_vec(),
        })
    }

    pub fn new_control(frame_type: FrameType, sequence: u32, payload: &[u8]) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            frame_type,
            flags: FrameFlags::new(),
            sequence,
            connection_id: 0, // Control frames don't have connection ID
            length: payload.len() as u16,
            payload: payload.to_vec(),
        }
    }

    pub fn new_ping(sequence: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::Ping,
            flags: FrameFlags::new(),
            sequence,
            connection_id: 0,
            length: 0,
            payload: Vec::new(),
        }
    }

    pub fn new_pong(sequence: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::Pong,
            flags: FrameFlags::new(),
            sequence,
            connection_id: 0,
            length: 0,
            payload: Vec::new(),
        }
    }

    pub fn new_close(sequence: u32, reason: &str) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::Close,
            flags: FrameFlags::new(),
            sequence,
            connection_id: 0,
            length: reason.len() as u16,
            payload: reason.as_bytes().to_vec(),
        }
    }

    pub fn new_connect(connection_id: u32, service_port: u16, protocol: Protocol) -> Self {
        // Payload format: [port(2 bytes)][protocol(1 byte)]
        let mut payload = Vec::with_capacity(3);
        payload.extend_from_slice(&service_port.to_be_bytes());
        payload.push(protocol.as_u8());

        Self {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::Connect,
            flags: FrameFlags::new(),
            sequence: 0,
            connection_id,
            length: 3,
            payload,
        }
    }

    pub fn new_connect_ack(connection_id: u32, success: bool) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::ConnectAck,
            flags: FrameFlags::new(),
            sequence: 0,
            connection_id,
            length: 1,
            payload: vec![if success { 1 } else { 0 }],
        }
    }

    // Accessors
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn is_fin(&self) -> bool {
        self.flags.has(FrameFlags::FIN)
    }

    pub fn is_rst(&self) -> bool {
        self.flags.has(FrameFlags::RST)
    }

    pub fn is_udp(&self) -> bool {
        self.flags.has(FrameFlags::UDP)
    }

    pub fn flags(&self) -> FrameFlags {
        self.flags
    }

    // Flag setters
    pub fn set_fin(&mut self) {
        self.flags.set(FrameFlags::FIN);
    }

    pub fn set_rst(&mut self) {
        self.flags.set(FrameFlags::RST);
    }

    pub fn set_udp(&mut self) {
        self.flags.set(FrameFlags::UDP);
    }

    pub fn set_flag(&mut self, flag: FrameFlags) {
        self.flags.set(flag);
    }

    // Serialization (before encryption)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());

        // Header: version(1) + type(1) + flags(1) + seq(4) + conn_id(4) + len(2)
        bytes.push(self.version);
        bytes.push(self.frame_type.as_u8());
        bytes.push(self.flags.bits());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.connection_id.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(FrameError::TooShort {
                need: FRAME_HEADER_SIZE,
                got: data.len(),
            });
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(FrameError::InvalidVersion(version));
        }

        let frame_type = FrameType::from_u8(data[1]).ok_or(FrameError::InvalidType(data[1]))?;

        let flags = FrameFlags::from_bits(data[2]);

        let sequence = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        let connection_id = u32::from_be_bytes([data[7], data[8], data[9], data[10]]);
        let length = u16::from_be_bytes([data[11], data[12]]);

        // CRITICAL: Validate length before conversion to prevent integer overflow
        if length as usize > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge {
                size: length as usize,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let payload_start = FRAME_HEADER_SIZE;
        let payload_end = payload_start
            .checked_add(length as usize)
            .ok_or(FrameError::IntegerOverflow)?;

        if data.len() < payload_end {
            return Err(FrameError::TooShort {
                need: payload_end,
                got: data.len(),
            });
        }

        let payload = data[payload_start..payload_end].to_vec();

        Ok(Self {
            version,
            frame_type,
            flags,
            sequence,
            connection_id,
            length,
            payload,
        })
    }
}

// WireFrame Struct
#[derive(Debug, Clone)]
pub struct WireFrame {
    data: Vec<u8>,
}

impl WireFrame {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

// Frame Codec
pub struct FrameCodec {
    session_crypto: Arc<SessionCrypto>,
}

impl FrameCodec {
    pub fn new(session_crypto: Arc<SessionCrypto>) -> Self {
        Self { session_crypto }
    }

    /// Encode a frame for transmission (encrypt)
    pub fn encode(&self, frame: &Frame) -> Result<WireFrame, FrameError> {
        let plaintext = frame.to_bytes();

        let encrypted_frame = self
            .session_crypto
            .encrypt_outbound(&plaintext)
            .map_err(|_| FrameError::EncryptionFailed)?;

        Ok(WireFrame::new(encrypted_frame.to_bytes()))
    }

    /// Decode a wire frame (decrypt)
    pub fn decode(&self, wire_frame: &WireFrame) -> Result<Frame, FrameError> {
        let encrypted_frame = crate::crypto::EncryptedFrame::from_bytes(wire_frame.as_bytes())
            .map_err(|_| FrameError::DecryptionFailed)?;

        let decrypted = self
            .session_crypto
            .decrypt_inbound(&encrypted_frame)
            .map_err(|_| FrameError::DecryptionFailed)?;

        Frame::from_bytes(&decrypted)
    }
}

// FrameError
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("Invalid frame version: {0}")]
    InvalidVersion(u8),

    #[error("Invalid frame type: {0}")]
    InvalidType(u8),

    #[error("Frame too short: need {need}, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("MAC verification failed")]
    MacFailed,

    #[error("Payload too large: {size} bytes (max: {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("Integer overflow in frame size calculation")]
    IntegerOverflow,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = Frame::new_data(1, 42, b"hello world").unwrap();
        let bytes = frame.to_bytes();
        let decoded = Frame::from_bytes(&bytes).unwrap();

        assert_eq!(frame.sequence(), decoded.sequence());
        assert_eq!(frame.connection_id(), decoded.connection_id());
        assert_eq!(frame.payload(), decoded.payload());
        assert_eq!(frame.frame_type(), decoded.frame_type());
    }

    #[test]
    fn test_frame_flags() {
        let mut flags = FrameFlags::new();
        assert!(!flags.has(FrameFlags::FIN));

        flags.set(FrameFlags::FIN);
        assert!(flags.has(FrameFlags::FIN));

        flags.set(FrameFlags::RST);
        assert!(flags.has(FrameFlags::FIN));
        assert!(flags.has(FrameFlags::RST));

        flags.clear(FrameFlags::FIN);
        assert!(!flags.has(FrameFlags::FIN));
        assert!(flags.has(FrameFlags::RST));
    }

    #[test]
    fn test_frame_type_conversion() {
        assert_eq!(FrameType::from_u8(0x01), Some(FrameType::Data));
        assert_eq!(FrameType::from_u8(0x05), Some(FrameType::Ping));
        assert_eq!(FrameType::from_u8(0x0A), Some(FrameType::Connect));
        assert_eq!(FrameType::from_u8(0xFF), None);
    }

    #[test]
    fn test_payload_too_large() {
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = Frame::new_data(1, 0, &large_payload);
        assert!(matches!(result, Err(FrameError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_ping_pong_frames() {
        let ping = Frame::new_ping(100);
        assert_eq!(ping.frame_type(), FrameType::Ping);
        assert_eq!(ping.sequence(), 100);
        assert_eq!(ping.payload().len(), 0);

        let pong = Frame::new_pong(101);
        assert_eq!(pong.frame_type(), FrameType::Pong);
        assert_eq!(pong.sequence(), 101);
    }

    #[test]
    fn test_connect_frame() {
        let connect = Frame::new_connect(42, 8080, Protocol::Tcp);
        assert_eq!(connect.frame_type(), FrameType::Connect);
        assert_eq!(connect.connection_id(), 42);
        assert_eq!(connect.payload().len(), 3);

        // Decode payload
        let port = u16::from_be_bytes([connect.payload()[0], connect.payload()[1]]);
        let protocol = Protocol::from_u8(connect.payload()[2]).unwrap();

        assert_eq!(port, 8080);
        assert_eq!(protocol, Protocol::Tcp);
    }
}
