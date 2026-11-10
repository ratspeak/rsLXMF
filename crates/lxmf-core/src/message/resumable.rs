//! Durable form of a signed message that has not finished delivery.
use super::*;

/// The signed header (destination, source, signature) ends here, and an LXMF
/// payload would begin.
const HEADER_LEN: usize = 96;
/// `0xC1` is never valid MessagePack, so no LXMF parser reads a stored form as
/// a message.
const MAGIC: [u8; 4] = [0xc1, b'L', b'X', b'R'];
const VERSION: u8 = 2;
/// Version 1 stored an integer floor; it is still read.
const VERSION_INTEGER_FLOOR: u8 = 1;
const DIGEST_LEN: usize = 16;
const FLOOR_AT: usize = HEADER_LEN + MAGIC.len() + 1;
const STAMP_AT: usize = FLOOR_AT + 2;

/// A signed, unstamped message stored so delivery can resume after a restart.
///
/// Version 2 holds, in order:
/// - the signed header: destination, source and signature (96 bytes);
/// - the bytes `0xC1`, `L`, `X`, `R`, then the version byte;
/// - the stamp cost the message was signed under, as a big-endian fixed-point
///   cost on the 1/256 grid, 0 meaning none (version 1 held a presence byte
///   and an integer cost);
/// - reserved slots for a finished recipient stamp (a length byte of 0, 16
///   or 32, then the stamp) and a propagation envelope (a big-endian `u32`
///   length, then the envelope). Both are written empty, and a reader of
///   this version ignores filled slots and redoes that work;
/// - the signed payload;
/// - the first 16 bytes of the SHA-256 of everything before them.
///
/// It is not a wire message: [`LxMessage::unpack`] rejects it, because byte
/// 96 is `0xC1`. Restore it with
/// [`LxmRouter::restore_signed`](crate::router::LxmRouter::restore_signed).
#[derive(Clone, PartialEq, Eq)]
pub struct ResumableLxMessage {
    bytes: Bytes,
    stamp_cost_floor: Option<u16>,
    payload_at: usize,
}

impl std::fmt::Debug for ResumableLxMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumableLxMessage")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl ResumableLxMessage {
    pub(super) fn new(wire: &[u8], stamp_cost: Option<f64>) -> Self {
        let floor_fp = stamp_cost
            .and_then(|cost| crate::stamper::cost_to_fp(cost).ok())
            .unwrap_or(0);
        let stamp_cost = (floor_fp > 0).then_some(floor_fp);
        let mut bytes = Vec::with_capacity(wire.len() + STAMP_AT + 5 + DIGEST_LEN);
        bytes.extend_from_slice(&wire[..HEADER_LEN]);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&floor_fp.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        let payload_at = bytes.len();
        bytes.extend_from_slice(&wire[HEADER_LEN..]);
        let digest = sha256(&bytes);
        bytes.extend_from_slice(&digest[..DIGEST_LEN]);
        Self {
            bytes: bytes.into(),
            stamp_cost_floor: stamp_cost,
            payload_at,
        }
    }

    /// Check a stored form's structure and digest. The signature is checked
    /// when the message is restored, against the sender's key.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Result<Self, MessageError> {
        let bytes = bytes.into();
        let invalid =
            |reason: &str| MessageError::UnpackFailed(format!("resumable message: {reason}"));
        if bytes.len() < STAMP_AT + 5 + 1 + DIGEST_LEN {
            return Err(invalid("too short"));
        }
        if bytes[HEADER_LEN..HEADER_LEN + MAGIC.len()] != MAGIC {
            return Err(invalid("not a stored message"));
        }
        let version = bytes[HEADER_LEN + MAGIC.len()];
        if version != VERSION && version != VERSION_INTEGER_FLOOR {
            return Err(invalid("unsupported version"));
        }
        let digest_at = bytes.len() - DIGEST_LEN;
        if sha256(&bytes[..digest_at])[..DIGEST_LEN] != bytes[digest_at..] {
            return Err(invalid("damaged"));
        }
        let floor = [bytes[FLOOR_AT], bytes[FLOOR_AT + 1]];
        let stamp_cost_floor = match (version, floor) {
            (_, [0, 0]) => None,
            (VERSION_INTEGER_FLOOR, [1, cost]) => Some(u16::from(cost.min(100)) * 256),
            (VERSION, _) if u16::from_be_bytes(floor) <= crate::stamper::STAMP_COST_CAP_FP => {
                Some(u16::from_be_bytes(floor))
            }
            _ => return Err(invalid("invalid stamp cost")),
        };
        let stamp_len = usize::from(bytes[STAMP_AT]);
        if !matches!(stamp_len, 0 | 16 | 32) {
            return Err(invalid("invalid recipient stamp"));
        }
        let envelope_len_at = STAMP_AT + 1 + stamp_len;
        let envelope_len = bytes
            .get(envelope_len_at..envelope_len_at + 4)
            .map(|len| u32::from_be_bytes(len.try_into().expect("four bytes")) as usize)
            .ok_or_else(|| invalid("truncated"))?;
        let payload_at = (envelope_len_at + 4)
            .checked_add(envelope_len)
            .filter(|at| *at < digest_at)
            .ok_or_else(|| invalid("truncated"))?;
        if bytes[payload_at] != 0x94 {
            return Err(invalid("payload is not a signed, unstamped body"));
        }
        Ok(Self {
            bytes,
            stamp_cost_floor,
            payload_at,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn stamp_cost_floor(&self) -> Option<f64> {
        self.stamp_cost_floor
            .map(|fp| crate::stamper::cost_from_fp(u32::from(fp)))
    }

    /// The signed, unstamped message. Its signature is not yet checked.
    pub(crate) fn unverified_message(&self) -> Result<LxMessage, MessageError> {
        let digest_at = self.bytes.len() - DIGEST_LEN;
        let mut wire = Vec::with_capacity(HEADER_LEN + digest_at - self.payload_at);
        wire.extend_from_slice(&self.bytes[..HEADER_LEN]);
        wire.extend_from_slice(&self.bytes[self.payload_at..digest_at]);
        LxMessage::unpack_owned(wire.into(), MessageDecodeLimits::default())
    }
}
