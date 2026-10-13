//! Immutable signed LXMF messages and checked outbound construction.
//!
//! Construct [`LxMessageDraft`], sign it, then finalize its recipient stamp.
//! Received and finalized messages retain one exact immutable wire image.
use crate::constants::*;
use crate::types::PropagationTransientId;
use bytes::Bytes;
use rns_crypto::sha::{full_hash, sha256, truncated_hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Write;
use std::ops::{Deref, DerefMut, Range};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
mod draft;
mod field;
pub use draft::{LxMessageDraft, SignedLxMessage};
use field::FieldIndex;
pub use field::{
    EncodedFieldValue, FieldId, FieldMapKey, FieldValue, FieldValueRef, Fields, UniqueFieldMap,
};

/// Lossy projection with a single exact-sized allocation. Standard UTF-8
/// replacement semantics are preserved, but geometric String growth cannot
/// exceed the processing lease's three-output-bytes-per-input-byte allowance.
fn bounded_lossy_text(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Cow::Borrowed(text);
    }
    let required = bytes
        .utf8_chunks()
        .map(|chunk| chunk.valid().len() + if chunk.invalid().is_empty() { 0 } else { 3 })
        .sum();
    let mut text = String::with_capacity(required);
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            text.push('\u{fffd}');
        }
    }
    debug_assert_eq!(text.len(), required);
    Cow::Owned(text)
}

pub type MessageCallback = Arc<dyn Fn(&LxMessage) + Send + Sync>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioField<'a> {
    pub mode: u8,
    pub bytes: &'a [u8],
}
#[derive(Clone, Default)]
pub struct MessageCallbacks {
    pub on_delivered: Option<MessageCallback>,
    pub on_failed: Option<MessageCallback>,
}
impl std::fmt::Debug for MessageCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageCallbacks")
            .field("on_delivered", &self.on_delivered.is_some())
            .field("on_failed", &self.on_failed.is_some())
            .finish()
    }
}
/// Mutable delivery observations; none can change a message's authenticated bytes.
#[derive(Debug, Clone)]
pub struct MessageMetadata {
    pub state: MessageState,
    pub method: DeliveryMethod,
    pub ratchet_id: Option<[u8; 32]>,
    pub delivery_attempts: u32,
    pub last_delivery_attempt: f64,
    pub next_delivery_attempt: f64,
    pub unverified_reason: Option<UnverifiedReason>,
    pub representation: DeliveryRepresentation,
    pub transport_encrypted: bool,
    pub transport_encryption: Option<String>,
    pub incoming: bool,
    pub source_blackholed: bool,
    pub progress: f64,
    pub auto_compress: bool,
    pub callbacks: MessageCallbacks,
}
impl Default for MessageMetadata {
    fn default() -> Self {
        Self {
            state: MessageState::Generating,
            method: DeliveryMethod::Direct,
            ratchet_id: None,
            delivery_attempts: 0,
            last_delivery_attempt: 0.,
            next_delivery_attempt: 0.,
            unverified_reason: None,
            representation: DeliveryRepresentation::Unknown,
            transport_encrypted: false,
            transport_encryption: None,
            incoming: false,
            source_blackholed: false,
            progress: 0.,
            auto_compress: true,
            callbacks: MessageCallbacks::default(),
        }
    }
}
/// Local parser/construction profile, independent of transport size admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageDecodeLimits {
    pub max_wire_bytes: usize,
    pub max_top_level_fields: usize,
}
impl Default for MessageDecodeLimits {
    fn default() -> Self {
        Self {
            max_wire_bytes: 134_217_727,
            max_top_level_fields: 4096,
        }
    }
}
impl MessageDecodeLimits {
    fn check_wire(self, length: usize) -> Result<(), MessageError> {
        if length > self.max_wire_bytes {
            Err(MessageError::TooLarge {
                size: length,
                limit: self.max_wire_bytes,
            })
        } else {
            Ok(())
        }
    }
}
/// Recipient stamp bytes. Construction does not itself authenticate the stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientStamp {
    Ticket([u8; 16]),
    ProofOfWork([u8; 32]),
}
impl RecipientStamp {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ticket(b) => b,
            Self::ProofOfWork(b) => b,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            16 => Some(Self::Ticket(bytes.try_into().ok()?)),
            32 => Some(Self::ProofOfWork(bytes.try_into().ok()?)),
            _ => None,
        }
    }
}
/// One finalized or received image. All clones share the image and field indexes.
///
/// Signed content cannot be assigned after finalization:
/// ```compile_fail
/// use lxmf_core::message::LxMessage;
/// fn change(message: &mut LxMessage) { message.message_id = [0; 32]; }
/// ```
/// Recipient stamps must be supplied before the complete image is frozen:
/// ```compile_fail
/// use lxmf_core::message::{LxMessage, RecipientStamp};
/// fn change(message: &mut LxMessage) {
///     message.stamp = Some(RecipientStamp::Ticket([0; 16]));
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LxMessage {
    wire: Bytes,
    indexes: Arc<[FieldIndex]>,
    title: Range<usize>,
    content: Range<usize>,
    timestamp: f64,
    message_id: [u8; 32],
    stamp: Option<RecipientStamp>,
    limits: MessageDecodeLimits,
    pub metadata: MessageMetadata,
}
impl Deref for LxMessage {
    type Target = MessageMetadata;
    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}
impl DerefMut for LxMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.metadata
    }
}
/// Source-bound authentication of an immutable message; cannot be constructed by callers.
/// ```compile_fail
/// use lxmf_core::message::{LxMessage, VerifiedLxMessage};
/// fn counterfeit(message: &LxMessage) {
///     let _ = VerifiedLxMessage { message, source_public_key: [0; 64] };
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedLxMessage<'a> {
    message: &'a LxMessage,
    source_public_key: [u8; 64],
}
/// Authentication retained across an asynchronous handoff. The frozen message
/// clone shares its original wire image and field index; callers cannot replace
/// either the authenticated bytes or the source key.
#[derive(Debug)]
pub struct OwnedVerifiedLxMessage {
    message: LxMessage,
    source_public_key: [u8; 64],
}
impl OwnedVerifiedLxMessage {
    pub fn as_verified(&self) -> VerifiedLxMessage<'_> {
        VerifiedLxMessage {
            message: &self.message,
            source_public_key: self.source_public_key,
        }
    }
}
impl<'a> VerifiedLxMessage<'a> {
    pub fn message(&self) -> &'a LxMessage {
        self.message
    }
    pub fn source_public_key(&self) -> &[u8; 64] {
        &self.source_public_key
    }
    pub fn to_owned(&self) -> OwnedVerifiedLxMessage {
        OwnedVerifiedLxMessage {
            message: self.message.clone(),
            source_public_key: self.source_public_key,
        }
    }
}
impl LxMessage {
    pub fn destination_hash(&self) -> [u8; 16] {
        self.wire[..16].try_into().expect("parsed header")
    }
    pub fn source_hash(&self) -> [u8; 16] {
        self.wire[16..32].try_into().expect("parsed header")
    }
    pub fn signature(&self) -> [u8; 64] {
        self.wire[32..96].try_into().expect("parsed header")
    }
    pub fn message_id(&self) -> [u8; 32] {
        self.message_id
    }
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }
    pub fn title_bytes(&self) -> &[u8] {
        &self.wire[self.title.clone()]
    }
    pub fn content_bytes(&self) -> &[u8] {
        &self.wire[self.content.clone()]
    }
    pub fn title_text(&self) -> Cow<'_, str> {
        bounded_lossy_text(self.title_bytes())
    }
    pub fn content_text(&self) -> Cow<'_, str> {
        bounded_lossy_text(self.content_bytes())
    }
    pub fn fields(&self) -> Fields<'_> {
        Fields {
            wire: &self.wire,
            indexes: &self.indexes,
        }
    }
    pub fn get_field(&self, id: impl Into<FieldId>) -> Option<FieldValueRef<'_>> {
        self.fields().get(id)
    }
    pub fn recipient_stamp(&self) -> Option<&RecipientStamp> {
        self.stamp.as_ref()
    }
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Shared ownership for asynchronous storage without copying the message.
    pub fn wire_owned(&self) -> Bytes {
        self.wire.clone()
    }
    pub fn decode_limits(&self) -> MessageDecodeLimits {
        self.limits
    }
    pub fn packed_len(&self) -> Result<usize, MessageError> {
        Ok(self.wire.len())
    }
    pub fn pack(&self) -> Result<Vec<u8>, MessageError> {
        Ok(self.wire.to_vec())
    }
    pub fn pack_payload(&self) -> Result<Vec<u8>, MessageError> {
        Ok(self.wire[96..].to_vec())
    }
    pub fn compute_hash(&self) -> Result<[u8; 32], MessageError> {
        Ok(self.message_id)
    }
    pub fn pack_propagated(&self) -> Result<Vec<u8>, MessageError> {
        self.pack()
    }
    pub fn unpack_propagated(data: &[u8]) -> Result<Self, MessageError> {
        Self::unpack(data)
    }
    pub fn pack_opportunistic_encrypted<F>(&self, encrypt: F) -> Result<Vec<u8>, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        encrypt(&self.wire[16..])
    }
    /// Check a detached signature only; this grants no source-identity authority.
    pub fn verify_signature(&self, key: &rns_crypto::ed25519::Ed25519PublicKey) -> bool {
        let mut signed = Vec::with_capacity(self.wire.len() + 32);
        signed.extend_from_slice(&self.wire[..32]);
        if let Some(body) = first_four_msgpack_array_body(&self.wire[96..]) {
            signed.push(0x94);
            signed.extend_from_slice(body);
        } else {
            signed.extend_from_slice(&self.wire[96..]);
        }
        signed.extend_from_slice(&self.message_id);
        key.verify(&signed, &self.signature()).is_ok()
    }
    /// Verify both the claimed LXMF source and its signature, without mutation.
    pub fn verify(
        &self,
        source_public_key: &[u8; 64],
    ) -> Result<VerifiedLxMessage<'_>, MessageError> {
        let identity = rns_identity::identity::Identity::from_public_key(source_public_key)
            .map_err(|_| MessageError::InvalidSignature)?;
        let expected = rns_identity::destination::Destination::hash_from_name_and_identity(
            "lxmf.delivery",
            Some(&identity.hash),
        );
        if expected != self.source_hash() {
            return Err(MessageError::SourceMismatch);
        }
        let key = rns_crypto::ed25519::Ed25519PublicKey::from_bytes(
            source_public_key[32..].try_into().expect("public key half"),
        )
        .map_err(|_| MessageError::InvalidSignature)?;
        if !self.verify_signature(&key) {
            return Err(MessageError::InvalidSignature);
        }
        Ok(VerifiedLxMessage {
            message: self,
            source_public_key: *source_public_key,
        })
    }
    pub fn unpack(data: &[u8]) -> Result<Self, MessageError> {
        let limits = MessageDecodeLimits::default();
        limits.check_wire(data.len())?;
        Self::unpack_owned(Bytes::copy_from_slice(data), limits)
    }
    pub fn unpack_owned(wire: Bytes, limits: MessageDecodeLimits) -> Result<Self, MessageError> {
        limits.check_wire(wire.len())?;
        if wire.len() < 97 {
            return Err(MessageError::TooShort(wire.len()));
        }
        let mut input = &wire[96..];
        let count = read_msgpack_array_len(&mut input)?;
        if count < 4 {
            return Err(MessageError::UnpackFailed("payload array too short".into()));
        }
        let timestamp = read_msgpack_float(&mut input)?;
        let title = read_text_range(&wire, &mut input)?;
        let content = read_text_range(&wire, &mut input)?;
        let mut indexes = Vec::new();
        if input.first().is_some_and(|m| msgpack_marker_is_map(*m)) {
            let count = read_msgpack_map_len(&mut input)? as usize;
            if count > limits.max_top_level_fields {
                return Err(MessageError::TooManyFields);
            }
            if count > input.len() / 2 {
                return Err(MessageError::UnpackFailed("impossible field count".into()));
            }
            count
                .checked_mul(std::mem::size_of::<FieldIndex>())
                .ok_or(MessageError::TooManyFields)?;
            indexes
                .try_reserve_exact(count)
                .map_err(|_| MessageError::TooManyFields)?;
            for _ in 0..count {
                let id = FieldId::try_from(read_msgpack_integer(&mut input)?)?;
                let start = wire.len() - input.len();
                skip_msgpack_value(&mut input, 0)?;
                indexes.push(FieldIndex {
                    id,
                    range: start..wire.len() - input.len(),
                });
            }
            indexes.sort_unstable_by_key(|entry| entry.id);
            if indexes.windows(2).any(|pair| pair[0].id == pair[1].id) {
                return Err(MessageError::DuplicateField);
            }
        } else {
            skip_msgpack_value(&mut input, 0)?;
        }
        let stamp = if count > 4 {
            read_recipient_stamp(&mut input)?
        } else {
            None
        };
        let destination = wire[..16].try_into().expect("header");
        let source = wire[16..32].try_into().expect("header");
        let message_id = Self::message_id_from_payload(&destination, &source, &wire[96..]);
        Ok(Self {
            wire,
            indexes: indexes.into(),
            title,
            content,
            timestamp,
            message_id,
            stamp,
            limits,
            metadata: MessageMetadata {
                incoming: true,
                ..MessageMetadata::default()
            },
        })
    }
    /// Stamp checking is pure; the returned value is valid only for this request's policy.
    pub fn validate_stamp_with_tickets(
        &self,
        target_cost: u8,
        tickets: Option<&[Vec<u8>]>,
    ) -> bool {
        self.validated_stamp_value(target_cost, tickets).is_some()
    }
    pub fn validated_stamp_value(
        &self,
        target_cost: u8,
        tickets: Option<&[Vec<u8>]>,
    ) -> Option<u16> {
        let stamp = self.stamp.as_ref()?.as_bytes();
        if let Some(tickets) = tickets {
            for ticket in tickets {
                if ticket.len() != TICKET_LENGTH {
                    continue;
                }
                let mut material = [0u8; 48];
                material[..16].copy_from_slice(ticket);
                material[16..].copy_from_slice(&self.message_id);
                if stamp == truncated_hash(&material) {
                    return Some(COST_TICKET);
                }
            }
        }
        let stamp = <&[u8; 32]>::try_from(stamp).ok()?;
        let work = crate::stamper::stamp_workblock(&self.message_id, STAMP_WORKBLOCK_EXPAND_ROUNDS);
        crate::stamper::stamp_valid(stamp, target_cost, &work)
            .then(|| crate::stamper::stamp_value(&work, stamp) as u16)
    }
    /// Update [`auto_compress`](MessageMetadata::auto_compress) based on a peer's cached announce app_data.
    ///
    /// Matches Python `LXMessage.determine_compression_support` — LXMessage.py:510-513.
    /// Fail-open: no cached app_data and legacy peers without a feature list
    /// default to compression enabled; only an explicit feature list omitting
    /// `SF_COMPRESSION` disables it.
    pub fn determine_compression_support(&mut self, peer_app_data: Option<&[u8]>) {
        self.auto_compress = peer_app_data
            .map(crate::handlers::compression_support_from_app_data)
            .unwrap_or(true);
    }

    /// Register a callback fired when this message transitions to `Delivered`.
    ///
    /// Python reference: `LXMessage.register_delivery_callback` — LXMessage.py:264-265.
    pub fn register_delivery_callback<F>(&mut self, callback: F)
    where
        F: Fn(&LxMessage) + Send + Sync + 'static,
    {
        self.callbacks.on_delivered = Some(Arc::new(callback));
    }

    /// Register a callback fired when this message transitions to `Failed`.
    ///
    /// Python reference: `LXMessage.register_failed_callback` — LXMessage.py:267-268.
    pub fn register_failed_callback<F>(&mut self, callback: F)
    where
        F: Fn(&LxMessage) + Send + Sync + 'static,
    {
        self.callbacks.on_failed = Some(Arc::new(callback));
    }

    /// Fire the registered delivery callback, if any. Idempotent on repeated calls.
    pub fn notify_delivered(&self) {
        if let Some(ref cb) = self.callbacks.on_delivered {
            cb(self);
        }
    }

    /// Fire the registered failure callback, if any. Idempotent on repeated calls.
    pub fn notify_failed(&self) {
        if let Some(ref cb) = self.callbacks.on_failed {
            cb(self);
        }
    }

    /// Decode the first native LXMF file attachment while borrowing its bytes
    /// from this message. Only the small filename is allocated.
    pub fn first_file_attachment(&self) -> Result<Option<(String, &[u8])>, MessageError> {
        let Some(field) = self.fields().get(FIELD_FILE_ATTACHMENTS) else {
            return Ok(None);
        };
        let mut input = field.encoded();
        if read_msgpack_array_len(&mut input)? == 0 {
            return Ok(None);
        }
        if read_msgpack_array_len(&mut input)? < 2 {
            return Err(MessageError::UnpackFailed(
                "file attachment entry requires name and data".to_string(),
            ));
        }
        let file_name = bounded_lossy_text(read_msgpack_string_or_binary(&mut input)?).into_owned();
        let data = read_msgpack_binary(&mut input)?;
        Ok(Some((file_name, data)))
    }

    /// Decode the native LXMF image field while borrowing its image bytes
    /// from this message. Only the short format string is allocated.
    pub fn image_attachment(&self) -> Result<Option<(String, &[u8])>, MessageError> {
        let Some(field) = self.fields().get(FIELD_IMAGE) else {
            return Ok(None);
        };
        let mut input = field.encoded();
        if read_msgpack_array_len(&mut input)? < 2 {
            return Err(MessageError::UnpackFailed(
                "image field requires format and data".to_string(),
            ));
        }
        let format = bounded_lossy_text(read_msgpack_string_or_binary(&mut input)?).into_owned();
        let data = read_msgpack_binary(&mut input)?;
        Ok(Some((format, data)))
    }

    /// Decode the native LXMF audio field while borrowing its audio bytes.
    ///
    /// The field must be exactly `[mode, bytes]`, with an integer mode in
    /// `0..=255` and a MessagePack binary payload. A malformed audio field is
    /// reported only by this accessor; it does not invalidate the enclosing
    /// message or its other fields.
    pub fn audio_field(&self) -> Result<Option<AudioField<'_>>, MessageError> {
        let Some(field) = self.fields().get(FIELD_AUDIO) else {
            return Ok(None);
        };
        let mut input = field.encoded();
        let item_count = read_msgpack_array_len(&mut input)?;
        if item_count != 2 {
            return Err(MessageError::UnpackFailed(
                "audio field requires exactly mode and data".to_string(),
            ));
        }
        let mode = read_msgpack_integer_u8_strict(&mut input)?;
        let bytes = read_msgpack_binary(&mut input)?;
        if !input.is_empty() {
            return Err(MessageError::UnpackFailed(
                "audio field has trailing bytes".to_string(),
            ));
        }
        Ok(Some(AudioField { mode, bytes }))
    }

    fn message_id_from_payload(
        destination_hash: &[u8; 16],
        source_hash: &[u8; 16],
        payload: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(destination_hash);
        hasher.update(source_hash);
        if let Some(body) = first_four_msgpack_array_body(payload) {
            hasher.update([0x94]);
            hasher.update(body);
        } else {
            hasher.update(payload);
        }
        hasher.finalize().into()
    }

    /// Unpack a propagation wrapper `msgpack([timestamp, [lxmf_data, ...]])`, where each entry is
    /// `dest_hash(16) + encrypted_data + ?propagation_stamp`. The caller must decrypt and then
    /// call [`Self::unpack`] on the decrypted bytes.
    ///
    /// Python reference: `LXMRouter.lxmf_propagation` / `propagation_resource_concluded`.
    pub fn unpack_propagation_wrapper(data: &[u8]) -> Result<(f64, Vec<Vec<u8>>), MessageError> {
        let wrapper: (f64, Vec<Vec<u8>>) = rmp_serde::from_slice(data)
            .map_err(|e| MessageError::UnpackFailed(format!("propagation wrapper: {e}")))?;
        Ok(wrapper)
    }

    /// Smallest possible valid propagation entry: anything at or below
    /// `LXMF_OVERHEAD + STAMP_SIZE` cannot carry a message (Python
    /// `LXStamper.validate_pn_stamp` rejects it before building a workblock).
    pub const MIN_PROPAGATION_ENTRY_SIZE: usize =
        crate::constants::LXMF_OVERHEAD + crate::constants::STAMP_SIZE + 1;

    /// [`Self::unpack_propagation_wrapper`] with ingest bounds applied before
    /// any per-entry stamp validation can be reached. `max_transfer_bytes` is
    /// the receiving node's configured propagation/transfer limit. Each stamp
    /// validation builds a ~256 KB workblock, so a wrapper stuffed with junk
    /// entries is a CPU-amplification vector — under-floor entries and
    /// transfers whose entry count couldn't possibly be legitimate are
    /// rejected cheaply here instead.
    pub fn unpack_propagation_wrapper_bounded(
        data: &[u8],
        max_transfer_bytes: usize,
    ) -> Result<(f64, Vec<Vec<u8>>), MessageError> {
        let (timestamp, entries) = parse_propagation_wrapper(data, max_transfer_bytes)?;
        Ok((
            timestamp,
            entries
                .into_iter()
                .map(std::borrow::Cow::into_owned)
                .collect(),
        ))
    }

    /// Bounded propagation parsing that shares canonical binary entries with
    /// the received wire image. Legacy arrays of bytes remain accepted, with
    /// their length checked before allocating the decoded entry.
    pub fn unpack_propagation_wrapper_owned(
        data: Bytes,
        max_transfer_bytes: usize,
    ) -> Result<(f64, Vec<Bytes>), MessageError> {
        let (timestamp, entries) = parse_propagation_wrapper(&data, max_transfer_bytes)?;
        let entries = entries
            .into_iter()
            .map(|entry| match entry {
                std::borrow::Cow::Borrowed(entry) => data.slice_ref(entry),
                std::borrow::Cow::Owned(entry) => Bytes::from(entry),
            })
            .collect();
        Ok((timestamp, entries))
    }

    /// Compute `transient_id = full_hash(lxmf_data)` for a propagation blob.
    ///
    /// The input must be `dest_hash + encrypted_data` without the propagation stamp; callers must
    /// strip the trailing 32-byte stamp first if present. Python computes the transient ID
    /// before the stamp is appended.
    pub fn compute_propagation_transient_id(lxmf_data: &[u8]) -> PropagationTransientId {
        full_hash(lxmf_data)
    }

    pub fn cancel(&mut self) {
        if self.state == MessageState::Outbound || self.state == MessageState::Sending {
            self.state = MessageState::Cancelled;
        }
    }

    pub fn mark_failed(&mut self) {
        self.state = MessageState::Failed;
        self.notify_failed();
    }

    pub fn mark_rejected(&mut self) {
        self.state = MessageState::Rejected;
    }

    pub fn mark_delivered(&mut self) {
        self.state = MessageState::Delivered;
        self.notify_delivered();
    }

    /// Mark transmission as in progress.
    ///
    /// Python reference: LXMessage.py:479, 499 — DIRECT and PROPAGATED messages enter SENDING
    /// when transmission begins.
    pub fn mark_sending(&mut self) {
        self.state = MessageState::Sending;
    }

    pub fn mark_sent(&mut self) {
        self.state = MessageState::Sent;
    }

    /// Encode the message as `lxm://<base64url(dest_hash || encrypted_data)>`.
    ///
    /// Python encrypts everything after the destination hash with the destination identity
    /// before emitting paper/QR content. The caller supplies that identity encryption closure,
    /// keeping this crate independent from any concrete identity store.
    ///
    /// Python reference: LXMessage.py:443-455 and LXMessage.py:687-705.
    pub fn to_paper_uri<F>(&self, encrypt_fn: F) -> Result<String, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        use base64::Engine;
        if self.method != DeliveryMethod::Paper {
            return Err(MessageError::PackFailed(
                "paper URI requires DeliveryMethod::Paper".to_string(),
            ));
        }

        let packed = self.wire_bytes();
        let encrypted = encrypt_fn(&packed[DESTINATION_LENGTH..])?;
        let mut paper_packed = Vec::with_capacity(DESTINATION_LENGTH + encrypted.len());
        paper_packed.extend_from_slice(&packed[..DESTINATION_LENGTH]);
        paper_packed.extend_from_slice(&encrypted);
        if paper_packed.len() > PAPER_MDU {
            return Err(MessageError::PackFailed(format!(
                "paper message exceeds maximum size: {} > {}",
                paper_packed.len(),
                PAPER_MDU
            )));
        }

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&paper_packed);
        Ok(format!("lxm://{encoded}"))
    }

    /// Decode an `lxm://` paper URI and return `(destination_hash, encrypted_data)`.
    pub fn decode_paper_uri(uri: &str) -> Result<([u8; 16], Vec<u8>), MessageError> {
        use base64::Engine;
        let data = uri
            .strip_prefix("lxm://")
            .ok_or_else(|| MessageError::InvalidUri("missing lxm:// prefix".to_string()))?;

        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|e| MessageError::InvalidUri(format!("base64url decode failed: {e}")))?;

        if bytes.len() < LXMF_OVERHEAD {
            return Err(MessageError::TooShort(bytes.len()));
        }

        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(&bytes[..DESTINATION_LENGTH]);
        Ok((destination_hash, bytes[DESTINATION_LENGTH..].to_vec()))
    }

    /// Decode an upstream-compatible encrypted `lxm://` paper URI.
    ///
    /// The caller supplies the local destination identity decryption closure. On success the
    /// decrypted wire message is unpacked exactly like Python's `ingest_lxm_uri` path.
    pub fn from_paper_uri<F>(uri: &str, decrypt_fn: F) -> Result<Self, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        let (destination_hash, encrypted_data) = Self::decode_paper_uri(uri)?;
        let decrypted = decrypt_fn(&encrypted_data)?;
        let mut packed = Vec::with_capacity(DESTINATION_LENGTH + decrypted.len());
        packed.extend_from_slice(&destination_hash);
        packed.extend_from_slice(&decrypted);
        let mut message = Self::unpack(&packed)?;
        message.method = DeliveryMethod::Paper;
        message.representation = DeliveryRepresentation::Paper;
        Ok(message)
    }

    /// Alias for [`Self::to_paper_uri`]; returns `None` if packing or encryption fails.
    pub fn as_uri<F>(&self, encrypt_fn: F) -> Option<String>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        self.to_paper_uri(encrypt_fn).ok()
    }

    /// Alias for [`Self::from_paper_uri`]. Python reference: LXMessage.py:685-731.
    pub fn from_uri<F>(uri: &str, decrypt_fn: F) -> Result<Self, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        Self::from_paper_uri(uri, decrypt_fn)
    }

    /// Pack the message into a container for file storage.
    ///
    /// Layout is a msgpack map `{state: u8, lxmf_bytes: bin, transport_encrypted: bool,
    /// transport_encryption: str?, method: u8}`.
    pub fn pack_container(&self) -> Result<Vec<u8>, MessageError> {
        let container = MessageContainerRef {
            state: self.state as u8,
            lxmf_bytes: self.wire_bytes(),
            transport_encrypted: self.transport_encrypted,
            transport_encryption: self.transport_encryption.as_deref(),
            method: self.method as u8,
        };
        rmp_serde::to_vec(&container).map_err(|e| MessageError::PackFailed(e.to_string()))
    }

    /// Unpack a message from a container (Python parity: `unpack_from_file` in LXMessage.py).
    pub fn unpack_container(data: &[u8]) -> Result<Self, MessageError> {
        if data.len() > MessageDecodeLimits::default().max_wire_bytes + 65_536 {
            return Err(MessageError::UnpackFailed(
                "container exceeds size limit".into(),
            ));
        }
        let container: MessageContainer =
            rmp_serde::from_slice(data).map_err(|e| MessageError::UnpackFailed(e.to_string()))?;

        let mut msg =
            Self::unpack_owned(container.lxmf_bytes.into(), MessageDecodeLimits::default())?;

        msg.state = match container.state {
            0x00 => MessageState::Generating,
            0x01 => MessageState::Outbound,
            0x02 => MessageState::Sending,
            0x04 => MessageState::Sent,
            0x08 => MessageState::Delivered,
            0xFD => MessageState::Rejected,
            0xFE => MessageState::Cancelled,
            0xFF => MessageState::Failed,
            _ => MessageState::Generating,
        };

        msg.transport_encrypted = container.transport_encrypted;
        msg.transport_encryption = container.transport_encryption;

        msg.method = match container.method {
            0x01 => DeliveryMethod::Opportunistic,
            0x02 => DeliveryMethod::Direct,
            0x03 => DeliveryMethod::Propagated,
            0x05 => DeliveryMethod::Paper,
            _ => DeliveryMethod::Direct,
        };

        Ok(msg)
    }

    /// Write the message to `directory_path`, named by the message hash.
    ///
    /// Writes are atomic (unique tmp file + fsync + rename) so concurrent
    /// readers never observe a partial file — Python `write_to_directory`,
    /// LXMessage.py:674-696 (1.0.1). Python additionally serializes the write
    /// under a per-message persist lock; in Rust concurrent persists of one
    /// message are already exclusive-borrow serialized or hit unique tmp
    /// files, with the rename as the atomic last-writer-wins step.
    pub fn write_to_directory(&self, directory_path: &str) -> Result<String, MessageError> {
        let hash = self.message_id();
        let file_name = rns_crypto::hex_encode(&hash);
        let file_path = format!("{directory_path}/{file_name}");

        let container_data = self.pack_container()?;
        crate::persist::write_file_atomic(std::path::Path::new(&file_path), &container_data)
            .map_err(|e| MessageError::PackFailed(format!("write failed: {e}")))?;

        Ok(file_path)
    }

    /// Read a message from a container file (Python parity: `unpack_from_file`).
    pub fn read_from_file(file_path: &str) -> Result<Self, MessageError> {
        use std::io::Read;
        let file = std::fs::File::open(file_path)
            .map_err(|e| MessageError::UnpackFailed(format!("read failed: {e}")))?;
        let maximum = MessageDecodeLimits::default().max_wire_bytes + 65_536;
        let mut data = Vec::new();
        file.take((maximum + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|e| MessageError::UnpackFailed(format!("read failed: {e}")))?;
        let message = Self::unpack_container(&data)?;
        if let Some(name) = std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            && name.len() == 64
            && name.bytes().all(|b| b.is_ascii_hexdigit())
            && !name.eq_ignore_ascii_case(&hex::encode(message.message_id()))
        {
            return Err(MessageError::HistoricalHashMismatch);
        }
        Ok(message)
    }
}

type ParsedPropagationWrapper<'a> = (f64, Vec<std::borrow::Cow<'a, [u8]>>);

fn parse_propagation_wrapper(
    data: &[u8],
    max_transfer_bytes: usize,
) -> Result<ParsedPropagationWrapper<'_>, MessageError> {
    let invalid =
        |reason: &str| MessageError::UnpackFailed(format!("propagation wrapper: {reason}"));
    if data.len() > max_transfer_bytes {
        return Err(invalid("wire image exceeds transfer limit"));
    }
    let mut input = data;
    if read_msgpack_array_len(&mut input)? != 2 {
        return Err(invalid("expected timestamp and entries"));
    }
    let timestamp = if matches!(input.first(), Some(0xca | 0xcb)) {
        read_msgpack_float(&mut input)?
    } else {
        read_msgpack_integer(&mut input)? as f64
    };
    let count = usize::try_from(read_msgpack_array_len(&mut input)?)
        .map_err(|_| invalid("entry count overflow"))?;
    // Each accepted entry must be present in this image and meet the size
    // floor. Refuse forged array lengths before reserving the entry index.
    let maximum = input.len().min(max_transfer_bytes) / LxMessage::MIN_PROPAGATION_ENTRY_SIZE;
    if count > maximum {
        return Err(invalid("entry count exceeds possible transfer size"));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| invalid("entry index allocation failed"))?;
    for _ in 0..count {
        let entry = if matches!(input.first(), Some(0xc4..=0xc6)) {
            std::borrow::Cow::Borrowed(read_msgpack_binary(&mut input)?)
        } else {
            let len = usize::try_from(read_msgpack_array_len(&mut input)?)
                .map_err(|_| invalid("entry length overflow"))?;
            if len < LxMessage::MIN_PROPAGATION_ENTRY_SIZE || len > input.len() {
                return Err(invalid("invalid legacy byte-array length"));
            }
            let mut decoded = Vec::new();
            decoded
                .try_reserve_exact(len)
                .map_err(|_| invalid("entry allocation failed"))?;
            for _ in 0..len {
                decoded.push(read_msgpack_integer_u8_strict(&mut input)?);
            }
            std::borrow::Cow::Owned(decoded)
        };
        if entry.len() < LxMessage::MIN_PROPAGATION_ENTRY_SIZE {
            return Err(invalid("entry below minimum message size"));
        }
        entries.push(entry);
    }
    // rmp-serde's historical convenience API permits trailing bytes. The
    // bounded ingress API requires one complete wrapper, without hidden data.
    if !input.is_empty() {
        return Err(invalid("trailing wrapper data"));
    }
    Ok((timestamp, entries))
}

fn read_msgpack_array_len(input: &mut &[u8]) -> Result<u32, MessageError> {
    let marker = take_msgpack(input, 1)?[0];
    match marker {
        0x90..=0x9f => Ok(u32::from(marker & 0x0f)),
        0xdc => Ok(u32::from(u16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        ))),
        0xdd => Ok(u32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        )),
        _ => Err(MessageError::UnpackFailed(
            "expected MessagePack array".to_string(),
        )),
    }
}

pub(crate) fn read_msgpack_string_or_binary<'a>(
    input: &mut &'a [u8],
) -> Result<&'a [u8], MessageError> {
    let marker = take_msgpack(input, 1)?[0];
    let length = match marker {
        0xa0..=0xbf => usize::from(marker & 0x1f),
        0xd9 | 0xc4 => usize::from(take_msgpack(input, 1)?[0]),
        0xda | 0xc5 => usize::from(u16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        )),
        0xdb | 0xc6 => usize::try_from(u32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        ))
        .map_err(|_| MessageError::UnpackFailed("field length overflow".to_string()))?,
        _ => {
            return Err(MessageError::UnpackFailed(
                "expected MessagePack string or binary value".to_string(),
            ));
        }
    };
    take_msgpack(input, length)
}

fn read_msgpack_binary<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], MessageError> {
    let marker = take_msgpack(input, 1)?[0];
    let length = match marker {
        0xc4 => usize::from(take_msgpack(input, 1)?[0]),
        0xc5 => usize::from(u16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        )),
        0xc6 => usize::try_from(u32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        ))
        .map_err(|_| MessageError::UnpackFailed("field length overflow".to_string()))?,
        _ => {
            return Err(MessageError::UnpackFailed(
                "expected MessagePack binary value".to_string(),
            ));
        }
    };
    take_msgpack(input, length)
}

fn take_msgpack<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], MessageError> {
    if input.len() < length {
        return Err(MessageError::UnpackFailed(
            "truncated MessagePack attachment field".to_string(),
        ));
    }
    let (value, remaining) = input.split_at(length);
    *input = remaining;
    Ok(value)
}

fn first_four_msgpack_array_body(payload: &[u8]) -> Option<&[u8]> {
    let mut input = payload;
    let count = read_msgpack_array_len(&mut input).ok()?;
    if count <= 4 {
        return None;
    }
    let body = input;
    for _ in 0..4 {
        skip_msgpack_value(&mut input, 0).ok()?;
    }
    Some(&body[..body.len() - input.len()])
}

fn read_msgpack_float(input: &mut &[u8]) -> Result<f64, MessageError> {
    match take_msgpack(input, 1)?[0] {
        0xca => Ok(f64::from(f32::from_bits(u32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        )))),
        0xcb => Ok(f64::from_bits(u64::from_be_bytes(
            take_msgpack(input, 8)?.try_into().expect("exact length"),
        ))),
        _ => Err(MessageError::UnpackFailed(
            "timestamp is not float".to_string(),
        )),
    }
}

const fn msgpack_marker_is_map(marker: u8) -> bool {
    matches!(marker, 0x80..=0x8f | 0xde | 0xdf)
}

fn read_msgpack_map_len(input: &mut &[u8]) -> Result<u32, MessageError> {
    match take_msgpack(input, 1)?[0] {
        marker @ 0x80..=0x8f => Ok(u32::from(marker & 0x0f)),
        0xde => Ok(u32::from(u16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        ))),
        0xdf => Ok(u32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        )),
        _ => Err(MessageError::UnpackFailed(
            "expected MessagePack map".to_string(),
        )),
    }
}

fn read_msgpack_integer(input: &mut &[u8]) -> Result<i128, MessageError> {
    let marker = take_msgpack(input, 1)?[0];
    let value = match marker {
        0x00..=0x7f => i128::from(marker),
        0xe0..=0xff => i128::from(marker as i8),
        0xcc => i128::from(take_msgpack(input, 1)?[0]),
        0xcd => i128::from(u16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        )),
        0xce => i128::from(u32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        )),
        0xcf => i128::from(u64::from_be_bytes(
            take_msgpack(input, 8)?.try_into().expect("exact length"),
        )),
        0xd0 => i128::from(i8::from_be_bytes(
            take_msgpack(input, 1)?.try_into().expect("exact length"),
        )),
        0xd1 => i128::from(i16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        )),
        0xd2 => i128::from(i32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        )),
        0xd3 => i128::from(i64::from_be_bytes(
            take_msgpack(input, 8)?.try_into().expect("exact length"),
        )),
        _ => {
            return Err(MessageError::UnpackFailed(
                "expected MessagePack integer".to_string(),
            ));
        }
    };
    Ok(value)
}

fn read_msgpack_integer_u8_strict(input: &mut &[u8]) -> Result<u8, MessageError> {
    u8::try_from(read_msgpack_integer(input)?).map_err(|_| MessageError::InvalidByte)
}
pub(crate) fn skip_msgpack_value(input: &mut &[u8], depth: usize) -> Result<(), MessageError> {
    if depth >= 64 {
        return Err(MessageError::UnpackFailed(
            "MessagePack nesting exceeds limit".to_string(),
        ));
    }
    let marker = take_msgpack(input, 1)?[0];
    match marker {
        0x00..=0x7f | 0xc0 | 0xc2..=0xc3 | 0xe0..=0xff => Ok(()),
        0x80..=0x8f => skip_msgpack_values(input, depth, u32::from(marker & 0x0f) * 2),
        0x90..=0x9f => skip_msgpack_values(input, depth, u32::from(marker & 0x0f)),
        0xa0..=0xbf => {
            take_msgpack(input, usize::from(marker & 0x1f))?;
            Ok(())
        }
        0xc1 => Err(MessageError::UnpackFailed(
            "reserved MessagePack marker".to_string(),
        )),
        0xc4 | 0xd9 => {
            let length = usize::from(take_msgpack(input, 1)?[0]);
            take_msgpack(input, length)?;
            Ok(())
        }
        0xc5 | 0xda => {
            let length = usize::from(u16::from_be_bytes(
                take_msgpack(input, 2)?.try_into().expect("exact length"),
            ));
            take_msgpack(input, length)?;
            Ok(())
        }
        0xc6 | 0xdb => {
            let length = usize::try_from(u32::from_be_bytes(
                take_msgpack(input, 4)?.try_into().expect("exact length"),
            ))
            .map_err(|_| MessageError::UnpackFailed("value length overflow".to_string()))?;
            take_msgpack(input, length)?;
            Ok(())
        }
        0xc7 => {
            let length = usize::from(take_msgpack(input, 1)?[0]);
            take_msgpack(input, length.saturating_add(1))?;
            Ok(())
        }
        0xc8 => {
            let length = usize::from(u16::from_be_bytes(
                take_msgpack(input, 2)?.try_into().expect("exact length"),
            ));
            take_msgpack(input, length.saturating_add(1))?;
            Ok(())
        }
        0xc9 => {
            let length = usize::try_from(u32::from_be_bytes(
                take_msgpack(input, 4)?.try_into().expect("exact length"),
            ))
            .map_err(|_| MessageError::UnpackFailed("extension length overflow".to_string()))?;
            take_msgpack(input, length.saturating_add(1))?;
            Ok(())
        }
        0xca => {
            take_msgpack(input, 4)?;
            Ok(())
        }
        0xcb | 0xcf | 0xd3 => {
            take_msgpack(input, 8)?;
            Ok(())
        }
        0xcc | 0xd0 => {
            take_msgpack(input, 1)?;
            Ok(())
        }
        0xcd | 0xd1 => {
            take_msgpack(input, 2)?;
            Ok(())
        }
        0xce | 0xd2 => {
            take_msgpack(input, 4)?;
            Ok(())
        }
        0xd4 => {
            take_msgpack(input, 2)?;
            Ok(())
        }
        0xd5 => {
            take_msgpack(input, 3)?;
            Ok(())
        }
        0xd6 => {
            take_msgpack(input, 5)?;
            Ok(())
        }
        0xd7 => {
            take_msgpack(input, 9)?;
            Ok(())
        }
        0xd8 => {
            take_msgpack(input, 17)?;
            Ok(())
        }
        0xdc => {
            let count = u32::from(u16::from_be_bytes(
                take_msgpack(input, 2)?.try_into().expect("exact length"),
            ));
            skip_msgpack_values(input, depth, count)
        }
        0xdd => {
            let count =
                u32::from_be_bytes(take_msgpack(input, 4)?.try_into().expect("exact length"));
            skip_msgpack_values(input, depth, count)
        }
        0xde => {
            let count = u32::from(u16::from_be_bytes(
                take_msgpack(input, 2)?.try_into().expect("exact length"),
            ));
            skip_msgpack_values(input, depth, count.saturating_mul(2))
        }
        0xdf => {
            let count =
                u32::from_be_bytes(take_msgpack(input, 4)?.try_into().expect("exact length"));
            skip_msgpack_values(input, depth, count.saturating_mul(2))
        }
    }
}

fn skip_msgpack_values(input: &mut &[u8], depth: usize, count: u32) -> Result<(), MessageError> {
    for _ in 0..count {
        skip_msgpack_value(input, depth + 1)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct MessageContainerRef<'a> {
    state: u8,
    #[serde(serialize_with = "serialize_bytes")]
    lxmf_bytes: &'a [u8],
    transport_encrypted: bool,
    transport_encryption: Option<&'a str>,
    method: u8,
}

/// Container format for on-disk message storage. Python parity: `packed_container` dict.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageContainer {
    state: u8,
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    lxmf_bytes: Vec<u8>,
    transport_encrypted: bool,
    transport_encryption: Option<String>,
    method: u8,
}

fn serialize_bytes<S: serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(data)
}

fn deserialize_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct BytesVisitor;
    impl<'de> serde::de::Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("byte array")
        }
        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? {
                bytes.push(b);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_any(BytesVisitor)
}

fn serialize_optional_bytes<S: serde::Serializer>(
    stamp: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match stamp {
        Some(bytes) => serializer.serialize_some(&BinBytes(bytes)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    struct OptionalBytesVisitor;
    impl<'de> serde::de::Visitor<'de> for OptionalBytesVisitor {
        type Value = Option<Vec<u8>>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("optional byte string")
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            deserialize_bytes(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(OptionalBytesVisitor)
}

struct BinBytes<'a>(&'a [u8]);

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("serialized length overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl serde::Serialize for BinBytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

struct ImageFieldRef<'a> {
    format: &'a str,
    bytes: &'a [u8],
}

impl serde::Serialize for ImageFieldRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(self.format)?;
        tuple.serialize_element(&BinBytes(self.bytes))?;
        tuple.end()
    }
}

struct AudioFieldRef<'a> {
    mode: u8,
    bytes: &'a [u8],
}

impl serde::Serialize for AudioFieldRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.mode)?;
        tuple.serialize_element(&BinBytes(self.bytes))?;
        tuple.end()
    }
}

struct FileAttachmentsFieldRef<'a> {
    file_name: &'a str,
    bytes: &'a [u8],
}

impl serde::Serialize for FileAttachmentsFieldRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeSeq, SerializeTuple};

        struct AttachmentRef<'a> {
            file_name: &'a str,
            bytes: &'a [u8],
        }

        impl serde::Serialize for AttachmentRef<'_> {
            fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
                let mut tuple = serializer.serialize_tuple(2)?;
                tuple.serialize_element(self.file_name)?;
                tuple.serialize_element(&BinBytes(self.bytes))?;
                tuple.end()
            }
        }

        let mut attachments = serializer.serialize_seq(Some(1))?;
        attachments.serialize_element(&AttachmentRef {
            file_name: self.file_name,
            bytes: self.bytes,
        })?;
        attachments.end()
    }
}

#[cfg(test)]
struct PropagationWrapperRef<'a> {
    timestamp: f64,
    entries: &'a [&'a [u8]],
}

#[cfg(test)]
impl serde::Serialize for PropagationWrapperRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(2)?;
        tup.serialize_element(&self.timestamp)?;
        tup.serialize_element(&PropagationEntriesRef(self.entries))?;
        tup.end()
    }
}

#[cfg(test)]
struct PropagationEntriesRef<'a>(&'a [&'a [u8]]);

#[cfg(test)]
impl serde::Serialize for PropagationEntriesRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            seq.serialize_element(&BinBytes(entry))?;
        }
        seq.end()
    }
}

/// Semantic DTO for explicitly constructing payloads, never an archival authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub timestamp: f64,
    #[serde(
        serialize_with = "serialize_as_bin",
        deserialize_with = "deserialize_bin_or_str"
    )]
    pub title: String,
    #[serde(
        serialize_with = "serialize_as_bin",
        deserialize_with = "deserialize_bin_or_str"
    )]
    pub content: String,
    #[serde(with = "field::map_serde")]
    pub fields: BTreeMap<FieldId, FieldValue>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_bytes",
        deserialize_with = "deserialize_optional_bytes"
    )]
    pub stamp: Option<Vec<u8>>,
}
fn serialize_as_bin<S: serde::Serializer>(s: &String, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(s.as_bytes())
}

/// Accept either msgpack `bin` or `str` for backwards compatibility with older peers.
fn deserialize_bin_or_str<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    struct BinOrStrVisitor;
    impl serde::de::Visitor<'_> for BinOrStrVisitor {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("string or binary data")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_string())
        }
        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<String, E> {
            String::from_utf8(v.to_vec()).map_err(E::custom)
        }
    }
    deserializer.deserialize_any(BinOrStrVisitor)
}

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("stored message hash differs from its historical filename; original retained")]
    HistoricalHashMismatch,
    #[error("reply ticket has not been durably committed")]
    TicketNotCommitted,
    #[error("message exceeds local profile: {size} > {limit}")]
    TooLarge { size: usize, limit: usize },
    #[error("too many LXMF fields")]
    TooManyFields,
    #[error("field ID outside MessagePack integer domain")]
    InvalidFieldId,
    #[error("duplicate LXMF field ID")]
    DuplicateField,
    #[error("integer outside byte range")]
    InvalidByte,
    #[error("invalid message signature")]
    InvalidSignature,
    #[error("public key does not bind claimed source")]
    SourceMismatch,

    #[error("message too short: {0} bytes")]
    TooShort(usize),
    #[error("pack failed: {0}")]
    PackFailed(String),
    #[error("unpack failed: {0}")]
    UnpackFailed(String),
    #[error("message not signed")]
    NotSigned,
    #[error("invalid URI: {0}")]
    InvalidUri(String),
}

fn read_text_range(wire: &[u8], input: &mut &[u8]) -> Result<Range<usize>, MessageError> {
    if input
        .first()
        .is_some_and(|marker| matches!(*marker,0xa0..=0xbf|0xc4..=0xc6|0xd9..=0xdb))
    {
        let bytes = read_msgpack_string_or_binary(input)?;
        let start = bytes.as_ptr() as usize - wire.as_ptr() as usize;
        Ok(start..start + bytes.len())
    } else {
        skip_msgpack_value(input, 0)?;
        Ok(0..0)
    }
}
fn read_recipient_stamp(input: &mut &[u8]) -> Result<Option<RecipientStamp>, MessageError> {
    match input.first().copied() {
        Some(0xc4..=0xc6) => Ok(RecipientStamp::from_bytes(read_msgpack_binary(input)?)),
        Some(0x90..=0x9f | 0xdc | 0xdd) => {
            let count = read_msgpack_array_len(input)? as usize;
            if count != 16 && count != 32 {
                for _ in 0..count {
                    skip_msgpack_value(input, 0)?;
                }
                return Ok(None);
            }
            let mut bytes = [0u8; 32];
            let mut valid = true;
            for slot in &mut bytes[..count] {
                match u8::try_from(read_msgpack_integer(input)?) {
                    Ok(byte) => *slot = byte,
                    Err(_) => valid = false,
                }
            }
            Ok(if valid {
                RecipientStamp::from_bytes(&bytes[..count])
            } else {
                None
            })
        }
        Some(_) => {
            skip_msgpack_value(input, 0)?;
            Ok(None)
        }
        None => Err(MessageError::UnpackFailed(
            "missing MessagePack stamp".into(),
        )),
    }
}
#[cfg(test)]
mod tests;

/// Test fixtures still cross the production signing/finalization boundary.
#[cfg(test)]
pub(crate) fn test_message(
    destination: [u8; 16],
    source: [u8; 16],
    title: &str,
    content: &str,
    method: DeliveryMethod,
) -> LxMessage {
    LxMessageDraft::new(destination, source, title, content, method)
        .unwrap()
        .sign(&rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(
            &[1; 32],
        ))
        .unwrap()
        .finalize(None)
        .unwrap()
}
