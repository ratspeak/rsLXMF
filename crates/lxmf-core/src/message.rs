//! LXMF message construction, packing, unpacking, and state machine.
//!
//! Python reference: LXMF/LXMessage.py.
//!
//! # Wire formats
//!
//! Direct / link / opportunistic:
//! `[dest_hash:16][src_hash:16][signature:64][msgpack([ts, title, content, fields, ?stamp])]`.
//! Title and content are msgpack `bin` (not `str`) to match Python/C++.
//!
//! Propagation (LXMessage.py:434-441):
//! ```text
//! encrypted_data     = destination.encrypt(packed[16..])
//! lxmf_data          = packed[..16] + encrypted_data
//! transient_id       = full_hash(lxmf_data)
//! lxmf_data         += ?propagation_stamp
//! propagation_packed = msgpack([timestamp, [lxmf_data]])
//! ```
//!
//! Signed blob: `dest_hash + src_hash + payload + SHA256(dest_hash + src_hash + payload)`
//! (LXMessage.py:380-383).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rns_crypto::sha::{full_hash, sha256, truncated_hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::constants::*;
use crate::types::PropagationTransientId;

/// Shared handler invoked on per-message state transitions.
pub type MessageCallback = Arc<dyn Fn(&LxMessage) + Send + Sync>;

/// Per-message delivery and failure callbacks.
///
/// Invoked by [`LxMessage::notify_delivered`] / [`LxMessage::notify_failed`] when the router
/// observes a state transition for a tracked outbound message.
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

/// An LXMF message.
#[derive(Debug, Clone)]
pub struct LxMessage {
    pub destination_hash: [u8; 16],
    pub source_hash: [u8; 16],
    pub title: String,
    pub content: String,
    /// Application-level fields keyed by field ID.
    pub fields: BTreeMap<u8, Vec<u8>>,
    /// Field IDs whose values are already msgpack-encoded LXMF values.
    ///
    /// Most custom fields are byte strings and must serialize as msgpack `bin`.
    /// Native structured fields such as `FIELD_IMAGE = [format, bytes]` and
    /// `FIELD_FILE_ATTACHMENTS = [[name, bytes], ...]` must serialize as their
    /// contained msgpack value instead.
    pub msgpack_field_ids: BTreeSet<u8>,
    /// Unix epoch seconds.
    pub timestamp: f64,
    pub signature: Option<[u8; 64]>,
    pub signature_validated: bool,
    pub state: MessageState,
    pub method: DeliveryMethod,
    /// Message stamp, if present.
    ///
    /// LXMF uses 32-byte PoW stamps and 16-byte ticket stamps, so this must stay
    /// byte-sized instead of forcing the PoW length.
    pub stamp: Option<Vec<u8>>,
    /// Propagation PoW stamp, if present (32 bytes).
    pub propagation_stamp: Option<[u8; 32]>,
    pub ratchet_id: Option<[u8; 32]>,
    pub delivery_attempts: u32,
    /// Unix timestamp of the last delivery attempt; 0.0 means never attempted.
    pub last_delivery_attempt: f64,
    /// Absolute Unix timestamp before which the message must not be re-attempted.
    /// Mirrors Python LXMF `LXMessage.next_delivery_attempt`: set to
    /// `now + PATH_REQUEST_WAIT` after a path request, `now + DELIVERY_RETRY_WAIT`
    /// after a link attempt. 0.0 = no explicit deadline (router falls back to
    /// `last_delivery_attempt + DELIVERY_RETRY_WAIT`).
    pub next_delivery_attempt: f64,
    /// SHA-256 of the packed message.
    pub hash: Option<[u8; 32]>,
    /// Alias for [`hash`](Self::hash) set after packing.
    pub message_id: Option<[u8; 32]>,
    /// Full hash used by the propagation offer/get protocol.
    pub transient_id: Option<PropagationTransientId>,
    /// Destination-required stamp cost for outbound stamp generation.
    pub stamp_cost: Option<u8>,
    /// Outbound ticket for stamp bypass (16 bytes).
    pub outbound_ticket: Option<[u8; 16]>,
    /// Ask the router to include a reply ticket before this message is signed.
    ///
    /// Python reference: `LXMessage.include_ticket`.
    pub include_ticket: bool,
    /// Computed stamp value: leading zero bits, or `COST_TICKET`.
    pub stamp_value: Option<u16>,
    pub unverified_reason: Option<UnverifiedReason>,
    pub representation: DeliveryRepresentation,
    pub transport_encrypted: bool,
    /// Original msgpack payload bytes, stored on inbound messages so signature verification
    /// can use the exact bytes that were signed. Avoids re-serialization mismatches for fields
    /// with complex types (arrays, maps).
    pub wire_payload: Option<Vec<u8>>,
    pub transport_encryption: Option<String>,
    pub incoming: bool,
    /// True when the source identity is blackholed at the transport layer.
    ///
    /// Python sets this during `unpack_from_bytes` via `Reticulum.is_blackholed`
    /// (LXMessage.py:172, 803-805); `LXMRouter.lxmf_delivery` then drops such
    /// messages before processing (LXMRouter.py:1739-1741). Rust unpacking has
    /// no transport access, so embedders set it from the blackhole query
    /// surface before processing.
    pub source_blackholed: bool,
    /// Delivery progress in `0.0..=1.0`.
    pub progress: f64,
    /// Whether the direct-delivery resource should be bz2-compressed by the RNS layer.
    ///
    /// Set optimistically to `true` on outbound construction to mirror Python's
    /// `LXMessage.auto_compress`. Gets cleared by
    /// [`determine_compression_support`](Self::determine_compression_support) when a peer's
    /// announce indicates no `SF_COMPRESSION` capability.
    pub auto_compress: bool,
    /// Optional per-message delivery / failure callbacks.
    pub callbacks: MessageCallbacks,
}

impl LxMessage {
    /// Construct a new outbound message.
    pub fn new(
        destination_hash: [u8; 16],
        source_hash: [u8; 16],
        title: &str,
        content: &str,
        method: DeliveryMethod,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        Self {
            destination_hash,
            source_hash,
            title: title.to_string(),
            content: content.to_string(),
            fields: BTreeMap::new(),
            msgpack_field_ids: BTreeSet::new(),
            timestamp,
            signature: None,
            signature_validated: false,
            state: MessageState::Generating,
            method,
            stamp: None,
            propagation_stamp: None,
            ratchet_id: None,
            delivery_attempts: 0,
            last_delivery_attempt: 0.0,
            next_delivery_attempt: 0.0,
            hash: None,
            message_id: None,
            transient_id: None,
            stamp_cost: None,
            outbound_ticket: None,
            include_ticket: false,
            stamp_value: None,
            unverified_reason: None,
            representation: DeliveryRepresentation::Unknown,
            transport_encrypted: false,
            transport_encryption: None,
            wire_payload: None,
            incoming: false,
            source_blackholed: false,
            progress: 0.0,
            auto_compress: true,
            callbacks: MessageCallbacks::default(),
        }
    }

    /// Update [`auto_compress`](Self::auto_compress) based on a peer's cached announce app_data.
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

    pub fn set_field(&mut self, field_id: u8, data: Vec<u8>) {
        self.fields.insert(field_id, data);
        self.msgpack_field_ids.remove(&field_id);
    }

    /// Set a field value that is already encoded as one complete msgpack value.
    ///
    /// Use this for native structured LXMF fields. For example, Python/Sideband
    /// encode `FIELD_IMAGE` as the value `["webp", image_bytes]`, not as a
    /// binary blob containing the bytes of that msgpack array.
    pub fn set_msgpack_field(&mut self, field_id: u8, data: Vec<u8>) -> Result<(), MessageError> {
        let mut cursor = std::io::Cursor::new(&data);
        rmpv::decode::read_value(&mut cursor)
            .map_err(|e| MessageError::PackFailed(format!("invalid msgpack field: {e}")))?;
        if cursor.position() != data.len() as u64 {
            return Err(MessageError::PackFailed(
                "invalid msgpack field: trailing bytes".to_string(),
            ));
        }
        self.fields.insert(field_id, data);
        self.msgpack_field_ids.insert(field_id);
        Ok(())
    }

    /// Encode and install the native LXMF image field without first cloning
    /// `image_bytes` into an intermediate `rmpv::Value` tree.
    ///
    /// The wire value remains exactly `[format, image_bytes]`.
    pub fn set_image_field(
        &mut self,
        format: &str,
        image_bytes: &[u8],
    ) -> Result<(), MessageError> {
        let encoded = rmp_serde::to_vec(&ImageFieldRef {
            format,
            bytes: image_bytes,
        })
        .map_err(|error| MessageError::PackFailed(error.to_string()))?;
        self.fields.insert(FIELD_IMAGE, encoded);
        self.msgpack_field_ids.insert(FIELD_IMAGE);
        Ok(())
    }

    /// Encode and install one native LXMF file attachment without first
    /// cloning `file_bytes` into an intermediate `rmpv::Value` tree.
    ///
    /// The wire value remains exactly `[[file_name, file_bytes]]`.
    pub fn set_file_attachment_field(
        &mut self,
        file_name: &str,
        file_bytes: &[u8],
    ) -> Result<(), MessageError> {
        let encoded = rmp_serde::to_vec(&FileAttachmentsFieldRef {
            file_name,
            bytes: file_bytes,
        })
        .map_err(|error| MessageError::PackFailed(error.to_string()))?;
        self.fields.insert(FIELD_FILE_ATTACHMENTS, encoded);
        self.msgpack_field_ids.insert(FIELD_FILE_ATTACHMENTS);
        Ok(())
    }

    pub fn get_field(&self, field_id: u8) -> Option<&Vec<u8>> {
        self.fields.get(&field_id)
    }

    /// Decode the first native LXMF file attachment while borrowing its bytes
    /// from this message. Only the small filename is allocated.
    pub fn first_file_attachment(&self) -> Result<Option<(String, &[u8])>, MessageError> {
        let Some(field) = self.fields.get(&FIELD_FILE_ATTACHMENTS) else {
            return Ok(None);
        };
        let mut input = field.as_slice();
        if read_msgpack_array_len(&mut input)? == 0 {
            return Ok(None);
        }
        if read_msgpack_array_len(&mut input)? < 2 {
            return Err(MessageError::UnpackFailed(
                "file attachment entry requires name and data".to_string(),
            ));
        }
        let file_name =
            String::from_utf8_lossy(read_msgpack_string_or_binary(&mut input)?).into_owned();
        let data = read_msgpack_binary(&mut input)?;
        Ok(Some((file_name, data)))
    }

    /// Decode the native LXMF image field while borrowing its image bytes
    /// from this message. Only the short format string is allocated.
    pub fn image_attachment(&self) -> Result<Option<(String, &[u8])>, MessageError> {
        let Some(field) = self.fields.get(&FIELD_IMAGE) else {
            return Ok(None);
        };
        let mut input = field.as_slice();
        if read_msgpack_array_len(&mut input)? < 2 {
            return Err(MessageError::UnpackFailed(
                "image field requires format and data".to_string(),
            ));
        }
        let format =
            String::from_utf8_lossy(read_msgpack_string_or_binary(&mut input)?).into_owned();
        let data = read_msgpack_binary(&mut input)?;
        Ok(Some((format, data)))
    }

    /// Pack the payload as `msgpack([timestamp, title, content, fields, ?stamp])`.
    pub fn pack_payload(&self) -> Result<Vec<u8>, MessageError> {
        self.pack_payload_inner(self.stamp.as_deref())
    }

    /// Pack the payload for signing, always as a 4-element array with `stamp = None`.
    ///
    /// Python strips the stamp element before verification and re-packs as 4 elements
    /// (LXMessage.py:742-745). Matching that here keeps sign/verify bytes stable.
    fn pack_payload_for_signing(&self) -> Result<Vec<u8>, MessageError> {
        self.pack_payload_inner(None)
    }

    /// Stream the payload directly into one output buffer. Structured LXMF
    /// fields are already complete MessagePack values, so writing their bytes
    /// verbatim avoids decoding a potentially large attachment into an owned
    /// `rmpv::Value` tree merely to encode it again.
    fn pack_payload_inner(&self, stamp: Option<&[u8]>) -> Result<Vec<u8>, MessageError> {
        let capacity = self
            .title
            .len()
            .checked_add(self.content.len())
            .and_then(|length| {
                self.fields
                    .values()
                    .try_fold(length, |total, field| total.checked_add(field.len()))
            })
            .and_then(|length| length.checked_add(stamp.map_or(0, <[u8]>::len)))
            .and_then(|length| length.checked_add(64))
            .ok_or_else(|| MessageError::PackFailed("packed length overflow".to_string()))?;
        let mut output = Vec::with_capacity(capacity);
        self.write_payload(&mut output, stamp)?;
        Ok(output)
    }

    fn packed_payload_len(&self, stamp: Option<&[u8]>) -> Result<usize, MessageError> {
        let mut counter = CountingWriter::default();
        self.write_payload(&mut counter, stamp)?;
        Ok(counter.bytes)
    }

    fn write_payload<W: Write>(
        &self,
        writer: &mut W,
        stamp: Option<&[u8]>,
    ) -> Result<(), MessageError> {
        fn length(value: usize, what: &str) -> Result<u32, MessageError> {
            u32::try_from(value)
                .map_err(|_| MessageError::PackFailed(format!("{what} exceeds MessagePack limits")))
        }

        fn packed(error: impl std::fmt::Display) -> MessageError {
            MessageError::PackFailed(error.to_string())
        }

        rmp::encode::write_array_len(writer, if stamp.is_some() { 5 } else { 4 })
            .map_err(packed)?;
        rmp::encode::write_f64(writer, self.timestamp).map_err(packed)?;
        rmp::encode::write_bin_len(writer, length(self.title.len(), "title")?).map_err(packed)?;
        writer.write_all(self.title.as_bytes()).map_err(packed)?;
        rmp::encode::write_bin_len(writer, length(self.content.len(), "content")?)
            .map_err(packed)?;
        writer.write_all(self.content.as_bytes()).map_err(packed)?;
        rmp::encode::write_map_len(writer, length(self.fields.len(), "field count")?)
            .map_err(packed)?;
        for (field_id, field) in &self.fields {
            rmp::encode::write_uint(writer, u64::from(*field_id)).map_err(packed)?;
            if self.msgpack_field_ids.contains(field_id) {
                writer.write_all(field).map_err(packed)?;
            } else {
                rmp::encode::write_bin_len(writer, length(field.len(), "field")?)
                    .map_err(packed)?;
                writer.write_all(field).map_err(packed)?;
            }
        }
        if let Some(stamp) = stamp {
            rmp::encode::write_bin_len(writer, length(stamp.len(), "stamp")?).map_err(packed)?;
            writer.write_all(stamp).map_err(packed)?;
        }
        Ok(())
    }

    /// Exact full wire length without allocating the packed message. This is
    /// used for application envelope admission before the router constructs
    /// the one contiguous signing/Resource buffer.
    pub fn packed_len(&self) -> Result<usize, MessageError> {
        self.signature.ok_or(MessageError::NotSigned)?;
        let payload = self.packed_payload_len(self.stamp.as_deref())?;
        (DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH)
            .checked_add(payload)
            .ok_or_else(|| MessageError::PackFailed("packed length overflow".to_string()))
    }

    /// Pack the full message for wire transmission as
    /// `dest_hash || src_hash || signature || payload` (Python/C++ Propagated format).
    pub fn pack(&self) -> Result<Vec<u8>, MessageError> {
        let sig = self.signature.ok_or(MessageError::NotSigned)?;
        let payload_len = self.packed_payload_len(self.stamp.as_deref())?;
        let mut packed =
            Vec::with_capacity(DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH + payload_len);
        packed.extend_from_slice(&self.destination_hash);
        packed.extend_from_slice(&self.source_hash);
        packed.extend_from_slice(&sig);
        self.write_payload(&mut packed, self.stamp.as_deref())?;
        Ok(packed)
    }

    fn signed_data_for_signing(&self) -> Result<(Vec<u8>, [u8; 32]), MessageError> {
        let payload_len = self.packed_payload_len(None)?;
        let mut signed_data = Vec::with_capacity(DESTINATION_LENGTH * 2 + payload_len + 32);
        signed_data.extend_from_slice(&self.destination_hash);
        signed_data.extend_from_slice(&self.source_hash);
        self.write_payload(&mut signed_data, None)?;
        let message_hash = sha256(&signed_data);
        signed_data.extend_from_slice(&message_hash);
        Ok((signed_data, message_hash))
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

    /// Pack a message for propagation delivery.
    ///
    /// Encrypts everything after the destination hash using `encrypt_fn` (ECIES against the
    /// destination identity's public key, matching Python `destination.encrypt()`), then wraps
    /// as `msgpack([timestamp, [lxmf_data]])`. Returns `(propagation_packed, transient_id)`.
    ///
    /// Python reference: LXMessage.py:434-441.
    pub fn pack_propagated_encrypted<F>(
        &mut self,
        encrypt_fn: F,
    ) -> Result<(Vec<u8>, PropagationTransientId), MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        let (packed, transient_id, _) = self.pack_propagated_encrypted_inner(encrypt_fn, None)?;
        Ok((packed, transient_id))
    }

    /// Pack a propagated message and always append a propagation-node stamp.
    ///
    /// Python always generates a propagation stamp for `PROPAGATED` messages,
    /// even when the target cost is zero. A zero-cost stamp is the all-zero
    /// 32-byte value, which still gives propagation nodes the expected wire
    /// layout for validation and storage.
    pub fn pack_propagated_encrypted_with_stamp<F>(
        &mut self,
        encrypt_fn: F,
        target_cost: u8,
    ) -> Result<(Vec<u8>, PropagationTransientId, u32), MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        self.pack_propagated_encrypted_inner(encrypt_fn, Some(target_cost))
    }

    /// Pack the payload that Reticulum carries for Opportunistic delivery.
    ///
    /// Python `LXMessage.__as_packet()` encrypts the complete LXMF packet after
    /// the leading destination hash because the RNS packet header already
    /// carries that destination. Keeping this helper in core prevents callers
    /// from reimplementing the destination-prefix stripping differently.
    pub fn pack_opportunistic_encrypted<F>(&self, encrypt_fn: F) -> Result<Vec<u8>, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        let packed = self.pack()?;
        if packed.len() <= DESTINATION_LENGTH {
            return Err(MessageError::PackFailed(
                "packed LXMF message missing opportunistic payload tail".to_string(),
            ));
        }
        encrypt_fn(&packed[DESTINATION_LENGTH..])
    }

    fn pack_propagated_encrypted_inner<F>(
        &mut self,
        encrypt_fn: F,
        propagation_stamp_cost: Option<u8>,
    ) -> Result<(Vec<u8>, PropagationTransientId, u32), MessageError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, MessageError>,
    {
        let packed = self.pack()?;

        let encrypted_data = encrypt_fn(&packed[DESTINATION_LENGTH..])?;

        let mut lxmf_data = Vec::with_capacity(DESTINATION_LENGTH + encrypted_data.len());
        lxmf_data.extend_from_slice(&packed[..DESTINATION_LENGTH]);
        lxmf_data.extend_from_slice(&encrypted_data);

        // transient_id is computed before the propagation stamp is appended.
        let tid = full_hash(&lxmf_data);
        self.transient_id = Some(tid);

        let mut stamp_value = 0;
        if let Some(target_cost) = propagation_stamp_cost {
            if self.propagation_stamp.is_none() {
                let (stamp, value) = crate::stamper::generate_stamp(
                    &tid,
                    target_cost,
                    crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
                )
                .ok_or_else(|| {
                    MessageError::PackFailed("failed to generate propagation stamp".to_string())
                })?;
                self.propagation_stamp = Some(stamp);
                stamp_value = value;
            }
        }

        if let Some(ref prop_stamp) = self.propagation_stamp {
            if stamp_value == 0 {
                let workblock = crate::stamper::stamp_workblock(
                    &tid,
                    crate::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN,
                );
                stamp_value = crate::stamper::stamp_value(&workblock, prop_stamp);
            }
            lxmf_data.extend_from_slice(prop_stamp);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let entries: [&[u8]; 1] = [&lxmf_data];
        let wrapper = PropagationWrapperRef {
            timestamp: now,
            entries: &entries,
        };
        let propagation_packed =
            rmp_serde::to_vec(&wrapper).map_err(|e| MessageError::PackFailed(e.to_string()))?;

        Ok((propagation_packed, tid, stamp_value))
    }

    /// Backward-compatible propagation pack when no destination identity is available. Produces
    /// the same wire format as [`Self::pack`]; prefer [`Self::pack_propagated_encrypted`] when
    /// encryption is possible.
    pub fn pack_propagated(&self) -> Result<Vec<u8>, MessageError> {
        self.pack()
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
        if data.len() > max_transfer_bytes {
            return Err(MessageError::UnpackFailed(format!(
                "propagation wrapper: {} bytes exceeds transfer limit {}",
                data.len(),
                max_transfer_bytes
            )));
        }

        let (timestamp, entries) = Self::unpack_propagation_wrapper(data)?;

        let max_entries = max_transfer_bytes / Self::MIN_PROPAGATION_ENTRY_SIZE;
        if entries.len() > max_entries {
            return Err(MessageError::UnpackFailed(format!(
                "propagation wrapper: {} entries exceeds maximum {} for transfer limit",
                entries.len(),
                max_entries
            )));
        }
        if let Some(undersized) = entries
            .iter()
            .position(|e| e.len() < Self::MIN_PROPAGATION_ENTRY_SIZE)
        {
            return Err(MessageError::UnpackFailed(format!(
                "propagation wrapper: entry {} below minimum message size",
                undersized
            )));
        }

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

    /// Unpack a wire message: `dest_hash(16) + src_hash(16) + signature(64) + msgpack_payload`.
    pub fn unpack(data: &[u8]) -> Result<Self, MessageError> {
        let min_size = DESTINATION_LENGTH * 2 + SIGNATURE_LENGTH;
        if data.len() < min_size + 1 {
            return Err(MessageError::TooShort(data.len()));
        }

        let mut dest_hash = [0u8; 16];
        dest_hash.copy_from_slice(&data[..16]);

        let mut src_hash = [0u8; 16];
        src_hash.copy_from_slice(&data[16..32]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[32..96]);

        let payload_data = &data[96..];
        let payload = Self::unpack_payload_streamed(payload_data)?;

        let hash = Self::message_id_from_payload(&dest_hash, &src_hash, payload_data);

        let mut msg = Self {
            destination_hash: dest_hash,
            source_hash: src_hash,
            title: payload.title,
            content: payload.content,
            fields: payload.fields,
            msgpack_field_ids: payload.msgpack_field_ids,
            timestamp: payload.timestamp,
            signature: Some(signature),
            signature_validated: false,
            state: MessageState::Generating,
            method: DeliveryMethod::Direct,
            stamp: payload.stamp,
            propagation_stamp: None,
            ratchet_id: None,
            delivery_attempts: 0,
            last_delivery_attempt: 0.0,
            next_delivery_attempt: 0.0,
            hash: Some(hash),
            message_id: Some(hash),
            transient_id: None,
            stamp_cost: None,
            outbound_ticket: None,
            include_ticket: false,
            stamp_value: None,
            unverified_reason: None,
            representation: DeliveryRepresentation::Unknown,
            transport_encrypted: false,
            transport_encryption: None,
            wire_payload: Some(payload_data.to_vec()),
            incoming: true,
            source_blackholed: false,
            progress: 0.0,
            auto_compress: true,
            callbacks: MessageCallbacks::default(),
        };

        // Default to the message hash for direct messages. Propagation callers
        // overwrite via [`compute_propagation_transient_id`].
        msg.transient_id = Some(hash);

        Ok(msg)
    }

    /// Parse the payload without constructing an owned `rmpv::Value` tree.
    /// Complex field values are copied once from their exact encoded range;
    /// large attachment bytes are never duplicated during structural decode.
    fn unpack_payload_streamed(payload_data: &[u8]) -> Result<MessagePayload, MessageError> {
        let mut input = payload_data;
        let item_count = read_msgpack_array_len(&mut input)?;
        if item_count < 4 {
            return Err(MessageError::UnpackFailed(format!(
                "payload array too short: {item_count}"
            )));
        }

        let timestamp = read_msgpack_float(&mut input)?;
        let title = read_msgpack_text_or_empty(&mut input)?;
        let content = read_msgpack_text_or_empty(&mut input)?;

        let mut fields = BTreeMap::new();
        let mut msgpack_field_ids = BTreeSet::new();
        if input
            .first()
            .is_some_and(|marker| msgpack_marker_is_map(*marker))
        {
            let field_count = read_msgpack_map_len(&mut input)?;
            for _ in 0..field_count {
                let key = read_msgpack_integer_u8(&mut input)?;
                let value_bytes = if input
                    .first()
                    .is_some_and(|marker| matches!(*marker, 0xc4..=0xc6))
                {
                    read_msgpack_binary(&mut input)?.to_vec()
                } else {
                    let encoded = input;
                    skip_msgpack_value(&mut input, 0)?;
                    let consumed = encoded.len() - input.len();
                    msgpack_field_ids.insert(key);
                    encoded[..consumed].to_vec()
                };
                fields.insert(key, value_bytes);
            }
        } else {
            skip_msgpack_value(&mut input, 0)?;
        }

        let stamp = if item_count > 4 {
            match input.first().copied() {
                Some(0xc4..=0xc6) => {
                    let bytes = read_msgpack_binary(&mut input)?;
                    (bytes.len() == TICKET_LENGTH || bytes.len() == 32).then(|| bytes.to_vec())
                }
                Some(0x90..=0x9f | 0xdc | 0xdd) => {
                    let count = read_msgpack_array_len(&mut input)? as usize;
                    if count == TICKET_LENGTH || count == 32 {
                        let mut bytes = Vec::with_capacity(count);
                        for _ in 0..count {
                            bytes.push(read_msgpack_integer_u8(&mut input)?);
                        }
                        Some(bytes)
                    } else {
                        for _ in 0..count {
                            skip_msgpack_value(&mut input, 0)?;
                        }
                        None
                    }
                }
                Some(0xc0) => {
                    take_msgpack(&mut input, 1)?;
                    None
                }
                Some(_) => {
                    skip_msgpack_value(&mut input, 0)?;
                    None
                }
                None => {
                    return Err(MessageError::UnpackFailed(
                        "missing MessagePack stamp".to_string(),
                    ));
                }
            }
        } else {
            None
        };

        Ok(MessagePayload {
            timestamp,
            title,
            content,
            fields,
            msgpack_field_ids,
            stamp,
        })
    }

    /// Alias for [`Self::unpack`]; all formats share the same
    /// `dest_hash + src_hash + sig + payload` layout.
    pub fn unpack_propagated(data: &[u8]) -> Result<Self, MessageError> {
        Self::unpack(data)
    }

    pub fn compute_hash(&mut self) -> Result<[u8; 32], MessageError> {
        let payload = self.pack_payload_for_signing()?;
        let hash =
            Self::message_id_from_payload(&self.destination_hash, &self.source_hash, &payload);
        self.hash = Some(hash);
        self.message_id = Some(hash);
        self.transient_id = Some(hash);
        Ok(hash)
    }

    /// Sign the message with an identity's signing key.
    ///
    /// Signed blob: `dest_hash + src_hash + payload + SHA256(dest_hash + src_hash + payload)`
    /// (Python LXMessage.py:380-383, shared with C++ ratcom/ratdeck).
    pub fn sign(
        &mut self,
        signing_key: &rns_crypto::ed25519::Ed25519PrivateKey,
    ) -> Result<(), MessageError> {
        let (signed_data, message_hash) = self.signed_data_for_signing()?;

        self.signature = Some(signing_key.sign(&signed_data));
        self.hash = Some(message_hash);
        self.message_id = Some(message_hash);
        self.transient_id = Some(message_hash);
        self.state = MessageState::Outbound;
        Ok(())
    }

    /// Sign the message via an external signing function (hardware-identity variant of
    /// [`Self::sign`]). The signed blob is the same as [`Self::sign`]; `sign_fn` must return a
    /// 64-byte Ed25519 signature.
    pub fn sign_with<F, E>(&mut self, sign_fn: F) -> Result<(), MessageError>
    where
        F: FnOnce(&[u8]) -> Result<[u8; 64], E>,
        E: std::fmt::Display,
    {
        let (signed_data, message_hash) = self.signed_data_for_signing()?;

        let signature = sign_fn(&signed_data)
            .map_err(|e| MessageError::PackFailed(format!("signing failed: {e}")))?;

        self.signature = Some(signature);
        self.hash = Some(message_hash);
        self.message_id = Some(message_hash);
        self.transient_id = Some(message_hash);
        self.state = MessageState::Outbound;
        Ok(())
    }

    /// Verify the signature against `verify_key`. Signed blob matches [`Self::sign`].
    pub fn verify(&mut self, verify_key: &rns_crypto::ed25519::Ed25519PublicKey) -> bool {
        let sig = match self.signature {
            Some(s) => s,
            None => return false,
        };

        // Build the signed bytes once. Inbound wire payloads are borrowed and
        // their fifth stamp element is omitted by slicing the first four
        // encoded elements, avoiding an owned MessagePack value tree.
        let payload_capacity = self
            .wire_payload
            .as_ref()
            .map_or_else(|| self.packed_payload_len(None).unwrap_or(0), Vec::len);
        let mut signed_data = Vec::with_capacity(64 + payload_capacity);
        signed_data.extend_from_slice(&self.destination_hash);
        signed_data.extend_from_slice(&self.source_hash);
        if let Some(wire_payload) = self.wire_payload.as_deref() {
            if let Some(body) = first_four_msgpack_array_body(wire_payload) {
                signed_data.push(0x94);
                signed_data.extend_from_slice(body);
            } else {
                signed_data.extend_from_slice(wire_payload);
            }
        } else if self.write_payload(&mut signed_data, None).is_err() {
            return false;
        }
        let message_hash = sha256(&signed_data);
        signed_data.extend_from_slice(&message_hash);

        let valid = verify_key.verify(&signed_data, &sig).is_ok();
        self.signature_validated = valid;
        if valid {
            // Fields now own the canonical values needed by the application;
            // the full duplicate wire payload is no longer needed.
            self.wire_payload = None;
        }
        valid
    }

    /// Generate or retrieve the PoW stamp for this message.
    ///
    /// Priority:
    /// 1. If an outbound ticket is set, derive a ticket-based stamp
    ///    `stamp = truncated_hash(ticket || message_id)`.
    /// 2. If no [`stamp_cost`](Self::stamp_cost) is set, no stamp is needed.
    /// 3. If a stamp is already cached, return it.
    /// 4. Otherwise, generate a PoW stamp matching the required cost.
    ///
    /// Python reference: LXMessage.py:301-332.
    pub fn get_stamp(&mut self) -> Option<Vec<u8>> {
        if let (Some(ticket), Some(message_id)) = (self.outbound_ticket, self.message_id) {
            let mut material = Vec::with_capacity(TICKET_LENGTH + 32);
            material.extend_from_slice(&ticket);
            material.extend_from_slice(&message_id);
            let hash = truncated_hash(&material).to_vec();
            self.stamp_value = Some(COST_TICKET);
            self.stamp = Some(hash.clone());
            return Some(hash);
        }

        // 2. No stamp cost required
        if self.stamp_cost.is_none() {
            self.stamp_value = None;
            return None;
        }

        // 3. Stamp already generated
        if let Some(stamp) = self.stamp.as_ref() {
            return Some(stamp.clone());
        }

        // 4. Generate PoW stamp
        let cost = self.stamp_cost.unwrap();
        if let Some(message_id) = self.message_id {
            if let Some((stamp, value)) =
                crate::stamper::generate_stamp(&message_id, cost, STAMP_WORKBLOCK_EXPAND_ROUNDS)
            {
                self.stamp_value = Some(value as u16);
                self.stamp = Some(stamp.to_vec());
                return Some(stamp.to_vec());
            }
        }

        None
    }

    /// Validate a stamp on this message.
    ///
    /// Python reference: LXMessage.py:278-299
    ///
    /// Priority order:
    ///   1. Check against tickets first: `stamp == truncated_hash(ticket + message_id)`
    ///   2. If no ticket match, validate as PoW stamp
    pub fn validate_stamp_with_tickets(
        &mut self,
        target_cost: u8,
        tickets: Option<&[Vec<u8>]>,
    ) -> bool {
        let message_id = match self.message_id.or(self.hash) {
            Some(id) => id,
            None => return false,
        };

        // A missing stamp can never match a ticket hash or a PoW workblock,
        // so it is always invalid (Python `validate_stamp`: the ticket loop
        // compares `self.stamp == hash`, which is False when stamp is None,
        // then `if self.stamp == None: return False`).
        let stamp = match self.stamp.as_deref() {
            Some(s) => s,
            None => return false,
        };

        // Ticket-based stamps take precedence over PoW.
        if let Some(ticket_list) = tickets {
            for ticket in ticket_list {
                let mut material = Vec::with_capacity(ticket.len() + 32);
                material.extend_from_slice(ticket);
                material.extend_from_slice(&message_id);
                let expected = truncated_hash(&material);
                if stamp == expected.as_ref() {
                    self.stamp_value = Some(COST_TICKET);
                    return true;
                }
            }
        }

        let Ok(stamp) = <&[u8; 32]>::try_from(stamp) else {
            return false;
        };
        let workblock = crate::stamper::stamp_workblock(&message_id, STAMP_WORKBLOCK_EXPAND_ROUNDS);
        if crate::stamper::stamp_valid(stamp, target_cost, &workblock) {
            self.stamp_value = Some(crate::stamper::stamp_value(&workblock, stamp) as u16);
            return true;
        }

        false
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

        let packed = self.pack()?;
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
        let packed = self.pack()?;
        let container = MessageContainer {
            state: self.state as u8,
            lxmf_bytes: packed,
            transport_encrypted: self.transport_encrypted,
            transport_encryption: self.transport_encryption.clone(),
            method: self.method as u8,
        };
        rmp_serde::to_vec(&container).map_err(|e| MessageError::PackFailed(e.to_string()))
    }

    /// Unpack a message from a container (Python parity: `unpack_from_file` in LXMessage.py).
    pub fn unpack_container(data: &[u8]) -> Result<Self, MessageError> {
        let container: MessageContainer =
            rmp_serde::from_slice(data).map_err(|e| MessageError::UnpackFailed(e.to_string()))?;

        let mut msg = Self::unpack(&container.lxmf_bytes)?;

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
        let hash = self.hash.ok_or(MessageError::NotSigned)?;
        let file_name = rns_crypto::hex_encode(&hash);
        let file_path = format!("{directory_path}/{file_name}");

        let container_data = self.pack_container()?;
        crate::persist::write_file_atomic(std::path::Path::new(&file_path), &container_data)
            .map_err(|e| MessageError::PackFailed(format!("write failed: {e}")))?;

        Ok(file_path)
    }

    /// Read a message from a container file (Python parity: `unpack_from_file`).
    pub fn read_from_file(file_path: &str) -> Result<Self, MessageError> {
        let data = std::fs::read(file_path)
            .map_err(|e| MessageError::UnpackFailed(format!("read failed: {e}")))?;
        Self::unpack_container(&data)
    }
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

fn read_msgpack_string_or_binary<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], MessageError> {
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

fn read_msgpack_text_or_empty(input: &mut &[u8]) -> Result<String, MessageError> {
    if input
        .first()
        .is_some_and(|marker| matches!(*marker, 0xa0..=0xbf | 0xc4..=0xc6 | 0xd9..=0xdb))
    {
        return Ok(String::from_utf8_lossy(read_msgpack_string_or_binary(input)?).into_owned());
    }
    skip_msgpack_value(input, 0)?;
    Ok(String::new())
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

fn read_msgpack_integer_u8(input: &mut &[u8]) -> Result<u8, MessageError> {
    let marker = take_msgpack(input, 1)?[0];
    let value = match marker {
        0x00..=0x7f => u64::from(marker),
        0xe0..=0xff => i64::from(marker as i8) as u64,
        0xcc => u64::from(take_msgpack(input, 1)?[0]),
        0xcd => u64::from(u16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        )),
        0xce => u64::from(u32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        )),
        0xcf => u64::from_be_bytes(take_msgpack(input, 8)?.try_into().expect("exact length")),
        0xd0 => i64::from(i8::from_be_bytes(
            take_msgpack(input, 1)?.try_into().expect("exact length"),
        )) as u64,
        0xd1 => i64::from(i16::from_be_bytes(
            take_msgpack(input, 2)?.try_into().expect("exact length"),
        )) as u64,
        0xd2 => i64::from(i32::from_be_bytes(
            take_msgpack(input, 4)?.try_into().expect("exact length"),
        )) as u64,
        0xd3 => {
            i64::from_be_bytes(take_msgpack(input, 8)?.try_into().expect("exact length")) as u64
        }
        _ => {
            return Err(MessageError::UnpackFailed(
                "expected MessagePack integer".to_string(),
            ));
        }
    };
    Ok(value as u8)
}

fn skip_msgpack_value(input: &mut &[u8], depth: usize) -> Result<(), MessageError> {
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

struct PropagationWrapperRef<'a> {
    timestamp: f64,
    entries: &'a [&'a [u8]],
}

impl serde::Serialize for PropagationWrapperRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(2)?;
        tup.serialize_element(&self.timestamp)?;
        tup.serialize_element(&PropagationEntriesRef(self.entries))?;
        tup.end()
    }
}

struct PropagationEntriesRef<'a>(&'a [&'a [u8]]);

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

/// Msgpack payload. Title and content serialize as `bin` (not `str`) to match Python's
/// `msgpack.packb(bytes_obj)` and C++'s `mpPackBin()`.
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
    #[serde(with = "field_map_serde")]
    pub fields: BTreeMap<u8, Vec<u8>>,
    #[serde(skip)]
    pub msgpack_field_ids: BTreeSet<u8>,
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

/// Custom serde for `BTreeMap<u8, Vec<u8>>` so field values serialize as msgpack `bin` rather
/// than arrays of ints, matching Python's `msgpack.packb(bytes_obj)`.
mod field_map_serde {
    use super::*;
    use serde::de::{self, MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    struct BytesWrapper<'a>(&'a [u8]);

    impl serde::Serialize for BytesWrapper<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    pub fn serialize<S>(map: &BTreeMap<u8, Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(k, &BytesWrapper(v))?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<u8, Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldMapVisitor;

        impl<'de> Visitor<'de> for FieldMapVisitor {
            type Value = BTreeMap<u8, Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map with u8 keys and byte values")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                const MAX_FIELD_SIZE: usize = 256 * 1024; // 256 KiB per field
                const MAX_TOTAL_FIELDS_SIZE: usize = 1024 * 1024; // 1 MiB total

                let mut map = BTreeMap::new();
                let mut total_size = 0usize;
                while let Some((key, value)) = access
                    .next_entry::<u8, Vec<u8>>()
                    .map_err(de::Error::custom)?
                {
                    if value.len() > MAX_FIELD_SIZE {
                        return Err(de::Error::custom("field exceeds maximum size"));
                    }
                    total_size += value.len();
                    if total_size > MAX_TOTAL_FIELDS_SIZE {
                        return Err(de::Error::custom("total fields size exceeds maximum"));
                    }
                    map.insert(key, value);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(FieldMapVisitor)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_message() {
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Hello",
            "World",
            DeliveryMethod::Direct,
        );
        assert_eq!(msg.state, MessageState::Generating);
        assert_eq!(msg.method, DeliveryMethod::Direct);
        assert!(msg.timestamp > 0.0);
        assert!(msg.signature.is_none());
        assert!(!msg.signature_validated);
        // Mirror Python LXMessage.py:145 default.
        assert!(msg.auto_compress);
    }

    #[test]
    fn test_register_delivery_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        let delivered = Arc::new(AtomicBool::new(false));
        let delivered_clone = delivered.clone();
        msg.register_delivery_callback(move |_m| {
            delivered_clone.store(true, Ordering::Relaxed);
        });

        msg.mark_delivered();
        assert_eq!(msg.state, MessageState::Delivered);
        assert!(delivered.load(Ordering::Relaxed));
    }

    #[test]
    fn test_register_failed_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        let failed = Arc::new(AtomicBool::new(false));
        let failed_clone = failed.clone();
        msg.register_failed_callback(move |_m| {
            failed_clone.store(true, Ordering::Relaxed);
        });

        msg.mark_failed();
        assert_eq!(msg.state, MessageState::Failed);
        assert!(failed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_determine_compression_support() {
        let mut msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);

        let supported = {
            use rmpv::Value;
            let arr = Value::Array(vec![
                Value::Binary(b"Peer".to_vec()),
                Value::from(8u64),
                Value::Array(vec![Value::from(crate::constants::SF_COMPRESSION as u64)]),
            ]);
            crate::encode_value(&arr)
        };
        msg.determine_compression_support(Some(&supported));
        assert!(msg.auto_compress);

        // Explicit feature list omitting SF_COMPRESSION disables compression.
        let no_compression = {
            use rmpv::Value;
            let arr = Value::Array(vec![
                Value::Binary(b"Peer".to_vec()),
                Value::from(8u64),
                Value::Array(vec![]),
            ]);
            crate::encode_value(&arr)
        };
        msg.determine_compression_support(Some(&no_compression));
        assert!(!msg.auto_compress);

        // Legacy <=0.9.8 2-element announce has no feature list — fail-open
        // (Python compression_support_from_app_data returns True, LXMF.py:160).
        let python_098 = {
            use rmpv::Value;
            let arr = Value::Array(vec![Value::Binary(b"Peer".to_vec()), Value::from(8u64)]);
            crate::encode_value(&arr)
        };
        msg.determine_compression_support(Some(&python_098));
        assert!(msg.auto_compress);

        // No peer data at all — defaults to compression on (LXMessage.py:513).
        msg.auto_compress = false;
        msg.determine_compression_support(None);
        assert!(msg.auto_compress);
    }

    #[test]
    fn test_source_blackholed_defaults_false() {
        // LXMessage.py:172 — source_blackholed initialises false; embedders
        // flip it from the transport blackhole tables after unpacking.
        let msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", DeliveryMethod::Direct);
        assert!(!msg.source_blackholed);

        let mut outbound = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Title",
            "Content",
            DeliveryMethod::Direct,
        );
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        outbound.sign(&key).unwrap();
        let packed = outbound.pack().unwrap();
        let unpacked = LxMessage::unpack(&packed).unwrap();
        assert!(!unpacked.source_blackholed);
    }

    #[test]
    fn test_pack_payload() {
        let msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        let payload = msg.pack_payload().unwrap();
        assert!(!payload.is_empty());
    }

    #[test]
    fn test_streamed_payload_byte_identical_to_owned() {
        // The direct writer must produce the same bytes as the serde model for
        // every ordinary-field stamp variant the protocol emits.
        let mut fields = BTreeMap::new();
        fields.insert(FIELD_IMAGE, b"\x00\x01\x02\x03".to_vec());
        fields.insert(FIELD_AUDIO, b"audio-bytes".to_vec());

        let cases = [None, Some(vec![0xAB; 32]), Some(vec![0xCD; TICKET_LENGTH])];
        for stamp in cases.iter() {
            let owned = MessagePayload {
                timestamp: 1700000000.0,
                title: "title".to_string(),
                content: "content body \u{1F600}".to_string(),
                fields: fields.clone(),
                msgpack_field_ids: BTreeSet::new(),
                stamp: stamp.clone(),
            };
            let owned_bytes = rmp_serde::to_vec(&owned).unwrap();
            let mut message = LxMessage::new(
                [0xAA; 16],
                [0xBB; 16],
                "title",
                "content body \u{1F600}",
                DeliveryMethod::Direct,
            );
            message.timestamp = 1700000000.0;
            message.fields = fields.clone();
            message.stamp = stamp.clone();
            let streamed_bytes = message.pack_payload().unwrap();
            assert_eq!(
                owned_bytes,
                streamed_bytes,
                "streamed serializer drifted for stamp={:?}",
                stamp.is_some()
            );
        }
    }

    #[test]
    fn test_sign_and_verify() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let pub_key = key.public_key();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Signed Message",
            "Content here",
            DeliveryMethod::Direct,
        );

        msg.sign(&key).unwrap();
        assert!(msg.signature.is_some());
        assert_eq!(msg.state, MessageState::Outbound);

        assert!(msg.verify(&pub_key));
        assert!(msg.signature_validated);
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let wrong_key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let wrong_pub = wrong_key.public_key();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        assert!(!msg.verify(&wrong_pub));
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Round Trip",
            "Full content test",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();

        let packed = msg.pack().unwrap();
        assert!(packed.len() > 96);
        let unpacked = LxMessage::unpack(&packed).unwrap();

        assert_eq!(unpacked.destination_hash, msg.destination_hash);
        assert_eq!(unpacked.source_hash, msg.source_hash);
        assert_eq!(unpacked.title, msg.title);
        assert_eq!(unpacked.content, msg.content);
        assert_eq!(unpacked.signature, msg.signature);
        assert!(unpacked.hash.is_some());
        assert!(unpacked.transient_id.is_some());
    }

    #[test]
    fn test_pack_propagated_unpack_roundtrip() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated Round Trip",
            "Full content test",
            DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();

        let packed = msg.pack_propagated().unwrap();
        let unpacked = LxMessage::unpack_propagated(&packed).unwrap();

        assert_eq!(unpacked.destination_hash, [0xAA; 16]);
        assert_eq!(unpacked.source_hash, [0xBB; 16]);
        assert_eq!(unpacked.title, msg.title);
        assert_eq!(unpacked.content, msg.content);
    }

    #[test]
    fn test_fields() {
        let mut msg = LxMessage::new([0; 16], [0; 16], "", "", DeliveryMethod::Direct);
        msg.set_field(FIELD_IMAGE, vec![1, 2, 3]);
        assert_eq!(msg.get_field(FIELD_IMAGE), Some(&vec![1, 2, 3]));
        assert_eq!(msg.get_field(FIELD_AUDIO), None);
    }

    #[test]
    fn test_msgpack_field_serializes_as_native_value() {
        use std::io::Cursor;

        let image_value = rmpv::Value::Array(vec![
            rmpv::Value::String("png".into()),
            rmpv::Value::Binary(vec![0x89, b'P', b'N', b'G']),
        ]);
        let mut image_bytes = Vec::new();
        rmpv::encode::write_value(&mut image_bytes, &image_value).unwrap();

        let mut msg = LxMessage::new(
            [0x11; 16],
            [0x22; 16],
            "Image",
            "Has image",
            DeliveryMethod::Direct,
        );
        msg.set_msgpack_field(FIELD_IMAGE, image_bytes.clone())
            .unwrap();

        let payload = msg.pack_payload().unwrap();
        let value = rmpv::decode::read_value(&mut Cursor::new(&payload)).unwrap();
        let arr = value.as_array().unwrap();
        let fields = arr[3].as_map().unwrap();
        let (_, field_value) = fields
            .iter()
            .find(|(k, _)| k.as_u64() == Some(FIELD_IMAGE as u64))
            .expect("FIELD_IMAGE present");
        assert!(
            field_value.as_array().is_some(),
            "FIELD_IMAGE must be an LXMF array value, not a bin-wrapped msgpack blob"
        );

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        msg.sign(&key).unwrap();
        let packed = msg.pack().unwrap();
        let unpacked = LxMessage::unpack(&packed).unwrap();
        assert_eq!(unpacked.get_field(FIELD_IMAGE), Some(&image_bytes));
        assert!(unpacked.msgpack_field_ids.contains(&FIELD_IMAGE));
    }

    #[test]
    fn test_file_attachment_field_serializes_as_native_lxmf_shape() {
        use std::io::Cursor;

        let attachment_value = rmpv::Value::Array(vec![rmpv::Value::Array(vec![
            rmpv::Value::String("note.txt".into()),
            rmpv::Value::Binary(b"hello".to_vec()),
        ])]);
        let mut attachment_bytes = Vec::new();
        rmpv::encode::write_value(&mut attachment_bytes, &attachment_value).unwrap();

        let mut msg = LxMessage::new(
            [0x11; 16],
            [0x22; 16],
            "File",
            "Has file",
            DeliveryMethod::Direct,
        );
        msg.set_msgpack_field(FIELD_FILE_ATTACHMENTS, attachment_bytes.clone())
            .unwrap();

        let payload = msg.pack_payload().unwrap();
        let value = rmpv::decode::read_value(&mut Cursor::new(&payload)).unwrap();
        let arr = value.as_array().unwrap();
        let fields = arr[3].as_map().unwrap();
        let (_, field_value) = fields
            .iter()
            .find(|(k, _)| k.as_u64() == Some(FIELD_FILE_ATTACHMENTS as u64))
            .expect("FIELD_FILE_ATTACHMENTS present");
        let attachment = field_value.as_array().unwrap()[0].as_array().unwrap();
        assert_eq!(attachment[0].as_str(), Some("note.txt"));
        assert_eq!(attachment[1].as_slice(), Some(&b"hello"[..]));

        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        msg.sign(&key).unwrap();
        let packed = msg.pack().unwrap();
        let unpacked = LxMessage::unpack(&packed).unwrap();
        assert_eq!(
            unpacked.get_field(FIELD_FILE_ATTACHMENTS),
            Some(&attachment_bytes)
        );
        assert!(unpacked.msgpack_field_ids.contains(&FIELD_FILE_ATTACHMENTS));
    }

    #[test]
    fn typed_image_field_matches_existing_msgpack_wire_value() {
        let image_bytes = [0x89, b'P', b'N', b'G'];
        let expected_value = rmpv::Value::Array(vec![
            rmpv::Value::String("png".into()),
            rmpv::Value::Binary(image_bytes.to_vec()),
        ]);
        let mut expected = Vec::new();
        rmpv::encode::write_value(&mut expected, &expected_value).unwrap();

        let mut msg = LxMessage::new([0; 16], [0; 16], "", "", DeliveryMethod::Direct);
        msg.set_image_field("png", &image_bytes).unwrap();

        assert_eq!(msg.get_field(FIELD_IMAGE), Some(&expected));
        assert!(msg.msgpack_field_ids.contains(&FIELD_IMAGE));
    }

    #[test]
    fn typed_file_attachment_matches_existing_msgpack_wire_value() {
        let file_bytes = b"hello";
        let expected_value = rmpv::Value::Array(vec![rmpv::Value::Array(vec![
            rmpv::Value::String("note.txt".into()),
            rmpv::Value::Binary(file_bytes.to_vec()),
        ])]);
        let mut expected = Vec::new();
        rmpv::encode::write_value(&mut expected, &expected_value).unwrap();

        let mut msg = LxMessage::new([0; 16], [0; 16], "", "", DeliveryMethod::Direct);
        msg.set_file_attachment_field("note.txt", file_bytes)
            .unwrap();

        assert_eq!(msg.get_field(FIELD_FILE_ATTACHMENTS), Some(&expected));
        assert!(msg.msgpack_field_ids.contains(&FIELD_FILE_ATTACHMENTS));
    }

    #[test]
    fn native_attachment_decoders_borrow_large_payload_bytes() {
        let file_bytes = vec![0x5a; 2 * 1024 * 1024];
        let mut msg = LxMessage::new([0; 16], [0; 16], "", "", DeliveryMethod::Direct);
        msg.set_file_attachment_field("large.bin", &file_bytes)
            .unwrap();
        let encoded = msg.get_field(FIELD_FILE_ATTACHMENTS).unwrap();
        let encoded_start = encoded.as_ptr() as usize;
        let encoded_end = encoded_start + encoded.len();
        let (name, borrowed) = msg.first_file_attachment().unwrap().unwrap();
        assert_eq!(name, "large.bin");
        assert_eq!(borrowed, file_bytes);
        assert!((encoded_start..encoded_end).contains(&(borrowed.as_ptr() as usize)));

        msg.set_image_field("webp", &file_bytes).unwrap();
        let encoded = msg.get_field(FIELD_IMAGE).unwrap();
        let encoded_start = encoded.as_ptr() as usize;
        let encoded_end = encoded_start + encoded.len();
        let (format, borrowed) = msg.image_attachment().unwrap().unwrap();
        assert_eq!(format, "webp");
        assert_eq!(borrowed, file_bytes);
        assert!((encoded_start..encoded_end).contains(&(borrowed.as_ptr() as usize)));
    }

    #[test]
    fn verified_inbound_attachment_releases_duplicate_wire_payload() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut outbound = LxMessage::new(
            [0x11; 16],
            [0x22; 16],
            "",
            "large inbound",
            DeliveryMethod::Direct,
        );
        outbound
            .set_file_attachment_field("large.bin", &vec![0x77; 2 * 1024 * 1024])
            .unwrap();
        outbound.sign(&key).unwrap();
        outbound.stamp = Some(vec![0x44; TICKET_LENGTH]);
        let packed = outbound.pack().unwrap();

        let mut inbound = LxMessage::unpack(&packed).unwrap();
        assert!(inbound.wire_payload.is_some());
        assert!(inbound.verify(&key.public_key()));
        assert!(inbound.wire_payload.is_none());
        let (name, data) = inbound.first_file_attachment().unwrap().unwrap();
        assert_eq!(name, "large.bin");
        assert_eq!(data.len(), 2 * 1024 * 1024);
    }

    #[test]
    fn exact_packed_len_matches_wire_without_allocating_a_second_message() {
        let mut msg = LxMessage::new(
            [0x11; 16],
            [0x22; 16],
            "title",
            "content",
            DeliveryMethod::Direct,
        );
        msg.set_file_attachment_field("large.bin", &vec![0x5a; 2 * 1024 * 1024])
            .unwrap();
        msg.signature = Some([0x33; 64]);
        assert_eq!(msg.packed_len().unwrap(), msg.pack().unwrap().len());
    }

    #[test]
    fn test_state_transitions() {
        let mut msg = LxMessage::new([0; 16], [0; 16], "", "", DeliveryMethod::Direct);
        assert_eq!(msg.state, MessageState::Generating);

        msg.state = MessageState::Outbound;
        msg.cancel();
        assert_eq!(msg.state, MessageState::Cancelled);
    }

    #[test]
    fn test_base64url_roundtrip() {
        use base64::Engine;
        let data = b"Hello, LXMF World! This is a test message.";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_paper_uri() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();

        let mut msg = LxMessage::new(
            [0x11; 16],
            [0x22; 16],
            "Paper",
            "Message",
            DeliveryMethod::Paper,
        );
        msg.sign(&key).unwrap();

        let uri = msg
            .to_paper_uri(|plaintext| Ok(plaintext.to_vec()))
            .unwrap();
        assert!(uri.starts_with("lxm://"));

        let decoded =
            LxMessage::from_paper_uri(&uri, |ciphertext| Ok(ciphertext.to_vec())).unwrap();
        assert_eq!(decoded.destination_hash, msg.destination_hash);
        assert_eq!(decoded.title, "Paper");
        assert_eq!(decoded.method, DeliveryMethod::Paper);
        assert_eq!(decoded.representation, DeliveryRepresentation::Paper);
    }

    #[test]
    fn test_paper_uri_uses_identity_encryption() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let recipient = rns_identity::identity::Identity::new();

        let mut msg = LxMessage::new(
            recipient.hash,
            [0xBB; 16],
            "Paper",
            "encrypted",
            DeliveryMethod::Paper,
        );
        msg.sign(&key).unwrap();
        let plaintext_tail = msg.pack().unwrap()[DESTINATION_LENGTH..].to_vec();

        let uri = msg
            .to_paper_uri(|plaintext| {
                recipient
                    .encrypt(plaintext, None)
                    .map_err(|e| MessageError::PackFailed(e.to_string()))
            })
            .unwrap();
        let (dest_hash, encrypted_tail) = LxMessage::decode_paper_uri(&uri).unwrap();
        assert_eq!(dest_hash, recipient.hash);
        assert_ne!(encrypted_tail, plaintext_tail);

        let decoded = LxMessage::from_paper_uri(&uri, |ciphertext| {
            recipient
                .decrypt(ciphertext, None, false)
                .map_err(|e| MessageError::UnpackFailed(e.to_string()))
        })
        .unwrap();
        assert_eq!(decoded.destination_hash, recipient.hash);
        assert_eq!(decoded.content, "encrypted");
    }

    #[test]
    fn test_sign_sets_hash() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Hash",
            "Content",
            DeliveryMethod::Direct,
        );
        assert!(msg.hash.is_none());
        msg.sign(&key).unwrap();
        assert!(msg.hash.is_some());
        // SHA-256(dest_hash || src_hash || payload)
        let payload = msg.pack_payload().unwrap();
        let mut hashed_part = Vec::new();
        hashed_part.extend_from_slice(&msg.destination_hash);
        hashed_part.extend_from_slice(&msg.source_hash);
        hashed_part.extend_from_slice(&payload);
        let expected = rns_crypto::sha::sha256(&hashed_part);
        assert_eq!(msg.hash.unwrap(), expected);
    }

    #[test]
    fn test_unpack_sets_python_message_id() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Hash",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        let expected = msg.hash.unwrap();

        let unpacked = LxMessage::unpack(&msg.pack().unwrap()).unwrap();

        assert_eq!(unpacked.hash, Some(expected));
        assert_eq!(unpacked.message_id, Some(expected));
    }

    #[test]
    fn test_unpack_hash_strips_stamp() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Stamped",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        let expected = msg.hash.unwrap();
        msg.stamp = Some(vec![0x42; 32]);

        let unpacked = LxMessage::unpack(&msg.pack().unwrap()).unwrap();

        assert_eq!(unpacked.hash, Some(expected));
        assert_eq!(unpacked.message_id, Some(expected));
    }

    #[test]
    fn test_sign_verify_with_message_hash_appended() {
        // Signed data = dest_hash || src_hash || payload || SHA256(dest_hash || src_hash || payload)
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let pub_key = key.public_key();

        let mut msg = LxMessage::new(
            [0x11; 16],
            [0x22; 16],
            "Test",
            "Body",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();

        let payload = msg.pack_payload().unwrap();
        let mut hashed_part = Vec::new();
        hashed_part.extend_from_slice(&msg.destination_hash);
        hashed_part.extend_from_slice(&msg.source_hash);
        hashed_part.extend_from_slice(&payload);
        let message_hash = rns_crypto::sha::sha256(&hashed_part);
        let mut signed_data = hashed_part;
        signed_data.extend_from_slice(&message_hash);

        let sig = msg.signature.unwrap();
        assert!(pub_key.verify(&signed_data, &sig).is_ok());
        assert!(msg.verify(&pub_key));
    }

    #[test]
    fn test_unpack_bin_encoded_title_content() {
        // Interop: C++/Python senders emit title/content as msgpack `bin`, not `str`.
        // Hand-build a 4-element payload: [timestamp, title(bin), content(bin), fields(map)].
        let mut payload = Vec::new();

        // fixarray of 4 elements
        payload.push(0x94);

        // float64 timestamp
        payload.push(0xCB);
        payload.extend_from_slice(&1700000000.0_f64.to_be_bytes());

        // bin8 "Hello"
        payload.push(0xC4);
        payload.push(5);
        payload.extend_from_slice(b"Hello");

        // bin8 "World body"
        payload.push(0xC4);
        payload.push(10);
        payload.extend_from_slice(b"World body");

        // fixmap of 0 elements
        payload.push(0x80);

        let mut wire = Vec::new();
        wire.extend_from_slice(&[0xAA; 16]);
        wire.extend_from_slice(&[0xBB; 16]);
        wire.extend_from_slice(&[0x00; 64]);
        wire.extend_from_slice(&payload);

        let msg = LxMessage::unpack(&wire).unwrap();
        assert_eq!(msg.title, "Hello");
        assert_eq!(msg.content, "World body");
        assert_eq!(msg.destination_hash, [0xAA; 16]);
        assert_eq!(msg.source_hash, [0xBB; 16]);
    }

    #[test]
    fn test_unpack_too_short() {
        assert!(LxMessage::unpack(&[0; 10]).is_err());
        // 96-byte header alone is too short -- payload is required
        assert!(LxMessage::unpack(&[0; 96]).is_err());
    }

    #[test]
    fn test_pack_unpack_container_roundtrip() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Container Test",
            "Content for container",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        msg.state = MessageState::Delivered;
        msg.transport_encrypted = true;
        msg.transport_encryption = Some("Curve25519".to_string());

        let container_data = msg.pack_container().unwrap();
        assert!(!container_data.is_empty());

        let unpacked = LxMessage::unpack_container(&container_data).unwrap();
        assert_eq!(unpacked.state, MessageState::Delivered);
        assert_eq!(unpacked.method, DeliveryMethod::Direct);
        assert!(unpacked.transport_encrypted);
        assert_eq!(unpacked.transport_encryption.as_deref(), Some("Curve25519"));
        assert_eq!(unpacked.title, "Container Test");
        assert_eq!(unpacked.content, "Content for container");
    }

    #[test]
    fn test_pack_unpack_container_method_variants() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        for method in [
            DeliveryMethod::Paper,
            DeliveryMethod::Direct,
            DeliveryMethod::Propagated,
        ] {
            let mut msg = LxMessage::new([0xAA; 16], [0xBB; 16], "t", "c", method);
            msg.sign(&key).unwrap();
            let unpacked = LxMessage::unpack_container(&msg.pack_container().unwrap()).unwrap();
            assert_eq!(
                unpacked.method, method,
                "method round-trip for {:?}",
                method
            );
        }
    }

    #[test]
    fn test_new_message_fields() {
        let msg = LxMessage::new([0; 16], [0; 16], "", "", DeliveryMethod::Direct);
        assert_eq!(msg.representation, DeliveryRepresentation::Unknown);
        assert!(msg.unverified_reason.is_none());
        assert!(!msg.transport_encrypted);
        assert!(!msg.incoming);
        assert_eq!(msg.progress, 0.0);
    }

    #[test]
    fn test_compute_hash() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Hash Test",
            "Content",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        let hash = msg.compute_hash().unwrap();
        assert_ne!(hash, [0u8; 32]);
        assert!(msg.transient_id.is_some());
    }

    #[test]
    fn test_sign_sets_message_id() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Content",
            DeliveryMethod::Direct,
        );
        assert!(msg.message_id.is_none());
        msg.sign(&key).unwrap();
        assert!(msg.message_id.is_some());
        assert_eq!(msg.message_id, msg.hash);
    }

    #[test]
    fn test_pack_propagated_encrypted() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Propagated Encrypted",
            "Content body here",
            DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();

        let (propagation_packed, tid) = msg
            .pack_propagated_encrypted(|plaintext| {
                // Marker-byte prepend stands in for real encryption
                let mut out = vec![0xFF];
                out.extend_from_slice(plaintext);
                Ok(out)
            })
            .unwrap();

        assert!(!propagation_packed.is_empty());
        assert_eq!(msg.transient_id, Some(tid));
        assert_ne!(tid, [0u8; 32]);

        let (ts, entries) = LxMessage::unpack_propagation_wrapper(&propagation_packed).unwrap();
        assert!(ts > 0.0);
        assert_eq!(entries.len(), 1);

        let raw_wrapper =
            rmpv::decode::read_value(&mut std::io::Cursor::new(&propagation_packed)).unwrap();
        match raw_wrapper {
            rmpv::Value::Array(items) => match &items[1] {
                rmpv::Value::Array(entries) => {
                    assert!(matches!(entries.first(), Some(rmpv::Value::Binary(_))));
                }
                other => panic!("propagation entries should be msgpack array, got {other:?}"),
            },
            other => panic!("propagation wrapper should be msgpack array, got {other:?}"),
        }

        let lxmf_data = &entries[0];
        assert_eq!(&lxmf_data[..16], &[0xAA; 16]);
    }

    /// T0-7: the bounded wrapper decode must reject CPU-amplification shapes
    /// (junk-stuffed entry lists) cheaply, before per-entry stamp validation
    /// could build any ~256 KB workblocks; legitimate transfers still pass.
    #[test]
    fn test_unpack_propagation_wrapper_bounded() {
        let entry_floor = LxMessage::MIN_PROPAGATION_ENTRY_SIZE;
        let limit = 16 * 1024;

        // Hostile: thousands of tiny entries in a small blob.
        let junk: Vec<Vec<u8>> = (0..2000).map(|_| vec![0xAB; 3]).collect();
        let hostile = rmp_serde::to_vec(&(1000.0f64, junk)).unwrap();
        assert!(hostile.len() <= limit, "test blob must fit the limit");
        assert!(LxMessage::unpack_propagation_wrapper_bounded(&hostile, limit).is_err());

        // Hostile: a single under-floor entry hidden among valid-sized ones.
        let mixed: Vec<Vec<u8>> = vec![vec![0xAB; entry_floor], vec![0xAB; entry_floor - 1]];
        let mixed_blob = rmp_serde::to_vec(&(1000.0f64, mixed)).unwrap();
        assert!(LxMessage::unpack_propagation_wrapper_bounded(&mixed_blob, limit).is_err());

        // Hostile: blob bigger than the configured transfer limit.
        let oversize: Vec<Vec<u8>> = vec![vec![0xAB; 2 * limit]];
        let oversize_blob = rmp_serde::to_vec(&(1000.0f64, oversize)).unwrap();
        assert!(LxMessage::unpack_propagation_wrapper_bounded(&oversize_blob, limit).is_err());

        // Legitimate multi-entry sync passes and round-trips.
        let good: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; entry_floor + 64]).collect();
        let good_blob = rmp_serde::to_vec(&(1000.0f64, good.clone())).unwrap();
        let (ts, entries) =
            LxMessage::unpack_propagation_wrapper_bounded(&good_blob, limit).unwrap();
        assert_eq!(ts, 1000.0);
        assert_eq!(entries, good);
    }

    #[test]
    fn test_pack_opportunistic_encrypted_strips_destination_hash() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Opportunistic",
            "Content body here",
            DeliveryMethod::Opportunistic,
        );
        msg.sign(&key).unwrap();
        let packed = msg.pack().unwrap();
        let expected_tail = packed[DESTINATION_LENGTH..].to_vec();

        let encrypted = msg
            .pack_opportunistic_encrypted(|plaintext| {
                assert_eq!(plaintext, expected_tail.as_slice());
                let mut out = vec![0xEE];
                out.extend_from_slice(plaintext);
                Ok(out)
            })
            .unwrap();

        assert_eq!(encrypted[0], 0xEE);
        assert_eq!(&encrypted[1..], expected_tail.as_slice());
    }

    #[test]
    fn test_propagation_transient_id() {
        let lxmf_data = vec![0xAA; 100];
        let tid = LxMessage::compute_propagation_transient_id(&lxmf_data);
        assert_eq!(tid.len(), 32);

        let tid2 = LxMessage::compute_propagation_transient_id(&lxmf_data);
        assert_eq!(tid, tid2);

        let other_data = vec![0xBB; 100];
        let tid3 = LxMessage::compute_propagation_transient_id(&other_data);
        assert_ne!(tid, tid3);
    }

    #[test]
    fn test_propagation_transient_id_matches_full_hash() {
        use rns_crypto::sha::full_hash;

        let lxmf_data = vec![0x42; 200];
        let tid = LxMessage::compute_propagation_transient_id(&lxmf_data);
        let expected_full = full_hash(&lxmf_data);
        assert_eq!(tid, expected_full);
    }

    #[test]
    fn test_get_stamp_with_ticket() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Ticket",
            "Test",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();

        let ticket = [0x42; 16];
        msg.outbound_ticket = Some(ticket);

        let stamp = msg.get_stamp();
        assert!(stamp.is_some());
        assert_eq!(msg.stamp_value, Some(COST_TICKET));

        // stamp = truncated_hash(ticket || message_id)
        let message_id = msg.message_id.unwrap();
        let mut material = Vec::new();
        material.extend_from_slice(&ticket);
        material.extend_from_slice(&message_id);
        let expected = truncated_hash(&material).to_vec();
        assert_eq!(stamp.unwrap(), expected);
    }

    #[test]
    fn test_get_stamp_no_cost() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "NoCost",
            "Test",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        msg.stamp_cost = None;

        let stamp = msg.get_stamp();
        assert!(stamp.is_none());
        assert!(msg.stamp_value.is_none());
    }

    #[test]
    fn test_validate_stamp_with_ticket() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Validate Ticket",
            "Test",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();

        let ticket = vec![0x42; 16];
        let message_id = msg.message_id.unwrap();
        let mut material = Vec::new();
        material.extend_from_slice(&ticket);
        material.extend_from_slice(&message_id);
        let stamp = truncated_hash(&material).to_vec();
        msg.stamp = Some(stamp);

        let valid = msg.validate_stamp_with_tickets(16, Some(std::slice::from_ref(&ticket)));
        assert!(valid);
        assert_eq!(msg.stamp_value, Some(COST_TICKET));
    }

    #[test]
    fn test_validate_stamp_wrong_ticket() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Wrong Ticket",
            "Test",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        msg.stamp = Some(vec![0xFF; 32]);

        let valid = msg.validate_stamp_with_tickets(16, Some(&[vec![0x42; 16]]));
        // Must fail both the ticket check and the PoW check
        assert!(!valid);
    }

    #[test]
    fn test_validate_stamp_no_stamp() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "No Stamp",
            "Test",
            DeliveryMethod::Direct,
        );
        msg.sign(&key).unwrap();
        msg.stamp = None;

        let valid = msg.validate_stamp_with_tickets(16, None);
        assert!(!valid);
    }

    #[test]
    fn test_pack_propagated_encrypted_with_prop_stamp() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Prop Stamp",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();
        msg.propagation_stamp = Some([0xDD; 32]);

        let (propagation_packed, _tid) = msg
            .pack_propagated_encrypted(|plaintext| Ok(plaintext.to_vec()))
            .unwrap();

        let (_, entries) = LxMessage::unpack_propagation_wrapper(&propagation_packed).unwrap();
        assert_eq!(entries.len(), 1);

        // lxmf_data = dest_hash(16) || encrypted_data || propagation_stamp(32)
        let lxmf_entry = &entries[0];
        assert_eq!(&lxmf_entry[..16], &[0xAA; 16]);
        let last_32 = &lxmf_entry[lxmf_entry.len() - 32..];
        assert_eq!(last_32, &[0xDD; 32]);
    }

    #[test]
    fn test_pack_propagated_encrypted_with_zero_cost_stamp() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();

        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Prop Stamp",
            "Content",
            DeliveryMethod::Propagated,
        );
        msg.sign(&key).unwrap();

        let (propagation_packed, _tid, _value) = msg
            .pack_propagated_encrypted_with_stamp(|plaintext| Ok(plaintext.to_vec()), 0)
            .unwrap();

        let (_, entries) = LxMessage::unpack_propagation_wrapper(&propagation_packed).unwrap();
        let lxmf_entry = &entries[0];
        assert_eq!(lxmf_entry.len(), msg.pack().unwrap().len() + 32);
        assert_eq!(&lxmf_entry[lxmf_entry.len() - 32..], &[0u8; 32]);
        assert!(crate::stamper::validate_pn_stamp(lxmf_entry, 0).is_some());
    }

    #[test]
    fn test_uri_roundtrip() {
        let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Test",
            "Hello via paper",
            DeliveryMethod::Paper,
        );
        msg.sign(&key).unwrap();

        let uri = msg.as_uri(|plaintext| Ok(plaintext.to_vec())).unwrap();
        assert!(uri.starts_with("lxm://"));

        let decoded = LxMessage::from_uri(&uri, |ciphertext| Ok(ciphertext.to_vec())).unwrap();
        assert_eq!(decoded.content, "Hello via paper");
        assert_eq!(decoded.title, "Test");
        assert_eq!(decoded.destination_hash, [0xAA; 16]);
        assert_eq!(decoded.source_hash, [0xBB; 16]);
    }

    #[test]
    fn test_from_uri_invalid_prefix() {
        let result =
            LxMessage::from_uri("https://example.com", |ciphertext| Ok(ciphertext.to_vec()));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_uri_invalid_base64() {
        let result = LxMessage::from_uri("lxm://not-valid-base64!!!", |ciphertext| {
            Ok(ciphertext.to_vec())
        });
        assert!(result.is_err());
    }

    use proptest::prelude::*;

    proptest! {
        /// Full LxMessage pack → unpack round-trip over the reasonable
        /// input space. Explicit `test_pack_unpack_roundtrip` uses one
        /// hand-picked case; proptest widens to arbitrary title/content
        /// strings, arbitrary dest/source hashes, and all sendable
        /// delivery methods. Catches msgpack/serde drift + unicode
        /// normalization bugs in the title/content payload.
        #[test]
        fn proptest_message_pack_unpack_roundtrip(
            destination_hash: [u8; 16],
            source_hash: [u8; 16],
            // Cap string length to keep the test fast; long content is
            // already covered by test_pack_unpack_container_roundtrip.
            title in ".{0,128}",
            content in ".{0,512}",
            method_idx in 0u8..=2,
        ) {
            let method = match method_idx {
                0 => DeliveryMethod::Opportunistic,
                1 => DeliveryMethod::Direct,
                _ => DeliveryMethod::Propagated,
            };
            let key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
            let mut msg = LxMessage::new(destination_hash, source_hash, &title, &content, method);
            msg.sign(&key).unwrap();

            let packed = msg.pack().unwrap();
            let unpacked = LxMessage::unpack(&packed).unwrap();

            prop_assert_eq!(unpacked.destination_hash, destination_hash);
            prop_assert_eq!(unpacked.source_hash, source_hash);
            prop_assert_eq!(&unpacked.title, &title);
            prop_assert_eq!(&unpacked.content, &content);
            prop_assert_eq!(unpacked.signature, msg.signature);
        }
    }
}
