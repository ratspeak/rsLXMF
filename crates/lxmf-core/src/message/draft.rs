//! Checked mutable construction followed by consuming signature/finalization.
use super::*;
use rns_crypto::ed25519::Ed25519PrivateKey;
/// Mutable outbound semantics. This type cannot be submitted as a wire message.
/// ```compile_fail
/// use lxmf_core::message::LxMessageDraft;
/// fn send_unsigned(draft: LxMessageDraft) { let _ = draft.wire_bytes(); }
/// ```
#[derive(Debug, Clone)]
pub struct LxMessageDraft {
    destination: [u8; 16],
    source: [u8; 16],
    title: Bytes,
    content: Bytes,
    timestamp: f64,
    fields: BTreeMap<FieldId, FieldValue>,
    limits: MessageDecodeLimits,
    pub metadata: MessageMetadata,
    pub include_ticket: bool,
    pub outbound_ticket: Option<[u8; 16]>,
    pub stamp_cost: Option<u8>,
    ticket_barrier: Option<Arc<()>>,
}
impl Deref for LxMessageDraft {
    type Target = MessageMetadata;
    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}
impl DerefMut for LxMessageDraft {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.metadata
    }
}
/// Frozen signed body awaiting its optional recipient stamp. Not a sendable type.
#[derive(Debug)]
pub struct SignedLxMessage {
    message: LxMessage,
    outbound_ticket: Option<[u8; 16]>,
    stamp_cost: Option<u8>,
}
impl Deref for SignedLxMessage {
    type Target = MessageMetadata;
    fn deref(&self) -> &Self::Target {
        &self.message.metadata
    }
}
impl DerefMut for SignedLxMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message.metadata
    }
}
impl LxMessageDraft {
    pub fn new(
        destination: [u8; 16],
        source: [u8; 16],
        title: &str,
        content: &str,
        method: DeliveryMethod,
    ) -> Result<Self, MessageError> {
        Self::new_with_limits(
            destination,
            source,
            title,
            content,
            method,
            MessageDecodeLimits::default(),
        )
    }
    pub fn new_with_limits(
        destination: [u8; 16],
        source: [u8; 16],
        title: &str,
        content: &str,
        method: DeliveryMethod,
        limits: MessageDecodeLimits,
    ) -> Result<Self, MessageError> {
        limits.check_wire(
            title
                .len()
                .checked_add(content.len())
                .and_then(|n| n.checked_add(110))
                .ok_or_else(|| MessageError::PackFailed("length overflow".into()))?,
        )?;
        let draft = Self {
            destination,
            source,
            title: Bytes::copy_from_slice(title.as_bytes()),
            content: Bytes::copy_from_slice(content.as_bytes()),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            fields: BTreeMap::new(),
            limits,
            metadata: MessageMetadata {
                method,
                ..MessageMetadata::default()
            },
            include_ticket: false,
            outbound_ticket: None,
            stamp_cost: None,
            ticket_barrier: None,
        };
        draft.checked_wire_len()?;
        Ok(draft)
    }
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination
    }
    pub fn source_hash(&self) -> [u8; 16] {
        self.source
    }
    pub fn timestamp(&self) -> f64 {
        self.timestamp
    }
    pub fn title_bytes(&self) -> &[u8] {
        &self.title
    }
    pub fn content_bytes(&self) -> &[u8] {
        &self.content
    }
    pub fn fields(&self) -> &BTreeMap<FieldId, FieldValue> {
        &self.fields
    }
    pub(crate) fn mark_ticket_pending(&mut self, owner: Arc<()>) {
        self.ticket_barrier = Some(owner);
    }
    pub(crate) fn release_ticket_barrier(&mut self, owner: &Arc<()>) -> bool {
        if self
            .ticket_barrier
            .as_ref()
            .is_some_and(|pending| Arc::ptr_eq(pending, owner))
        {
            self.ticket_barrier = None;
            true
        } else {
            false
        }
    }
    pub fn get_field(&self, id: impl Into<FieldId>) -> Option<&FieldValue> {
        self.fields.get(&id.into())
    }
    pub fn set_timestamp(&mut self, value: f64) -> Result<(), MessageError> {
        if !value.is_finite() {
            return Err(MessageError::PackFailed(
                "nonfinite outbound timestamp".into(),
            ));
        }
        self.timestamp = value;
        Ok(())
    }
    pub fn set_title(&mut self, value: &str) -> Result<(), MessageError> {
        self.set_text(value, true)
    }
    pub fn set_content(&mut self, value: &str) -> Result<(), MessageError> {
        self.set_text(value, false)
    }
    fn set_text(&mut self, value: &str, title: bool) -> Result<(), MessageError> {
        self.limits.check_wire(value.len())?;
        let next = Bytes::copy_from_slice(value.as_bytes());
        let old = if title {
            std::mem::replace(&mut self.title, next)
        } else {
            std::mem::replace(&mut self.content, next)
        };
        if let Err(e) = self.checked_wire_len() {
            if title {
                self.title = old
            } else {
                self.content = old
            };
            return Err(e);
        }
        Ok(())
    }
    pub fn set_field(
        &mut self,
        id: impl Into<FieldId>,
        bytes: impl Into<Bytes>,
    ) -> Result<(), MessageError> {
        self.set_field_value(id, FieldValue::Binary(bytes.into()))
    }
    pub fn set_msgpack_field(
        &mut self,
        id: impl Into<FieldId>,
        bytes: impl Into<Bytes>,
    ) -> Result<(), MessageError> {
        self.set_field_value(
            id,
            FieldValue::MessagePack(EncodedFieldValue::new(bytes.into())?),
        )
    }
    pub fn set_field_value(
        &mut self,
        id: impl Into<FieldId>,
        value: FieldValue,
    ) -> Result<(), MessageError> {
        let id = id.into();
        if !self.fields.contains_key(&id) && self.fields.len() >= self.limits.max_top_level_fields {
            return Err(MessageError::TooManyFields);
        }
        let old = self.fields.insert(id, value);
        if let Err(e) = self.checked_wire_len() {
            match old {
                Some(v) => {
                    self.fields.insert(id, v);
                }
                None => {
                    self.fields.remove(&id);
                }
            };
            return Err(e);
        }
        Ok(())
    }
    pub fn remove_field(&mut self, id: impl Into<FieldId>) -> Option<FieldValue> {
        self.fields.remove(&id.into())
    }
    pub fn set_image_field(&mut self, format: &str, bytes: &[u8]) -> Result<(), MessageError> {
        self.limits.check_wire(bytes.len())?;
        let encoded = rmp_serde::to_vec(&ImageFieldRef { format, bytes }).map_err(packed)?;
        self.set_msgpack_field(FIELD_IMAGE, encoded)
    }
    pub fn set_audio_field(&mut self, mode: u8, bytes: &[u8]) -> Result<(), MessageError> {
        self.limits.check_wire(bytes.len())?;
        let encoded = rmp_serde::to_vec(&AudioFieldRef { mode, bytes }).map_err(packed)?;
        self.set_msgpack_field(FIELD_AUDIO, encoded)
    }
    pub fn set_file_attachment_field(
        &mut self,
        file_name: &str,
        bytes: &[u8],
    ) -> Result<(), MessageError> {
        self.limits.check_wire(bytes.len())?;
        let encoded =
            rmp_serde::to_vec(&FileAttachmentsFieldRef { file_name, bytes }).map_err(packed)?;
        self.set_msgpack_field(FIELD_FILE_ATTACHMENTS, encoded)
    }
    /// Exact unsigned payload, for diagnostics; it is not a transmittable message.
    pub fn pack_payload(&self) -> Result<Vec<u8>, MessageError> {
        let size = self.checked_wire_len()?;
        let mut out = Vec::with_capacity(size - 96);
        self.write_payload(&mut out)?;
        Ok(out)
    }
    pub fn checked_wire_len(&self) -> Result<usize, MessageError> {
        if self.fields.len() > self.limits.max_top_level_fields {
            return Err(MessageError::TooManyFields);
        }
        let mut counter = CountingWriter::default();
        self.write_payload(&mut counter)?;
        let len = counter
            .bytes
            .checked_add(96)
            .ok_or_else(|| packed("length overflow"))?;
        self.limits.check_wire(len)?;
        Ok(len)
    }
    fn write_payload<W: Write>(&self, out: &mut W) -> Result<(), MessageError> {
        rmp::encode::write_array_len(out, 4).map_err(packed)?;
        rmp::encode::write_f64(out, self.timestamp).map_err(packed)?;
        write_bin(out, &self.title)?;
        write_bin(out, &self.content)?;
        rmp::encode::write_map_len(out, length(self.fields.len())?).map_err(packed)?;
        for (id, value) in &self.fields {
            if id.as_i128() >= 0 {
                rmp::encode::write_uint(out, u64::try_from(id.as_i128()).map_err(packed)?)
                    .map_err(packed)?;
            } else {
                rmp::encode::write_sint(out, i64::try_from(id.as_i128()).map_err(packed)?)
                    .map_err(packed)?;
            }
            match value {
                FieldValue::Binary(b) => write_bin(out, b)?,
                FieldValue::MessagePack(v) => out.write_all(v.encoded()).map_err(packed)?,
            }
        }
        Ok(())
    }
    pub fn sign(self, key: &Ed25519PrivateKey) -> Result<SignedLxMessage, MessageError> {
        self.sign_with(|bytes| Ok::<_, std::convert::Infallible>(key.sign(bytes)))
    }
    pub fn sign_with<F, E>(self, sign: F) -> Result<SignedLxMessage, MessageError>
    where
        F: FnOnce(&[u8]) -> Result<[u8; 64], E>,
        E: std::fmt::Display,
    {
        if self.ticket_barrier.is_some() {
            return Err(MessageError::TicketNotCommitted);
        }
        let size = self.checked_wire_len()?;
        let mut signed = Vec::with_capacity(size);
        signed.extend_from_slice(&self.destination);
        signed.extend_from_slice(&self.source);
        self.write_payload(&mut signed)?;
        let id = sha256(&signed);
        signed.extend_from_slice(&id);
        let signature = sign(&signed).map_err(packed)?;
        let mut wire = Vec::with_capacity(size);
        wire.extend_from_slice(&self.destination);
        wire.extend_from_slice(&self.source);
        wire.extend_from_slice(&signature);
        wire.extend_from_slice(&signed[32..signed.len() - 32]);
        drop(signed);
        let mut message = LxMessage::unpack_owned(wire.into(), self.limits)?;
        message.metadata = self.metadata;
        message.incoming = false;
        message.state = MessageState::Outbound;
        Ok(SignedLxMessage {
            message,
            outbound_ticket: self.outbound_ticket,
            stamp_cost: self.stamp_cost,
        })
    }
}
impl SignedLxMessage {
    pub(crate) fn restored(
        message: LxMessage,
        outbound_ticket: Option<[u8; 16]>,
        stamp_cost: Option<u8>,
    ) -> Self {
        Self {
            message,
            outbound_ticket,
            stamp_cost,
        }
    }
    /// Store this message so its delivery can resume after a restart, under
    /// the same id. The stored form keeps the signing stamp cost as a floor.
    pub fn to_resumable(&self) -> ResumableLxMessage {
        ResumableLxMessage::new(&self.message.wire, self.stamp_cost)
    }
    pub fn timestamp(&self) -> f64 {
        self.message.timestamp()
    }
    /// Complete no-stamp wire length; finalization can add a recipient stamp.
    pub fn packed_len(&self) -> Result<usize, MessageError> {
        self.message.packed_len()
    }
    /// Signed payload length, without exposing sendable bytes before finalization.
    pub fn payload_len(&self) -> usize {
        self.message.wire_bytes().len() - 96
    }
    pub fn title_bytes(&self) -> &[u8] {
        self.message.title_bytes()
    }
    pub fn content_bytes(&self) -> &[u8] {
        self.message.content_bytes()
    }
    pub fn title_text(&self) -> std::borrow::Cow<'_, str> {
        self.message.title_text()
    }
    pub fn content_text(&self) -> std::borrow::Cow<'_, str> {
        self.message.content_text()
    }
    pub fn message_id(&self) -> [u8; 32] {
        self.message.message_id()
    }
    pub fn destination_hash(&self) -> [u8; 16] {
        self.message.destination_hash()
    }
    pub fn source_hash(&self) -> [u8; 16] {
        self.message.source_hash()
    }
    pub fn fields(&self) -> Fields<'_> {
        self.message.fields()
    }
    pub fn stamp_cost(&self) -> Option<u8> {
        self.stamp_cost
    }
    pub fn outbound_ticket(&self) -> Option<[u8; 16]> {
        self.outbound_ticket
    }
    /// Compute the optional recipient stamp without changing the signed body.
    pub fn generate_recipient_stamp(&self) -> Result<Option<RecipientStamp>, MessageError> {
        if let Some(ticket) = self.outbound_ticket {
            let mut material = [0u8; 48];
            material[..16].copy_from_slice(&ticket);
            material[16..].copy_from_slice(&self.message_id());
            return Ok(Some(RecipientStamp::Ticket(truncated_hash(&material))));
        }
        let Some(cost) = self.stamp_cost else {
            return Ok(None);
        };
        crate::stamper::generate_stamp(&self.message_id(), cost, STAMP_WORKBLOCK_EXPAND_ROUNDS)
            .map(|(stamp, _)| Some(RecipientStamp::ProofOfWork(stamp)))
            .ok_or_else(|| packed("recipient stamp generation failed"))
    }
    pub fn finalize(self, stamp: Option<RecipientStamp>) -> Result<LxMessage, MessageError> {
        let Some(stamp) = stamp else {
            return Ok(self.message);
        };
        let size = self
            .message
            .wire
            .len()
            .checked_add(2 + stamp.as_bytes().len())
            .ok_or_else(|| packed("length overflow"))?;
        self.message.limits.check_wire(size)?;
        let mut wire = Vec::with_capacity(size);
        wire.extend_from_slice(&self.message.wire);
        wire[96] = 0x95;
        write_bin(&mut wire, stamp.as_bytes())?;
        let mut message = LxMessage::unpack_owned(wire.into(), self.message.limits)?;
        debug_assert_eq!(message.message_id, self.message.message_id);
        message.metadata = self.message.metadata;
        Ok(message)
    }
}
fn packed(error: impl std::fmt::Display) -> MessageError {
    MessageError::PackFailed(error.to_string())
}
fn length(value: usize) -> Result<u32, MessageError> {
    u32::try_from(value).map_err(packed)
}
fn write_bin<W: Write>(out: &mut W, bytes: &[u8]) -> Result<(), MessageError> {
    rmp::encode::write_bin_len(out, length(bytes.len())?).map_err(packed)?;
    out.write_all(bytes).map_err(packed)
}
