//! Full-width LXMF field keys and coherent binary/structured values.
use super::{MessageError, read_msgpack_binary, skip_msgpack_value};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{fmt, ops::Range};

/// A MessagePack integer field key, preserving the complete signed/unsigned domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldId(i128);
impl FieldId {
    pub const fn as_i128(self) -> i128 {
        self.0
    }
    pub fn as_standard(self) -> Option<u8> {
        u8::try_from(self.0).ok()
    }
}
macro_rules! field_from { ($($t:ty),*) => { $(impl From<$t> for FieldId { fn from(v:$t)->Self { Self(i128::from(v)) } })* }; }
field_from!(u8, u16, u32, u64, i8, i16, i32, i64);
impl TryFrom<i128> for FieldId {
    type Error = MessageError;
    fn try_from(v: i128) -> Result<Self, Self::Error> {
        if v < i128::from(i64::MIN) || v > i128::from(u64::MAX) {
            return Err(MessageError::InvalidFieldId);
        }
        Ok(Self(v))
    }
}
impl Serialize for FieldId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0 >= 0 {
            s.serialize_u64(u64::try_from(self.0).map_err(serde::ser::Error::custom)?)
        } else {
            s.serialize_i64(i64::try_from(self.0).map_err(serde::ser::Error::custom)?)
        }
    }
}
impl<'de> Deserialize<'de> for FieldId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = FieldId;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a signed or unsigned 64-bit integer")
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<FieldId, E> {
                Ok(v.into())
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<FieldId, E> {
                Ok(v.into())
            }
            fn visit_i128<E: serde::de::Error>(self, v: i128) -> Result<FieldId, E> {
                FieldId::try_from(v).map_err(E::custom)
            }
            fn visit_u128<E: serde::de::Error>(self, v: u128) -> Result<FieldId, E> {
                u64::try_from(v).map(FieldId::from).map_err(E::custom)
            }
        }
        d.deserialize_any(V)
    }
}

/// One structurally valid encoded MessagePack value. Storage cannot be mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFieldValue(Bytes);
impl EncodedFieldValue {
    pub fn new(bytes: Bytes) -> Result<Self, MessageError> {
        let mut remaining = bytes.as_ref();
        skip_msgpack_value(&mut remaining, 0)?;
        if !remaining.is_empty() {
            return Err(MessageError::UnpackFailed("trailing field bytes".into()));
        }
        Ok(Self(bytes))
    }
    pub fn encoded(&self) -> &[u8] {
        &self.0
    }
}
/// A binary byte string or a native structured MessagePack value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Binary(Bytes),
    MessagePack(EncodedFieldValue),
}
impl Serialize for FieldValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Binary(b) => s.serialize_bytes(b),
            Self::MessagePack(v) => {
                let value = rmpv::decode::read_value(&mut v.encoded())
                    .map_err(serde::ser::Error::custom)?;
                value.serialize(s)
            }
        }
    }
}
impl<'de> Deserialize<'de> for FieldValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = rmpv::Value::deserialize(d)?;
        if let rmpv::Value::Binary(b) = value {
            return Ok(Self::Binary(b.into()));
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).map_err(serde::de::Error::custom)?;
        EncodedFieldValue::new(bytes.into())
            .map(Self::MessagePack)
            .map_err(serde::de::Error::custom)
    }
}

/// Borrowed exact encoded field value. Binary is never inferred to be structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldValueRef<'a> {
    pub(super) encoded: &'a [u8],
}
impl<'a> FieldValueRef<'a> {
    /// Borrow exactly one structurally valid value without decoding or copying it.
    /// Duplicate map keys remain opaque until a recognized schema asks for
    /// `unique_map`; binary payloads are never interpreted implicitly.
    pub fn from_encoded(encoded: &'a [u8]) -> Result<Self, MessageError> {
        let mut remaining = encoded;
        skip_msgpack_value(&mut remaining, 0)?;
        if !remaining.is_empty() {
            return Err(MessageError::UnpackFailed("trailing field bytes".into()));
        }
        Ok(Self { encoded })
    }
    /// Exact UTF-8 MessagePack text, without accepting a binary value as text.
    pub fn as_text(self) -> Option<&'a str> {
        if !matches!(self.encoded.first(), Some(0xa0..=0xbf | 0xd9..=0xdb)) {
            return None;
        }
        let mut input = self.encoded;
        let bytes = super::read_msgpack_string_or_binary(&mut input).ok()?;
        if !input.is_empty() {
            return None;
        }
        std::str::from_utf8(bytes).ok()
    }
    pub fn encoded(self) -> &'a [u8] {
        self.encoded
    }
    pub fn as_binary(self) -> Option<&'a [u8]> {
        let mut value = self.encoded;
        let bytes = read_msgpack_binary(&mut value).ok()?;
        value.is_empty().then_some(bytes)
    }
    /// Owned explicit copy, for constructing a new message deliberately.
    pub fn to_owned(self) -> FieldValue {
        match self.as_binary() {
            Some(b) => FieldValue::Binary(Bytes::copy_from_slice(b)),
            None => {
                FieldValue::MessagePack(EncodedFieldValue(Bytes::copy_from_slice(self.encoded)))
            }
        }
    }
}
#[derive(Debug, Clone)]
pub(super) struct FieldIndex {
    pub id: FieldId,
    pub range: Range<usize>,
}
const _: () = assert!(std::mem::size_of::<FieldIndex>() <= 32);
/// Numeric-key ordered view; original field wire order stays in the message.
#[derive(Debug, Clone, Copy)]
pub struct Fields<'a> {
    pub(super) wire: &'a [u8],
    pub(super) indexes: &'a [FieldIndex],
}
impl<'a> Fields<'a> {
    pub fn get(self, id: impl Into<FieldId>) -> Option<FieldValueRef<'a>> {
        let id = id.into();
        self.indexes
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .map(|i| FieldValueRef {
                encoded: &self.wire[self.indexes[i].range.clone()],
            })
    }
    pub fn contains(self, id: impl Into<FieldId>) -> bool {
        self.get(id).is_some()
    }
    pub fn len(self) -> usize {
        self.indexes.len()
    }
    pub fn is_empty(self) -> bool {
        self.indexes.is_empty()
    }
    pub fn iter(self) -> impl ExactSizeIterator<Item = (FieldId, FieldValueRef<'a>)> {
        self.indexes.iter().map(move |entry| {
            (
                entry.id,
                FieldValueRef {
                    encoded: &self.wire[entry.range.clone()],
                },
            )
        })
    }
}

pub(super) mod map_serde {
    use super::*;
    use std::collections::BTreeMap;
    pub fn serialize<S: serde::Serializer>(
        map: &BTreeMap<FieldId, FieldValue>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        map.serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<FieldId, FieldValue>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = BTreeMap<FieldId, FieldValue>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unique integer fields")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut map = BTreeMap::new();
                while let Some(key) = access.next_key::<FieldId>()? {
                    if map.len()
                        >= super::super::MessageDecodeLimits::default().max_top_level_fields
                    {
                        return Err(serde::de::Error::custom("too many fields"));
                    }
                    if map.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate field ID"));
                    }
                    let value = access.next_value()?;
                    map.insert(key, value);
                }
                Ok(map)
            }
        }
        d.deserialize_map(V)
    }
}

/// Validated schema-map keys. Integer encodings normalize; text is exact UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldMapKey<'a> {
    Integer(FieldId),
    Text(&'a str),
}
/// Borrowed map values with a compact sorted key-offset index.
///
/// Intended for recognized reaction/chat/game schemas. Unknown structured fields
/// remain opaque and need not request this semantic validation. The index uses
/// four bytes per entry (at most twice the encoded field size), with no value copies.
#[derive(Debug)]
pub struct UniqueFieldMap<'a> {
    encoded: &'a [u8],
    offsets: Vec<u32>,
}
impl<'a> FieldValueRef<'a> {
    pub fn unique_map(self) -> Result<UniqueFieldMap<'a>, MessageError> {
        let mut input = self.encoded;
        let count = super::read_msgpack_map_len(&mut input)? as usize;
        if count > input.len() / 2 {
            return Err(MessageError::UnpackFailed(
                "impossible nested map count".into(),
            ));
        }
        let mut offsets = Vec::new();
        offsets
            .try_reserve_exact(count)
            .map_err(|_| MessageError::UnpackFailed("nested map index allocation".into()))?;
        for _ in 0..count {
            offsets.push(
                u32::try_from(self.encoded.len() - input.len())
                    .map_err(|_| MessageError::InvalidFieldId)?,
            );
            read_map_key(&mut input)?;
            skip_msgpack_value(&mut input, 0)?;
        }
        if !input.is_empty() {
            return Err(MessageError::UnpackFailed(
                "trailing nested map bytes".into(),
            ));
        }
        let key_at = |offset: &u32| {
            read_map_key(&mut &self.encoded[*offset as usize..])
                .expect("validated immutable map key")
        };
        offsets.sort_unstable_by(|a, b| key_at(a).cmp(&key_at(b)));
        if offsets
            .windows(2)
            .any(|pair| key_at(&pair[0]) == key_at(&pair[1]))
        {
            return Err(MessageError::DuplicateField);
        }
        Ok(UniqueFieldMap {
            encoded: self.encoded,
            offsets,
        })
    }
}
impl<'a> UniqueFieldMap<'a> {
    pub fn len(&self) -> usize {
        self.offsets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }
    pub fn get(&self, key: FieldMapKey<'_>) -> Option<FieldValueRef<'a>> {
        let index = self
            .offsets
            .binary_search_by(|offset| {
                read_map_key(&mut &self.encoded[*offset as usize..])
                    .expect("validated map key")
                    .cmp(&key)
            })
            .ok()?;
        let mut input = &self.encoded[self.offsets[index] as usize..];
        read_map_key(&mut input).ok()?;
        let value = input;
        skip_msgpack_value(&mut input, 0).ok()?;
        Some(FieldValueRef {
            encoded: &value[..value.len() - input.len()],
        })
    }
}
fn read_map_key<'a>(input: &mut &'a [u8]) -> Result<FieldMapKey<'a>, MessageError> {
    if input
        .first()
        .is_some_and(|marker| matches!(*marker,0xa0..=0xbf|0xd9..=0xdb))
    {
        let text = super::read_msgpack_string_or_binary(input)?;
        Ok(FieldMapKey::Text(std::str::from_utf8(text).map_err(
            |_| MessageError::UnpackFailed("map key is not UTF-8".into()),
        )?))
    } else {
        Ok(FieldMapKey::Integer(FieldId::try_from(
            super::read_msgpack_integer(input)?,
        )?))
    }
}
