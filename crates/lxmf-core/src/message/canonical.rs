//! MessagePack decoding with the acceptance rules of the umsgpack decoder used
//! by Python LXMF, and its canonical re-encoding (`umsgpack.packb(unpackb(x))`).
use super::MessageError;
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

const MAX_DEPTH: usize = 64;
// datetime.min / datetime.max relative to the Unix epoch, in microseconds.
const MIN_TIMESTAMP_MICROS: i128 = -62_135_596_800 * 1_000_000;
const MAX_TIMESTAMP_MICROS: i128 = 253_402_300_799 * 1_000_000 + 999_999;

/// Python value identity of a decoded map key.
#[derive(Debug)]
enum Key {
    Nil,
    Number(i128),
    Float(u64),
    NaN,
    Str(Vec<u8>),
    Bin(Vec<u8>),
    Ext(i8, Vec<u8>),
    Time(i128),
    Tuple(Vec<Key>),
    Unhashable,
}

impl Key {
    fn same(&self, other: &Key) -> bool {
        match (self, other) {
            (Key::Nil, Key::Nil) => true,
            (Key::Number(a), Key::Number(b)) => a == b,
            (Key::Float(a), Key::Float(b)) => a == b,
            (Key::Str(a), Key::Str(b)) | (Key::Bin(a), Key::Bin(b)) => a == b,
            (Key::Ext(t, a), Key::Ext(u, b)) => t == u && a == b,
            (Key::Time(a), Key::Time(b)) => a == b,
            (Key::Tuple(a), Key::Tuple(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.same(y))
            }
            _ => false,
        }
    }
    fn hashable(&self) -> bool {
        match self {
            Key::Unhashable => false,
            Key::Tuple(items) => items.iter().all(Key::hashable),
            _ => true,
        }
    }
    fn contains_nan(&self) -> bool {
        match self {
            Key::NaN => true,
            Key::Tuple(items) => items.iter().any(Key::contains_nan),
            _ => false,
        }
    }
    fn from_float(value: f64) -> Key {
        if value.is_nan() {
            Key::NaN
        } else if value.fract() == 0.0 && value.abs() < 1.0e38 {
            Key::Number(value as i128)
        } else {
            Key::Float(value.to_bits())
        }
    }
}

// Equality is reflexive for every key that reaches the index (NaN keys never do).
impl PartialEq for Key {
    fn eq(&self, other: &Key) -> bool {
        self.same(other)
    }
}
impl Eq for Key {}
impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Key::Nil => 0u8.hash(state),
            Key::Number(n) => (1u8, n).hash(state),
            Key::Float(bits) => (2u8, bits).hash(state),
            Key::NaN => 3u8.hash(state),
            Key::Str(v) => (4u8, v).hash(state),
            Key::Bin(v) => (5u8, v).hash(state),
            Key::Ext(t, v) => (6u8, t, v).hash(state),
            Key::Time(t) => (7u8, t).hash(state),
            Key::Tuple(items) => {
                8u8.hash(state);
                items.len().hash(state);
                for item in items {
                    item.hash(state);
                }
            }
            Key::Unhashable => 9u8.hash(state),
        }
    }
}

fn fail(reason: &str) -> MessageError {
    MessageError::UnpackFailed(reason.to_string())
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], MessageError> {
    if input.len() < length {
        return Err(fail("truncated MessagePack value"));
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn be(input: &mut &[u8], width: usize) -> Result<u64, MessageError> {
    Ok(take(input, width)?
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)))
}

fn emit(out: &mut Option<&mut Vec<u8>>, bytes: &[u8]) {
    if let Some(out) = out.as_deref_mut() {
        out.extend_from_slice(bytes);
    }
}

fn write_int(out: &mut Vec<u8>, value: i128) {
    if value < 0 {
        if value >= -32 {
            out.push(value as i8 as u8);
        } else if value >= i128::from(i8::MIN) {
            out.push(0xd0);
            out.push(value as i8 as u8);
        } else if value >= i128::from(i16::MIN) {
            out.push(0xd1);
            out.extend_from_slice(&(value as i16).to_be_bytes());
        } else if value >= i128::from(i32::MIN) {
            out.push(0xd2);
            out.extend_from_slice(&(value as i32).to_be_bytes());
        } else {
            out.push(0xd3);
            out.extend_from_slice(&(value as i64).to_be_bytes());
        }
    } else if value < 128 {
        out.push(value as u8);
    } else if value <= i128::from(u8::MAX) {
        out.push(0xcc);
        out.push(value as u8);
    } else if value <= i128::from(u16::MAX) {
        out.push(0xcd);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= i128::from(u32::MAX) {
        out.push(0xce);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&(value as u64).to_be_bytes());
    }
}

fn write_sized(out: &mut Vec<u8>, length: usize, fix: Option<(u8, usize)>, wide: [u8; 3]) {
    match fix {
        Some((base, limit)) if length < limit => out.push(base | length as u8),
        _ if length <= usize::from(u8::MAX) && wide[0] != 0 => {
            out.push(wide[0]);
            out.push(length as u8);
        }
        _ if length <= usize::from(u16::MAX) => {
            out.push(wide[1]);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => {
            out.push(wide[2]);
            out.extend_from_slice(&(length as u32).to_be_bytes());
        }
    }
}

fn write_ext(out: &mut Vec<u8>, ext_type: i8, data: &[u8]) {
    match data.len() {
        1 => out.push(0xd4),
        2 => out.push(0xd5),
        4 => out.push(0xd6),
        8 => out.push(0xd7),
        16 => out.push(0xd8),
        length => write_sized(out, length, None, [0xc7, 0xc8, 0xc9]),
    }
    out.push(ext_type as u8);
    out.extend_from_slice(data);
}

fn timestamp_micros(data: &[u8]) -> Result<i128, MessageError> {
    let (seconds, micros) = match data.len() {
        4 => (
            i128::from(u32::from_be_bytes(data.try_into().expect("length"))),
            0,
        ),
        8 => {
            let value = u64::from_be_bytes(data.try_into().expect("length"));
            (
                i128::from(value & 0x3_ffff_ffff),
                i128::from(value >> 34) / 1000,
            )
        }
        12 => (
            i128::from(i64::from_be_bytes(data[4..12].try_into().expect("length"))),
            i128::from(u32::from_be_bytes(data[0..4].try_into().expect("length"))) / 1000,
        ),
        _ => return Err(fail("unsupported MessagePack timestamp")),
    };
    let total = seconds * 1_000_000 + micros;
    if !(MIN_TIMESTAMP_MICROS..=MAX_TIMESTAMP_MICROS).contains(&total) {
        return Err(fail("MessagePack timestamp out of range"));
    }
    Ok(total)
}

fn write_timestamp(out: &mut Vec<u8>, total: i128) {
    let seconds = total.div_euclid(1_000_000);
    let micros = total.rem_euclid(1_000_000);
    if micros == 0 && (0..=i128::from(u32::MAX)).contains(&seconds) {
        out.extend_from_slice(&[0xd6, 0xff]);
        out.extend_from_slice(&(seconds as u32).to_be_bytes());
    } else if (0..(1i128 << 34)).contains(&seconds) {
        let value = ((micros as u64 * 1000) << 34) | seconds as u64;
        out.extend_from_slice(&[0xd7, 0xff]);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.extend_from_slice(&[0xc7, 0x0c, 0xff]);
        out.extend_from_slice(&((micros * 1000) as u32).to_be_bytes());
        out.extend_from_slice(&(seconds as i64).to_be_bytes());
    }
}

/// Decode one value, writing its canonical encoding to `out` when present.
/// Returns the value's key identity when `want_key` is set.
fn walk(
    input: &mut &[u8],
    mut out: Option<&mut Vec<u8>>,
    want_key: bool,
    depth: usize,
) -> Result<Option<Key>, MessageError> {
    if depth >= MAX_DEPTH {
        return Err(fail("MessagePack nesting exceeds limit"));
    }
    let marker = take(input, 1)?[0];
    let number = |value: i128, out: Option<&mut Vec<u8>>| {
        if let Some(out) = out {
            write_int(out, value);
        }
        Ok(want_key.then_some(Key::Number(value)))
    };
    match marker {
        0x00..=0x7f => number(i128::from(marker), out),
        0xe0..=0xff => number(i128::from(marker as i8), out),
        0xcc => number(i128::from(be(input, 1)?), out),
        0xcd => number(i128::from(be(input, 2)?), out),
        0xce => number(i128::from(be(input, 4)?), out),
        0xcf => number(i128::from(be(input, 8)?), out),
        0xd0 => number(i128::from(be(input, 1)? as u8 as i8), out),
        0xd1 => number(i128::from(be(input, 2)? as u16 as i16), out),
        0xd2 => number(i128::from(be(input, 4)? as u32 as i32), out),
        0xd3 => number(i128::from(be(input, 8)? as i64), out),
        0xc0 => {
            emit(&mut out, &[0xc0]);
            Ok(want_key.then_some(Key::Nil))
        }
        0xc1 => Err(fail("reserved MessagePack marker")),
        0xc2 | 0xc3 => {
            emit(&mut out, &[marker]);
            Ok(want_key.then_some(Key::Number(i128::from(marker == 0xc3))))
        }
        0xca | 0xcb => {
            let value = if marker == 0xca {
                f64::from(f32::from_bits(be(input, 4)? as u32))
            } else {
                f64::from_bits(be(input, 8)?)
            };
            if let Some(out) = out {
                out.push(0xcb);
                out.extend_from_slice(&value.to_bits().to_be_bytes());
            }
            Ok(want_key.then(|| Key::from_float(value)))
        }
        0xa0..=0xbf | 0xd9..=0xdb => {
            let length = match marker {
                0xd9 => be(input, 1)?,
                0xda => be(input, 2)?,
                0xdb => be(input, 4)?,
                _ => u64::from(marker & 0x1f),
            } as usize;
            let data = take(input, length)?;
            if std::str::from_utf8(data).is_err() {
                return Err(fail("MessagePack string is invalid UTF-8"));
            }
            if let Some(out) = out {
                write_sized(out, length, Some((0xa0, 32)), [0xd9, 0xda, 0xdb]);
                out.extend_from_slice(data);
            }
            Ok(want_key.then(|| Key::Str(data.to_vec())))
        }
        0xc4..=0xc6 => {
            let length = be(input, 1 << (marker - 0xc4))? as usize;
            let data = take(input, length)?;
            if let Some(out) = out {
                write_sized(out, length, None, [0xc4, 0xc5, 0xc6]);
                out.extend_from_slice(data);
            }
            Ok(want_key.then(|| Key::Bin(data.to_vec())))
        }
        0xc7..=0xc9 | 0xd4..=0xd8 => {
            let length = match marker {
                0xc7 => be(input, 1)? as usize,
                0xc8 => be(input, 2)? as usize,
                0xc9 => be(input, 4)? as usize,
                _ => 1 << (marker - 0xd4),
            };
            let ext_type = take(input, 1)?[0] as i8;
            let data = take(input, length)?;
            if ext_type == -1 {
                let total = timestamp_micros(data)?;
                if let Some(out) = out {
                    write_timestamp(out, total);
                }
                return Ok(want_key.then_some(Key::Time(total)));
            }
            if let Some(out) = out {
                write_ext(out, ext_type, data);
            }
            Ok(want_key.then(|| Key::Ext(ext_type, data.to_vec())))
        }
        0x90..=0x9f | 0xdc | 0xdd => {
            let count = match marker {
                0xdc => be(input, 2)?,
                0xdd => be(input, 4)?,
                _ => u64::from(marker & 0x0f),
            };
            if let Some(out) = out.as_deref_mut() {
                write_sized(out, count as usize, Some((0x90, 16)), [0, 0xdc, 0xdd]);
            }
            let mut items = Vec::new();
            for _ in 0..count {
                let item = walk(input, out.as_deref_mut(), want_key, depth + 1)?;
                if let Some(item) = item {
                    items.push(item);
                }
            }
            Ok(want_key.then_some(Key::Tuple(items)))
        }
        0x80..=0x8f | 0xde | 0xdf => {
            let count = match marker {
                0xde => be(input, 2)?,
                0xdf => be(input, 4)?,
                _ => u64::from(marker & 0x0f),
            };
            walk_map(input, out, count, depth)?;
            Ok(want_key.then_some(Key::Unhashable))
        }
    }
}

struct Entry {
    encoded_key: Vec<u8>,
    encoded_value: Vec<u8>,
}

fn walk_map(
    input: &mut &[u8],
    out: Option<&mut Vec<u8>>,
    count: u64,
    depth: usize,
) -> Result<(), MessageError> {
    let writing = out.is_some();
    let mut entries: Vec<Entry> = Vec::new();
    let mut index: HashMap<Key, usize> = HashMap::new();
    for _ in 0..count {
        let is_list = matches!(input.first(), Some(0x90..=0x9f | 0xdc | 0xdd));
        let mut encoded_key = Vec::new();
        let key = walk(input, writing.then_some(&mut encoded_key), true, depth + 1)?
            .expect("key requested");
        // Lists become tuples and bypass the duplicate check; later ones overwrite.
        if !is_list {
            if !key.hashable() {
                return Err(fail("unhashable MessagePack map key"));
            }
            if index.contains_key(&key) {
                return Err(fail("duplicate MessagePack map key"));
            }
        }
        let mut encoded_value = Vec::new();
        walk(
            input,
            writing.then_some(&mut encoded_value),
            false,
            depth + 1,
        )?;
        if !key.hashable() {
            return Err(fail("unhashable MessagePack map key"));
        }
        let existing = if key.contains_nan() {
            None
        } else {
            index.get(&key).copied()
        };
        match existing {
            Some(position) => entries[position].encoded_value = encoded_value,
            None => {
                if !key.contains_nan() {
                    index.insert(key, entries.len());
                }
                entries.push(Entry {
                    encoded_key,
                    encoded_value,
                });
            }
        }
    }
    if let Some(out) = out {
        write_sized(out, entries.len(), Some((0x80, 16)), [0, 0xde, 0xdf]);
        for entry in entries {
            out.extend_from_slice(&entry.encoded_key);
            out.extend_from_slice(&entry.encoded_value);
        }
    }
    Ok(())
}

/// Check that the leading value decodes under the umsgpack rules; trailing bytes are ignored.
pub(crate) fn validate_leading(bytes: &[u8]) -> Result<(), MessageError> {
    let mut input = bytes;
    walk(&mut input, None, false, 0).map(|_| ())
}

/// Canonical re-encoding of exactly one value.
pub(crate) fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, MessageError> {
    let mut input = bytes;
    let mut out = Vec::with_capacity(bytes.len());
    walk(&mut input, Some(&mut out), false, 0)?;
    if !input.is_empty() {
        return Err(fail("trailing MessagePack bytes"));
    }
    Ok(out)
}

/// The payload bytes Python hashes: the received bytes, or the canonical
/// re-encoding of the first four elements when a stamp is present.
pub(crate) fn hashed_payload(payload: &[u8]) -> Result<Cow<'_, [u8]>, MessageError> {
    let mut input = payload;
    let count = match take(&mut input, 1)?[0] {
        marker @ 0x90..=0x9f => u64::from(marker & 0x0f),
        0xdc => be(&mut input, 2)?,
        0xdd => be(&mut input, 4)?,
        _ => return Err(fail("expected MessagePack array")),
    };
    if count <= 4 {
        return Ok(Cow::Borrowed(payload));
    }
    let mut out = vec![0x94];
    for _ in 0..4 {
        walk(&mut input, Some(&mut out), false, 1)?;
    }
    Ok(Cow::Owned(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(hex_in: &str) -> Result<String, MessageError> {
        canonicalize(&hex::decode(hex_in).unwrap()).map(hex::encode)
    }

    #[test]
    fn reencodes_minimally_and_widens_floats() {
        assert_eq!(canon("91ca3fc00000").unwrap(), "91cb3ff8000000000000");
        assert_eq!(canon("cd0005").unwrap(), "05");
        assert_eq!(canon("d9026869").unwrap(), "a26869");
        assert_eq!(canon("de00010102").unwrap(), "810102");
        assert_eq!(canon("c50001aa").unwrap(), "c401aa");
        assert_eq!(canon("c701050a").unwrap(), "d4050a");
        assert_eq!(canon("d0ff").unwrap(), "ff");
    }

    #[test]
    fn rejects_duplicates_by_python_equality() {
        assert!(canon("820101 0102".replace(' ', "").as_str()).is_err());
        assert!(canon("8201 01cb3ff0000000000000 02".replace(' ', "").as_str()).is_err());
        assert!(canon("82c301 0102".replace(' ', "").as_str()).is_err());
        assert!(canon("82a1610 1c4016102".replace(' ', "").as_str()).is_ok());
        assert!(
            canon(
                "82cb7ff8000000000000 01cb7ff8000000000000 02"
                    .replace(' ', "")
                    .as_str()
            )
            .is_ok()
        );
    }

    #[test]
    fn list_keys_overwrite_instead_of_failing() {
        assert_eq!(canon("82910101910102").unwrap(), "81910102");
        assert!(canon("81918001 01".replace(' ', "").as_str()).is_err());
        assert!(canon("818001 01".replace(' ', "").as_str()).is_err());
    }

    #[test]
    fn rejects_invalid_text_and_reserved_marker() {
        assert!(canon("a1ff").is_err());
        assert!(canon("c1").is_err());
        assert!(canon("c7").is_err());
    }
}
