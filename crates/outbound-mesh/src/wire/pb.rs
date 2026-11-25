//! The subset of protobuf 3 wire encoding the protocol uses (spec §2.1):
//! varints, length-delimited fields and skipping of unknown fields. Messages
//! are encoded and decoded by hand from the field tables of the
//! specification, so no generated code or schema file is involved.

use std::fmt;

/// A malformed protobuf message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PbError {
    Truncated,
    VarintTooLong,
    /// Wire types 3 and 4 (groups) and 6, 7 are not used by the protocol.
    UnsupportedWireType(u8),
    FieldZero,
    /// A field has a different wire type than its table entry.
    WrongType(u32),
    /// A value is out of range for its field (for example a `uint32` above
    /// `u32::MAX`, or a string that is not UTF-8).
    BadValue(u32),
    /// A repeated field has more entries than this node accepts.
    TooMany(u32),
}

impl fmt::Display for PbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PbError::Truncated => f.write_str("protobuf message is truncated"),
            PbError::VarintTooLong => f.write_str("protobuf varint is too long"),
            PbError::UnsupportedWireType(t) => write!(f, "protobuf wire type {t} is not supported"),
            PbError::FieldZero => f.write_str("protobuf field number 0"),
            PbError::WrongType(n) => write!(f, "protobuf field {n} has the wrong wire type"),
            PbError::BadValue(n) => write!(f, "protobuf field {n} has an invalid value"),
            PbError::TooMany(n) => write!(f, "protobuf field {n} has too many entries"),
        }
    }
}

impl std::error::Error for PbError {}

/// One field value as it appears on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}

impl<'a> Value<'a> {
    pub fn u64(self, field: u32) -> Result<u64, PbError> {
        match self {
            Value::Varint(v) => Ok(v),
            _ => Err(PbError::WrongType(field)),
        }
    }

    pub fn u32(self, field: u32) -> Result<u32, PbError> {
        u32::try_from(self.u64(field)?).map_err(|_| PbError::BadValue(field))
    }

    /// `int32`: negative values are sign-extended to ten bytes on the wire.
    pub fn i32(self, field: u32) -> Result<i32, PbError> {
        Ok(self.u64(field)? as i64 as i32)
    }

    pub fn i64(self, field: u32) -> Result<i64, PbError> {
        Ok(self.u64(field)? as i64)
    }

    pub fn bool(self, field: u32) -> Result<bool, PbError> {
        Ok(self.u64(field)? != 0)
    }

    pub fn bytes(self, field: u32) -> Result<&'a [u8], PbError> {
        match self {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(PbError::WrongType(field)),
        }
    }

    pub fn str(self, field: u32) -> Result<&'a str, PbError> {
        std::str::from_utf8(self.bytes(field)?).map_err(|_| PbError::BadValue(field))
    }
}

/// Iterates over the fields of one message.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(message: &'a [u8]) -> Self {
        Self { rest: message }
    }

    fn varint(&mut self) -> Result<u64, PbError> {
        let mut value = 0u64;
        for i in 0..10 {
            let (&byte, rest) = self.rest.split_first().ok_or(PbError::Truncated)?;
            self.rest = rest;
            let bits = u64::from(byte & 0x7f);
            // The tenth byte may only carry the top bit of a u64.
            if i == 9 && bits > 1 {
                return Err(PbError::VarintTooLong);
            }
            value |= bits << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(PbError::VarintTooLong)
    }

    /// The next value of a packed repeated varint field (read the field's
    /// bytes with [`Reader::new`] first), or `None` at the end.
    pub fn next_varint(&mut self) -> Result<Option<u64>, PbError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        self.varint().map(Some)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PbError> {
        if self.rest.len() < len {
            return Err(PbError::Truncated);
        }
        let (taken, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(taken)
    }

    /// The next field, or `None` at the end of the message.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<(u32, Value<'a>)>, PbError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = u32::try_from(key >> 3).map_err(|_| PbError::BadValue(0))?;
        if field == 0 {
            return Err(PbError::FieldZero);
        }
        let value = match (key & 7) as u8 {
            0 => Value::Varint(self.varint()?),
            1 => Value::Fixed64(u64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            2 => {
                let len = usize::try_from(self.varint()?).map_err(|_| PbError::Truncated)?;
                Value::Bytes(self.take(len)?)
            }
            5 => Value::Fixed32(u32::from_le_bytes(self.take(4)?.try_into().unwrap())),
            other => return Err(PbError::UnsupportedWireType(other)),
        };
        Ok(Some((field, value)))
    }
}

/// Builds one message. Scalars equal to their default are written only
/// through the `opt_*` methods (proto3 `optional`) or when the caller asks.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn raw_varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.buf.push((value as u8) | 0x80);
            value >>= 7;
        }
        self.buf.push(value as u8);
    }

    fn key(&mut self, field: u32, wire: u8) {
        self.raw_varint((u64::from(field) << 3) | u64::from(wire));
    }

    /// A varint field, always written (proto3 `optional` or repeated).
    pub fn opt_u64(&mut self, field: u32, value: u64) -> &mut Self {
        self.key(field, 0);
        self.raw_varint(value);
        self
    }

    /// A varint field, skipped when zero (plain proto3 scalar).
    pub fn u64(&mut self, field: u32, value: u64) -> &mut Self {
        if value != 0 {
            self.opt_u64(field, value);
        }
        self
    }

    pub fn u32(&mut self, field: u32, value: u32) -> &mut Self {
        self.u64(field, u64::from(value))
    }

    pub fn opt_u32(&mut self, field: u32, value: u32) -> &mut Self {
        self.opt_u64(field, u64::from(value))
    }

    /// `int64` / `int32`: negative values take ten bytes, as protobuf does.
    pub fn i64(&mut self, field: u32, value: i64) -> &mut Self {
        self.u64(field, value as u64)
    }

    pub fn bool(&mut self, field: u32, value: bool) -> &mut Self {
        self.u64(field, u64::from(value))
    }

    /// A length-delimited field, always written (strings and bytes inside
    /// `repeated` or `optional`, and embedded messages).
    pub fn opt_bytes(&mut self, field: u32, value: &[u8]) -> &mut Self {
        self.key(field, 2);
        self.raw_varint(value.len() as u64);
        self.buf.extend_from_slice(value);
        self
    }

    /// A length-delimited field, skipped when empty (plain proto3 scalar).
    pub fn bytes(&mut self, field: u32, value: &[u8]) -> &mut Self {
        if !value.is_empty() {
            self.opt_bytes(field, value);
        }
        self
    }

    pub fn str(&mut self, field: u32, value: &str) -> &mut Self {
        self.bytes(field, value.as_bytes())
    }

    /// An embedded message; always written, even when empty.
    pub fn message(&mut self, field: u32, value: &[u8]) -> &mut Self {
        self.opt_bytes(field, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip() {
        for value in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut writer = Writer::new();
            writer.opt_u64(1, value);
            let bytes = writer.finish();
            let mut reader = Reader::new(&bytes);
            assert_eq!(reader.next().unwrap(), Some((1, Value::Varint(value))));
            assert_eq!(reader.next().unwrap(), None);
        }
    }

    #[test]
    fn known_encoding() {
        // Field 1 = 150, field 2 = "testing": the protobuf documentation's
        // own examples.
        let mut writer = Writer::new();
        writer.u32(1, 150).str(2, "testing");
        assert_eq!(
            writer.finish(),
            [0x08, 0x96, 0x01, 0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g']
        );
    }

    #[test]
    fn defaults_are_skipped_unless_optional() {
        let mut writer = Writer::new();
        writer.u32(1, 0).str(2, "").bool(3, false).opt_u32(4, 0);
        assert_eq!(writer.finish(), [0x20, 0x00]);
    }

    #[test]
    fn negative_int64_takes_ten_bytes() {
        let mut writer = Writer::new();
        writer.i64(1, -1);
        let bytes = writer.finish();
        assert_eq!(bytes.len(), 11);
        let (_, value) = Reader::new(&bytes).next().unwrap().unwrap();
        assert_eq!(value.i64(1).unwrap(), -1);
        assert_eq!(value.i32(1).unwrap(), -1);
    }

    #[test]
    fn skips_fixed_fields_and_rejects_garbage() {
        let bytes = [0x09, 1, 0, 0, 0, 0, 0, 0, 0, 0x15, 2, 0, 0, 0];
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.next().unwrap(), Some((1, Value::Fixed64(1))));
        assert_eq!(reader.next().unwrap(), Some((2, Value::Fixed32(2))));
        assert_eq!(reader.next().unwrap(), None);

        assert_eq!(Reader::new(&[0x0a, 5, 1]).next(), Err(PbError::Truncated));
        assert_eq!(Reader::new(&[0x08]).next(), Err(PbError::Truncated));
        assert_eq!(
            Reader::new(&[0x0b]).next(),
            Err(PbError::UnsupportedWireType(3))
        );
        assert_eq!(Reader::new(&[0x00, 0x00]).next(), Err(PbError::FieldZero));
        assert_eq!(
            Reader::new(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).next(),
            Err(PbError::VarintTooLong)
        );
    }

    #[test]
    fn packed_varints() {
        let mut reader = Reader::new(&[1, 0x96, 0x01, 3]);
        assert_eq!(reader.next_varint().unwrap(), Some(1));
        assert_eq!(reader.next_varint().unwrap(), Some(150));
        assert_eq!(reader.next_varint().unwrap(), Some(3));
        assert_eq!(reader.next_varint().unwrap(), None);
        assert_eq!(Reader::new(&[0x80]).next_varint(), Err(PbError::Truncated));
    }

    #[test]
    fn typed_accessors_check_ranges() {
        assert_eq!(Value::Varint(1 << 32).u32(5), Err(PbError::BadValue(5)));
        assert_eq!(Value::Bytes(b"x").u64(5), Err(PbError::WrongType(5)));
        assert_eq!(Value::Bytes(&[0xff]).str(5), Err(PbError::BadValue(5)));
        assert_eq!(Value::Varint(2).bool(5), Ok(true));
    }
}
