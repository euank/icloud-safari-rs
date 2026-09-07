//! Small lossless protobuf-wire reader used for undocumented Apple messages.

use crate::{Error, Result};

const MAX_MESSAGE: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Varint(u64),
    Fixed64(u64),
    Bytes(Vec<u8>),
    Fixed32(u32),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub number: u32,
    pub value: Value,
    /// The original key and value bytes, retained for lossless archival.
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Message {
    pub fields: Vec<Field>,
}

impl Message {
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_MESSAGE {
            return Err(Error::Protobuf("message exceeds size limit"));
        }
        let mut offset = 0;
        let mut fields = Vec::new();
        while offset < input.len() {
            let start = offset;
            let key = read_varint(input, &mut offset)?;
            let number =
                u32::try_from(key >> 3).map_err(|_| Error::Protobuf("field number overflow"))?;
            if number == 0 || number > 0x1fff_ffff {
                return Err(Error::Protobuf("invalid field number"));
            }
            let value = match key & 7 {
                0 => Value::Varint(read_varint(input, &mut offset)?),
                1 => {
                    let bytes = take(input, &mut offset, 8)?;
                    Value::Fixed64(u64::from_le_bytes(bytes.try_into().unwrap()))
                }
                2 => {
                    let len = usize::try_from(read_varint(input, &mut offset)?)
                        .map_err(|_| Error::Protobuf("length overflow"))?;
                    Value::Bytes(take(input, &mut offset, len)?.to_vec())
                }
                5 => {
                    let bytes = take(input, &mut offset, 4)?;
                    Value::Fixed32(u32::from_le_bytes(bytes.try_into().unwrap()))
                }
                _ => return Err(Error::Protobuf("unsupported or obsolete wire type")),
            };
            fields.push(Field {
                number,
                value,
                raw: input[start..offset].to_vec(),
            });
        }
        Ok(Self { fields })
    }

    pub fn values(&self, number: u32) -> impl Iterator<Item = &Value> {
        self.fields
            .iter()
            .filter(move |field| field.number == number)
            .map(|field| &field.value)
    }

    pub fn first_bytes(&self, number: u32) -> Option<&[u8]> {
        self.values(number).find_map(|value| match value {
            Value::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
    }

    pub fn first_varint(&self, number: u32) -> Option<u64> {
        self.values(number).find_map(|value| match value {
            Value::Varint(value) => Some(*value),
            _ => None,
        })
    }

    /// Re-encode the message. Untouched fields retain their original bytes,
    /// including non-canonical varints and unknown fields.
    pub fn encode(&self) -> Vec<u8> {
        self.fields
            .iter()
            .flat_map(|field| field.raw.iter().copied())
            .collect()
    }

    /// Replace the first length-delimited field, preserving every other field
    /// byte-for-byte. Returns false when the field is absent or has another
    /// wire type.
    pub fn replace_first_bytes(&mut self, number: u32, value: &[u8]) -> bool {
        let Some(field) = self.fields.iter_mut().find(|field| field.number == number) else {
            return false;
        };
        if !matches!(field.value, Value::Bytes(_)) {
            return false;
        }
        let mut raw = Vec::new();
        encode_bytes(number, value, &mut raw);
        field.value = Value::Bytes(value.to_vec());
        field.raw = raw;
        true
    }

    /// Set a varint field, appending it when absent.
    pub fn set_varint(&mut self, number: u32, value: u64) {
        let mut raw = Vec::new();
        encode_uint(number, value, &mut raw);
        if let Some(field) = self.fields.iter_mut().find(|field| field.number == number) {
            field.value = Value::Varint(value);
            field.raw = raw;
        } else {
            self.fields.push(Field {
                number,
                value: Value::Varint(value),
                raw,
            });
        }
    }
}

pub fn read_varint(input: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *input
            .get(*offset)
            .ok_or(Error::Protobuf("truncated varint"))?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err(Error::Protobuf("varint overflow"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Error::Protobuf("varint overflow"))
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(Error::Protobuf("length overflow"))?;
    let value = input
        .get(*offset..end)
        .ok_or(Error::Protobuf("truncated field"))?;
    *offset = end;
    Ok(value)
}

pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn encode_key(number: u32, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint((u64::from(number) << 3) | u64::from(wire_type), out);
}

pub fn encode_uint(number: u32, value: u64, out: &mut Vec<u8>) {
    encode_key(number, 0, out);
    encode_varint(value, out);
}

pub fn encode_bytes(number: u32, value: &[u8], out: &mut Vec<u8>) {
    encode_key(number, 2, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

pub fn encode_string(number: u32, value: &str, out: &mut Vec<u8>) {
    encode_bytes(number, value.as_bytes(), out);
}

pub fn decode_delimited(mut input: &[u8]) -> Result<Vec<Message>> {
    let mut messages = Vec::new();
    while !input.is_empty() {
        let mut offset = 0;
        let len = usize::try_from(read_varint(input, &mut offset)?)
            .map_err(|_| Error::Protobuf("frame length overflow"))?;
        input = input
            .get(offset..)
            .ok_or(Error::Protobuf("truncated frame"))?;
        let body = input.get(..len).ok_or(Error::Protobuf("truncated frame"))?;
        messages.push(Message::parse(body)?);
        input = &input[len..];
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fields_and_retains_wire_bytes() {
        let mut bytes = Vec::new();
        encode_uint(1, 300, &mut bytes);
        encode_bytes(4, b"hello", &mut bytes);
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.first_varint(1), Some(300));
        assert_eq!(message.first_bytes(4), Some(b"hello".as_slice()));
        assert_eq!(message.fields.concat_raw(), bytes);
    }

    trait ConcatRaw {
        fn concat_raw(&self) -> Vec<u8>;
    }
    impl ConcatRaw for [Field] {
        fn concat_raw(&self) -> Vec<u8> {
            self.iter().flat_map(|field| field.raw.clone()).collect()
        }
    }

    #[test]
    fn rejects_truncation_and_overflow() {
        assert!(Message::parse(&[0x0a, 0x02, 0x01]).is_err());
        assert!(Message::parse(&[0x80; 11]).is_err());
        assert!(Message::parse(&[0]).is_err());
    }

    #[test]
    fn patches_one_field_without_reencoding_unknown_fields() {
        let bytes = [0x08, 0x81, 0x00, 0x12, 0x01, b'a', 0x18, 0x07];
        let mut message = Message::parse(&bytes).unwrap();
        assert!(message.replace_first_bytes(2, b"longer"));
        assert_eq!(&message.encode()[..3], &[0x08, 0x81, 0x00]);
        assert_eq!(
            Message::parse(&message.encode()).unwrap().first_bytes(2),
            Some(b"longer".as_slice())
        );
        message.set_varint(4, 1);
        assert_eq!(
            Message::parse(&message.encode()).unwrap().first_varint(4),
            Some(1)
        );
    }
}
