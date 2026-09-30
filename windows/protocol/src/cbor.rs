use std::collections::BTreeMap;

use crate::error::ProtocolError;
use crate::types::{MAX_MESSAGE_SIZE, MAX_NESTING_DEPTH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    Unsigned(u64),
    Bytes(Vec<u8>),
    Text(String),
    Map(BTreeMap<u16, CborValue>),
}

pub fn encode(value: &CborValue) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new();
    encoder.encode_value(value, 0)?;
    Ok(encoder.into_bytes())
}

pub fn decode(data: &[u8]) -> Result<CborValue, ProtocolError> {
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::OversizedMessage);
    }

    let mut decoder = Decoder::new(data);
    let value = decoder.decode_value(0)?;

    if !decoder.is_empty() {
        return Err(ProtocolError::Malformed);
    }

    Ok(value)
}

struct Encoder {
    data: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            data: Vec::with_capacity(128),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    fn ensure_size(&self, additional: usize) -> Result<(), ProtocolError> {
        if self.data.len().saturating_add(additional) > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::OversizedMessage);
        }

        Ok(())
    }

    fn push_uint_with_major(&mut self, major: u8, value: u64) -> Result<(), ProtocolError> {
        match value {
            0..=23 => {
                self.ensure_size(1)?;
                self.data.push(major | value as u8);
            }
            24..=0xff => {
                self.ensure_size(2)?;
                self.data.push(major | 24);
                self.data.push(value as u8);
            }
            0x100..=0xffff => {
                self.ensure_size(3)?;
                self.data.push(major | 25);
                self.data.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.ensure_size(5)?;
                self.data.push(major | 26);
                self.data.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.ensure_size(9)?;
                self.data.push(major | 27);
                self.data.extend_from_slice(&value.to_be_bytes());
            }
        }

        Ok(())
    }

    fn encode_value(&mut self, value: &CborValue, depth: usize) -> Result<(), ProtocolError> {
        match value {
            CborValue::Unsigned(value) => {
                self.push_uint_with_major(0x00, *value)?;
            }
            CborValue::Bytes(bytes) => {
                self.push_uint_with_major(0x40, bytes.len() as u64)?;
                self.ensure_size(bytes.len())?;
                self.data.extend_from_slice(bytes);
            }
            CborValue::Text(text) => {
                let bytes = text.as_bytes();
                self.push_uint_with_major(0x60, bytes.len() as u64)?;
                self.ensure_size(bytes.len())?;
                self.data.extend_from_slice(bytes);
            }
            CborValue::Map(map) => {
                if depth >= MAX_NESTING_DEPTH {
                    return Err(ProtocolError::NestingTooDeep);
                }

                self.push_uint_with_major(0xa0, map.len() as u64)?;

                for (key, value) in map {
                    self.push_uint_with_major(0x00, u64::from(*key))?;
                    self.encode_value(value, depth + 1)?;
                }
            }
        }

        Ok(())
    }
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        if self.remaining() < 1 {
            return Err(ProtocolError::Malformed);
        }

        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        if self.remaining() < 2 {
            return Err(ProtocolError::Malformed);
        }

        let bytes = [self.data[self.pos], self.data[self.pos + 1]];
        self.pos += 2;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        if self.remaining() < 4 {
            return Err(ProtocolError::Malformed);
        }

        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];

        self.pos += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        if self.remaining() < 8 {
            return Err(ProtocolError::Malformed);
        }

        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ];

        self.pos += 8;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_argument(&mut self, minor: u8) -> Result<u64, ProtocolError> {
        match minor {
            0..=23 => Ok(u64::from(minor)),
            24 => {
                let value = u64::from(self.read_u8()?);
                if value < 24 {
                    return Err(ProtocolError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            25 => {
                let value = u64::from(self.read_u16()?);
                if value <= 0xff {
                    return Err(ProtocolError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            26 => {
                let value = u64::from(self.read_u32()?);
                if value <= 0xffff {
                    return Err(ProtocolError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            27 => {
                let value = self.read_u64()?;
                if value <= 0xffff_ffff {
                    return Err(ProtocolError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            31 => Err(ProtocolError::UnsupportedType),
            _ => Err(ProtocolError::Malformed),
        }
    }

    fn decode_value(&mut self, depth: usize) -> Result<CborValue, ProtocolError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let minor = initial & 0x1f;

        match major {
            0 => {
                let value = self.read_argument(minor)?;
                Ok(CborValue::Unsigned(value))
            }
            2 => {
                let len = self.read_argument(minor)?;

                if len > MAX_MESSAGE_SIZE as u64 {
                    return Err(ProtocolError::OversizedMessage);
                }

                let len = usize::try_from(len).map_err(|_| ProtocolError::OversizedMessage)?;

                if self.remaining() < len {
                    return Err(ProtocolError::Malformed);
                }

                let bytes = self.data[self.pos..self.pos + len].to_vec();
                self.pos += len;

                Ok(CborValue::Bytes(bytes))
            }
            3 => {
                let len = self.read_argument(minor)?;

                if len > MAX_MESSAGE_SIZE as u64 {
                    return Err(ProtocolError::OversizedMessage);
                }

                let len = usize::try_from(len).map_err(|_| ProtocolError::OversizedMessage)?;

                if self.remaining() < len {
                    return Err(ProtocolError::Malformed);
                }

                let bytes = &self.data[self.pos..self.pos + len];
                self.pos += len;

                let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::Malformed)?;

                Ok(CborValue::Text(text.to_owned()))
            }
            5 => {
                if depth >= MAX_NESTING_DEPTH {
                    return Err(ProtocolError::NestingTooDeep);
                }

                let len = self.read_argument(minor)?;

                if len > MAX_MESSAGE_SIZE as u64 {
                    return Err(ProtocolError::OversizedMessage);
                }

                let mut map = BTreeMap::new();
                let mut previous_key: Option<u16> = None;

                for _ in 0..len {
                    let key_initial = self.read_u8()?;
                    let key_major = key_initial >> 5;
                    let key_minor = key_initial & 0x1f;

                    if key_major != 0 {
                        return Err(ProtocolError::InvalidMapKey);
                    }

                    let key = self.read_argument(key_minor)?;

                    if key > u16::MAX as u64 {
                        return Err(ProtocolError::InvalidMapKey);
                    }

                    let key = key as u16;

                    if let Some(previous) = previous_key
                        && key <= previous
                    {
                        return Err(ProtocolError::NonCanonicalEncoding);
                    }

                    previous_key = Some(key);

                    let value = self.decode_value(depth + 1)?;
                    map.insert(key, value);
                }

                Ok(CborValue::Map(map))
            }
            _ => Err(ProtocolError::UnsupportedType),
        }
    }
}
