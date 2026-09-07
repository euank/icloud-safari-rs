//! Minimal strict DER reader. Unknown nodes retain their complete encoded bytes.

use crate::{Error, Result};

const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub content: Vec<u8>,
    pub children: Vec<Node>,
    pub raw: Vec<u8>,
}

impl Node {
    pub fn parse_exact(input: &[u8]) -> Result<Self> {
        let (node, used) = parse_one(input, 0)?;
        if used != input.len() {
            return Err(Error::Der("trailing bytes"));
        }
        Ok(node)
    }

    pub fn octets(&self) -> Option<&[u8]> {
        (self.class == 0 && self.tag == 4 && !self.constructed).then_some(&self.content)
    }

    pub fn integer_u64(&self) -> Result<u64> {
        if self.class != 0 || self.tag != 2 || self.constructed || self.content.is_empty() {
            return Err(Error::Der("expected positive INTEGER"));
        }
        if self.content[0] & 0x80 != 0 {
            return Err(Error::Der("negative INTEGER"));
        }
        if self.content.len() > 1 && self.content[0] == 0 && self.content[1] & 0x80 == 0 {
            return Err(Error::Der("non-minimal INTEGER"));
        }
        if self.content.len() > 9 || (self.content.len() == 9 && self.content[0] != 0) {
            return Err(Error::Der("INTEGER overflow"));
        }
        Ok(self
            .content
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
    }

    pub fn descendants(&self) -> Vec<&Node> {
        let mut nodes = vec![self];
        for child in &self.children {
            nodes.extend(child.descendants());
        }
        nodes
    }
}

fn parse_one(input: &[u8], depth: usize) -> Result<(Node, usize)> {
    if depth > MAX_DEPTH {
        return Err(Error::Der("nesting limit exceeded"));
    }
    let first = *input.first().ok_or(Error::Der("truncated tag"))?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut offset = 1;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        tag = 0;
        let mut count = 0;
        loop {
            let byte = *input.get(offset).ok_or(Error::Der("truncated tag"))?;
            offset += 1;
            if count == 0 && byte & 0x7f == 0 {
                return Err(Error::Der("non-minimal tag"));
            }
            tag = tag
                .checked_shl(7)
                .and_then(|value| value.checked_add(u32::from(byte & 0x7f)))
                .ok_or(Error::Der("tag overflow"))?;
            count += 1;
            if byte & 0x80 == 0 {
                break;
            }
            if count > 5 {
                return Err(Error::Der("tag overflow"));
            }
        }
    }
    let first_len = *input.get(offset).ok_or(Error::Der("truncated length"))?;
    offset += 1;
    let len = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let count = usize::from(first_len & 0x7f);
        if count == 0 {
            return Err(Error::Der("indefinite length is not DER"));
        }
        if count > std::mem::size_of::<usize>() {
            return Err(Error::Der("length overflow"));
        }
        let bytes = input
            .get(offset..offset + count)
            .ok_or(Error::Der("truncated length"))?;
        offset += count;
        if bytes[0] == 0 {
            return Err(Error::Der("non-minimal length"));
        }
        let value = bytes
            .iter()
            .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
        if value < 128 {
            return Err(Error::Der("non-minimal length"));
        }
        value
    };
    let end = offset
        .checked_add(len)
        .ok_or(Error::Der("length overflow"))?;
    let content = input
        .get(offset..end)
        .ok_or(Error::Der("truncated value"))?;
    let mut children = Vec::new();
    if constructed {
        let mut child_offset = 0;
        while child_offset < content.len() {
            let (child, used) = parse_one(&content[child_offset..], depth + 1)?;
            child_offset += used;
            children.push(child);
        }
    }
    Ok((
        Node {
            class,
            constructed,
            tag,
            content: content.to_vec(),
            children,
            raw: input[..end].to_vec(),
        },
        end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_der() {
        let node = Node::parse_exact(&hex::decode("300702010104020102").unwrap()).unwrap();
        assert_eq!(node.children[0].integer_u64().unwrap(), 1);
        assert_eq!(node.children[1].octets(), Some(&[1, 2][..]));
    }

    #[test]
    fn rejects_ber_and_truncation() {
        assert!(Node::parse_exact(&[0x30, 0x80, 0, 0]).is_err());
        assert!(Node::parse_exact(&[0x04, 2, 1]).is_err());
    }
}
