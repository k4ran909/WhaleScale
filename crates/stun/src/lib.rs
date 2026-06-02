//! Minimal, dependency-light STUN (RFC 5389) codec.
//!
//! Only what WhaleScale needs: encode a Binding Request, parse a request on the
//! server, encode a Binding Success Response carrying the sender's reflexive
//! address as XOR-MAPPED-ADDRESS, and parse that address back on the client.
//!
//! Pure functions (no IO) so both `stun-server` and `agent-core` can share them
//! and unit-test the wire format directly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;

pub const TYPE_BINDING_REQUEST: u16 = 0x0001;
pub const TYPE_BINDING_SUCCESS: u16 = 0x0101;

pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const HEADER_LEN: usize = 20;
const FAMILY_V4: u8 = 0x01;
const FAMILY_V6: u8 = 0x02;

pub type TransactionId = [u8; 12];

/// Generate a random 96-bit transaction id.
pub fn random_transaction_id() -> TransactionId {
    use rand::RngCore;
    let mut id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

/// A decoded STUN message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub msg_type: u16,
    pub length: u16,
    pub txid: TransactionId,
}

/// Encode a Binding Request (header only, no attributes).
pub fn encode_binding_request(txid: TransactionId) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(&TYPE_BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // length: no attributes
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&txid);
    buf
}

/// Parse and validate a STUN message header. Returns `None` if the buffer is
/// too short or the magic cookie is wrong.
pub fn parse_header(buf: &[u8]) -> Option<Header> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let length = u16::from_be_bytes([buf[2], buf[3]]);
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    Some(Header {
        msg_type,
        length,
        txid,
    })
}

/// Encode a Binding Success Response echoing `txid`, carrying `addr` as
/// XOR-MAPPED-ADDRESS.
pub fn encode_binding_response(txid: TransactionId, addr: SocketAddr) -> Vec<u8> {
    let value = encode_xor_mapped_address(txid, addr);
    let attr_len = value.len() as u16;
    let body_len = 4 + attr_len; // attribute header + value

    let mut buf = Vec::with_capacity(HEADER_LEN + body_len as usize);
    buf.extend_from_slice(&TYPE_BINDING_SUCCESS.to_be_bytes());
    buf.extend_from_slice(&body_len.to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&txid);
    // Attribute: XOR-MAPPED-ADDRESS
    buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    buf.extend_from_slice(&attr_len.to_be_bytes());
    buf.extend_from_slice(&value);
    buf
}

/// Scan a message's attributes for XOR-MAPPED-ADDRESS and decode it.
pub fn parse_xor_mapped_address(buf: &[u8]) -> Option<SocketAddr> {
    let header = parse_header(buf)?;
    let mut off = HEADER_LEN;
    let end = HEADER_LEN + header.length as usize;
    if end > buf.len() {
        return None;
    }
    while off + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let attr_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        let val_start = off + 4;
        let val_end = val_start + attr_len;
        if val_end > buf.len() {
            return None;
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return decode_xor_mapped_address(header.txid, &buf[val_start..val_end]);
        }
        // Advance, honoring 4-byte padding.
        off = val_start + attr_len.div_ceil(4) * 4;
    }
    None
}

// --- XOR-MAPPED-ADDRESS value codec ---------------------------------------

fn encode_xor_mapped_address(txid: TransactionId, addr: SocketAddr) -> Vec<u8> {
    let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    match addr.ip() {
        IpAddr::V4(v4) => {
            let xaddr = u32::from(v4) ^ MAGIC_COOKIE;
            let mut v = Vec::with_capacity(8);
            v.push(0); // reserved
            v.push(FAMILY_V4);
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend_from_slice(&xaddr.to_be_bytes());
            v
        }
        IpAddr::V6(v6) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(&txid);
            let addr_bytes = v6.octets();
            let mut xaddr = [0u8; 16];
            for i in 0..16 {
                xaddr[i] = addr_bytes[i] ^ key[i];
            }
            let mut v = Vec::with_capacity(20);
            v.push(0);
            v.push(FAMILY_V6);
            v.extend_from_slice(&xport.to_be_bytes());
            v.extend_from_slice(&xaddr);
            v
        }
    }
}

fn decode_xor_mapped_address(txid: TransactionId, val: &[u8]) -> Option<SocketAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let xport = u16::from_be_bytes([val[2], val[3]]);
    let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
    match family {
        FAMILY_V4 => {
            if val.len() < 8 {
                return None;
            }
            let xaddr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
            let addr = Ipv4Addr::from(xaddr ^ MAGIC_COOKIE);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        FAMILY_V6 => {
            if val.len() < 20 {
                return None;
            }
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(&txid);
            let mut addr = [0u8; 16];
            for i in 0..16 {
                addr[i] = val[4 + i] ^ key[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let txid = random_transaction_id();
        let req = encode_binding_request(txid);
        let h = parse_header(&req).expect("valid header");
        assert_eq!(h.msg_type, TYPE_BINDING_REQUEST);
        assert_eq!(h.length, 0);
        assert_eq!(h.txid, txid);
    }

    #[test]
    fn rejects_bad_cookie() {
        let mut req = encode_binding_request(random_transaction_id());
        req[4] ^= 0xFF; // corrupt magic cookie
        assert!(parse_header(&req).is_none());
    }

    #[test]
    fn xor_mapped_address_v4_roundtrip() {
        let txid = random_transaction_id();
        let addr: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let resp = encode_binding_response(txid, addr);
        let parsed = parse_xor_mapped_address(&resp).expect("address present");
        assert_eq!(parsed, addr);
        // Response echoes the transaction id and is a success response.
        let h = parse_header(&resp).unwrap();
        assert_eq!(h.msg_type, TYPE_BINDING_SUCCESS);
        assert_eq!(h.txid, txid);
    }

    #[test]
    fn xor_mapped_address_v6_roundtrip() {
        let txid = random_transaction_id();
        let addr: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        let resp = encode_binding_response(txid, addr);
        let parsed = parse_xor_mapped_address(&resp).expect("address present");
        assert_eq!(parsed, addr);
    }
}
