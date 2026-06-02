//! C ABI for WhaleScale's agent core, consumed by the iOS (Swift) and Android
//! (Kotlin/JNI) clients. The mobile apps own only the OS TUN device + UDP
//! socket; all WireGuard cryptography lives in `agent-core` and is reached
//! through the functions below.
//!
//! Memory model: keys are fixed 32-byte buffers; packet buffers are
//! caller-allocated. Functions never allocate memory the caller must free,
//! except [`ws_peer_new`] which returns an opaque handle freed by
//! [`ws_peer_free`]. All functions are safe to call with valid pointers.
//!
//! Action return codes (encapsulate/decapsulate):
//!   `0`  WS_ACTION_NONE      — nothing to do
//!   `1`  WS_ACTION_NETWORK   — send `out` bytes to the peer over UDP
//!   `2`  WS_ACTION_TUNNEL    — write `out` bytes to the local TUN device
//!  `-1`  WS_ERR              — internal error
//!  `-2`  WS_ERR_BUFFER       — `out` buffer too small / null argument

use std::slice;

use ws_agent_core::keys::{decode_key, WgKeypair};
use ws_agent_core::wireguard::{Action, Peer};

pub const WS_ACTION_NONE: i32 = 0;
pub const WS_ACTION_NETWORK: i32 = 1;
pub const WS_ACTION_TUNNEL: i32 = 2;
pub const WS_ERR: i32 = -1;
pub const WS_ERR_BUFFER: i32 = -2;

/// Generate a WireGuard keypair into two caller-provided 32-byte buffers.
/// Returns 0 on success, `WS_ERR_BUFFER` on a null pointer.
///
/// # Safety
/// `out_private` and `out_public` must point to writable 32-byte buffers.
#[no_mangle]
pub unsafe extern "C" fn ws_generate_keypair(out_private: *mut u8, out_public: *mut u8) -> i32 {
    if out_private.is_null() || out_public.is_null() {
        return WS_ERR_BUFFER;
    }
    let kp = WgKeypair::generate();
    let (priv_bytes, pub_bytes) = match (decode_key(&kp.private_key), decode_key(&kp.public_key)) {
        (Some(a), Some(b)) => (a, b),
        _ => return WS_ERR,
    };
    slice::from_raw_parts_mut(out_private, 32).copy_from_slice(&priv_bytes);
    slice::from_raw_parts_mut(out_public, 32).copy_from_slice(&pub_bytes);
    0
}

/// Opaque WireGuard peer session handle.
pub struct WsPeer {
    peer: Peer,
}

/// Create a peer session. Returns null on failure.
///
/// # Safety
/// `private_key` and `peer_public` must each point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ws_peer_new(
    private_key: *const u8,
    peer_public: *const u8,
    index: u32,
) -> *mut WsPeer {
    if private_key.is_null() || peer_public.is_null() {
        return std::ptr::null_mut();
    }
    let mut priv_key = [0u8; 32];
    let mut pub_key = [0u8; 32];
    priv_key.copy_from_slice(slice::from_raw_parts(private_key, 32));
    pub_key.copy_from_slice(slice::from_raw_parts(peer_public, 32));

    match Peer::new(priv_key, pub_key, index) {
        Ok(peer) => Box::into_raw(Box::new(WsPeer { peer })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a peer session created by [`ws_peer_new`].
///
/// # Safety
/// `handle` must be a value returned by [`ws_peer_new`] (or null).
#[no_mangle]
pub unsafe extern "C" fn ws_peer_free(handle: *mut WsPeer) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Encrypt an outbound IP packet (empty input triggers a handshake).
///
/// # Safety
/// Pointers must be valid for their stated lengths; `out_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ws_peer_encapsulate(
    handle: *mut WsPeer,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    run(handle, input, input_len, out, out_cap, out_len, true)
}

/// Process an inbound UDP datagram from the peer.
///
/// # Safety
/// Pointers must be valid for their stated lengths; `out_len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ws_peer_decapsulate(
    handle: *mut WsPeer,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    run(handle, input, input_len, out, out_cap, out_len, false)
}

#[allow(clippy::too_many_arguments)]
unsafe fn run(
    handle: *mut WsPeer,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    encap: bool,
) -> i32 {
    if handle.is_null() || out_len.is_null() {
        return WS_ERR_BUFFER;
    }
    let peer = &mut (*handle).peer;
    let packet: &[u8] = if input.is_null() || input_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(input, input_len)
    };

    let action = if encap {
        peer.encapsulate(packet)
    } else {
        peer.decapsulate(packet)
    };

    let (code, bytes) = match action {
        Ok(Action::None) => return WS_ACTION_NONE,
        Ok(Action::ToNetwork(b)) => (WS_ACTION_NETWORK, b),
        Ok(Action::ToTunnel(b)) => (WS_ACTION_TUNNEL, b),
        Err(_) => return WS_ERR,
    };

    if out.is_null() || bytes.len() > out_cap {
        return WS_ERR_BUFFER;
    }
    slice::from_raw_parts_mut(out, bytes.len()).copy_from_slice(&bytes);
    *out_len = bytes.len();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_transport_through_ffi() {
        unsafe {
            let mut a_priv = [0u8; 32];
            let mut a_pub = [0u8; 32];
            let mut b_priv = [0u8; 32];
            let mut b_pub = [0u8; 32];
            assert_eq!(
                ws_generate_keypair(a_priv.as_mut_ptr(), a_pub.as_mut_ptr()),
                0
            );
            assert_eq!(
                ws_generate_keypair(b_priv.as_mut_ptr(), b_pub.as_mut_ptr()),
                0
            );

            let a = ws_peer_new(a_priv.as_ptr(), b_pub.as_ptr(), 0);
            let b = ws_peer_new(b_priv.as_ptr(), a_pub.as_ptr(), 1);
            assert!(!a.is_null() && !b.is_null());

            let mut buf = [0u8; 2048];
            let mut len = 0usize;

            // A -> handshake init
            let code = ws_peer_encapsulate(
                a,
                std::ptr::null(),
                0,
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            );
            assert_eq!(code, WS_ACTION_NETWORK);
            let init = buf[..len].to_vec();

            // B -> handshake response
            let code = ws_peer_decapsulate(
                b,
                init.as_ptr(),
                init.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            );
            assert_eq!(code, WS_ACTION_NETWORK);
            let resp = buf[..len].to_vec();

            // A completes handshake
            ws_peer_decapsulate(
                a,
                resp.as_ptr(),
                resp.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            );

            // A -> data packet
            let mut packet = [0u8; 20];
            packet[0] = 0x45;
            packet[3] = 20;
            packet[8] = 64;
            packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
            packet[16..20].copy_from_slice(&[100, 64, 0, 2]);
            let code = ws_peer_encapsulate(
                a,
                packet.as_ptr(),
                packet.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            );
            assert_eq!(code, WS_ACTION_NETWORK);
            let encrypted = buf[..len].to_vec();

            // B recovers the exact packet
            let code = ws_peer_decapsulate(
                b,
                encrypted.as_ptr(),
                encrypted.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
            );
            assert_eq!(code, WS_ACTION_TUNNEL);
            assert_eq!(&buf[..len], &packet[..]);

            ws_peer_free(a);
            ws_peer_free(b);
        }
    }
}
