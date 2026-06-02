/*
 * WhaleScale agent C ABI.
 *
 * The iOS (Swift) and Android (Kotlin/JNI) clients link the `whalescale`
 * static/dynamic library and call these functions. The app owns the OS TUN
 * device and UDP socket; all WireGuard cryptography lives in the Rust core.
 *
 * Generate this header in CI with cbindgen, or keep it in sync by hand.
 */
#ifndef WHALESCALE_H
#define WHALESCALE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Action / error codes returned by encapsulate / decapsulate. */
#define WS_ACTION_NONE     0  /* nothing to do                         */
#define WS_ACTION_NETWORK  1  /* send `out` to the peer over UDP       */
#define WS_ACTION_TUNNEL   2  /* write `out` to the local TUN device   */
#define WS_ERR            -1  /* internal error                        */
#define WS_ERR_BUFFER     -2  /* null arg or `out` buffer too small    */

/* Opaque per-peer WireGuard session. */
typedef struct WsPeer WsPeer;

/* Fill two 32-byte buffers with a fresh keypair. Returns 0 on success. */
int32_t ws_generate_keypair(uint8_t *out_private, uint8_t *out_public);

/* Create a session from our 32-byte private key and the peer's 32-byte public
 * key. `index` is a locally-unique session id. Returns NULL on failure. */
WsPeer *ws_peer_new(const uint8_t *private_key,
                    const uint8_t *peer_public,
                    uint32_t index);

/* Destroy a session created by ws_peer_new. */
void ws_peer_free(WsPeer *handle);

/* Encrypt an outbound IP packet. Pass input=NULL,input_len=0 to drive the
 * handshake. On WS_ACTION_*, `out_len` receives the number of bytes written. */
int32_t ws_peer_encapsulate(WsPeer *handle,
                            const uint8_t *input, size_t input_len,
                            uint8_t *out, size_t out_cap, size_t *out_len);

/* Process an inbound UDP datagram from the peer. */
int32_t ws_peer_decapsulate(WsPeer *handle,
                            const uint8_t *input, size_t input_len,
                            uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WHALESCALE_H */
