/* Diffie-Hellman handshake between Device1 (initiator) and Device2 (responder).
 *
 * Runs over a short TCP control connection between the two devices
 * (device-to-device traffic is never forwarded, so NFQUEUE does not touch it).
 * Protected data forwarding starts only after this handshake succeeds.
 *
 *   Initiator                                    Responder
 *   HELLO_I: type|ver|rand_i(32)|g^a(256)  --->
 *                                          <---  HELLO_R: type|ver|rand_r(32)|g^b(256)|MAC_r(32)
 *   FINISH:  type|MAC_i(32)                --->
 *
 *   shared              = g^ab mod p
 *   session || confirm  = HKDF-SHA256(salt = rand_i || rand_r, ikm = shared || PSK)
 *   th                  = SHA256(HELLO_I || HELLO_R without MAC)
 *   MAC_r = HMAC-SHA256(confirm, "responder" || th)
 *   MAC_i = HMAC-SHA256(confirm, "initiator" || th)
 *
 * The MACs give key confirmation; with a PSK they also authenticate the peer,
 * which blocks man-in-the-middle attacks on plain Diffie-Hellman.
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "crypto.h"
#include <stddef.h>
#include <stdint.h>

int hs_initiator(int fd, const uint8_t *psk, size_t psk_len, session_t *out);
int hs_responder(int fd, const uint8_t *psk, size_t psk_len, session_t *out);

/* Network wrappers. Return 0 on success. */
int hs_connect(const char *peer, int port, const uint8_t *psk, size_t psk_len,
               int retries, session_t *out);
int hs_listen(const char *bind_addr, int port, const char *expected_peer,
              const uint8_t *psk, size_t psk_len, session_t *out);

#endif
