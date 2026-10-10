/* Cryptographic primitives for the secure inline channel.
 *
 *  - Finite-field Diffie-Hellman, RFC 3526 2048-bit MODP group 14 (g = 2)
 *  - HKDF-SHA256: DH secret -> session key + confirm key
 *  - AES-256-GCM per packet, 96-bit nonce = direction prefix || counter
 *  - Sliding-window anti-replay (like IPsec ESP)
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/bn.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define KEY_LEN          32   /* AES-256 */
#define TAG_LEN          16   /* AES-GCM tag */
#define CTR_LEN           8   /* explicit nonce part, sent in every packet */
#define NONCE_PREFIX_LEN  4   /* implicit nonce part (direction id) */
#define NONCE_LEN        12
#define OVERHEAD (TAG_LEN + CTR_LEN)  /* bytes added to each protected payload */
#define DH_PUB_LEN      256   /* 2048-bit public values */
#define REPLAY_WIN     1024   /* replay window size in packets */

enum {
    CRYPTO_OK            = 0,
    CRYPTO_ERR_AUTH      = -1,  /* tag verification failed */
    CRYPTO_ERR_REPLAY    = -2,  /* replayed or too-old counter */
    CRYPTO_ERR_EXHAUSTED = -3,  /* send counter used up: new handshake needed */
    CRYPTO_ERR_INTERNAL  = -4,
    CRYPTO_ERR_INVALID   = -5   /* bad input (e.g. invalid DH value) */
};

/* ---------- Diffie-Hellman ---------- */
typedef struct {
    BIGNUM *priv;              /* secret exponent a */
    uint8_t pub[DH_PUB_LEN];   /* g^a mod p, big-endian, zero padded */
} dh_keypair_t;

int  dh_generate(dh_keypair_t *kp);
int  dh_shared_secret(const dh_keypair_t *kp, const uint8_t peer_pub[DH_PUB_LEN],
                      uint8_t shared[DH_PUB_LEN]);
void dh_free(dh_keypair_t *kp);
int  dh_group_selftest(void);  /* checks p is a 2048-bit safe prime */

/* HKDF-SHA256(salt, ikm = shared || psk) -> session_key || confirm_key */
int derive_keys(const uint8_t *shared, size_t shared_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *psk, size_t psk_len,
                uint8_t session_key[KEY_LEN], uint8_t confirm_key[KEY_LEN]);

/* ---------- replay window ---------- */
typedef struct {
    int      has_top;
    uint64_t top;
    uint64_t bits[REPLAY_WIN / 64];   /* circular bitmap indexed by ctr % WIN */
} replay_window_t;

void replay_init(replay_window_t *w);
int  replay_check(const replay_window_t *w, uint64_t ctr);  /* 1 = acceptable */
void replay_update(replay_window_t *w, uint64_t ctr);

/* ---------- session ---------- */
typedef struct {
    uint8_t key[KEY_LEN];
    uint8_t tx_prefix[NONCE_PREFIX_LEN];
    uint8_t rx_prefix[NONCE_PREFIX_LEN];
    uint64_t tx_counter;
    int tx_exhausted;
    replay_window_t replay;
    pthread_mutex_t lock;
} session_t;

void session_init(session_t *s, const uint8_t key[KEY_LEN], int is_initiator);
void session_destroy(session_t *s);

/* out receives pt_len + OVERHEAD bytes: ciphertext || tag || counter */
int session_seal(session_t *s, const uint8_t *pt, size_t pt_len,
                 const uint8_t *aad, size_t aad_len, uint8_t *out);

/* in = ciphertext || tag || counter; out receives in_len - OVERHEAD bytes */
int session_open(session_t *s, const uint8_t *in, size_t in_len,
                 const uint8_t *aad, size_t aad_len, uint8_t *out, size_t *out_len);

const char *crypto_strerror(int err);

#endif
