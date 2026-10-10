#include "crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

/* RFC 3526, 2048-bit MODP group (group 14) */
static const char *DH_P_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

/* Each direction uses its own fixed nonce prefix, so the two devices,
 * which share one session key, can never produce the same nonce. */
static const uint8_t PREFIX_INITIATOR[NONCE_PREFIX_LEN] = {0, 0, 0, 1};
static const uint8_t PREFIX_RESPONDER[NONCE_PREFIX_LEN] = {0, 0, 0, 2};

static BIGNUM *dh_p(void)
{
    BIGNUM *p = NULL;
    BN_hex2bn(&p, DH_P_HEX);
    return p;
}

/* ------------------------------------------------------------------ */
/* Diffie-Hellman                                                     */
/* ------------------------------------------------------------------ */
int dh_generate(dh_keypair_t *kp)
{
    int rc = CRYPTO_ERR_INTERNAL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = dh_p(), *g = BN_new(), *range = BN_new(), *A = BN_new();
    kp->priv = BN_secure_new();
    if (!ctx || !p || !g || !range || !A || !kp->priv)
        goto out;

    /* a uniformly random in [2, p-2] */
    if (!BN_set_word(g, 2) || !BN_sub(range, p, g) || !BN_sub_word(range, 1) ||
        !BN_priv_rand_range(kp->priv, range) || !BN_add_word(kp->priv, 2))
        goto out;
    BN_set_flags(kp->priv, BN_FLG_CONSTTIME);

    /* A = g^a mod p (constant time) */
    if (!BN_mod_exp_mont_consttime(A, g, kp->priv, p, ctx, NULL))
        goto out;
    if (BN_bn2binpad(A, kp->pub, DH_PUB_LEN) != DH_PUB_LEN)
        goto out;
    rc = CRYPTO_OK;
out:
    if (rc != CRYPTO_OK) {
        BN_clear_free(kp->priv);
        kp->priv = NULL;
    }
    BN_free(p); BN_free(g); BN_free(range); BN_free(A); BN_CTX_free(ctx);
    return rc;
}

int dh_shared_secret(const dh_keypair_t *kp, const uint8_t peer_pub[DH_PUB_LEN],
                     uint8_t shared[DH_PUB_LEN])
{
    int rc = CRYPTO_ERR_INTERNAL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = dh_p(), *y = BN_bin2bn(peer_pub, DH_PUB_LEN, NULL);
    BIGNUM *pm1 = BN_new(), *q = BN_new(), *t = BN_new(), *s = BN_new();
    if (!ctx || !p || !y || !pm1 || !q || !t || !s)
        goto out;

    /* Validate the peer value: 1 < y < p-1, and y^q == 1 (prime-order
     * subgroup, q = (p-1)/2). Rejects values that force a weak secret. */
    if (!BN_copy(pm1, p) || !BN_sub_word(pm1, 1) || !BN_rshift1(q, pm1))
        goto out;
    if (BN_cmp(y, BN_value_one()) <= 0 || BN_cmp(y, pm1) >= 0) {
        rc = CRYPTO_ERR_INVALID;
        goto out;
    }
    if (!BN_mod_exp(t, y, q, p, ctx))
        goto out;
    if (!BN_is_one(t)) {
        rc = CRYPTO_ERR_INVALID;
        goto out;
    }

    /* s = y^a mod p */
    if (!BN_mod_exp_mont_consttime(s, y, kp->priv, p, ctx, NULL))
        goto out;
    if (BN_bn2binpad(s, shared, DH_PUB_LEN) != DH_PUB_LEN)
        goto out;
    rc = CRYPTO_OK;
out:
    BN_free(p); BN_free(y); BN_free(pm1); BN_free(q); BN_free(t);
    BN_clear_free(s); BN_CTX_free(ctx);
    return rc;
}

void dh_free(dh_keypair_t *kp)
{
    BN_clear_free(kp->priv);
    kp->priv = NULL;
}

int dh_group_selftest(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = dh_p(), *q = BN_new();
    int ok = ctx && p && q && BN_num_bits(p) == 2048 &&
             BN_rshift1(q, p) &&   /* (p-1)/2 == p >> 1 since p is odd */
             BN_check_prime(p, ctx, NULL) == 1 &&
             BN_check_prime(q, ctx, NULL) == 1;
    BN_free(p); BN_free(q); BN_CTX_free(ctx);
    return ok;
}

/* ------------------------------------------------------------------ */
/* HKDF                                                               */
/* ------------------------------------------------------------------ */
int derive_keys(const uint8_t *shared, size_t shared_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *psk, size_t psk_len,
                uint8_t session_key[KEY_LEN], uint8_t confirm_key[KEY_LEN])
{
    static const char info[] = "secure-inline-channel v1 keys";
    uint8_t ikm[DH_PUB_LEN + 256];
    uint8_t okm[2 * KEY_LEN];
    size_t okm_len = sizeof okm;
    int rc = CRYPTO_ERR_INTERNAL;

    if (shared_len + psk_len > sizeof ikm)
        return CRYPTO_ERR_INVALID;
    memcpy(ikm, shared, shared_len);
    if (psk_len)
        memcpy(ikm + shared_len, psk, psk_len);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx &&
        EVP_PKEY_derive_init(pctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)(shared_len + psk_len)) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)info,
                                    (int)strlen(info)) > 0 &&
        EVP_PKEY_derive(pctx, okm, &okm_len) > 0 && okm_len == sizeof okm) {
        memcpy(session_key, okm, KEY_LEN);
        memcpy(confirm_key, okm + KEY_LEN, KEY_LEN);
        rc = CRYPTO_OK;
    }
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_cleanse(ikm, sizeof ikm);
    OPENSSL_cleanse(okm, sizeof okm);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Replay window                                                      */
/* ------------------------------------------------------------------ */
#define BIT_GET(w, c) (((w)->bits[((c) % REPLAY_WIN) / 64] >> ((c) % 64)) & 1)
#define BIT_SET(w, c) ((w)->bits[((c) % REPLAY_WIN) / 64] |= 1ULL << ((c) % 64))
#define BIT_CLR(w, c) ((w)->bits[((c) % REPLAY_WIN) / 64] &= ~(1ULL << ((c) % 64)))

void replay_init(replay_window_t *w)
{
    memset(w, 0, sizeof *w);
}

int replay_check(const replay_window_t *w, uint64_t ctr)
{
    if (!w->has_top || ctr > w->top)
        return 1;
    if (w->top - ctr >= REPLAY_WIN)
        return 0;                     /* too old */
    return !BIT_GET(w, ctr);          /* already seen? */
}

void replay_update(replay_window_t *w, uint64_t ctr)
{
    if (!w->has_top || ctr > w->top) {
        uint64_t from = w->has_top ? w->top + 1 : 0;
        if (!w->has_top || ctr - from >= REPLAY_WIN)
            memset(w->bits, 0, sizeof w->bits);
        else
            for (uint64_t i = from; i <= ctr; i++)
                BIT_CLR(w, i);        /* slots that slid out of the window */
        w->top = ctr;
        w->has_top = 1;
    }
    BIT_SET(w, ctr);
}

/* ------------------------------------------------------------------ */
/* Session                                                            */
/* ------------------------------------------------------------------ */
void session_init(session_t *s, const uint8_t key[KEY_LEN], int is_initiator)
{
    memset(s, 0, sizeof *s);
    memcpy(s->key, key, KEY_LEN);
    memcpy(s->tx_prefix, is_initiator ? PREFIX_INITIATOR : PREFIX_RESPONDER, 4);
    memcpy(s->rx_prefix, is_initiator ? PREFIX_RESPONDER : PREFIX_INITIATOR, 4);
    replay_init(&s->replay);
    pthread_mutex_init(&s->lock, NULL);
}

void session_destroy(session_t *s)
{
    pthread_mutex_destroy(&s->lock);
    OPENSSL_cleanse(s->key, KEY_LEN);
}

static void put_be64(uint8_t *b, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { b[i] = (uint8_t)v; v >>= 8; }
}

static uint64_t get_be64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

int session_seal(session_t *s, const uint8_t *pt, size_t pt_len,
                 const uint8_t *aad, size_t aad_len, uint8_t *out)
{
    uint8_t nonce[NONCE_LEN];
    uint64_t ctr;
    int len, rc = CRYPTO_ERR_INTERNAL;

    /* Reserve a counter value: it is never handed out twice in a session. */
    pthread_mutex_lock(&s->lock);
    if (s->tx_exhausted) {
        pthread_mutex_unlock(&s->lock);
        return CRYPTO_ERR_EXHAUSTED;
    }
    ctr = s->tx_counter++;
    if (s->tx_counter == 0)           /* wrapped after 2^64 packets */
        s->tx_exhausted = 1;
    pthread_mutex_unlock(&s->lock);

    memcpy(nonce, s->tx_prefix, NONCE_PREFIX_LEN);
    put_be64(nonce + NONCE_PREFIX_LEN, ctr);

    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c &&
        EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) &&
        EVP_EncryptInit_ex(c, NULL, NULL, s->key, nonce) &&
        EVP_EncryptUpdate(c, NULL, &len, aad, (int)aad_len) &&
        EVP_EncryptUpdate(c, out, &len, pt, (int)pt_len) &&
        EVP_EncryptFinal_ex(c, out + len, &len) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, out + pt_len)) {
        put_be64(out + pt_len + TAG_LEN, ctr);   /* counter trailer */
        rc = CRYPTO_OK;
    }
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int session_open(session_t *s, const uint8_t *in, size_t in_len,
                 const uint8_t *aad, size_t aad_len, uint8_t *out, size_t *out_len)
{
    uint8_t nonce[NONCE_LEN], tag[TAG_LEN];
    int len, rc;

    if (in_len < OVERHEAD)
        return CRYPTO_ERR_AUTH;
    size_t ct_len = in_len - OVERHEAD;
    const uint8_t *ctr_bytes = in + ct_len + TAG_LEN;
    uint64_t ctr = get_be64(ctr_bytes);

    pthread_mutex_lock(&s->lock);
    int fresh = replay_check(&s->replay, ctr);
    pthread_mutex_unlock(&s->lock);
    if (!fresh)
        return CRYPTO_ERR_REPLAY;

    memcpy(nonce, s->rx_prefix, NONCE_PREFIX_LEN);
    memcpy(nonce + NONCE_PREFIX_LEN, ctr_bytes, CTR_LEN);
    memcpy(tag, in + ct_len, TAG_LEN);

    rc = CRYPTO_ERR_INTERNAL;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c &&
        EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) &&
        EVP_DecryptInit_ex(c, NULL, NULL, s->key, nonce) &&
        EVP_DecryptUpdate(c, NULL, &len, aad, (int)aad_len) &&
        EVP_DecryptUpdate(c, out, &len, in, (int)ct_len) &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {
        /* Final fails if the tag does not match */
        rc = EVP_DecryptFinal_ex(c, out + len, &len) > 0 ? CRYPTO_OK : CRYPTO_ERR_AUTH;
    }
    EVP_CIPHER_CTX_free(c);
    if (rc != CRYPTO_OK) {
        OPENSSL_cleanse(out, ct_len);   /* never release unauthenticated data */
        return rc;
    }

    pthread_mutex_lock(&s->lock);
    if (!replay_check(&s->replay, ctr)) {   /* lost a race with another thread */
        pthread_mutex_unlock(&s->lock);
        return CRYPTO_ERR_REPLAY;
    }
    replay_update(&s->replay, ctr);
    pthread_mutex_unlock(&s->lock);
    *out_len = ct_len;
    return CRYPTO_OK;
}

const char *crypto_strerror(int err)
{
    switch (err) {
    case CRYPTO_OK:            return "ok";
    case CRYPTO_ERR_AUTH:      return "AES-GCM tag verification failed";
    case CRYPTO_ERR_REPLAY:    return "replayed or stale packet counter";
    case CRYPTO_ERR_EXHAUSTED: return "send counter exhausted";
    case CRYPTO_ERR_INVALID:   return "invalid input";
    default:                   return "internal crypto error";
    }
}
