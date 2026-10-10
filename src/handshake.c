#include "handshake.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define HS_VERSION   1
#define MSG_HELLO_I  1
#define MSG_HELLO_R  2
#define MSG_FINISH   3
#define RAND_LEN    32
#define MAC_LEN     32
#define HELLO_LEN   (2 + RAND_LEN + DH_PUB_LEN)
#define MAX_MSG   4096

/* ---------------- framing: 4-byte length + body ---------------- */
static int send_all(int fd, const uint8_t *b, size_t n)
{
    while (n) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        b += w; n -= (size_t)w;
    }
    return 0;
}

static int recv_exact(int fd, uint8_t *b, size_t n)
{
    while (n) {
        ssize_t r = recv(fd, b, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        b += r; n -= (size_t)r;
    }
    return 0;
}

static int send_msg(int fd, const uint8_t *msg, size_t len)
{
    uint32_t n = htonl((uint32_t)len);
    return send_all(fd, (uint8_t *)&n, 4) || send_all(fd, msg, len) ? -1 : 0;
}

/* Receives exactly `expect` bytes of body; anything else is an error. */
static int recv_msg(int fd, uint8_t *msg, size_t expect)
{
    uint32_t n;
    if (recv_exact(fd, (uint8_t *)&n, 4)) return -1;
    n = ntohl(n);
    if (n != expect || n > MAX_MSG) return -1;
    return recv_exact(fd, msg, n);
}

/* ---------------- helpers ---------------- */
static void sha256(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                   uint8_t out[32])
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, a, alen);
    EVP_DigestUpdate(c, b, blen);
    EVP_DigestFinal_ex(c, out, NULL);
    EVP_MD_CTX_free(c);
}

static void confirm_mac(const uint8_t key[KEY_LEN], const char *label,
                        const uint8_t th[32], uint8_t out[MAC_LEN])
{
    uint8_t buf[16 + 32];
    size_t l = strlen(label);
    unsigned int outlen = MAC_LEN;
    memcpy(buf, label, l);
    memcpy(buf + l, th, 32);
    HMAC(EVP_sha256(), key, KEY_LEN, buf, l + 32, out, &outlen);
}

static void log_key_id(const char *role, const uint8_t key[KEY_LEN])
{
    /* Fingerprint for logs, never the key itself. */
    uint8_t h[32];
    char hex[13];
    sha256((const uint8_t *)"key-id", 6, key, KEY_LEN, h);
    for (int i = 0; i < 6; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
    LOG_INFO("handshake complete (%s), key id %s", role, hex);
}

static int parse_hello(const uint8_t *m, int type, uint8_t **rand, uint8_t **pub)
{
    if (m[0] != type || m[1] != HS_VERSION) return -1;
    *rand = (uint8_t *)m + 2;
    *pub = (uint8_t *)m + 2 + RAND_LEN;
    return 0;
}

/* ---------------- roles ---------------- */
int hs_initiator(int fd, const uint8_t *psk, size_t psk_len, session_t *out)
{
    uint8_t hello_i[HELLO_LEN], hello_r[HELLO_LEN + MAC_LEN], finish[1 + MAC_LEN];
    uint8_t salt[2 * RAND_LEN], shared[DH_PUB_LEN], th[32], mac[MAC_LEN];
    uint8_t skey[KEY_LEN], ckey[KEY_LEN], *rand_r, *pub_r;
    dh_keypair_t kp = {0};
    int rc = -1;

    if (dh_generate(&kp) != CRYPTO_OK) return -1;
    hello_i[0] = MSG_HELLO_I;
    hello_i[1] = HS_VERSION;
    if (RAND_bytes(hello_i + 2, RAND_LEN) != 1) goto out;
    memcpy(hello_i + 2 + RAND_LEN, kp.pub, DH_PUB_LEN);
    if (send_msg(fd, hello_i, sizeof hello_i)) goto out;

    if (recv_msg(fd, hello_r, sizeof hello_r) ||
        parse_hello(hello_r, MSG_HELLO_R, &rand_r, &pub_r)) {
        LOG_WARN("handshake: bad or missing HELLO_R");
        goto out;
    }
    if (dh_shared_secret(&kp, pub_r, shared) != CRYPTO_OK) {
        LOG_WARN("handshake: invalid DH public value from responder");
        goto out;
    }
    memcpy(salt, hello_i + 2, RAND_LEN);
    memcpy(salt + RAND_LEN, rand_r, RAND_LEN);
    if (derive_keys(shared, sizeof shared, salt, sizeof salt, psk, psk_len,
                    skey, ckey) != CRYPTO_OK) goto out;

    sha256(hello_i, sizeof hello_i, hello_r, HELLO_LEN, th);
    confirm_mac(ckey, "responder", th, mac);
    if (CRYPTO_memcmp(mac, hello_r + HELLO_LEN, MAC_LEN) != 0) {
        LOG_WARN("handshake: responder key confirmation failed (wrong PSK or MITM?)");
        goto out;
    }
    finish[0] = MSG_FINISH;
    confirm_mac(ckey, "initiator", th, finish + 1);
    if (send_msg(fd, finish, sizeof finish)) goto out;

    session_init(out, skey, 1);
    log_key_id("initiator", skey);
    rc = 0;
out:
    dh_free(&kp);
    OPENSSL_cleanse(shared, sizeof shared);
    OPENSSL_cleanse(skey, sizeof skey);
    OPENSSL_cleanse(ckey, sizeof ckey);
    return rc;
}

int hs_responder(int fd, const uint8_t *psk, size_t psk_len, session_t *out)
{
    uint8_t hello_i[HELLO_LEN], hello_r[HELLO_LEN + MAC_LEN], finish[1 + MAC_LEN];
    uint8_t salt[2 * RAND_LEN], shared[DH_PUB_LEN], th[32], mac[MAC_LEN];
    uint8_t skey[KEY_LEN], ckey[KEY_LEN], *rand_i, *pub_i;
    dh_keypair_t kp = {0};
    int rc = -1;

    if (recv_msg(fd, hello_i, sizeof hello_i) ||
        parse_hello(hello_i, MSG_HELLO_I, &rand_i, &pub_i)) {
        LOG_WARN("handshake: bad or missing HELLO_I");
        return -1;
    }
    if (dh_generate(&kp) != CRYPTO_OK) return -1;

    hello_r[0] = MSG_HELLO_R;
    hello_r[1] = HS_VERSION;
    if (RAND_bytes(hello_r + 2, RAND_LEN) != 1) goto out;
    memcpy(hello_r + 2 + RAND_LEN, kp.pub, DH_PUB_LEN);

    if (dh_shared_secret(&kp, pub_i, shared) != CRYPTO_OK) {
        LOG_WARN("handshake: invalid DH public value from initiator");
        goto out;
    }
    memcpy(salt, rand_i, RAND_LEN);
    memcpy(salt + RAND_LEN, hello_r + 2, RAND_LEN);
    if (derive_keys(shared, sizeof shared, salt, sizeof salt, psk, psk_len,
                    skey, ckey) != CRYPTO_OK) goto out;

    sha256(hello_i, sizeof hello_i, hello_r, HELLO_LEN, th);
    confirm_mac(ckey, "responder", th, hello_r + HELLO_LEN);
    if (send_msg(fd, hello_r, sizeof hello_r)) goto out;

    if (recv_msg(fd, finish, sizeof finish) || finish[0] != MSG_FINISH) {
        LOG_WARN("handshake: bad or missing FINISH");
        goto out;
    }
    confirm_mac(ckey, "initiator", th, mac);
    if (CRYPTO_memcmp(mac, finish + 1, MAC_LEN) != 0) {
        LOG_WARN("handshake: initiator key confirmation failed (wrong PSK or MITM?)");
        goto out;
    }

    session_init(out, skey, 0);
    log_key_id("responder", skey);
    rc = 0;
out:
    dh_free(&kp);
    OPENSSL_cleanse(shared, sizeof shared);
    OPENSSL_cleanse(skey, sizeof skey);
    OPENSSL_cleanse(ckey, sizeof ckey);
    return rc;
}

/* ---------------- network wrappers ---------------- */
static void set_timeout(int fd, int seconds)
{
    struct timeval tv = {.tv_sec = seconds, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

int hs_connect(const char *peer, int port, const uint8_t *psk, size_t psk_len,
               int retries, session_t *out)
{
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, peer, &sa.sin_addr) != 1) {
        LOG_ERROR("bad peer address %s", peer);
        return -1;
    }
    for (int attempt = 1; attempt <= retries; attempt++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        set_timeout(fd, 10);
        if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0 &&
            hs_initiator(fd, psk, psk_len, out) == 0) {
            close(fd);
            return 0;
        }
        LOG_INFO("handshake attempt %d/%d with %s:%d failed", attempt, retries, peer, port);
        close(fd);
        sleep(1);
    }
    return -1;
}

int hs_listen(const char *bind_addr, int port, const char *expected_peer,
              const uint8_t *psk, size_t psk_len, session_t *out)
{
    int one = 1, rc = -1;
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    struct in_addr expected = {0};
    if (inet_pton(AF_INET, bind_addr, &sa.sin_addr) != 1 ||
        (expected_peer && inet_pton(AF_INET, expected_peer, &expected) != 1)) {
        LOG_ERROR("bad address");
        return -1;
    }
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return -1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(srv, (struct sockaddr *)&sa, sizeof sa) || listen(srv, 1)) {
        LOG_ERROR("cannot listen on %s:%d: %s", bind_addr, port, strerror(errno));
        close(srv);
        return -1;
    }
    LOG_INFO("waiting for handshake on %s:%d", bind_addr, port);
    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        int fd = accept(srv, (struct sockaddr *)&peer, &plen);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (expected_peer && peer.sin_addr.s_addr != expected.s_addr) {
            LOG_WARN("rejecting handshake from unexpected host %s", inet_ntoa(peer.sin_addr));
            close(fd);
            continue;
        }
        set_timeout(fd, 10);
        int ok = hs_responder(fd, psk, psk_len, out) == 0;
        close(fd);
        if (ok) { rc = 0; break; }
    }
    close(srv);
    return rc;
}
