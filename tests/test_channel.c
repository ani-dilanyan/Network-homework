/* Unit tests (no root needed):  make test */
#include "../src/crypto.h"
#include "../src/handshake.h"
#include "../src/log.h"
#include "../src/packet.h"
#include "../src/processor.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_failed = 0, g_run = 0;
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("    FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
            g_failed++;                                                    \
            return;                                                        \
        }                                                                  \
    } while (0)
#define RUN(fn)                                                            \
    do {                                                                   \
        int _before = g_failed;                                            \
        g_run++;                                                           \
        fn();                                                              \
        printf("%s %s\n", g_failed == _before ? "ok  " : "FAIL", #fn);     \
    } while (0)

/* Builds a valid TCP/IPv4 packet; returns its length. */
static size_t make_packet(uint8_t *buf, const char *src, const char *dst,
                          uint16_t sport, uint16_t dport,
                          const uint8_t *payload, size_t plen)
{
    memset(buf, 0, 40);
    buf[0] = 0x45;  buf[6] = 0x40;  buf[8] = 64;  buf[9] = 6;   /* DF, TTL, TCP */
    buf[4] = 0x12;  buf[5] = 0x34;
    inet_pton(AF_INET, src, buf + 12);
    inet_pton(AF_INET, dst, buf + 16);
    uint8_t *t = buf + 20;
    t[0] = sport >> 8; t[1] = sport & 0xFF; t[2] = dport >> 8; t[3] = dport & 0xFF;
    t[4] = 0; t[5] = 0; t[6] = 0x03; t[7] = 0xE8;     /* seq 1000 */
    t[8] = 0; t[9] = 0; t[10] = 0x07; t[11] = 0xD0;   /* ack 2000 */
    t[12] = 5 << 4; t[13] = 0x18; t[14] = 0xFA; t[15] = 0xF0;
    memcpy(buf + 40, payload, plen);
    pkt_finalize(buf, 20, 20, plen);
    return 40 + plen;
}

static void session_pair(session_t *a, session_t *b)
{
    uint8_t key[KEY_LEN];
    RAND_bytes(key, sizeof key);
    session_init(a, key, 1);
    session_init(b, key, 0);
}

/* ---------------- DH / checksums ---------------- */
static void test_dh_group_is_safe_prime(void) { CHECK(dh_group_selftest()); }

static void test_dh_agreement(void)
{
    dh_keypair_t a = {0}, b = {0};
    uint8_t s1[DH_PUB_LEN], s2[DH_PUB_LEN], bad[DH_PUB_LEN] = {0};
    CHECK(dh_generate(&a) == CRYPTO_OK && dh_generate(&b) == CRYPTO_OK);
    CHECK(dh_shared_secret(&a, b.pub, s1) == CRYPTO_OK);
    CHECK(dh_shared_secret(&b, a.pub, s2) == CRYPTO_OK);
    CHECK(memcmp(s1, s2, DH_PUB_LEN) == 0);
    bad[DH_PUB_LEN - 1] = 1;                             /* y = 1 */
    CHECK(dh_shared_secret(&a, bad, s1) == CRYPTO_ERR_INVALID);
    dh_free(&a); dh_free(&b);
}

static void test_known_ip_checksum(void)
{
    const uint8_t hdr[20] = {0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0, 0,
                             0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0, 0xc7};
    CHECK(inet_checksum(hdr, 20) == 0xB861);
}

static void test_built_packet_valid(void)
{
    uint8_t p[200];
    size_t n = make_packet(p, "10.0.1.2", "10.0.2.2", 40000, 8080,
                           (const uint8_t *)"odd", 3);   /* odd length */
    CHECK(pkt_verify_checksums(p, n));
}

/* ---------------- session ---------------- */
static void test_roundtrip_and_tamper(void)
{
    session_t a, b;
    uint8_t ct[64], pt[64];
    size_t n;
    session_pair(&a, &b);
    CHECK(session_seal(&a, (const uint8_t *)"data", 4, (const uint8_t *)"aad", 3, ct) == 0);
    CHECK(session_open(&b, ct, 4 + OVERHEAD, (const uint8_t *)"aad", 3, pt, &n) == 0);
    CHECK(n == 4 && memcmp(pt, "data", 4) == 0);

    CHECK(session_seal(&a, (const uint8_t *)"data", 4, (const uint8_t *)"aad", 3, ct) == 0);
    ct[0] ^= 1;
    CHECK(session_open(&b, ct, 4 + OVERHEAD, (const uint8_t *)"aad", 3, pt, &n) == CRYPTO_ERR_AUTH);
    ct[0] ^= 1;
    CHECK(session_open(&b, ct, 4 + OVERHEAD, (const uint8_t *)"AAD", 3, pt, &n) == CRYPTO_ERR_AUTH);
}

static void test_replay_and_reflection(void)
{
    session_t a, b;
    uint8_t ct[64], pt[64];
    size_t n;
    session_pair(&a, &b);
    session_seal(&a, (const uint8_t *)"x", 1, NULL, 0, ct);
    CHECK(session_open(&b, ct, 1 + OVERHEAD, NULL, 0, pt, &n) == 0);
    CHECK(session_open(&b, ct, 1 + OVERHEAD, NULL, 0, pt, &n) == CRYPTO_ERR_REPLAY);
    session_seal(&a, (const uint8_t *)"x", 1, NULL, 0, ct);
    /* the sender must not accept its own packet back (different nonce prefix) */
    CHECK(session_open(&a, ct, 1 + OVERHEAD, NULL, 0, pt, &n) == CRYPTO_ERR_AUTH);
}

static void test_nonces_unique(void)
{
    /* Counter is strictly increasing and carried in the trailer. */
    session_t a, b;
    uint8_t ct[64];
    uint64_t prev = 0;
    session_pair(&a, &b);
    for (int i = 0; i < 10000; i++) {
        session_seal(&a, (const uint8_t *)"same", 4, NULL, 0, ct);
        uint64_t c = 0;
        for (int k = 0; k < 8; k++) c = (c << 8) | ct[4 + TAG_LEN + k];
        CHECK(i == 0 ? c == 0 : c == prev + 1);
        prev = c;
    }
    CHECK(memcmp(a.tx_prefix, b.tx_prefix, NONCE_PREFIX_LEN) != 0);
}

static void test_out_of_order_window(void)
{
    session_t a, b;
    uint8_t ct[10][32], pt[32];
    size_t n;
    int order[10] = {3, 1, 0, 9, 2, 8, 4, 7, 6, 5};
    session_pair(&a, &b);
    for (int i = 0; i < 10; i++) {
        uint8_t v = (uint8_t)i;
        session_seal(&a, &v, 1, NULL, 0, ct[i]);
    }
    for (int k = 0; k < 10; k++) {
        CHECK(session_open(&b, ct[order[k]], 1 + OVERHEAD, NULL, 0, pt, &n) == 0);
        CHECK(pt[0] == order[k]);
    }
}

static void test_replay_window_old(void)
{
    replay_window_t w;
    replay_init(&w);
    replay_update(&w, 5000);
    CHECK(!replay_check(&w, 5000 - REPLAY_WIN));
    CHECK(replay_check(&w, 4999));
    replay_update(&w, 4999);
    CHECK(!replay_check(&w, 4999));
}

/* ---------------- processor (full packets) ---------------- */
static session_t s1, s2;
static processor_t dev1, dev2;
static uint8_t wire[IP_MAX_LEN + OVERHEAD], restored[IP_MAX_LEN + OVERHEAD];

static void setup_devices(void)
{
    uint32_t n1, n2, m;
    inet_pton(AF_INET, "10.0.1.0", &n1);
    inet_pton(AF_INET, "10.0.2.0", &n2);
    inet_pton(AF_INET, "255.255.255.0", &m);
    session_pair(&s1, &s2);
    processor_init(&dev1, &s1, n1, m);
    processor_init(&dev2, &s2, n2, m);
    processor_add_port(&dev1, 8080);
    processor_add_port(&dev2, 8080);
}

static void test_pc1_to_pc2_restored_exactly(void)
{
    uint8_t orig[1500], payload[1000];
    size_t wl, rl;
    for (int i = 0; i < 1000; i++) payload[i] = "GET / HTTP/1.1\r\n"[i % 16];
    size_t n = make_packet(orig, "10.0.1.2", "10.0.2.2", 40000, 8080, payload, 1000);

    CHECK(processor_process(&dev1, orig, n, wire, sizeof wire, &wl) == VERDICT_MODIFY);
    CHECK(wl == n + OVERHEAD);
    CHECK(memcmp(wire + 12, orig + 12, 8) == 0);     /* IP addresses kept */
    CHECK(memcmp(wire + 20, orig + 20, 12) == 0);    /* ports, seq, ack kept */
    CHECK(memmem(wire, wl, "HTTP", 4) == NULL);      /* payload encrypted */
    CHECK(pkt_verify_checksums(wire, wl));

    CHECK(processor_process(&dev2, wire, wl, restored, sizeof restored, &rl) == VERDICT_MODIFY);
    CHECK(rl == n && memcmp(restored, orig, n) == 0);
    CHECK(pkt_verify_checksums(restored, rl));
}

static void test_pc2_to_pc1(void)
{
    uint8_t orig[100];
    size_t wl, rl;
    size_t n = make_packet(orig, "10.0.2.2", "10.0.1.2", 8080, 40000,
                           (const uint8_t *)"reply", 5);
    CHECK(processor_process(&dev2, orig, n, wire, sizeof wire, &wl) == VERDICT_MODIFY);
    CHECK(processor_process(&dev1, wire, wl, restored, sizeof restored, &rl) == VERDICT_MODIFY);
    CHECK(rl == n && memcmp(restored, orig, n) == 0);
}

static void test_passthrough(void)
{
    uint8_t p[100];
    size_t wl;
    size_t n = make_packet(p, "10.0.1.2", "10.0.2.2", 40000, 8080, NULL, 0);
    CHECK(processor_process(&dev1, p, n, wire, sizeof wire, &wl) == VERDICT_ACCEPT);
    n = make_packet(p, "10.0.1.2", "10.0.2.2", 40000, 22, (const uint8_t *)"ssh", 3);
    CHECK(processor_process(&dev1, p, n, wire, sizeof wire, &wl) == VERDICT_ACCEPT);
}

static void test_tampered_packets_dropped(void)
{
    uint8_t orig[100];
    size_t wl, rl;
    size_t n = make_packet(orig, "10.0.1.2", "10.0.2.2", 40000, 8080,
                           (const uint8_t *)"secret data", 11);
    processor_process(&dev1, orig, n, wire, sizeof wire, &wl);
    wire[24] ^= 0xFF;                                   /* TCP sequence number */
    CHECK(processor_process(&dev2, wire, wl, restored, sizeof restored, &rl) == VERDICT_DROP);

    processor_process(&dev1, orig, n, wire, sizeof wire, &wl);
    wire[45] ^= 0x01;                                   /* payload byte */
    CHECK(processor_process(&dev2, wire, wl, restored, sizeof restored, &rl) == VERDICT_DROP);
}

static void test_retransmission_new_nonce(void)
{
    uint8_t orig[100], w1[200], w2[200];
    size_t l1, l2, rl;
    size_t n = make_packet(orig, "10.0.1.2", "10.0.2.2", 40000, 8080,
                           (const uint8_t *)"same segment", 12);
    processor_process(&dev1, orig, n, w1, sizeof w1, &l1);
    processor_process(&dev1, orig, n, w2, sizeof w2, &l2);
    CHECK(l1 == l2 && memcmp(w1, w2, l1) != 0);
    CHECK(processor_process(&dev2, w1, l1, restored, sizeof restored, &rl) == VERDICT_MODIFY);
    CHECK(processor_process(&dev2, w2, l2, restored, sizeof restored, &rl) == VERDICT_MODIFY);
    CHECK(rl == n && memcmp(restored, orig, n) == 0);
}

/* ---------------- handshake over a socketpair ---------------- */
typedef struct { int fd; const char *psk; session_t s; int rc; } hs_arg_t;

static void *responder_thread(void *p)
{
    hs_arg_t *a = p;
    a->rc = hs_responder(a->fd, (const uint8_t *)a->psk, strlen(a->psk), &a->s);
    return NULL;
}

static int run_handshake(const char *psk_i, const char *psk_r, session_t *si, hs_arg_t *r)
{
    int sv[2];
    pthread_t t;
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    r->fd = sv[1]; r->psk = psk_r;
    pthread_create(&t, NULL, responder_thread, r);
    int rc = hs_initiator(sv[0], (const uint8_t *)psk_i, strlen(psk_i), si);
    close(sv[0]);
    pthread_join(t, NULL);
    close(sv[1]);
    return rc;
}

static void test_handshake_keys_match(void)
{
    session_t si;
    hs_arg_t r;
    uint8_t ct[64], pt[64];
    size_t n;
    CHECK(run_handshake("psk", "psk", &si, &r) == 0 && r.rc == 0);
    session_seal(&si, (const uint8_t *)"ping", 4, NULL, 0, ct);
    CHECK(session_open(&r.s, ct, 4 + OVERHEAD, NULL, 0, pt, &n) == 0 && !memcmp(pt, "ping", 4));
    session_seal(&r.s, (const uint8_t *)"pong", 4, NULL, 0, ct);
    CHECK(session_open(&si, ct, 4 + OVERHEAD, NULL, 0, pt, &n) == 0 && !memcmp(pt, "pong", 4));
}

static void test_handshake_wrong_psk(void)
{
    session_t si;
    hs_arg_t r;
    CHECK(run_handshake("right", "wrong", &si, &r) != 0);
    CHECK(r.rc != 0);
}

int main(void)
{
    log_quiet = 1;
    RUN(test_dh_group_is_safe_prime);
    RUN(test_dh_agreement);
    RUN(test_known_ip_checksum);
    RUN(test_built_packet_valid);
    RUN(test_roundtrip_and_tamper);
    RUN(test_replay_and_reflection);
    RUN(test_nonces_unique);
    RUN(test_out_of_order_window);
    RUN(test_replay_window_old);
    setup_devices();
    RUN(test_pc1_to_pc2_restored_exactly);
    RUN(test_pc2_to_pc1);
    RUN(test_passthrough);
    RUN(test_tampered_packets_dropped);
    RUN(test_retransmission_new_nonce);
    RUN(test_handshake_keys_match);
    RUN(test_handshake_wrong_psk);
    printf("\n%d tests, %d failed\n", g_run, g_failed);
    return g_failed ? 1 : 0;
}
