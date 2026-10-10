/* Secure inline device daemon (run on Device1 and Device2).
 *
 * 1. Performs the Diffie-Hellman handshake with the peer device.
 * 2. Only after the session is established, binds to NFQUEUE and starts
 *    encrypting / decrypting the payload of selected forwarded TCP packets.
 *
 *   sudo ./bin/secure_device --role responder --peer 10.0.12.1 \
 *        --lan 10.0.2.0/24 --tcp-port 8080 --psk lab-secret      (Device2)
 *   sudo ./bin/secure_device --role initiator --peer 10.0.12.2 \
 *        --lan 10.0.1.0/24 --tcp-port 8080 --psk lab-secret      (Device1)
 */
#include "handshake.h"
#include "log.h"
#include "packet.h"
#include "processor.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

typedef struct {
    processor_t proc;
    uint8_t out[IP_MAX_LEN + OVERHEAD];
} ctx_t;

static int on_packet(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                     struct nfq_data *nfa, void *data)
{
    (void)msg;
    ctx_t *ctx = data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;
    unsigned char *pkt;
    int len = nfq_get_payload(nfa, &pkt);
    if (len < 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    size_t out_len = 0;
    switch (processor_process(&ctx->proc, pkt, (size_t)len, ctx->out,
                              sizeof ctx->out, &out_len)) {
    case VERDICT_MODIFY:
        return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)out_len, ctx->out);
    case VERDICT_ACCEPT:
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    default:
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

static int parse_cidr(const char *s, uint32_t *net, uint32_t *mask)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%s", s);
    char *slash = strchr(buf, '/');
    int bits = 32;
    if (slash) {
        *slash = 0;
        bits = atoi(slash + 1);
        if (bits < 0 || bits > 32) return -1;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return -1;
    *mask = bits ? htonl(0xFFFFFFFFu << (32 - bits)) : 0;
    *net = a.s_addr & *mask;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s --role initiator|responder --peer IP --lan CIDR [options]\n"
        "  --peer IP          address of the peer device\n"
        "  --lan CIDR         subnet of the host behind THIS device (e.g. 10.0.1.0/24)\n"
        "  --tcp-port N       protect TCP to/from port N (repeatable; default: all queued TCP)\n"
        "  --psk STRING       pre-shared key authenticating the DH exchange (recommended)\n"
        "  --bind IP          responder listen address (default 0.0.0.0)\n"
        "  --hs-port N        handshake port (default 7000)\n"
        "  --queue N          NFQUEUE number (default 0)\n"
        "  --stats-interval S seconds between stats lines (default 10)\n", prog);
}

int main(int argc, char **argv)
{
    const char *role = NULL, *peer = NULL, *lan = NULL, *bind_addr = "0.0.0.0";
    const char *psk = "";
    int hs_port = 7000, queue = 0, stats_interval = 10;
    static ctx_t ctx;               /* large buffer: keep off the stack */
    uint16_t ports[MAX_PORTS];
    int nports = 0;

    static const struct option opts[] = {
        {"role", required_argument, 0, 'r'},  {"peer", required_argument, 0, 'p'},
        {"lan", required_argument, 0, 'l'},   {"tcp-port", required_argument, 0, 't'},
        {"psk", required_argument, 0, 'k'},   {"bind", required_argument, 0, 'b'},
        {"hs-port", required_argument, 0, 'H'}, {"queue", required_argument, 0, 'q'},
        {"stats-interval", required_argument, 0, 's'}, {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
        switch (c) {
        case 'r': role = optarg; break;
        case 'p': peer = optarg; break;
        case 'l': lan = optarg; break;
        case 't':
            if (nports < MAX_PORTS) ports[nports++] = (uint16_t)atoi(optarg);
            break;
        case 'k': psk = optarg; break;
        case 'b': bind_addr = optarg; break;
        case 'H': hs_port = atoi(optarg); break;
        case 'q': queue = atoi(optarg); break;
        case 's': stats_interval = atoi(optarg); break;
        default: usage(argv[0]); return 2;
        }
    }
    uint32_t lan_net, lan_mask;
    if (!role || !peer || !lan || parse_cidr(lan, &lan_net, &lan_mask) ||
        (strcmp(role, "initiator") && strcmp(role, "responder"))) {
        usage(argv[0]);
        return 2;
    }
    if (!*psk)
        LOG_WARN("no --psk given: DH is unauthenticated (vulnerable to MITM)");

    /* ---- 1. handshake BEFORE any protected data is processed ---- */
    static session_t session;
    int hs = !strcmp(role, "initiator")
        ? hs_connect(peer, hs_port, (const uint8_t *)psk, strlen(psk), 30, &session)
        : hs_listen(bind_addr, hs_port, peer, (const uint8_t *)psk, strlen(psk), &session);
    if (hs != 0) {
        LOG_ERROR("could not establish a secure session with %s", peer);
        return 1;
    }

    processor_init(&ctx.proc, &session, lan_net, lan_mask);
    for (int i = 0; i < nports; i++)
        processor_add_port(&ctx.proc, ports[i]);

    /* ---- 2. NFQUEUE packet processing ---- */
    struct nfq_handle *h = nfq_open();
    if (!h) { LOG_ERROR("nfq_open failed (are you root?)"); return 1; }
    nfq_unbind_pf(h, AF_INET);       /* no-ops on modern kernels */
    nfq_bind_pf(h, AF_INET);
    struct nfq_q_handle *qh = nfq_create_queue(h, (uint16_t)queue, &on_packet, &ctx);
    if (!qh) { LOG_ERROR("cannot bind NFQUEUE %d", queue); nfq_close(h); return 1; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        LOG_ERROR("cannot set copy mode");
        return 1;
    }

    struct sigaction sa = {.sa_handler = on_signal};   /* no SA_RESTART */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int fd = nfq_fd(h);
    struct timeval tv = {.tv_sec = 1};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    char ports_str[128] = "all";
    if (nports) {
        size_t off = 0;
        for (int i = 0; i < nports; i++)
            off += (size_t)snprintf(ports_str + off, sizeof ports_str - off,
                                    i ? ",%u" : "%u", ports[i]);
    }
    LOG_INFO("session up; processing NFQUEUE %d (lan=%s, ports=%s)", queue, lan, ports_str);

    char buf[IP_MAX_LEN + 4096] __attribute__((aligned));
    char stats[512];
    time_t last = time(NULL);
    while (!g_stop) {
        ssize_t rv = recv(fd, buf, sizeof buf, 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, (int)rv);
        } else if (errno == ENOBUFS) {
            LOG_WARN("NFQUEUE overrun, packets lost");
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            LOG_ERROR("recv: %s", strerror(errno));
            break;
        }
        if (stats_interval > 0 && time(NULL) - last >= stats_interval) {
            processor_format_stats(&ctx.proc, stats, sizeof stats);
            LOG_INFO("stats: %s", stats);
            last = time(NULL);
        }
    }

    processor_format_stats(&ctx.proc, stats, sizeof stats);
    LOG_INFO("final stats: %s", stats);
    nfq_destroy_queue(qh);
    nfq_close(h);
    session_destroy(&session);
    return 0;
}
