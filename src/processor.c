#include "processor.h"
#include "log.h"
#include "packet.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

void processor_init(processor_t *p, session_t *s, uint32_t lan_net, uint32_t lan_mask)
{
    memset(p, 0, sizeof *p);
    p->session = s;
    p->lan_mask = lan_mask;
    p->lan_net = lan_net & lan_mask;
}

int processor_add_port(processor_t *p, uint16_t port)
{
    if (p->nports >= MAX_PORTS)
        return -1;
    p->ports[p->nports++] = port;
    return 0;
}

static int selected(const processor_t *p, const tcp_info_t *i)
{
    if (p->nports == 0)
        return 1;
    for (int k = 0; k < p->nports; k++)
        if (i->sport == p->ports[k] || i->dport == p->ports[k])
            return 1;
    return 0;
}

static void log_drop(const tcp_info_t *i, const char *why)
{
    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &i->saddr, s, sizeof s);
    inet_ntop(AF_INET, &i->daddr, d, sizeof d);
    LOG_WARN("drop %s:%u -> %s:%u: %s", s, i->sport, d, i->dport, why);
}

verdict_t processor_process(processor_t *p, const uint8_t *in, size_t in_len,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    tcp_info_t i;
    uint8_t aad[AAD_LEN];

    if (pkt_parse(in, in_len, &i) != 0) {
        p->stats.pass_non_tcp++;
        return VERDICT_ACCEPT;
    }
    if (!selected(p, &i)) {
        p->stats.pass_unselected++;
        return VERDICT_ACCEPT;
    }
    if (i.payload_len == 0) {        /* SYN, pure ACK, FIN: nothing to protect */
        p->stats.pass_no_payload++;
        return VERDICT_ACCEPT;
    }

    /* Direction: packets from our own LAN go out encrypted; everything else
     * selected came from the peer device and must be decrypted. */
    int outbound = (i.saddr & p->lan_mask) == p->lan_net;
    pkt_aad(in, &i, aad);
    memcpy(out, in, i.payload_off);  /* keep the original IP + TCP headers */

    if (outbound) {
        size_t new_total = i.payload_off + i.payload_len + OVERHEAD;
        if (new_total > IP_MAX_LEN || new_total > out_cap) {
            p->stats.drop_too_large++;
            log_drop(&i, "packet too large after encryption");
            return VERDICT_DROP;
        }
        int rc = session_seal(p->session, in + i.payload_off, i.payload_len,
                              aad, sizeof aad, out + i.payload_off);
        if (rc != CRYPTO_OK) {
            p->stats.drop_other++;
            log_drop(&i, crypto_strerror(rc));
            return VERDICT_DROP;
        }
        pkt_finalize(out, i.ihl, i.thl, i.payload_len + OVERHEAD);
        *out_len = new_total;
        p->stats.encrypted++;
        return VERDICT_MODIFY;
    }

    size_t pt_len = 0;
    int rc = session_open(p->session, in + i.payload_off, i.payload_len,
                          aad, sizeof aad, out + i.payload_off, &pt_len);
    if (rc != CRYPTO_OK) {
        if (rc == CRYPTO_ERR_AUTH) p->stats.drop_auth++;
        else if (rc == CRYPTO_ERR_REPLAY) p->stats.drop_replay++;
        else p->stats.drop_other++;
        log_drop(&i, crypto_strerror(rc));
        return VERDICT_DROP;
    }
    pkt_finalize(out, i.ihl, i.thl, pt_len);
    *out_len = i.payload_off + pt_len;
    p->stats.decrypted++;
    return VERDICT_MODIFY;
}

void processor_format_stats(const processor_t *p, char *buf, size_t len)
{
    const proc_stats_t *s = &p->stats;
    snprintf(buf, len,
             "encrypted=%lu decrypted=%lu pass_no_payload=%lu pass_unselected=%lu "
             "pass_non_tcp=%lu drop_auth=%lu drop_replay=%lu drop_too_large=%lu "
             "drop_other=%lu",
             s->encrypted, s->decrypted, s->pass_no_payload, s->pass_unselected,
             s->pass_non_tcp, s->drop_auth, s->drop_replay, s->drop_too_large,
             s->drop_other);
}
