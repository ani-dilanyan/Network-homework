/* Per-packet decision: encrypt / decrypt / pass / drop.
 * Independent of NFQUEUE so it can be unit tested. */
#ifndef PROCESSOR_H
#define PROCESSOR_H

#include "crypto.h"
#include <stddef.h>
#include <stdint.h>

#define MAX_PORTS 16

typedef enum { VERDICT_ACCEPT, VERDICT_MODIFY, VERDICT_DROP } verdict_t;

typedef struct {
    unsigned long encrypted, decrypted;
    unsigned long pass_non_tcp, pass_unselected, pass_no_payload;
    unsigned long drop_auth, drop_replay, drop_too_large, drop_other;
} proc_stats_t;

typedef struct {
    session_t *session;
    uint32_t lan_net, lan_mask;   /* network byte order */
    uint16_t ports[MAX_PORTS];
    int nports;                   /* 0 = every TCP packet given to us */
    proc_stats_t stats;
} processor_t;

void processor_init(processor_t *p, session_t *s, uint32_t lan_net, uint32_t lan_mask);
int  processor_add_port(processor_t *p, uint16_t port);

/* For VERDICT_MODIFY the new packet is written to out (out_cap >= in_len + OVERHEAD). */
verdict_t processor_process(processor_t *p, const uint8_t *in, size_t in_len,
                            uint8_t *out, size_t out_cap, size_t *out_len);

void processor_format_stats(const processor_t *p, char *buf, size_t len);

#endif
