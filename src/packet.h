/* Minimal IPv4/TCP parsing and checksum handling.
 *
 * The original IP and TCP headers are kept byte for byte; after the payload
 * changes size we only update the IP Total Length, the IP header checksum
 * and the TCP checksum.
 */
#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>

#define IP_MAX_LEN 65535
#define AAD_LEN    20   /* src IP (4) + dst IP (4) + TCP ports/seq/ack (12) */

typedef struct {
    size_t ihl;          /* IP header length incl. options */
    size_t thl;          /* TCP header length incl. options */
    size_t payload_off;  /* = ihl + thl */
    size_t payload_len;
    uint32_t saddr, daddr;   /* network byte order */
    uint16_t sport, dport;   /* host byte order */
} tcp_info_t;

/* RFC 1071 one's-complement checksum (finalised, host byte order). */
uint16_t inet_checksum(const uint8_t *data, size_t len);

/* Returns 0 if raw is an unfragmented TCP/IPv4 packet, -1 otherwise. */
int pkt_parse(const uint8_t *raw, size_t len, tcp_info_t *info);

/* Header fields bound into the AES-GCM tag (fields constant in transit). */
void pkt_aad(const uint8_t *pkt, const tcp_info_t *info, uint8_t aad[AAD_LEN]);

/* Set Total Length = ihl + thl + payload_len and recompute both checksums. */
void pkt_finalize(uint8_t *pkt, size_t ihl, size_t thl, size_t payload_len);

/* 1 if IP header and TCP checksums are both valid. */
int pkt_verify_checksums(const uint8_t *pkt, size_t len);

#endif
