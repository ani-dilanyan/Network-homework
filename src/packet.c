#include "packet.h"

#include <arpa/inet.h>
#include <string.h>

#define PROTO_TCP 6

static uint32_t csum_add(uint32_t sum, const uint8_t *data, size_t len)
{
    while (len > 1) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len)                      /* odd length: pad with a zero byte */
        sum += (uint32_t)data[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t inet_checksum(const uint8_t *data, size_t len)
{
    return csum_fold(csum_add(0, data, len));
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

int pkt_parse(const uint8_t *raw, size_t len, tcp_info_t *info)
{
    if (len < 20 || (raw[0] >> 4) != 4)
        return -1;
    size_t ihl = (size_t)(raw[0] & 0x0F) * 4;
    size_t total = rd16(raw + 2);
    if (ihl < 20 || total > len || total < ihl)
        return -1;
    if (rd16(raw + 6) & 0x3FFF)   /* MF flag or fragment offset: fragment */
        return -1;
    if (raw[9] != PROTO_TCP || total < ihl + 20)
        return -1;
    size_t thl = (size_t)(raw[ihl + 12] >> 4) * 4;
    if (thl < 20 || total < ihl + thl)
        return -1;

    info->ihl = ihl;
    info->thl = thl;
    info->payload_off = ihl + thl;
    info->payload_len = total - ihl - thl;
    memcpy(&info->saddr, raw + 12, 4);
    memcpy(&info->daddr, raw + 16, 4);
    info->sport = rd16(raw + ihl);
    info->dport = rd16(raw + ihl + 2);
    return 0;
}

void pkt_aad(const uint8_t *pkt, const tcp_info_t *info, uint8_t aad[AAD_LEN])
{
    memcpy(aad, pkt + 12, 8);              /* source + destination address */
    memcpy(aad + 8, pkt + info->ihl, 12);  /* ports, sequence, acknowledgement */
}

static uint32_t pseudo_header_sum(const uint8_t *pkt, size_t tcp_len)
{
    uint8_t ph[12];
    memcpy(ph, pkt + 12, 8);
    ph[8] = 0;
    ph[9] = PROTO_TCP;
    wr16(ph + 10, (uint16_t)tcp_len);
    return csum_add(0, ph, sizeof ph);
}

void pkt_finalize(uint8_t *pkt, size_t ihl, size_t thl, size_t payload_len)
{
    size_t total = ihl + thl + payload_len;
    size_t tcp_len = thl + payload_len;

    /* IPv4 Total Length + header checksum */
    wr16(pkt + 2, (uint16_t)total);
    wr16(pkt + 10, 0);
    wr16(pkt + 10, inet_checksum(pkt, ihl));

    /* TCP checksum over pseudo-header + TCP header + payload */
    uint8_t *tcp = pkt + ihl;
    wr16(tcp + 16, 0);
    uint32_t sum = pseudo_header_sum(pkt, tcp_len);
    wr16(tcp + 16, csum_fold(csum_add(sum, tcp, tcp_len)));
}

int pkt_verify_checksums(const uint8_t *pkt, size_t len)
{
    tcp_info_t i;
    if (pkt_parse(pkt, len, &i) != 0)
        return 0;
    if (inet_checksum(pkt, i.ihl) != 0)
        return 0;
    size_t tcp_len = i.thl + i.payload_len;
    uint32_t sum = pseudo_header_sum(pkt, tcp_len);
    return csum_fold(csum_add(sum, pkt + i.ihl, tcp_len)) == 0;
}
