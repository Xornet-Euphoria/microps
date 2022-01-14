#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[0];
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

int
ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *
ip_addr_ntop(const ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t version, ihl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *) data;
    version = hdr->vhl >> 4;
    ihl = hdr->vhl & 0xf;
    hlen = ihl * 4;

    fprintf(stderr, "chl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, version, ihl, hlen);
    fprintf(stderr, "tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "ttl: %u\n", hdr->ttl);
    fprintf(stderr, "protocol: %u\n", hdr->protocol);
    fprintf(stderr, "checksum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t version, hdr_l;
    uint16_t total_l, offset, mf_flag;

    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }

    hdr = (struct ip_hdr *)data;

    version = hdr->vhl >> 4;
    if (version != IP_VERSION_IPV4) {
        errorf("ip version error (not v4): version=%u", version);
        return;
    }

    hdr_l = (hdr->vhl & 0xf) << 2;
    if (len < hdr_l) {
        errorf("header length error: len=%zu < header length=%u", len, hdr_l);
    }

    total_l = ntoh16(hdr->total);
    if (len < total_l) {
        errorf("total length error: len=%zu < total length=%u", len, total_l);
    }

    if (cksum16((uint16_t *)data, hdr_l, 0) != 0) {
        errorf("checksum error: sum=0x%4x, verify=0x%4x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)data, hdr_l, -hdr->sum)));
    }

    offset = ntoh16(hdr->offset);
    mf_flag = offset & 0x2000;
    offset = offset & 0x1fff;

    if (mf_flag || offset) {
        errorf("fragments does not support");
        return;
    }

    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total_l);
    ip_dump(data, total_l);
}

int
ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    return 0;
}
