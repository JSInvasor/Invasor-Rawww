#pragma once

#ifndef TCP_ATTACK_H
#define TCP_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "../headers/attack_params.h"
#include "../headers/rand.h"

void* tcp_attack(void* arg);

#endif // TCP_ATTACK_H