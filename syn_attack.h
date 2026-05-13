#pragma once

#ifndef SYN_ATTACK_H
#define SYN_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "../headers/attack_params.h"

void* syn_attack(void* arg);

#endif // SYN_ATTACK_H