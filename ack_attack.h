#pragma once

#ifndef ACK_ATTACK_H
#define ACK_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "../headers/attack_params.h"

void* ack_attack(void* arg);

#endif // ACK_ATTACK_H