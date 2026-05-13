#pragma once

#ifndef GRE_ATTACK_H
#define GRE_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netinet/ip.h>

#include "../headers/attack_params.h"
#include "../headers/checksum.h"

void* gre_attack(void* arg);

#endif // GRE_ATTACK_H