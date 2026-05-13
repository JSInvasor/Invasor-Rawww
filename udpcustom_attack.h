#pragma once

#ifndef UDPCUSTOM_ATTACK_H
#define UDPCUSTOM_ATTACK_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "../headers/attack_params.h"

void* udpcustom_attack(void* arg);

#endif // UDPCUSTOM_ATTACK_H
