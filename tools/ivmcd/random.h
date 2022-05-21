// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Ilcoin Core developers
// All Rights Reserved. ILCoin Blockchain Project 2019©

#ifndef ILCOIN_RANDOM_H
#define ILCOIN_RANDOM_H

#include <ivmc/ivmc.hpp>

#include <stdint.h>

/**
 * Functions to gather random data via the OpenSSL PRNG
 */
void GetRandBytes(unsigned char* buf, int num);
uint64_t GetRand(uint64_t nMax);
int GetRandInt(int nMax);
ivmc::address GetRandHash();

#endif // ILCOIN_RANDOM_H
