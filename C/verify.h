#ifndef SCHNORR_VERIFY_INC
#define SCHNORR_VERIFY_INC

#include "util.h"

int SCHNORR_verify(SCHNORR_CTX* ctx, const unsigned char* pk, const unsigned char* m, const unsigned char* sig);

#endif