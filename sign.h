#ifndef SCHNORR_SIGN_INC
#define SCHNORR_SIGN_INC

#include "util.h"

unsigned char* SCHNORR_sign(SCHNORR_CTX* ctx, const unsigned char* sk, const unsigned char* m);

#endif