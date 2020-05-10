#include "util.h"

int main() {
    SCHNORR_CTX* ctx = SCHNORR_CTX_new();

    SCHNORR_CTX_free(ctx);

    return 0;
}