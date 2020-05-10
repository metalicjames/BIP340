#include "verify.h"

int main() {
    unsigned char sig[64];
    const char sig_str[] = "067E337AD551B2276EC705E43F0920926A9CE08AC68159F9D258C9BBA412781C9F059FCDF4824F13B3D7C1305316F956704BB3FEA2C26142E18ACD90A90C947E";

    for(size_t i = 0; i < sizeof(sig); i++) {
        sscanf(&sig_str[i*2], "%2hhx", &sig[i]);
    }

    unsigned char pk[32];
    const char pk_str[] = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";

    for(size_t i = 0; i < sizeof(pk); i++) {
        sscanf(&pk_str[i*2], "%2hhx", &pk[i]);
    }

    unsigned char m[32];
    const char m_str[] = "0000000000000000000000000000000000000000000000000000000000000000";

    for(size_t i = 0; i < sizeof(m); i++) {
        sscanf(&m_str[i*2], "%2hhx", &m[i]);
    }


    SCHNORR_CTX* ctx = SCHNORR_CTX_new();

    if(SCHNORR_verify(ctx, pk, m, sig) != 1) {
        return -1;
    }

    SCHNORR_CTX_free(ctx);

    return 0;
}