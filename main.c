#include "sign.h"
#include "verify.h"

int main() {
    unsigned char sig[64];
    const char sig_str[] = "0E12B8C520948A776753A96F21ABD7FDC2D7D0C0DDC90851BE17B04E75EF86A47EF0DA46C4DC4D0D1BCB8668C2CE16C54C7C23A6716EDE303AF86774917CF928";

    for(size_t i = 0; i < sizeof(sig); i++) {
        sscanf(&sig_str[i*2], "%2hhx", &sig[i]);
    }

    unsigned char pk[32];
    const char pk_str[] = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";

    for(size_t i = 0; i < sizeof(pk); i++) {
        sscanf(&pk_str[i*2], "%2hhx", &pk[i]);
    }

    unsigned char m[32];
    const char m_str[] = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89";

    for(size_t i = 0; i < sizeof(m); i++) {
        sscanf(&m_str[i*2], "%2hhx", &m[i]);
    }


    SCHNORR_CTX* ctx = SCHNORR_CTX_new();

    if(SCHNORR_verify(ctx, pk, m, sig) != 1) {
        return -1;
    }

    unsigned char* nsig = SCHNORR_sign(ctx, pk, m);
    if(nsig == NULL) {
        return -1;
    }

    print_buf(nsig, 64);
    
    unsigned char* npk = pk_from_sk(ctx, pk);
    print_buf(npk, 32);

    SCHNORR_CTX_free(ctx);

    return 0;
}