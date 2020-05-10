#include <string.h>

#include "verify.h"

int SCHNORR_verify(SCHNORR_CTX* ctx, const unsigned char* pk, const unsigned char* m, const unsigned char* sig) {
    int retval = 0;
    
    BIGNUM* P_int = NULL;
    EC_POINT* P = NULL;
    BIGNUM* r = NULL;
    BIGNUM* s = NULL;
    unsigned char* P_bytes = NULL;
    unsigned char* e_bytes = NULL;
    BIGNUM* e_unmod = NULL;
    BIGNUM* e = NULL;
    EC_POINT* R = NULL;
    BIGNUM* x = NULL;

    P_int = BN_new();
    if(P_int == NULL) {
        goto cleanup;
    }

    if(!BN_bin2bn(pk, SK_LEN, P_int)) {
        goto cleanup;
    }

    P = lift_x_even_y(ctx, P_int);
    if(P == NULL) {
        goto cleanup;
    }

    r = BN_new();
    if(r == NULL) {
        goto cleanup;
    }

    if(!BN_bin2bn(sig, SK_LEN, r)) {
        goto cleanup;
    }

    if(BN_cmp(r, ctx->p) != -1) {
        goto cleanup;
    }

    s = BN_new();
    if(s == NULL) {
        goto cleanup;
    }

    if(!BN_bin2bn(sig + SK_LEN, SK_LEN, s)) {
        goto cleanup;
    }

    const BIGNUM* order = EC_GROUP_get0_order(ctx->group);

    if(BN_cmp(s, order) != -1) {
        goto cleanup;
    }

    P_bytes = point_bytes(ctx, P);
    if(P_bytes == NULL) {
        goto cleanup;
    }

    unsigned char challenge_payload[SK_LEN*3];
    memcpy(challenge_payload, sig, SK_LEN);
    memcpy(&challenge_payload[SK_LEN], P_bytes, SK_LEN);
    memcpy(&challenge_payload[SK_LEN*2], m, SK_LEN);

    e_bytes = tagged_hash(ctx, CHALLENGE_TAG, sizeof(CHALLENGE_TAG) - 1, challenge_payload, SK_LEN*3);
    if(e_bytes == NULL) {
        goto cleanup;
    }

    e_unmod = BN_bin2bn(e_bytes, SHA256_DIGEST_LENGTH, NULL);
    if(e_unmod == NULL) {
        goto cleanup;
    }

    e = BN_new();
    if(e == NULL) {
        goto cleanup;
    }

    if(!BN_mod(e, e_unmod, order, ctx->bn_ctx)) {
        goto cleanup;
    }

    R = EC_POINT_new(ctx->group);
    if(R == NULL) {
        goto cleanup;
    }

    if(!EC_POINT_mul(ctx->group, R, s, P, e, ctx->bn_ctx)) {
        goto cleanup;
    }

    if(has_square_y(ctx, R) != 1) {
        goto cleanup;
    }

    x = BN_new();
    if(x == NULL) {
        goto cleanup;
    }

    if(!EC_POINT_get_affine_coordinates(ctx->group, R, x, NULL, ctx->bn_ctx)) {
        goto cleanup;
    }

    if(BN_cmp(x, r) != 0) {
        goto cleanup;
    }

    retval = 1;

    cleanup:
    BN_free(P_int);
    EC_POINT_free(P);
    BN_free(r);
    BN_free(s);
    free(P_bytes);
    BN_free(e);
    BN_free(e_unmod);
    free(e_bytes);
    EC_POINT_free(R);
    BN_free(x);

    return retval;
}