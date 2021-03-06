#include <string.h>

#include <openssl/rand.h>

#include "verify.h"

unsigned char* SCHNORR_sign(SCHNORR_CTX* ctx, const unsigned char* sk, const unsigned char* m) {
    BIGNUM* d_prime = NULL;
    EC_POINT* P = NULL;
    BIGNUM* d = NULL;
    unsigned char* a = NULL;
    unsigned char* a_hash = NULL;
    unsigned char* d_bytes = NULL;
    unsigned char* t = NULL;
    unsigned char* rand = NULL;
    unsigned char* P_bytes = NULL;
    BIGNUM* k_unmod = NULL;
    BIGNUM* k_prime = NULL;
    EC_POINT* R = NULL;
    BIGNUM* k = NULL;
    unsigned char* R_bytes = NULL;
    unsigned char* e_bytes = NULL;
    BIGNUM* e_unmod = NULL;
    BIGNUM* e = NULL;
    unsigned char* sig = NULL;
    BIGNUM* ed = NULL;
    BIGNUM* s = NULL;

    d_prime = BN_bin2bn(sk, SK_LEN, NULL);
    if(d_prime == NULL) {
        goto cleanup;
    }

    if(BN_is_zero(d_prime)) {
        goto cleanup;
    }

    const BIGNUM* order = EC_GROUP_get0_order(ctx->group);

    if(BN_cmp(d_prime, order) != -1) {
        goto cleanup;
    }

    P = EC_POINT_new(ctx->group);
    if(P == NULL) {
        goto cleanup;
    }
 
    if(!EC_POINT_mul(ctx->group, P, d_prime, NULL, NULL, ctx->bn_ctx)) {
        goto cleanup;
    }

    if(has_even_y(ctx, P)) {
        d = BN_dup(d_prime);
        if(d == NULL) {
            goto cleanup;
        }
    } else {
        d = BN_new();
        if(d == NULL) {
            goto cleanup;
        }

        if(!BN_sub(d, order, d_prime)) {
            goto cleanup;
        }
    }

    a = malloc(A_LEN);
    if(a == NULL) {
        goto cleanup;
    }

    if(RAND_bytes(a, A_LEN) != 1) {
        goto cleanup;
    }

    a_hash = tagged_hash(ctx, AUX_TAG, sizeof(AUX_TAG) - 1, a, A_LEN);
    if(a_hash == NULL) {
        goto cleanup;
    }

    d_bytes = malloc(SHA256_DIGEST_LENGTH);
    if(d_bytes == NULL) {
        goto cleanup;
    }

    if(BN_bn2binpad(d, d_bytes, SHA256_DIGEST_LENGTH) != SHA256_DIGEST_LENGTH) {
        goto cleanup;
    }

    t = malloc(SHA256_DIGEST_LENGTH);
    if(t == NULL) {
        goto cleanup;
    }

    for(size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        t[i] = d_bytes[i] ^ a_hash[i];
    }

    P_bytes = point_bytes(ctx, P);
    if(P_bytes == NULL) {
        goto cleanup;
    }

    unsigned char nonce_payload[SHA256_DIGEST_LENGTH*3];

    memcpy(nonce_payload, t, SHA256_DIGEST_LENGTH);
    memcpy(&nonce_payload[SHA256_DIGEST_LENGTH], P_bytes, SK_LEN);
    memcpy(&nonce_payload[SHA256_DIGEST_LENGTH + SK_LEN], m, MESSAGE_LEN);

    rand = tagged_hash(ctx, NONCE_TAG, sizeof(NONCE_TAG) - 1, nonce_payload, SHA256_DIGEST_LENGTH*3);
    if(rand == NULL) {
        goto cleanup;
    }

    k_unmod = BN_bin2bn(rand, SHA256_DIGEST_LENGTH, NULL);
    if(k_unmod == NULL) {
        goto cleanup;
    }

    k_prime = BN_new();
    if(k_prime == NULL) {
        goto cleanup;
    }

    if(!BN_mod(k_prime, k_unmod, order, ctx->bn_ctx)) {
        goto cleanup;
    }

    if(BN_is_zero(k_prime)) {
        goto cleanup;
    }

    R = EC_POINT_new(ctx->group);
    if(R == NULL) {
        goto cleanup;
    }
 
    if(!EC_POINT_mul(ctx->group, R, k_prime, NULL, NULL, ctx->bn_ctx)) {
        goto cleanup;
    }

    const int R_retval = has_square_y(ctx, R);
    if(R_retval < 0) {
        goto cleanup;
    }

    if(R_retval) {
        k = BN_dup(k_prime);
        if(k == NULL) {
            goto cleanup;
        }
    } else {
        k = BN_new();
        if(k == NULL) {
            goto cleanup;
        }

        if(!BN_sub(k, order, k_prime)) {
            goto cleanup;
        }
    }

    R_bytes = point_bytes(ctx, R);
    if(R_bytes == NULL) {
        goto cleanup;
    }

    unsigned char challenge_payload[SK_LEN*3];
    memcpy(challenge_payload, R_bytes, SK_LEN);
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

    ed = BN_new();
    if(ed == NULL) {
        goto cleanup;
    }

    if(!BN_mod_mul(ed, e, d, order, ctx->bn_ctx)) {
        goto cleanup;
    }

    s = BN_new();
    if(s == NULL) {
        goto cleanup;
    }

    if(!BN_mod_add(s, k, ed, order, ctx->bn_ctx)) {
        goto cleanup;
    }

    unsigned char s_bytes[SK_LEN];
    if(BN_bn2binpad(s, s_bytes, SK_LEN) != SK_LEN) {
        goto cleanup;
    }

    sig = malloc(SK_LEN*2);
    if(sig == NULL) {
        goto cleanup;
    }

    memcpy(sig, R_bytes, SK_LEN);
    memcpy(sig + SK_LEN, s_bytes, SK_LEN);

    if(SCHNORR_verify(ctx, P_bytes, m, sig) != 1) {
        goto error;
    }

    goto cleanup;

    error:
    free(sig);
    sig = NULL;

    cleanup:
    BN_free(d_prime);
    EC_POINT_free(P);
    BN_free(d);
    free(a);
    free(a_hash);
    free(d_bytes);
    free(t);
    free(P_bytes);
    free(rand);
    BN_free(k_prime);
    BN_free(k_unmod);
    EC_POINT_free(R);
    BN_free(k);
    free(R_bytes);
    free(e_bytes);
    BN_free(e_unmod);
    BN_free(e);
    BN_free(ed);
    BN_free(s);

    return sig;
}