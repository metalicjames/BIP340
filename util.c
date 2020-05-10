#include <string.h>

#include "util.h"

SCHNORR_CTX* SCHNORR_CTX_new() {
    SCHNORR_CTX* ret = NULL;
    BIGNUM* n = NULL;
    BIGNUM* a = NULL;
    BIGNUM* b = NULL;
    BIGNUM* Gx = NULL;
    BIGNUM* Gy = NULL;
    EC_POINT* G = NULL;

    ret = malloc(sizeof(SCHNORR_CTX));
    if(ret == NULL) {
        goto error;
    }
    ret->bn_ctx = NULL;
    ret->group = NULL;
    ret->sha256_ctx = NULL;
    ret->p = NULL;

    if(!BN_hex2bn(&ret->p, FIELD_SIZE)) {
        goto error;
    }

    if(!BN_hex2bn(&n, CURVE_ORDER)) {
        goto error;
    }

    a = BN_new();
    if(a == NULL) {
        goto error;
    }

    if(!BN_hex2bn(&b, CURVE_B)) {
        goto error;
    }

    ret->bn_ctx = BN_CTX_new();
    if(ret->bn_ctx == NULL) {
        goto error;
    }

    ret->group = EC_GROUP_new_curve_GFp(ret->p, a, b, ret->bn_ctx);
    if(ret->group == NULL) {
        goto error;
    }

    
    if(!BN_hex2bn(&Gx, GENERATOR_X)) {
        goto error;
    }

    
    if(!BN_hex2bn(&Gy, GENERATOR_Y)) {
        goto error;
    }

    G = EC_POINT_new(ret->group);
    if(G == NULL) {
        goto error;
    }

    if(!EC_POINT_set_affine_coordinates(ret->group, G, Gx, Gy, ret->bn_ctx)) {
        goto error;
    }

    if(!EC_GROUP_set_generator(ret->group, G, n, BN_value_one())) {
        goto error;
    }

    ret->sha256_ctx = malloc(sizeof(SHA256_CTX));
    if(ret->sha256_ctx == NULL) {
        goto error;
    }

    goto cleanup;

    error:
    SCHNORR_CTX_free(ret);

    cleanup:
    BN_free(n);
    BN_free(a);
    BN_free(b);
    BN_free(Gx);
    BN_free(Gy);
    EC_POINT_free(G);

    return ret;
}

void SCHNORR_CTX_free(SCHNORR_CTX* ctx) {
    if(ctx != NULL) {
        BN_CTX_free(ctx->bn_ctx);
        EC_GROUP_free(ctx->group);
        free(ctx->sha256_ctx);
        BN_free(ctx->p);
    }
    free(ctx);
}

int has_even_y(const SCHNORR_CTX* ctx, const EC_POINT* P) {
    int retval = -1;
    BIGNUM* y = NULL;

    y = BN_new();
    if(y == NULL) {
        goto cleanup;
    }

    if(!EC_POINT_get_affine_coordinates(ctx->group, P, NULL, y, ctx->bn_ctx)) {
        goto cleanup;
    }

    retval = !BN_is_odd(y);

    cleanup:
    BN_free(y);

    return retval;
}

unsigned char* tagged_hash(SCHNORR_CTX* ctx, const char* tag, const size_t taglen, const unsigned char* x, const size_t xlen) {
    unsigned char* tag_hash = NULL;
    unsigned char* output = NULL;

    tag_hash = malloc(SHA256_DIGEST_LENGTH);
    if(tag_hash == NULL) {
        goto cleanup;
    }

    if(!SHA256_Init(ctx->sha256_ctx)) {
        goto cleanup;
    }

    if(!SHA256_Update(ctx->sha256_ctx, tag, taglen)) {
        goto cleanup;
    }

    if(!SHA256_Final(tag_hash, ctx->sha256_ctx)) {
        goto cleanup;
    }

    output = malloc(SHA256_DIGEST_LENGTH);
    if(output == NULL) {
        goto error;
    }

    if(!SHA256_Init(ctx->sha256_ctx)) {
        goto error;
    }

    if(!SHA256_Update(ctx->sha256_ctx, tag_hash, SHA256_DIGEST_LENGTH)) {
        goto error;
    }
    
    if(!SHA256_Update(ctx->sha256_ctx, tag_hash, SHA256_DIGEST_LENGTH)) {
        goto error;
    }
    
    if(!SHA256_Update(ctx->sha256_ctx, x, xlen)) {
        goto error;
    }

    if(!SHA256_Final(output, ctx->sha256_ctx)) {
        goto error;
    }

    error:
    free(output);

    cleanup:
    free(tag_hash);

    return output;
}

unsigned char* point_bytes(SCHNORR_CTX* ctx, const EC_POINT* P) {
    BIGNUM* x = NULL;
    unsigned char* retval = NULL;

    x = BN_new();
    if(x == NULL) {
        goto cleanup;
    }

    if(!EC_POINT_get_affine_coordinates(ctx->group, P, x, NULL, ctx->bn_ctx)) {
        goto cleanup;
    }

    retval = malloc(sizeof(SK_LEN));
    if(retval == NULL) {
        goto error;
    }

    if(BN_bn2binpad(x, retval, sizeof(SK_LEN)) != sizeof(SK_LEN)) {
        goto error;
    }

    error:
    free(retval);

    cleanup:
    BN_free(x);

    return retval;
}

int is_square(SCHNORR_CTX* ctx, const BIGNUM* x) {
    int retval = -1;
    BIGNUM* pval = NULL;
    BIGNUM* legendre = NULL;

    pval = BN_new();
    if(pval == NULL) {
        goto cleanup;
    }

    if(!BN_sub(pval, x, BN_value_one())) {
        goto cleanup;
    }

    if(!BN_rshift1(pval, pval)) {
        goto cleanup;
    }

    legendre = BN_new();
    if(legendre == NULL) {
        goto cleanup;
    }

    if(!BN_mod_exp(legendre, x, pval, ctx->p, ctx->bn_ctx)) {
        goto cleanup;
    }

    retval = BN_is_one(legendre);

    cleanup:
    BN_free(pval);
    BN_free(legendre);

    return retval;
}

int has_square_y(SCHNORR_CTX* ctx, const EC_POINT* P) {
    int retval = -1;
    
    if(EC_POINT_is_at_infinity(ctx->group, P)) {
        return 0;
    }

    BIGNUM* y = BN_new();
    if(y == NULL) {
        goto cleanup;
    }

    if(!EC_POINT_get_affine_coordinates(ctx->group, P, NULL, y, ctx->bn_ctx)) {
        goto cleanup;
    }

    retval = is_square(ctx, y);

    cleanup:
    BN_free(y);

    return retval;
}

EC_POINT* lift_x_square_y(SCHNORR_CTX* ctx, const BIGNUM* x) {
    BIGNUM* c_1 = NULL;
    BIGNUM* three = NULL;
    BIGNUM* seven = NULL;
    BIGNUM* c = NULL;
    BIGNUM* p_plus = NULL;
    BIGNUM* y = NULL;
    BIGNUM* y_sq = NULL;
    EC_POINT* retval = NULL;

    if(!BN_dec2bn(&three, "3")) {
        goto cleanup;
    }

    c_1 = BN_new();
    if(c_1 == NULL) {
        goto cleanup;
    }

    if(!BN_mod_exp(c_1, x, three, ctx->p, ctx->bn_ctx)) {
        goto cleanup;
    }

    if(!BN_dec2bn(&seven, "7")) {
        goto cleanup;
    }

    c = BN_new();
    if(c == NULL) {
        goto cleanup;
    }

    if(!BN_mod_add(c, c_1, seven, ctx->p, ctx->bn_ctx)) {
        goto cleanup;
    }

    p_plus = BN_new();
    if(p_plus == NULL) {
        goto cleanup;
    }

    if(!BN_add(p_plus, ctx->p, BN_value_one())) {
        goto cleanup;
    }

    if(!BN_rshift(p_plus, p_plus, 2)) {
        goto cleanup;
    }

    y = BN_new();
    if(y == NULL) {
        goto cleanup;
    }

    if(!BN_mod_exp(y, c, p_plus, ctx->p, ctx->bn_ctx)) {
        goto cleanup;
    }

    y_sq = BN_new();
    if(y_sq == NULL) {
        goto cleanup;
    }

    if(!BN_mod_sqr(y_sq, y, ctx->p, ctx->bn_ctx)) {
        goto cleanup;
    }

    if(BN_cmp(c, y_sq) != 0) {
        goto cleanup;
    }

    retval = EC_POINT_new(ctx->group);
    if(retval == NULL) { 
        goto cleanup;
    }

    if(!EC_POINT_set_affine_coordinates(ctx->group, retval, x, y, ctx->bn_ctx)) {
        goto error;
    }

    if(!EC_POINT_is_on_curve(ctx->group, retval, ctx->bn_ctx)) {
        goto error;
    }

    if(EC_POINT_is_at_infinity(ctx->group, retval)) {
        goto error;
    }

    goto cleanup;

    error:
    EC_POINT_free(retval);
    retval = NULL;

    cleanup:
    BN_free(c_1);
    BN_free(three);
    BN_free(seven);
    BN_free(c);
    BN_free(p_plus);
    BN_free(y);
    BN_free(y_sq);

    return retval;
}

EC_POINT* lift_x_even_y(SCHNORR_CTX* ctx, const BIGNUM* x) {
    EC_POINT* retval = lift_x_square_y(ctx, x);

    if(retval == NULL) {
        return NULL;
    }

    const int even = has_even_y(ctx, retval);
    if(even < 0) {
        EC_POINT_free(retval);
        return NULL;
    }

    if(even) {
        return retval;
    } else {
        if(!EC_POINT_invert(ctx->group, retval, ctx->bn_ctx)) {
            EC_POINT_free(retval);
            return NULL;
        } else {
            return retval;
        }
    }
}