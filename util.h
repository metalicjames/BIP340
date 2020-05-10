#include <openssl/ec.h>
#include <openssl/sha.h>

#define SK_LEN 32
#define MESSAGE_LEN 32
#define A_LEN 32
#define FIELD_SIZE "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define CURVE_ORDER "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define CURVE_B "7"
#define GENERATOR_X "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define GENERATOR_Y "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
#define AUX_TAG "BIP340/aux"
#define NONCE_TAG "BIP340/nonce"
#define CHALLENGE_TAG "BIP340/challenge"

typedef struct {
    EC_GROUP* group;
    BN_CTX* bn_ctx;
    SHA256_CTX* sha256_ctx;
    BIGNUM* p;
} SCHNORR_CTX;

SCHNORR_CTX* SCHNORR_CTX_new();
void SCHNORR_CTX_free(SCHNORR_CTX* ctx);

int has_even_y(const SCHNORR_CTX* ctx, const EC_POINT* P);
unsigned char* tagged_hash(SCHNORR_CTX* ctx, const char* tag, const size_t taglen, const unsigned char* x, const size_t xlen);
unsigned char* point_bytes(SCHNORR_CTX* ctx, const EC_POINT* P);
int has_square_y(SCHNORR_CTX* ctx, const EC_POINT* P);