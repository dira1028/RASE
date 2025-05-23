#ifndef PQCLEAN_MLDSA87_CLEAN_SIGN_H
#define PQCLEAN_MLDSA87_CLEAN_SIGN_H
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stddef.h>
#include <stdint.h>

int PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk, double *keygen, double *pack_k);

int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk, double *unpack_s, double *sign, double *pack_s);

int PQCLEAN_MLDSA87_CLEAN_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk, double *unpack_s, double *sign, double *pack_s);

int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk, double *unpack_v, double *vrfy);

int PQCLEAN_MLDSA87_CLEAN_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk, double *unpack_v, double *vrfy);

#endif
