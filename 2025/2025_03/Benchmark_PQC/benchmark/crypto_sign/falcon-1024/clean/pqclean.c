/*
 * Wrapper for implementing the PQClean API.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "pqclean.h"
#include "api.h"
#include "inner.h"

#define NONCELEN 40

#include "randombytes.h"

/*
 * Encoding formats (nnnn = log of degree, 9 for Falcon-512, 10 for Falcon-1024)
 *
 *   private key:
 *      header byte: 0101nnnn
 *      private f  (6 or 5 bits by element, depending on degree)
 *      private g  (6 or 5 bits by element, depending on degree)
 *      private F  (8 bits by element)
 *
 *   public key:
 *      header byte: 0000nnnn
 *      public h   (14 bits by element)
 *
 *   signature:
 *      header byte: 0011nnnn
 *      nonce (r)  40 bytes
 *      value (s)  compressed format
 *
 *   message + signature:
 *      signature length   (2 bytes, big-endian)
 *      nonce              40 bytes
 *      message
 *      header byte:       0010nnnn
 *      value              compressed format
 *      (signature length is 1+len(value), not counting the nonce)
 */

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk, double *keygen, double *key_encode)
{
    union
    {
        uint8_t b[FALCON_KEYGEN_TEMP_10];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[1024], g[1024], F[1024];
    uint16_t h[1024];
    unsigned char seed[48];
    inner_shake256_context rng;
    size_t u, v;

    /*
     * Generate key pair.
     */

    struct timespec tA, tB, tC,tD;
    randombytes(seed, sizeof seed);

    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, sizeof seed);
    inner_shake256_flip(&rng);
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tA);
    PQCLEAN_FALCON1024_CLEAN_keygen(&rng, f, g, F, NULL, h, 10, tmp.b);
    clock_gettime(CLOCK_MONOTONIC, &tB);
    inner_shake256_ctx_release(&rng);

    /*
     * Encode private key.
     */
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tC);
    sk[0] = 0x50 + 10;
    u = 1;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        f, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10]);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        g, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10]);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        F, 10, PQCLEAN_FALCON1024_CLEAN_max_FG_bits[10]);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES)
    {
        return -1;
    }

    /*
     * Encode public key.
     */
    pk[0] = 0x00 + 10;
    v = PQCLEAN_FALCON1024_CLEAN_modq_encode(
        pk + 1, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1,
        h, 10);
    if (v != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
    {
        return -1;
    }
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tD);
    *keygen += (tB.tv_sec - tA.tv_sec) * 1000 + (tB.tv_nsec - tA.tv_nsec) / 1e6;
    *key_encode += (tD.tv_sec - tC.tv_sec) * 1000 + (tD.tv_nsec - tC.tv_nsec) / 1e6;

    return 0;
}

/*
 * Compute the signature. nonce[] receives the nonce and must have length
 * NONCELEN bytes. sigbuf[] receives the signature value (without nonce
 * or header byte), with *sigbuflen providing the maximum value length and
 * receiving the actual value length.
 *
 * If a signature could be computed but not encoded because it would
 * exceed the output buffer size, then an error is returned.
 *
 * Return value: 0 on success, -1 on error.
 */
static int
do_sign(uint8_t *nonce, uint8_t *sigbuf, size_t *sigbuflen,
    const uint8_t *m, size_t mlen, const uint8_t *sk, double *decode_s, double *hash_to_point, double *sign, double *encode_s)
{
    struct timespec tA, tB, tC, tD, tE, tF, tG;
    union
    {
        uint8_t b[72 * 1024];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[1024], g[1024], F[1024], G[1024];
    struct
    {
        int16_t sig[1024];
        uint16_t hm[1024];
    } r;
    unsigned char seed[48];
    inner_shake256_context sc;
    size_t u, v;

    /*
     * Decode the private key.
     */
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tA);
    if (sk[0] != 0x50 + 10)
    {
        return -1;
    }
    u = 1;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(
        f, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10],
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(
        g, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10],
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(
        F, 10, PQCLEAN_FALCON1024_CLEAN_max_FG_bits[10],
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES)
    {
        return -1;
    }
    if (!PQCLEAN_FALCON1024_CLEAN_complete_private(G, f, g, F, 10, tmp.b))
    {
        return -1;
    }
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tB);

    /*
     * Create a random nonce (40 bytes).
     */
    randombytes(nonce, NONCELEN);

    /*
     * Hash message nonce + message into a vector.
     */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tC);
    PQCLEAN_FALCON1024_CLEAN_hash_to_point_ct(&sc, r.hm, 10, tmp.b);
    clock_gettime(CLOCK_MONOTONIC, &tD);
    inner_shake256_ctx_release(&sc);

    /*
     * Initialize a RNG.
     */
    randombytes(seed, sizeof seed);
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed, sizeof seed);
    inner_shake256_flip(&sc);

    /*
     * Compute and return the signature.
     */
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tE);
    PQCLEAN_FALCON1024_CLEAN_sign_dyn(r.sig, &sc, f, g, F, G, r.hm, 10, tmp.b);
    clock_gettime(CLOCK_MONOTONIC, &tF);
    v = PQCLEAN_FALCON1024_CLEAN_comp_encode(sigbuf, *sigbuflen, r.sig, 10);
    clock_gettime(CLOCK_MONOTONIC, &tG);
    *decode_s += (tB.tv_sec - tA.tv_sec) * 1000 + (tB.tv_nsec - tA.tv_nsec) / 1e6;
    *hash_to_point += (tD.tv_sec - tC.tv_sec) * 1000 + (tD.tv_nsec - tC.tv_nsec) / 1e6;
    *sign += (tF.tv_sec - tE.tv_sec) * 1000 + (tF.tv_nsec - tE.tv_nsec) / 1e6;
    *encode_s += (tG.tv_sec - tF.tv_sec) * 1000 + (tG.tv_nsec - tF.tv_nsec) / 1e6;
    if (v != 0)
    {
        inner_shake256_ctx_release(&sc);
        *sigbuflen = v;
        /*--------------------시간측정-------------------------*/
        return 0;
    }
    return -1;
}

/*
 * Verify a sigature. The nonce has size NONCELEN bytes. sigbuf[]
 * (of size sigbuflen) contains the signature value, not including the
 * header byte or nonce. Return value is 0 on success, -1 on error.
 */
static int
do_verify(
    const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen,
    const uint8_t *m, size_t mlen, const uint8_t *pk, double *decode_v,double *hash_to_point, double *vrfy)
{
    union
    {
        uint8_t b[2 * 1024];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    uint16_t h[1024], hm[1024];
    int16_t sig[1024];
    inner_shake256_context sc;
    size_t v;

    /*
     * Decode public key.
     */
    
    struct timespec tA,tB,tC,tD,tE,tF;
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tA);
    if (pk[0] != 0x00 + 10)
    {
        return -1;
    }
    if (PQCLEAN_FALCON1024_CLEAN_modq_decode(h, 10,
                                             pk + 1, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
    {
        return -1;
    }
    PQCLEAN_FALCON1024_CLEAN_to_ntt_monty(h, 10);

    /*
     * Decode signature.
     */
    if (sigbuflen == 0)
    {
        return -1;
    }

    v = PQCLEAN_FALCON1024_CLEAN_comp_decode(sig, 10, sigbuf, sigbuflen);
    if (v == 0)
    {
        return -1;
    }
    if (v != sigbuflen)
    {
        if (sigbuflen == PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES - NONCELEN - 1)
        {
            while (v < sigbuflen)
            {
                if (sigbuf[v++] != 0)
                {
                    return -1;
                }
            }
        }
        else
        {
            return -1;
        }
    }
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tB);

    /*
     * Hash nonce + message into a vector.
     */
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, nonce, NONCELEN);
    inner_shake256_inject(&sc, m, mlen);
    inner_shake256_flip(&sc);
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tC);
    PQCLEAN_FALCON1024_CLEAN_hash_to_point_ct(&sc, hm, 10, tmp.b);
    clock_gettime(CLOCK_MONOTONIC, &tD);

    inner_shake256_ctx_release(&sc);

    /*
     * Verify signature.
     */

    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tE);
    if (!PQCLEAN_FALCON1024_CLEAN_verify_raw(hm, sig, h, 10, tmp.b))
    {
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &tF);
    *decode_v += (tB.tv_sec - tA.tv_sec) * 1000 + (tB.tv_nsec - tA.tv_nsec) / 1e6;
    *hash_to_point += (tD.tv_sec - tC.tv_sec) * 1000 + (tD.tv_nsec - tC.tv_nsec) / 1e6;
    *vrfy += (tF.tv_sec - tE.tv_sec) * 1000 + (tF.tv_nsec - tE.tv_nsec) / 1e6;
    return 0;
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk, double *decode_s, double *hash_to_point, double *sign, double *encode_s)
{
    size_t vlen;

    vlen = PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES - NONCELEN - 1;
    if (do_sign(sig + 1, sig + 1 + NONCELEN, &vlen, m, mlen, sk, decode_s, hash_to_point, sign, encode_s) < 0)
    {
        return -1;
    }
    sig[0] = 0x30 + 10;
    *siglen = 1 + NONCELEN + vlen;
    return 0;
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk, double *decode_v, double *hash_to_point, double *vrfy)
{
    if (siglen < 1 + NONCELEN)
    {
        return -1;
    }
    if (sig[0] != 0x30 + 10)
    {
        return -1;
    }
    return do_verify(sig + 1,
                     sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk, decode_v, hash_to_point, vrfy);
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk, double *decode_s,double *hash_to_point, double *sign, double *encode_s)
{
    uint8_t *pm, *sigbuf;
    size_t sigbuflen;

    /*
     * Move the message to its final location; this is a memmove() so
     * it handles overlaps properly.
     */
    memmove(sm + 2 + NONCELEN, m, mlen);
    pm = sm + 2 + NONCELEN;
    sigbuf = pm + 1 + mlen;
    sigbuflen = PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES - NONCELEN - 3;
    if (do_sign(sm + 2, sigbuf, &sigbuflen, pm, mlen, sk, decode_s, hash_to_point,sign, encode_s) < 0)
    {
        return -1;
    }
    pm[mlen] = 0x20 + 10;
    sigbuflen++;
    sm[0] = (uint8_t)(sigbuflen >> 8);
    sm[1] = (uint8_t)sigbuflen;
    *smlen = mlen + 2 + NONCELEN + sigbuflen;
    return 0;
}

/* see api.h */
int PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk, double *decode_v, double *hash_to_point, double *vrfy)
{
    const uint8_t *sigbuf;
    size_t pmlen, sigbuflen;

    if (smlen < 3 + NONCELEN)
    {
        return -1;
    }
    sigbuflen = ((size_t)sm[0] << 8) | (size_t)sm[1];
    if (sigbuflen < 2 || sigbuflen > (smlen - NONCELEN - 2))
    {
        return -1;
    }
    sigbuflen--;
    pmlen = smlen - NONCELEN - 3 - sigbuflen;
    if (sm[2 + NONCELEN + pmlen] != 0x20 + 10)
    {
        return -1;
    }
    sigbuf = sm + 2 + NONCELEN + pmlen + 1;

    /*
     * The 2-byte length header and the one-byte signature header
     * have been verified. Nonce is at sm+2, followed by the message
     * itself. Message length is in pmlen. sigbuf/sigbuflen point to
     * the signature value (excluding the header byte).
     */
    if (do_verify(sm + 2, sigbuf, sigbuflen,
                  sm + 2 + NONCELEN, pmlen, pk, decode_v, hash_to_point, vrfy) < 0)
    {
        return -1;
    }

    /*
     * Signature is correct, we just have to copy/move the message
     * to its final destination. The memmove() properly handles
     * overlaps.
     */
    memmove(m, sm + 2 + NONCELEN, pmlen);
    *mlen = pmlen;
    return 0;
}

int benchmark()
{
    uint8_t pk[100][PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[100][PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t m[1000];
    uint8_t sm[100][1000 + PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES];
    size_t smlen[100];
    size_t mlen = 1000;
    struct timespec t1, t2, t3, t4;

    double keypare, t_sign, t_vrfy = 0;
    double keygen, key_encode, decode_s, hash_to_point_s, sign, encode_s, decode_v, hash_to_point_v, vrfy = 0;

    printf("=========benchmark FALCON1024=========\n");
    for (int j = 0; j < 1000; j++)
    {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        for (int i = 0; i < 100; i++)
        {
            if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk[i], sk[i], &keygen, &key_encode) == -1)
            {
                printf("Error in PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair\n");
                return -1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        for (int i = 0; i < 100; i++)
        {
            if (PQCLEAN_FALCON1024_CLEAN_crypto_sign(sm[i], &smlen[i], m, mlen, sk[i], &decode_s, &hash_to_point_s, &sign, &encode_s) == -1)
            {
                printf("Error in PQCLEAN_FALCON1024_CLEAN_crypto_sign\n");
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t3);
        for (int i = 0; i < 100; i++)
        {
            if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(m, &mlen, sm[i], smlen[i], pk[i], &decode_v, &hash_to_point_v, &vrfy) == -1)
            {
                printf("Error in PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify\n");
                return -1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t4);
        keypare += (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
        t_sign += (t3.tv_sec - t2.tv_sec) * 1000.0 + (t3.tv_nsec - t2.tv_nsec) / 1e6;
        t_vrfy += (t4.tv_sec - t3.tv_sec) * 1000.0 + (t4.tv_nsec - t3.tv_nsec) / 1e6;
    }
    printf("----------------keypare----------------\n");
    printf("keygen : %f ms\n", keygen / 100000);
    printf("key_encode : %f ms\n", key_encode / 100000);
    printf("keypare : %f ms\n", keypare / 100000);
    printf("----------------sign----------------\n");
    printf("decode_s : %f ms\n", decode_s / 100000);
    printf("hash_to_point_s : %f ms\n", hash_to_point_s / 100000);
    printf("sign : %f ms\n", sign / 100000);
    printf("encode_s : %f ms\n", encode_s / 100000);
    printf("t_sign : %f ms\n", t_sign / 100000);
    printf("----------------vrfy----------------\n");
    printf("decode_v : %f ms\n", decode_v / 100000);
    printf("hash_to_point_v : %f ms\n", hash_to_point_v / 100000);
    printf("vrfy : %f ms\n", vrfy / 100000);
    printf("t_vrfy : %f ms\n", t_vrfy / 100000);
    printf("=====================================\n\n\n\n");
    return 0;
}
