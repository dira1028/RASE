#include "indcpa.h"
#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
/*************************************************
 * Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *              - uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes)
 **
 * Returns 0 (success)
 **************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk,
                                                     uint8_t *sk,
                                                     const uint8_t *coins)
{
    PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(pk, sk, coins);
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

/*************************************************
 * Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
 *
 * Description: Generates public and private key
 *              for CCA-secure Kyber key encapsulation mechanism
 *
 * Arguments:   - uint8_t *pk: pointer to output public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk,
                                              uint8_t *sk, double *keygen)
{
    struct timespec tA, tB;
    uint8_t coins[2 * KYBER_SYMBYTES];
    randombytes(coins, 2 * KYBER_SYMBYTES);

    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tA);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);
    clock_gettime(CLOCK_MONOTONIC, &tB);
    *keygen += (tB.tv_sec - tA.tv_sec) * 1000.0 + (tB.tv_nsec - tA.tv_nsec) / 1e6;
    return 0;
}

/*************************************************
 * Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *              - const uint8_t *coins: pointer to input randomness
 *                (an already allocated array filled with KYBER_SYMBYTES random bytes)
 **
 * Returns 0 (success)
 **************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(uint8_t *ct,
                                                 uint8_t *ss,
                                                 const uint8_t *pk,
                                                 const uint8_t *coins)
{
    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];

    memcpy(buf, coins, KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    memcpy(ss, kr, KYBER_SYMBYTES);
    return 0;
}

/*************************************************
 * Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct,
                                          uint8_t *ss,
                                          const uint8_t *pk, double *enc)
{
    struct timespec tA, tB;
    uint8_t coins[KYBER_SYMBYTES];
    randombytes(coins, KYBER_SYMBYTES);
    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tA);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, pk, coins);
    clock_gettime(CLOCK_MONOTONIC, &tB);
    *enc += (tB.tv_sec - tA.tv_sec) * 1000 + (tB.tv_nsec - tA.tv_nsec) / 1e6;
    return 0;
}

/*************************************************
 * Name:        PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - uint8_t *ss: pointer to output shared secret
 *                (an already allocated array of KYBER_SSBYTES bytes)
 *              - const uint8_t *ct: pointer to input cipher text
 *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
 *              - const uint8_t *sk: pointer to input private key
 *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
 *
 * Returns 0.
 *
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss,
                                          const uint8_t *ct,
                                          const uint8_t *sk, double *dec , double *gen_secretkey)
{
    struct timespec tA, tB, tC, tD;
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES + KYBER_SYMBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    /*--------------------시간측정-------------------------*/
    clock_gettime(CLOCK_MONOTONIC, &tA);
    PQCLEAN_MLKEM512_CLEAN_indcpa_dec(buf, ct, sk);
    clock_gettime(CLOCK_MONOTONIC, &tB);

    /* Multitarget countermeasure for coins + contributory KEM */
    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);
    fail = PQCLEAN_MLKEM512_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    /* Compute rejection key */
    /*--------------------시간측정-------------------------*/
//검증된 메세지를 바탕으로 
//공유 비밀키 생성하는 시간 측정.
    clock_gettime(CLOCK_MONOTONIC, &tC);
    rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);
    clock_gettime(CLOCK_MONOTONIC, &tD);

    *dec += (tB.tv_sec - tA.tv_sec) * 1000 + (tB.tv_nsec - tA.tv_nsec) / 1e6;
    *gen_secretkey += (tD.tv_sec - tC.tv_sec) * 1000 + (tD.tv_nsec - tC.tv_nsec) / 1e6;

    /* Copy true key to return buffer if fail is false */
    PQCLEAN_MLKEM512_CLEAN_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t)(1 - fail));

    return 0;
}

int benchmark()
{
    uint8_t *m = malloc(1000);
    uint8_t(*pk)[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES] = malloc(100 * sizeof(*pk));
    uint8_t(*sk)[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES] = malloc(100 * sizeof(*sk));
    uint8_t(*ct)[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES] = malloc(100 * sizeof(*ct));
    uint8_t(*ss)[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES] = malloc(100 * sizeof(*ss));

    struct timespec t1, t2, t3, t4;
    double keygen=0, enc=0, dec=0, gen_secretkey = 0;
    double keypare=0, t_enc=0, t_dec = 0;
    for (int i = 0; i < 1000; i++)
    {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        for (int j = 0; j < 100; j++)
        {
            if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk[j], sk[j], &keygen) == -1)
            {
                printf("Error in PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair\n");
                return -1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        for (int j = 0; j < 100; j++)
        {
            if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct[j], ss[j], pk[j], &enc) == -1)
            {
                printf("Error in PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc\n");
                return -1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t3);
        for (int j = 0; j < 100; j++)
        {
            if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss[j], ct[j], sk[j], &dec, &gen_secretkey) == -1)
            {
                printf("Error in PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec\n");
                return -1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t4);
        keypare += (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
        t_enc += (t3.tv_sec - t2.tv_sec) * 1000.0 + (t3.tv_nsec - t2.tv_nsec) / 1e6;
        t_dec += (t4.tv_sec - t3.tv_sec) * 1000.0 + (t4.tv_nsec - t3.tv_nsec) / 1e6;
    }
    printf("----------------benchmark KEM512----------------\n");
    printf("key_derand : %f ms\n", keygen / 100000);
    printf("keypair : %f ms\n", keypare / 100000);
    printf("enc : %f ms\n", enc / 100000);
    printf("t_enc : %f ms\n", t_enc / 100000);
    printf("dec : %f ms\n", dec / 100000);
    printf("gen_secretkey : %f ms\n", gen_secretkey / 100000);
    printf("t_dec : %f ms\n", t_dec / 100000);

    free(m);
    free(pk);
    free(sk);
    free(ct);
    free(ss);
    return 0;
}