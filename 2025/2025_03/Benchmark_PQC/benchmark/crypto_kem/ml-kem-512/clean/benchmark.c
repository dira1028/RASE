#include <stdio.h>
#include <time.h>
#include "kem.h"

int main()
{
    uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    int return_value;
    clock_t t1, t2, t3, t4;
    double diff_keygen, diff_encap, diff_decap, diff_total, diff_tt = 0, diff_kt = 0, diff_et = 0, diff_dt = 0;

    for (int j = 0; j < 100; j++)
    {
        t1 = clock();
        for (int i = 0; i < 100; i++)
        {
            if ((return_value = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk)) != 0)
            
            {
                printf("ERROR: %d\n", return_value);
                return -1;
            }
        }
        t2 = clock();
        for (int i = 0; i < 100; i++)
        {
            if ((return_value = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk)) != 0)
            {
                printf("ERROR: %d\n", return_value);
                return -1;
            }
        }
        t3 = clock();
        for (int i = 0; i < 100; i++)
        {
            if ((return_value = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk)) != 0)
            {
                printf("ERROR: %d\n", return_value);
                return -1;
            }
        }
        t4 = clock();
        diff_keygen = (double)(t2 - t1);
        diff_encap = (double)(t3 - t2);
        diff_decap = (double)(t4 - t3);
        diff_total = (double)(t4 - t1);
        diff_kt += diff_keygen;
        diff_et += diff_encap;
        diff_dt += diff_decap;
        diff_tt += diff_total;
    }
    diff_kt /= CLOCKS_PER_SEC;
    diff_et /= CLOCKS_PER_SEC;
    diff_dt /= CLOCKS_PER_SEC;
    diff_tt /= CLOCKS_PER_SEC;

    return 0;
}