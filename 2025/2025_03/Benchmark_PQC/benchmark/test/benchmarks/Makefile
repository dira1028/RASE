CC = gcc

COMMON_PATH = ../../common
CFLAGS = -g -I$(COMMON_PATH)
ifdef OS
    ifeq ($(OS), Windows_NT)
        CFLAGS += -I"C:/MinGW/lib/gcc/mingw32/6.3.0/include/c++/parallel"
    endif
endif
COMMON_SRCS = fips202.c randombytes.c aes.c nistseedexpander.c sha2.c sp800-185.c
LDFLAGS = $(addprefix $(COMMON_PATH)/, $(COMMON_SRCS))
BENCHMARK_FILE = benchmark.c


KYBER_SRCS = cbd.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c symmetric-shake.c verify.c 

KYBER512_CRYPTO_PATH = ../../crypto_kem/ml-kem-512/clean
KYBER512_CFLAGS = $(CFLAGS) -I$(KYBER512_CRYPTO_PATH)

KYBER768_CRYPTO_PATH = ../../crypto_kem/ml-kem-768/clean
KYBER768_CFLAGS = $(CFLAGS) -I$(KYBER768_CRYPTO_PATH)

KYBER1024_CRYPTO_PATH = ../../crypto_kem/ml-kem-1024/clean
KYBER1024_CFLAGS = $(CFLAGS) -I$(KYBER1024_CRYPTO_PATH)

# Falcon 설정
FALCON_SRCS = codec.c pqclean.c common.c fft.c fpr.c keygen.c sign.c rng.c vrfy.c

FALCON512_CRYPTO_PATH = ../../crypto_sign/falcon-512/clean
FALCON512_CFLAGS = $(CFLAGS) -I$(FALCON512_CRYPTO_PATH)

FALCON1024_CRYPTO_PATH = ../../crypto_sign/falcon-1024/clean
FALCON1024_CFLAGS = $(CFLAGS) -I$(FALCON1024_CRYPTO_PATH)

FALCONPADDED512_CRYPTO_PATH = ../../crypto_sign/falcon-padded-512/clean
FALCONPADDED512_CFLAGS = $(CFLAGS) -I$(FALCONPADDED512_CRYPTO_PATH)

FALCONPADDED1024_CRYPTO_PATH = ../../crypto_sign/falcon-padded-1024/clean
FALCONPADDED1024_CFLAGS = $(CFLAGS) -I$(FALCONPADDED1024_CRYPTO_PATH)

# MLDSA 설정
MLDSA_SRCS = ntt.c packing.c poly.c polyvec.c reduce.c rounding.c sign.c symmetric-shake.c

MLDSA_44_CRYPTO_PATH = ../../crypto_sign/ml-dsa-44/clean
MLDSA_44_CFLAGS = $(CFLAGS) -I$(MLDSA_44_CRYPTO_PATH)

MLDSA_65_CRYPTO_PATH = ../../crypto_sign/ml-dsa-65/clean
MLDSA_65_CFLAGS = $(CFLAGS) -I$(MLDSA_65_CRYPTO_PATH)

MLDSA_87_CRYPTO_PATH = ../../crypto_sign/ml-dsa-87/clean
MLDSA_87_CFLAGS = $(CFLAGS) -I$(MLDSA_87_CRYPTO_PATH)


SPHINCS_SHA_SRCS = address.c context_sha2.c fors.c hash_sha2.c merkle.c sign.c thash_sha2_simple.c utils.c utilsx1.c wots.c wotsx1.c
SPHINCS_SHAKE_SRCS = address.c context_shake.c fors.c hash_shake.c merkle.c sign.c thash_shake_simple.c utils.c utilsx1.c wots.c wotsx1.c
SPHINCS_SHA_AVX2_SRCS = address.c context_sha2.c fors.c hash_sha2.c hash_sha2x8.c merkle.c sha256avx.c sha256x8.c sha512x4.c sign.c thash_sha2_simple.c thash_sha2_simplex8.c utils.c utilsx8.c wots.c

# Sphincs+ sha 설정
SPHINCS128_CRYPTO_PATH = ../../crypto_sign/sphincs-sha2-128s-simple/clean
SPHINCS128_CFLAGS = $(CFLAGS) -I$(SPHINCS128_CRYPTO_PATH)

SPHINCS192_CRYPTO_PATH = ../../crypto_sign/sphincs-sha2-192f-simple/clean
SPHINCS192_CFLAGS = $(CFLAGS) -I$(SPHINCS192_CRYPTO_PATH)

SPHINCS256_CRYPTO_PATH = ../../crypto_sign/sphincs-sha2-256f-simple/clean
SPHINCS256_CFLAGS = $(CFLAGS) -I$(SPHINCS256_CRYPTO_PATH)

# Sphincs+ shake 설정
SPHINCS128_SHAKE_CRYPTO_PATH = ../../crypto_sign/sphincs-shake-128s-simple/clean
SPHINCS128_SHAKE_CFLAGS = $(CFLAGS) -I$(SPHINCS128_SHAKE_CRYPTO_PATH)

SPHINCS192_SHAKE_CRYPTO_PATH = ../../crypto_sign/sphincs-shake-192s-simple/clean
SPHINCS192_SHAKE_CFLAGS = $(CFLAGS) -I$(SPHINCS192_SHAKE_CRYPTO_PATH)

SPHINCS256_SHAKE_CRYPTO_PATH = ../../crypto_sign/sphincs-shake-256s-simple/clean
SPHINCS256_SHAKE_CFLAGS = $(CFLAGS) -I$(SPHINCS256_SHAKE_CRYPTO_PATH)

SPHINCS256_AVX2_SHA_CRYPTO_PATH = ../../crypto_sign/sphincs-sha2-256s-simple/avx2
SPHINCS256_AVX2_SHA_CFLAGS = $(CFLAGS) -I$(SPHINCS256_AVX2_SHA_CRYPTO_PATH)

#----------------------------------------------------kyber----------------------------------------------------#
benchmark_kyber512:
	$(CC) $(KYBER512_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(KYBER512_CRYPTO_PATH)/, $(KYBER_SRCS)) $(LDFLAGS)

benchmark_kyber768:
	$(CC) $(KYBER768_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(KYBER768_CRYPTO_PATH)/, $(KYBER_SRCS)) $(LDFLAGS)

benchmark_kyber1024:
	$(CC) $(KYBER1024_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(KYBER1024_CRYPTO_PATH)/, $(KYBER_SRCS)) $(LDFLAGS)

#----------------------------------------------------falcon----------------------------------------------------#
benchmark_falcon512:
	$(CC) $(FALCON512_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(FALCON512_CRYPTO_PATH)/, $(FALCON_SRCS)) $(LDFLAGS)

benchmark_falcon1024:
	$(CC) $(FALCON1024_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(FALCON1024_CRYPTO_PATH)/, $(FALCON_SRCS)) $(LDFLAGS)

benchmark_falconpadded512:
	$(CC) $(FALCONPADDED512_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(FALCONPADDED512_CRYPTO_PATH)/, $(FALCON_SRCS)) $(LDFLAGS)

benchmark_falconpadded1024:
	$(CC) $(FALCONPADDED1024_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(FALCONPADDED1024_CRYPTO_PATH)/, $(FALCON_SRCS)) $(LDFLAGS)

#----------------------------------------------------MLDSA----------------------------------------------------#
benchmark_MLDSA_44:
	$(CC) $(MLDSA_44_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(MLDSA_44_CRYPTO_PATH)/, $(MLDSA_SRCS)) $(LDFLAGS)

benchmark_MLDSA_65:
	$(CC) $(MLDSA_65_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(MLDSA_65_CRYPTO_PATH)/, $(MLDSA_SRCS)) $(LDFLAGS)

benchmark_MLDSA_87:
	$(CC) $(MLDSA_87_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(MLDSA_87_CRYPTO_PATH)/, $(MLDSA_SRCS)) $(LDFLAGS)

#----------------------------------------------------sphincs----------------------------------------------------#
benchmark_sphincs_sha_128:
	$(CC) $(SPHINCS128_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(SPHINCS128_CRYPTO_PATH)/, $(SPHINCS_SHA_SRCS)) $(LDFLAGS)

benchmark_sphincs_sha_192:
	$(CC) $(SPHINCS192_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(SPHINCS192_CRYPTO_PATH)/, $(SPHINCS_SHA_SRCS)) $(LDFLAGS)

benchmark_sphincs_sha_256:
	$(CC) $(SPHINCS256_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(SPHINCS256_CRYPTO_PATH)/, $(SPHINCS_SHA_SRCS)) $(LDFLAGS)

benchmark_sphincs_shake_128:
	$(CC) $(SPHINCS128_SHAKE_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(SPHINCS128_SHAKE_CRYPTO_PATH)/, $(SPHINCS_SHAKE_SRCS)) $(LDFLAGS)

benchmark_sphincs_shake_192:
	$(CC) $(SPHINCS192_SHAKE_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(SPHINCS192_SHAKE_CRYPTO_PATH)/, $(SPHINCS_SHAKE_SRCS)) $(LDFLAGS)

benchmark_sphincs_shake_256:
	$(CC) $(SPHINCS256_SHAKE_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(SPHINCS256_SHAKE_CRYPTO_PATH)/, $(SPHINCS_SHAKE_SRCS)) $(LDFLAGS)

benchmark_sphincs256_avx2_sha:
	$(CC) $(SPHINCS256_AVX2_SHA_CFLAGS) -o $@ $(BENCHMARK_FILE) $(addprefix $(SPHINCS256_AVX2_SHA_CRYPTO_PATH)/, $(SPHINCS_SHA_AVX2_SRCS)) $(LDFLAGS)

# 실행 순서대로 진행하는 타겟
all: 

run_kyber: benchmark_kyber512 benchmark_kyber768 benchmark_kyber1024
	./benchmark_kyber512
	./benchmark_kyber768
	./benchmark_kyber1024

run_falcon: benchmark_falcon512 benchmark_falcon1024 benchmark_falconpadded512 benchmark_falconpadded1024
	./benchmark_falcon512
	./benchmark_falcon1024
	./benchmark_falconpadded512
	./benchmark_falconpadded1024

run_MLDSA: benchmark_MLDSA_44 benchmark_MLDSA_65 benchmark_MLDSA_87
	./benchmark_MLDSA_44
	./benchmark_MLDSA_65
	./benchmark_MLDSA_87

run_sphincs:benchmark_sphincs_sha_128 benchmark_sphincs_sha_256
	./benchmark_sphincs_sha_256

run_sphincs_avx2: benchmark_sphincs256_avx2_sha
	./benchmark_sphincs256_avx2_sha

clean :
	rm -f benchmark_kyber512 benchmark_kyber768 benchmark_kyber1024 benchmark_falcon512 benchmark_falcon1024 benchmark_falconpadded512 benchmark_falconpadded1024 benchmark_MLDSA_44 benchmark_MLDSA_65 benchmark_MLDSA_87 benchmark_sphincs_sha_128 benchmark_sphincs_sha_192 benchmark_sphincs_sha_256 benchmark_sphincs_shake_128 benchmark_sphincs_shake_192 benchmark_sphincs_shake_256 benchmark_sphincs256_avx2_sha