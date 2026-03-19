#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ITERATIONS 50

double get_time() {
    return (double)clock() / CLOCKS_PER_SEC;
}

int main() {

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        printf("Error: Kyber512 not supported\n");
        return -1;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    double start, end;

    double keygen_time = 0;
    double encap_time = 0;
    double decap_time = 0;

    for (int i = 0; i < ITERATIONS; i++) {

        // Key Generation
        start = get_time();
        OQS_KEM_keypair(kem, public_key, secret_key);
        end = get_time();
        keygen_time += (end - start);

        // Encapsulation
        start = get_time();
        OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key);
        end = get_time();
        encap_time += (end - start);

        // Decapsulation
        start = get_time();
        OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key);
        end = get_time();
        decap_time += (end - start);
    }

    printf("\n===== liboqs C Benchmark (Kyber512) =====\n");
    printf("Iterations: %d\n", ITERATIONS);
    printf("Avg KeyGen Time: %f seconds\n", keygen_time / ITERATIONS);
    printf("Avg Encap Time : %f seconds\n", encap_time / ITERATIONS);
    printf("Avg Decap Time : %f seconds\n", decap_time / ITERATIONS);

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    OQS_KEM_free(kem);

    return 0;
}



