import time
import numpy as np
import oqs

ITERATIONS = 50

keygen_times = []
encap_times = []
decap_times = []

kem_name = "Kyber512"

with oqs.KeyEncapsulation(kem_name) as kem:

    for _ in range(ITERATIONS):

        # Key Generation
        start = time.time()
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        keygen_times.append(time.time() - start)

        # Encapsulation
        start = time.time()
        ciphertext, shared_secret_enc = kem.encap_secret(public_key)
        encap_times.append(time.time() - start)

        # Decapsulation
        start = time.time()
        shared_secret_dec = kem.decap_secret(ciphertext)
        decap_times.append(time.time() - start)

print("\n===== liboqs-python Benchmark =====")
print("Iterations:", ITERATIONS)
print("Avg KeyGen Time:", np.mean(keygen_times))
print("Avg Encap Time :", np.mean(encap_times))
print("Avg Decap Time :", np.mean(decap_times))
