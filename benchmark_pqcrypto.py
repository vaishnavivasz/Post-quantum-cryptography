import time
import os

ITERATIONS = 50

keygen_time = 0
encap_time = 0
decap_time = 0

for _ in range(ITERATIONS):

    # Simulated Key Generation
    start = time.time()
    public_key = os.urandom(800)   # simulate size
    secret_key = os.urandom(1600)
    keygen_time += (time.time() - start)

    # Simulated Encapsulation
    start = time.time()
    ciphertext = os.urandom(768)
    shared_secret_enc = os.urandom(32)
    encap_time += (time.time() - start)

    # Simulated Decapsulation
    start = time.time()
    shared_secret_dec = shared_secret_enc
    decap_time += (time.time() - start)

print("\n===== pqcrypto (Simulated) Benchmark =====")
print("Iterations:", ITERATIONS)
print("Avg KeyGen Time:", keygen_time / ITERATIONS)
print("Avg Encap Time :", encap_time / ITERATIONS)
print("Avg Decap Time :", decap_time / ITERATIONS)
