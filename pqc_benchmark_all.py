"""
=============================================================
  POST-QUANTUM CRYPTOGRAPHY — FULL BENCHMARK SUITE
  Operations : Key Generation | Encapsulation | Decapsulation
  Libraries  : liboqs-python (oqs) | pqcrypto
=============================================================
  Run: python pqc_benchmark_all.py
  Requirements:
      pip install oqs numpy
      pip install pqcrypto        (optional – see note below)
=============================================================
"""

import time
import numpy as np

# ── Library availability flags ─────────────────────────────
OQS_AVAILABLE    = False
PQCRYPTO_AVAILABLE = False

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    print("[WARNING] liboqs-python (oqs) not found. Install: pip install oqs")

try:
    from pqcrypto.kem import kyber512 as pq_kyber
    PQCRYPTO_AVAILABLE = True
except ImportError:
    print("[WARNING] pqcrypto not found or kyber512 unavailable. Install: pip install pqcrypto")

ITERATIONS = 50   # number of runs per operation
SEP        = "=" * 62


# ══════════════════════════════════════════════════════════════
#  SECTION 1 — KEY GENERATION BENCHMARK
# ══════════════════════════════════════════════════════════════

def bench_keygen_oqs():
    """liboqs-python  — Key Generation"""
    times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        kem = oqs.KeyEncapsulation("Kyber512")
        kem.generate_keypair()
        times.append(time.perf_counter() - t0)
    return times


def bench_keygen_pqcrypto():
    """pqcrypto  — Key Generation"""
    times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        pq_kyber.generate_keypair()
        times.append(time.perf_counter() - t0)
    return times


# ══════════════════════════════════════════════════════════════
#  SECTION 2 — ENCAPSULATION BENCHMARK
# ══════════════════════════════════════════════════════════════

def bench_encap_oqs():
    """liboqs-python  — Encapsulation"""
    # generate a single keypair once, benchmark encap only
    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()

    times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        _ciphertext, _shared_secret = kem.encap_secret(public_key)
        times.append(time.perf_counter() - t0)
    return times


def bench_encap_pqcrypto():
    """pqcrypto  — Encapsulation"""
    public_key, _secret_key = pq_kyber.generate_keypair()

    times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        pq_kyber.encrypt(public_key)        # encrypt() = encapsulate
        times.append(time.perf_counter() - t0)
    return times


# ══════════════════════════════════════════════════════════════
#  SECTION 3 — DECAPSULATION BENCHMARK
# ══════════════════════════════════════════════════════════════

def bench_decap_oqs():
    """liboqs-python  — Decapsulation"""
    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()
    ciphertext, _shared_secret = kem.encap_secret(public_key)

    times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        kem.decap_secret(ciphertext)
        times.append(time.perf_counter() - t0)
    return times


def bench_decap_pqcrypto():
    """pqcrypto  — Decapsulation"""
    public_key, secret_key = pq_kyber.generate_keypair()
    ciphertext, _shared_secret = pq_kyber.encrypt(public_key)

    times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        pq_kyber.decrypt(secret_key, ciphertext)    # decrypt() = decapsulate
        times.append(time.perf_counter() - t0)
    return times


# ══════════════════════════════════════════════════════════════
#  SECTION 4 — COMPATIBILITY CHECK
# ══════════════════════════════════════════════════════════════

def check_compatibility():
    print(f"\n{SEP}")
    print("  COMPATIBILITY CHECK")
    print(SEP)

    if OQS_AVAILABLE:
        kem_list = oqs.get_enabled_KEM_mechanisms()
        sig_list = oqs.get_enabled_sig_mechanisms()
        print(f"\n[liboqs-python] Supported KEM algorithms ({len(kem_list)}):")
        print("  " + ", ".join(kem_list[:8]) + " ...")
        print(f"\n[liboqs-python] Supported Signature algorithms ({len(sig_list)}):")
        print("  " + ", ".join(sig_list[:8]) + " ...")
    else:
        print("\n[liboqs-python] NOT available")

    if PQCRYPTO_AVAILABLE:
        print("\n[pqcrypto] Kyber512 module loaded successfully ✓")
        print("  Functions: generate_keypair(), encrypt(pk), decrypt(sk, ct)")
    else:
        print("\n[pqcrypto] NOT available")


# ══════════════════════════════════════════════════════════════
#  HELPERS — Statistics + Table Printer
# ══════════════════════════════════════════════════════════════

def stats(times):
    arr = np.array(times) * 1000   # convert to milliseconds
    return {
        "avg_ms"  : round(np.mean(arr),  4),
        "min_ms"  : round(np.min(arr),   4),
        "max_ms"  : round(np.max(arr),   4),
        "std_ms"  : round(np.std(arr),   4),
        "ops_sec" : round(1000 / np.mean(arr), 1),
    }


def print_section(title, rows):
    """
    rows = list of  (library_name, times_list | None)
    """
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)
    header = f"  {'Library':<22} {'Avg(ms)':>8} {'Min(ms)':>8} {'Max(ms)':>8} {'Std(ms)':>8} {'Ops/sec':>9}"
    print(header)
    print("  " + "-" * 58)

    for name, times in rows:
        if times is None:
            print(f"  {name:<22}  {'N/A — library not installed':}")
            continue
        s = stats(times)
        print(
            f"  {name:<22}"
            f"  {s['avg_ms']:>8}"
            f"  {s['min_ms']:>8}"
            f"  {s['max_ms']:>8}"
            f"  {s['std_ms']:>8}"
            f"  {s['ops_sec']:>9}"
        )


def speed_label(avg_ms):
    if avg_ms < 0.5:   return "⚡ Very Fast"
    if avg_ms < 1.5:   return "✅ Fast"
    if avg_ms < 5.0:   return "🔶 Moderate"
    return "🔴 Slow"


def print_summary(keygen_rows, encap_rows, decap_rows):
    print(f"\n{SEP}")
    print("  SUMMARY — SPEED & COMPATIBILITY COMPARISON")
    print(SEP)
    all_rows = [("Key Generation", keygen_rows),
                ("Encapsulation",  encap_rows),
                ("Decapsulation",  decap_rows)]

    for op_name, rows in all_rows:
        print(f"\n  [{op_name}]")
        print(f"  {'Library':<22} {'Avg (ms)':>10}  {'Speed':>14}  {'Compatible?':>12}")
        print("  " + "-" * 62)
        for lib_name, times in rows:
            if times is None:
                print(f"  {lib_name:<22}  {'N/A':>10}  {'—':>14}  {'Not installed':>12}")
            else:
                avg = stats(times)["avg_ms"]
                print(f"  {lib_name:<22}  {avg:>10}  {speed_label(avg):>14}  {'Yes ✓':>12}")


# ══════════════════════════════════════════════════════════════
#  SECTION 5 — liboqs C BENCHMARK (runs as subprocess)
# ══════════════════════════════════════════════════════════════

C_CODE = r"""
/* kyber_bench_full.c  — compile on Linux/WSL
   gcc kyber_bench_full.c -loqs -o kyber_bench_full && ./kyber_bench_full
*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ITERATIONS 50

double elapsed_ms(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1000.0
         + (e.tv_nsec - s.tv_nsec) / 1e6;
}

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) { fprintf(stderr, "KEM init failed\n"); return 1; }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    struct timespec t0, t1;
    double kg_total = 0, enc_total = 0, dec_total = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_KEM_keypair(kem, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        kg_total += elapsed_ms(t0, t1);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_KEM_encaps(kem, ct, ss_enc, pk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        enc_total += elapsed_ms(t0, t1);

        clock_gettime(CLOCK_MONOTONIC, &t0);
        OQS_KEM_decaps(kem, ss_dec, ct, sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        dec_total += elapsed_ms(t0, t1);
    }

    printf("\\n===== liboqs C — Kyber512 (%d iterations) =====\\n", ITERATIONS);
    printf("Key Generation  Avg: %.4f ms\\n", kg_total  / ITERATIONS);
    printf("Encapsulation   Avg: %.4f ms\\n", enc_total / ITERATIONS);
    printf("Decapsulation   Avg: %.4f ms\\n", dec_total / ITERATIONS);

    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    return 0;
}
"""


def write_c_file():
    with open("kyber_bench_full.c", "w") as f:
        f.write(C_CODE)
    print("\n[liboqs C] C source written to: kyber_bench_full.c")
    print("  To compile & run (WSL/Linux):")
    print("    gcc kyber_bench_full.c -loqs -o kyber_bench_full")
    print("    ./kyber_bench_full")


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print(f"\n{SEP}")
    print("  PQC LIBRARY BENCHMARK  —  Kyber512  (KEM)")
    print(f"  Iterations per operation: {ITERATIONS}")
    print(SEP)

    # ── Key Generation ──────────────────────────────────────
    print("\n[*] Running Key Generation benchmarks ...")
    oqs_kg    = bench_keygen_oqs()    if OQS_AVAILABLE     else None
    pq_kg     = bench_keygen_pqcrypto() if PQCRYPTO_AVAILABLE else None

    keygen_rows = [
        ("liboqs-python (oqs)", oqs_kg),
        ("pqcrypto",            pq_kg),
    ]
    print_section("KEY GENERATION", keygen_rows)

    # ── Encapsulation ───────────────────────────────────────
    print("\n[*] Running Encapsulation benchmarks ...")
    oqs_enc = bench_encap_oqs()    if OQS_AVAILABLE     else None
    pq_enc  = bench_encap_pqcrypto() if PQCRYPTO_AVAILABLE else None

    encap_rows = [
        ("liboqs-python (oqs)", oqs_enc),
        ("pqcrypto",            pq_enc),
    ]
    print_section("ENCAPSULATION", encap_rows)

    # ── Decapsulation ───────────────────────────────────────
    print("\n[*] Running Decapsulation benchmarks ...")
    oqs_dec = bench_decap_oqs()    if OQS_AVAILABLE     else None
    pq_dec  = bench_decap_pqcrypto() if PQCRYPTO_AVAILABLE else None

    decap_rows = [
        ("liboqs-python (oqs)", oqs_dec),
        ("pqcrypto",            pq_dec),
    ]
    print_section("DECAPSULATION", decap_rows)

    # ── Summary ─────────────────────────────────────────────
    print_summary(keygen_rows, encap_rows, decap_rows)

    # ── Compatibility ───────────────────────────────────────
    check_compatibility()

    # ── Write C file ────────────────────────────────────────
    write_c_file()

    print(f"\n{SEP}")
    print("  BENCHMARK COMPLETE")
    print(SEP)


if __name__ == "__main__":
    main()
