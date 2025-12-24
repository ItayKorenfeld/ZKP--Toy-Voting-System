// paillier.h - Header for Paillier cryptosystem

#ifndef PAILLIER_H
#define PAILLIER_H

#include <stdint.h>

typedef unsigned long long ull;

// Paillier key structure
typedef struct {
    ull n;         // Public modulus n = p * q
    ull nsquare;   // n^2 for ciphertext operations
    ull g;         // Generator (usually n + 1)
    ull mu;  
    ull lambda;      // Precomputed for decryption
} PaillierKey;

// Key generation (p and q are fixed internally for demo)
void paillier_keygen(PaillierKey *key);
int gcdExtended(int a, int b, int* x, int* y);

// Encrypt a message m (typically 0 or 1) with randomness r
ull paillier_encrypt(PaillierKey *key, ull m, ull r);

// Decrypt a ciphertext
ull paillier_decrypt(PaillierKey *key, ull c);

// Aggregate two ciphertexts: Enc(m1) * Enc(m2) = Enc(m1 + m2)
ull paillier_aggregate(PaillierKey *key, ull c1, ull c2);

// Modular exponentiation (optional export for testing)
ull modexp(ull base, ull exp, ull mod);
ull modinv(ull a, ull m);
ull gcd(ull a, ull b);
// L function for Paillier decryption
ull L(ull u, ull n);
ull simplified_mod_mul(ull a, ull b, ull m);
ull simplified_lcm(ull a, ull b);
#endif // PAILLIER_H