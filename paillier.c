// paillier.c - Paillier cryptosystem implementation

#include "paillier.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Helper: compute gcd
typedef unsigned long long ull;

 ull gcd(ull a, ull b) {
    while (b != 0) {
        ull temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
ull simplified_lcm(ull a, ull b) {
    if (a == 0 || b == 0) return 0;
    // To avoid overflow, divide a by gcd(a,b) before multiplying by b
    return (a / gcd(a, b)) * b;
}
ull simplified_mod_mul(ull a, ull b, ull m) {
    ull res = (a % m) * (b % m) % m;
    return res;
}

// L(u) = (u - 1) / n
 ull L(ull u, ull n) {
    return (u - 1) / n;
}

// Modular exponentiation: base^exp mod mod
ull modexp(ull base, ull exp, ull mod) {
    ull result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// Modular inverse using Extended Euclidean Algorithm
 ull modinv(ull a, ull m) {
    ull m0 = m;
    long long y = 0, x = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        // q is quotient
        ull q = a / m;
        ull t = m;

        // m is remainder now, process same as
        // Euclid's algo
        m = a % m, a = t;
        t = y;

        // Update y and x
        y = x - (long long)q * y;
        x = t;
    }

    // Make x positive
    if (x < 0)
        x += m0;

    return (ull)x;
   
}



// Generate keys (with small primes for demo)
void paillier_keygen(PaillierKey *key) {
    // Small demo primes (do NOT use in real systems!)
    ull p = 11, q =13;   //293,313
    key->n = p * q;             // n = pq = 91709
    key->nsquare = key->n * key->n; // n^2 = 8.4 million
    key->g = key->n + 1;        // Common choice for g
    key->lambda = simplified_lcm(p - 1, q - 1);

    // mu = (L(g^lambda mod n^2))^-1 mod n
    ull u = modexp(key->g, key->lambda, key->nsquare);
    ull l = L(u, key->n);
    key->mu = modinv(l, key->n);

    printf("   Paillier KeyGen: n=%llu, n^2=%llu, g=%llu, lambda=%llu, mu=%llu\n",
           key->n, key->nsquare, key->g, key->lambda, key->mu);
}

// Encrypt vote (0 or 1) with randomness r
ull paillier_encrypt(PaillierKey *key, ull m, ull r) {
    ull gm = modexp(key->g, m, key->nsquare);
    ull rn = modexp(r, key->n, key->nsquare);
    return simplified_mod_mul(gm, rn, key->nsquare);
}

// Decrypt ciphertext
ull paillier_decrypt(PaillierKey *key, ull C) {
    ull u = modexp(C, key->lambda, key->nsquare);
    ull l = L(u, key->n);
    ull m = simplified_mod_mul(l, key->mu, key->n); // Use mod_mul
    return m;
}

// Aggregate (multiply) ciphertexts
ull paillier_aggregate(PaillierKey *key, ull c1, ull c2) {
    return simplified_mod_mul(c1, c2, key->nsquare);
}
