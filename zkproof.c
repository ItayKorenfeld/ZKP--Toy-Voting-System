// zkproof.c - Zero-Knowledge OR-Proof for Paillier encrypted vote validity

#include "zkproof.h"
#include "paillier.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/sha.h> // or your own sha256

static ull hash_challenge(ull u0, ull u1, ull ciphertext, ull n_mod) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char input[100];
    snprintf(input, sizeof(input), "%llu|%llu|%llu", ciphertext, u0, u1);

    SHA256((unsigned char*)input, strlen(input), hash);

    // Take first 32 bytes as integer, reduce mod q
    unsigned int e = 0;
    for (int i = 0; i < 4; i++) {
        e = (e << 8) | hash[i];
    }

    return e % n_mod;
}


// Generate a ZK proof that the encrypted vote is 0 or 1
// Voter knows: vote v (0 or 1), randomness r
// Proof: commitment (u0, u1), response (s0, s1), challenge split (e0, e1)
void zkproof_generate(PaillierKey *key, ZKProof *proof, ull ciphertext, ull vote, ull r) {
    ull n = key->n;
    ull nsq = key->nsquare;

    ull x0=ciphertext;
    ull x1_inv = modinv(key->g, nsq);
    ull x1 = simplified_mod_mul(x0, x1_inv, nsq); // c



    // For the False Branch: pick random challenge and response, then compute commitment
    ull e_false; // Random challenge for the false branch
    ull s_false; // Random response for the false branch
    ull A_false_commitment;

    // For the True Branch: pick random commitment randomness (k_true), and derive challenge/response later
    ull k_true;
    ull A_true_commitment; // Based on k_true

    // Overall Challenge
    ull e_combined; // Derived from hash(A0, A1, C)

    if (vote == 0) { // Proving C is encryption of 0 (true branch is 0)
        // False branch (1-branch): Pick random e1, s1
        e_false = rand() % n;
        s_false = rand() % n; // s_false must be in Z_n, not nsq

        //testing
        //e_false=7;
       // s_false=4;
        
        // Calculate A1 (fake commitment for false branch)
        // A1 = (s1^n * X1^-e1) mod n^2 => A1 = (s1^n * (X1^e1)^-1) mod n^2
        ull s_false_pow_n = modexp(s_false, n, nsq);
        ull X1_pow_e_false = modexp(x1, e_false, nsq);
        ull X1_pow_e_false_inv = modinv(X1_pow_e_false, nsq);
        A_false_commitment = simplified_mod_mul(s_false_pow_n, X1_pow_e_false_inv, nsq);
        A_false_commitment = simplified_mod_mul(A_false_commitment, key->g, nsq); // A1 = g * (s1^n * X1^-e1)

        // True branch (0-branch): Pick random k0, compute A0
        k_true = rand() % n;
        //testing
        //k_true=2;
        A_true_commitment = modexp(k_true, n, nsq); // A0 = k0^n

        // Assign to proof structure for hashing
        proof->u0 = A_true_commitment;
        proof->u1 = A_false_commitment;

        // Compute combined challenge
        e_combined = hash_challenge(proof->u0, proof->u1, ciphertext, n);
        printf("e_combined = %llu\n", e_combined);
        //testing
       // e_combined=20;

        // Derive true challenge e0 and true response s0
        proof->e1 = e_false; // e1 is random
        proof->s1 = s_false; // s1 is random

        proof->e0 = (e_combined + n - proof->e1) % n; // e0 = e - e1 mod n
        // s0 = (k0 * r_original^e0) mod n
        ull r_orig_pow_e0 = modexp(r, proof->e0, n); // r_original is in Z_n
        proof->s0 = simplified_mod_mul(k_true, r_orig_pow_e0, n);

    } else { // vote == 1: Proving C is encryption of 1 (true branch is 1)
        // False branch (0-branch): Pick random e0, s0
        e_false = rand() % n;
        s_false = rand() % n; // s_false must be in Z_n, not nsq

        //testing
        //e_false=7;
        //s_false=4;

        // Calculate A0 (fake commitment for false branch)
        // A0 = (s0^n * X0^-e0) mod n^2
        ull s_false_pow_n = modexp(s_false, n, nsq);
        
        printf("s_false_pow_n = %llu\n", s_false_pow_n);
        ull X0_inv = modinv(x0, nsq);
        printf("X0_inv = %llu\n", X0_inv);
        ull X0_pow_e_false_inv = modexp(X0_inv,e_false, nsq);
        printf("X0_pow_e_false_inv = %llu\n", X0_pow_e_false_inv);
        A_false_commitment = simplified_mod_mul(s_false_pow_n, X0_pow_e_false_inv, nsq);
        

        // True branch (1-branch): Pick random k1, compute A1
        k_true = rand() % n;
        //testing
        //k_true=2;
        // A1 = g^1 * k1^n for C = g^1 * r1^n, so A1 = g * k1^n
        A_true_commitment = simplified_mod_mul(key->g, modexp(k_true, n, nsq), nsq); // A1 = g * k1^n
       

        // Assign to proof structure for hashing
        proof->u0 = A_false_commitment;
        proof->u1 = A_true_commitment;

        // Compute combined challenge
        e_combined = hash_challenge(proof->u0, proof->u1, ciphertext, n);
        

        // Derive true challenge e1 and true response s1
        proof->e0 = e_false; // e0 is random
        proof->s0 = s_false; // s0 is random

        proof->e1 = (e_combined + n - proof->e0) % n; // e1 = e - e0 mod n
        // s1 = (k1 * r_original^e1) mod n
        ull r_orig_pow_e1 = modexp(r, proof->e1, n); // r_original is in Z_n
        proof->s1 = simplified_mod_mul(k_true, r_orig_pow_e1, n);
        
}
}
// Verify the ZK proof
int zkproof_verify(PaillierKey *key, ZKProof *proof, ull ciphertext) {
    ull n = key->n;
    ull nsq = key->nsquare;

    // Recalculate combined challenge from received A0, A1
    ull e_recomputed = hash_challenge(proof->u0, proof->u1, ciphertext, n);
    
    

    // 1. Check if the challenge split is correct: e0 + e1 = e_recomputed (mod n)
    if ((proof->e0 + proof->e1) % n != e_recomputed) {
        printf("   ZKP Verification FAILED: Challenge sum mismatch.\n");
        printf("     e0 = %llu, e1 = %llu, recomputed e = %llu\n", proof->e0, proof->e1, e_recomputed);
        return 0;
    }

    // 2. Define X0 = C and X1 = C * g^-1 mod n^2
    ull X0 = ciphertext;
    ull X1_inverse_g = modinv(key->g, nsq);
    printf("X1_inverse_g = %llu\n", X1_inverse_g);
    ull X1 = simplified_mod_mul(ciphertext, X1_inverse_g, nsq);
    printf(" X1 = %llu\n", X1);

    // 3. Verify the 0-branch equation: s0^n == u0 * X0^e0 mod n^2
    ull s0_pow_n = modexp(proof->s0, n, nsq);
    ull X0_pow_e0 = modexp(X0, proof->e0, nsq);
    ull rhs0 = simplified_mod_mul(proof->u0, X0_pow_e0, nsq);
    if (s0_pow_n != rhs0) {
        printf("   ZKP Verification FAILED: 0-branch equation mismatch.\n");
        // For debugging:
         printf("     s0^n = %llu, rhs0 = %llu\n", s0_pow_n, rhs0);
        return 0;
    }


    // 4. Verify the 1-branch equation: (g * s1^n) == u1 * X1^e1 mod n^2
    ull s1_pow_n = modexp(proof->s1, n, nsq);
    printf("s1_pow_n = %llu\n", s1_pow_n);
    ull g_s1_pow_n = simplified_mod_mul(key->g, s1_pow_n, nsq);
    printf("g*s1^n = %llu\n", g_s1_pow_n);
    ull X1_pow_e1 = modexp(X1, proof->e1, nsq);
    printf("X1_pow_e1 = %llu\n", X1_pow_e1);
    ull rhs1 = simplified_mod_mul(proof->u1, X1_pow_e1, nsq);
    printf("rhs1 = %llu\n", rhs1);
    if (g_s1_pow_n != rhs1) {
        printf("   ZKP Verification FAILED: 1-branch equation mismatch.\n");
        // For debugging:
         printf("     g*s1^n = %llu, rhs1 = %llu\n", g_s1_pow_n, rhs1);
        return 0;
    }

    // If all checks pass
    return 1;
}
