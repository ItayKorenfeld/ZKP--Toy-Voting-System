// zkproof.h - Header for Zero-Knowledge Proof of Valid Vote

#ifndef ZKPROOF_H
#define ZKPROOF_H

#include "paillier.h"

// Structure to hold the ZK proof data
typedef struct {
    ull u0, u1;   // Commitments for vote 0 and 1
    ull e0, e1;   // Challenge split
    ull s0, s1;   // Responses
} ZKProof;

// Generate a zero-knowledge proof that encrypted vote is 0 or 1
void zkproof_generate(PaillierKey *key, ZKProof *proof, ull ciphertext, ull vote, ull r);

// Verify the ZK proof of valid vote (0 or 1)
int zkproof_verify(PaillierKey *key, ZKProof *proof, ull ciphertext);

#endif // ZKPROOF_H