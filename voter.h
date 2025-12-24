// voter.h - Header for voter simulation with Paillier and ZK proofs

#ifndef VOTER_H
#define VOTER_H

#include "paillier.h"
#include "zkproof.h"

// Simulates a voter casting a vote (0 or 1)
// Outputs the ciphertext and corresponding ZK proof
void voter_cast_vote(PaillierKey *key, ull vote, ull *ciphertext_out, ZKProof *proof_out);

#endif // VOTER_H