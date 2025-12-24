// voter.c - Simulates a voter casting a vote with encryption and ZK proof

#include "paillier.h"
#include "zkproof.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

void voter_cast_vote(PaillierKey *key, ull vote, ull *ciphertext_out, ZKProof *proof_out) {
    if (vote != 0 && vote != 1) {
        fprintf(stderr, "Invalid vote: must be 0 or 1\n");
        exit(1);
    }

    // Generate randomness r ∈ Z*_n
    ull r;
    do {
        r = rand() % key->n;
    } while (gcd(r, key->n) != 1);
    //r=2;// For testing, use a fixed r to ensure deterministic results

    // Encrypt the vote
    ull ciphertext = paillier_encrypt(key, vote, r);
    *ciphertext_out = ciphertext;

    // Generate ZK proof that vote ∈ {0, 1}
    zkproof_generate(key, proof_out, ciphertext, vote, r);

    printf("Voter cast vote %llu\n", vote);
    printf("Ciphertext: %llu\n", ciphertext);
    printf("ZK Proof: u0=%llu, u1=%llu, e0=%llu, e1=%llu, s0=%llu, s1=%llu\n",
           proof_out->u0, proof_out->u1, proof_out->e0, proof_out->e1, proof_out->s0, proof_out->s1);
}


