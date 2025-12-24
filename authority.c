// authority.c - Tallying authority: verifies ZK proofs and tallies encrypted votes

#include "paillier.h"
#include "zkproof.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_VOTES 1024

// Structure to store encrypted votes and their proofs
typedef struct {
    ull ciphertext;
    ZKProof proof;
} EncryptedVote;

// Verify all proofs and aggregate ciphertexts
int authority_tally_votes(PaillierKey *key, EncryptedVote *votes, int num_votes, ull *tally_ciphertext_out) {
    ull tally = 1; // Neutral element for multiplication mod n^2
    for (int i = 0; i < num_votes; i++) {
        if (!zkproof_verify(key, &votes[i].proof, votes[i].ciphertext)) {
            fprintf(stderr, "Invalid ZK proof for vote %d\n", i);
            return 0; // Failure
        }
        printf("Vote %d proof verified successfully\n", i);
        tally = paillier_aggregate(key, tally, votes[i].ciphertext);
    }
    *tally_ciphertext_out = tally;
    return 1; // Success
}

// Decrypt the final tally
ull authority_decrypt_tally(PaillierKey *key, ull tally_ciphertext) {
    return paillier_decrypt(key, tally_ciphertext);
}