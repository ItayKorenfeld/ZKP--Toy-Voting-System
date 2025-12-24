// main.c - Simulate end-to-end Paillier voting with ZK proofs

#include "paillier.h"
#include "zkproof.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "voter.h"
#include "authority.h"
#define NUM_VOTERS 2



extern int authority_tally_votes(PaillierKey *key, EncryptedVote *votes, int num_votes, ull *tally_ciphertext_out);
extern ull authority_decrypt_tally(PaillierKey *key, ull tally_ciphertext);

int main() {
    srand(time(NULL));

    // 1. Generate keys
    PaillierKey key;
    paillier_keygen(&key);
    printf("Public key: n = %llu, g = %llu\n", key.n, key.g);

    // 2. Simulate voters
    EncryptedVote votes[NUM_VOTERS];
    ull input_votes[NUM_VOTERS] = {1,0}; // Change this for other tests

    for (int i = 0; i < NUM_VOTERS; i++) {
        voter_cast_vote(&key, input_votes[i], &votes[i].ciphertext, &votes[i].proof);
    }

    // 3. Tally votes
    ull tally_cipher;
    if (!authority_tally_votes(&key, votes, NUM_VOTERS, &tally_cipher)) {
        fprintf(stderr, "Tallying failed due to invalid proof(s)\n");
        return 1;
    }

    // 4. Decrypt result
    ull result = authority_decrypt_tally(&key, tally_cipher);
    printf("\nFinal tally (YES votes): %llu out of %d\n", result, NUM_VOTERS);
    return 0;
}