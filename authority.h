#ifndef AUTHORITY_H
#define AUTHORITY_H

#include "paillier.h"
#include "zkproof.h"

typedef struct {
    ull ciphertext;
    ZKProof proof;
} EncryptedVote;

int authority_tally_votes(PaillierKey *key, EncryptedVote *votes, int num_votes, ull *tally_ciphertext_out);
ull authority_decrypt_tally(PaillierKey *key, ull tally_ciphertext);

#endif // AUTHORITY_H