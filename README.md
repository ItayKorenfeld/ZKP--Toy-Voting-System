# Privacy-Preserving Voting System (Toy Project)

This project demonstrates a **toy voting system** that applies modern cryptographic techniques to preserve voter privacy and ensure vote correctness.

The system uses **Paillier homomorphic encryption** to encrypt votes and enable secure tallying, along with **zero-knowledge proof (ZKP) techniques** to prove the validity of votes without revealing their content.

The project is designed for **educational purposes only**, focusing on understanding the cryptographic principles behind privacy-preserving electronic voting rather than providing a production-ready solution.

## Features
- Vote encryption using Paillier homomorphic encryption
- Secure vote aggregation without decrypting individual votes
- Zero-knowledge proof techniques to validate vote correctness
- Prevention of invalid or malformed votes
- Local (non-networked) voting simulation
- Clear separation between encryption, proof, and tallying logic

## Technical Notes
- This is a **toy / local simulation** and does not include:
  - Authentication mechanisms
  - Secure key distribution
  - Network communication
  - Resistance to malicious authorities
- ZKP proofs are implemented to demonstrate core ideas, not optimized protocols

## Disclaimer
This project is for **educational and demonstrative purposes only**.

It is not intended to be used as a real-world voting system.
The implementation does not provide full security guarantees, adversarial resistance, or legal compliance required for production voting systems.
