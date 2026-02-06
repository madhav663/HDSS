Hybrid Dual-Signature Scheme (HDSS)
A proof-of-concept project exploring a hybrid post-quantum digital signature scheme that combines Falcon and SPHINCS+ to improve resilience against future quantum attacks in blockchain and IoT environments.
This project focuses on design, implementation, and benchmarking, rather than production deployment.

Project Overview
With the advancement of quantum computing, classical digital signature schemes such as RSA and ECDSA are expected to become vulnerable. HDSS addresses this risk by aggregating two post-quantum signature algorithms into a single composite signature.
The core idea is simple:
A signature is considered valid only if all underlying post-quantum schemes verify successfully.
This increases security guarantees for long-lived and high-value systems such as blockchains and IoT infrastructures.

Key Objectives
Explore hybrid post-quantum signature design for quantum-resilient systems


Compare hybrid signatures with classical and individual PQC schemes


Study security vs performance trade-offs in real-world data scenarios



Key Features
Hybrid Dual-Signature Construction
 Combines Falcon (lattice-based) and SPHINCS+ (hash-based) signatures into a single verification workflow.


Proof-of-Concept Implementation
 Implemented core key generation, signing, and verification logic using Python and Golang.


Benchmarking Framework
 Evaluates HDSS against RSA, ECDSA, Falcon, and SPHINCS+ using metrics such as:


Signature validity


Signature size


Signing and verification latency


Tamper Detection
 Any modification to the signed message causes verification failure, demonstrating strong integrity guarantees in preliminary experiments.



Tech Stack
Languages: Python, Golang


Cryptography Focus:


Post-Quantum Cryptography (PQC)


Hybrid digital signatures


Blockchain and IoT security concepts



High-Level Workflow
Generate independent key pairs for Falcon and SPHINCS+


Sign the same message using both algorithms


Aggregate both signatures into a single HDSS signature


Verify each component signature independently


Accept the message only if all verifications succeed



Datasets Used
Real-world blockchain transaction datasets


IoT and structured CSV-based datasets


These datasets were used to simulate realistic signing and verification scenarios for benchmarking.

Security Considerations
Security relies on defense-in-depth: an attacker must break all underlying schemes to forge a valid signature


Designed to remain secure even if one algorithm becomes weaker in the future


Suitable for long-term trust systems where quantum resilience is prioritized



Limitations
Proof-of-concept and small-scale benchmarking only


Not integrated into a production blockchain or IoT platform


Higher computational cost and signature size compared to individual schemes


Full-scale deployment and optimization are outside the current scope



Future Work
Large-scale benchmarking on constrained IoT hardware


Optimization of signature size and signing latency


Formal security proofs and side-channel resistance analysis


Integration with blockchain execution layers and secure middleware
