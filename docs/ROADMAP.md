# go-cggmp-tss Development Roadmap

This document outlines the development milestones for the `go-cggmp-tss` library. The project aims to implement a secure, network-agnostic Threshold Signature Scheme (TSS) library based on the CGGMP21 protocol.

## Phase 1: Infrastructure & Primitives (基础架构与数学原语)

**Goal**: Establish the project skeleton and implement the underlying cryptographic primitives required for CGGMP21.

- [x] **Project Initialization**
    - [x] Initialize Git repository and Go Module structure.
    - [x] Define core interfaces (`PartyID`, `Message`, `StateMachine`) in `pkg/tss`.
    - [x] Set up CI/CD pipelines (Linting, Unit Tests).

- [x] **Cryptographic Primitives (`internal/crypto`)**
    - [x] **Paillier Encryption**: Implement Paillier homomorphic encryption scheme.
        - Key generation, Encryption, Decryption.
        - Homomorphic addition and scalar multiplication.
    - [ ] **Zero-Knowledge Proofs (ZKPs)**: Implement ZKPs required by CGGMP21.
        - [x] Schnorr Proof (for public key ownership).
        - [x] MtA (Multiplicative-to-Additive) protocol proofs.
        - [x] Range Proofs.
    - [x] **Commitment Scheme**: Implement secure hash commitment (e.g., SHA-256 based).

- [x] **Testing**: Achieve >95% unit test coverage for `internal/crypto`.

## Phase 2: Core Protocol - Key Generation (核心协议 - 密钥生成)

**Goal**: Implement the Distributed Key Generation (DKG) protocol.

- [ ] **Protocol Logic (`internal/protocol/keygen`)**
    - [ ] **Round 1**: Ephemeral key generation, Commitment creation, and Broadcast.
    - [ ] **Round 2**: VSS (Verifiable Secret Sharing) share generation and P2P distribution.
    - [ ] **Round 3**: VSS verification, de-commitment, and final public key calculation.
    - [ ] **Round 4**: Proof of Secret Key (Schnorr) verification.

- [ ] **State Machine Integration**
    - [ ] Implement the `StateMachine` interface for the KeyGen flow.
    - [ ] Handle state transitions and message routing logic.

- [ ] **Demo**: Create an in-memory example simulating 3 parties performing KeyGen.

## Phase 3: Core Protocol - Signing (核心协议 - 签名)

**Goal**: Implement the Threshold Signing protocol, including Pre-signing optimization.

- [ ] **Protocol Logic (`internal/protocol/sign`)**
    - [ ] **Round 1**: Nonce generation and commitment.
    - [ ] **Round 2**: MtA (Multiplicative-to-Additive) protocol execution (Gamma & K).
    - [ ] **Round 3**: Partial signature generation.
    - [ ] **Round 4**: Signature aggregation and verification.

- [ ] **Pre-signing Support**
    - [ ] Implement "Offline" phase (Pre-sign) to pre-calculate R values.
    - [ ] Implement "Online" phase for fast signature generation.

- [ ] **Curve Support**
    - [ ] Integrate `secp256k1` (Bitcoin/Ethereum).
    - [ ] Design abstraction for future `Ed25519` support.

- [ ] **Integration Testing**: End-to-end test: KeyGen -> Sign -> Verify on-chain (simulated).

## Phase 4: Hardening & Optimization (生产级加固)

**Goal**: Prepare the library for production use and security audits.

- [ ] **Concurrency & Performance**
    - [ ] Optimize heavy math operations using `goroutines` (Worker Pools).
    - [ ] Benchmark critical paths (Paillier ops, MtA).

- [ ] **Security & Fuzzing**
    - [ ] Implement Fuzz testing for `Update` methods (randomized inputs).
    - [ ] Review code for constant-time operations where applicable.
    - [ ] Dependency audit.

- [ ] **Documentation & Audit**
    - [ ] Write detailed Protocol Specification document.
    - [ ] Prepare code for third-party security audit.
    - [ ] Finalize public API documentation.
