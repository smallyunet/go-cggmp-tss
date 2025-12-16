# v0.0.2 Development Plan

This document outlines the planned features and improvements for version `v0.0.2` of `go-cggmp-tss`.

## Goals
The primary goal of v0.0.2 is to complete the core CGGMP21 protocol suite by adding **Key Refresh** and optimizing the signing process with **Pre-signing (Offline/Online split)**.

## Planned Features

### 1. Pre-signing Support (Offline/Online Split)
**Priority**: High
**Description**: Split the current Signing protocol into two phases:
- **Offline Phase**: Parties perform the heavy cryptographic operations (MtA, Nonce generation) *before* the message to be signed is known. This generates a "Pre-signature" or "Pre-processed" bundle.
- **Online Phase**: Once the message is known, parties use the Pre-signature to quickly generate the final signature. This significantly reduces the latency for the end-user.

**Tasks**:
- [x] Refactor `internal/protocol/sign` to decouple rounds that don't depend on the message.
- [x] Define a `PreSignature` data structure to store the intermediate state.
- [x] Create a new entry point `sign.NewPreSignStateMachine` (or similar).
- [x] Create a new entry point `sign.NewOnlineStateMachine` that accepts a `PreSignature`.

### 2. Key Refresh Protocol
**Priority**: High
**Description**: Implement the Key Refresh protocol. This allows parties to generate new secret shares for the *same* public key. This is crucial for security (proactive security) and is a prerequisite for changing the committee (Resharing).

**Tasks**:
- [x] Create `internal/protocol/refresh`.
- [x] Implement the Key Refresh rounds (similar to KeyGen but with zero-sum random values added to shares).
- [x] Ensure auxiliary info (Paillier keys, etc.) is also refreshed or verified.

### 3. Identifiable Abort
**Priority**: Medium
**Description**: Improve error handling to strictly identify which party caused a protocol failure (e.g., invalid ZKP, wrong commitment).

**Tasks**:
- [ ] Define a `Blame` error type containing `PartyID` and `Reason`.
- [ ] Update `Update` methods to return `Blame` errors where possible.

### 4. Ed25519 Support (Investigation)
**Priority**: Low (Stretch Goal)
**Description**: Investigate adding support for EdDSA (Ed25519). This requires a different curve interface and different ZKPs.

**Tasks**:
- [ ] Define a generic `Curve` interface that can support Twisted Edwards curves.
- [ ] Prototype Ed25519 scalar operations.

## Timeline
- **Week 1**: Design Pre-signing data structures and refactor `sign` package.
- **Week 2**: Implement Pre-signing Offline/Online flows.
- **Week 3**: Implement Key Refresh Protocol.
- **Week 4**: Testing and Integration.
