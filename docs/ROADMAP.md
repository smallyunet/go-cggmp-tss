# Roadmap

## Experimental Protocol Flows
- [x] Key Generation (CGGMP21 4-round)
- [x] Threshold Signing (CGGMP21 5-round)
- [x] Key Refresh (CGGMP21 4-round)
- [x] Key Resharing (Committee and threshold changes)
- [x] Presigning (Offline preprocessing for faster signing)
- [x] Identification Protocol (ZKP for key ownership)
- [ ] True batch signing (the current compatibility helper signs only the first message)
- [x] Performance Benchmarks
- [x] `secp256k1` Curve Support

## Planned Features

### Phase 1: Optimization
- [x] 1-Round KeyGen (using simpler assumptions)

### Phase 2: Ecosystem
- [x] WebAssembly (WASM) support (v0.0.8)
- [x] Mobile bindings (iOS/Android) (v0.0.9)

## v0.1.0 Security and API Baseline

### Client Binding Parity
- [x] Key Refresh support in mobile bindings
- [x] Key Refresh support in WASM bindings

### API Hardening
- [x] Add a supported public `cggmp` facade
- [x] Remove `internal/...` imports from user-facing examples and docs
- [x] Validate parameters, participant membership, message type and routing
- [x] Bind wire messages to a minimum 16-byte session ID
- [x] Expand cross-platform protocol parity tests for bindings

### Documentation
- [x] Add end-to-end binding tests that cover KeyGen -> Refresh -> Sign

## Required Before Production Use

- [ ] Implement and integrate all malicious-security proofs required by CGGMP21
- [ ] Bind Fiat-Shamir transcripts to canonical protocol context
- [ ] Add independent interoperability vectors
- [ ] Complete external security audit
- [ ] Implement durable state serialization and crash recovery
