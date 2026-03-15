# Roadmap

## Supported Features (v0.0.5)
- [x] Key Generation (CGGMP21 4-round)
- [x] Threshold Signing (CGGMP21 5-round)
- [x] Key Refresh (CGGMP21 4-round)
- [x] Key Resharing (Committee and threshold changes)
- [x] Presigning (Offline preprocessing for faster signing)
- [x] Identification Protocol (ZKP for key ownership)
- [x] Batch Signing
- [x] Performance Benchmarks
- [x] `secp256k1` Curve Support

## Planned Features

### Phase 1: Optimization
- [x] 1-Round KeyGen (using simpler assumptions)

### Phase 2: Ecosystem
- [x] WebAssembly (WASM) support (v0.0.8)
- [x] Mobile bindings (iOS/Android) (v0.0.9)

## Next Release Focus (v0.1.0)

### Client Binding Parity
- [x] Key Refresh support in mobile bindings
- [x] Key Refresh support in WASM bindings

### API Hardening
- [ ] Reduce reliance on `internal/...` imports in user-facing examples and docs
- [ ] Expand cross-platform protocol parity tests for bindings

### Documentation
- [ ] Add end-to-end binding examples that cover KeyGen -> Refresh -> Sign
