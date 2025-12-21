# Changelog

All notable changes to this project will be documented in this file.

## [v0.0.5] - 2025-12-22
### Added
- **Polynomial Tests**: Comprehensive test suite for polynomial package (91.7% coverage).
- **E2E Tests**: Full protocol flow tests for KeyGen→Sign and KeyGen→Refresh.
- **Example Code**: Runnable example demonstrating 2-of-3 threshold signature.
- **Linting**: Added golangci-lint configuration and CI integration.

### Fixed
- Updated CHANGELOG to include all v0.0.4 features.
- Cleaned up go.mod dependencies.

## [v0.0.4] - 2025-12-21
### Added
- **Key Resharing**: Support for changing the committee (resharing shares to new parties) and threshold changes.
- **Presigning**: Offline preprocessing phase for faster online signing.
- **Identification Protocol**: ZKP (Schnorr proofs) for key ownership verification.
- **Batch Signing**: Support for signing multiple messages efficiently.
- **Performance Benchmarks**: Comprehensive benchmarks for all protocols (KeyGen, Sign, Refresh, Presign, Identify).

## [v0.0.3] - 2025-12-21

### Added
- **Key Refresh Protocol**: Full support for updating private key shares without changing the public key (CGGMP21 Auxiliary Info & Key Refresh).
- **Roadmap**: Created `docs/ROADMAP.md` to track project status and future plans.
- **Documentation**: Updated `USAGE.md` with a guide for Key Refresh.

## [v0.0.2] - 2025-11-15
### Added
- Threshold Signing protocol implementation.

## [v0.0.1] - 2025-10-01
### Added
- Initial release with Key Generation (DKG) support.
