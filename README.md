# go-cggmp-tss

[![Go Reference](https://pkg.go.dev/badge/github.com/smallyu/go-cggmp-tss.svg)](https://pkg.go.dev/github.com/smallyu/go-cggmp-tss)
[![CI](https://github.com/smallyu/go-cggmp-tss/actions/workflows/ci.yml/badge.svg)](https://github.com/smallyu/go-cggmp-tss/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A pure Go implementation of the **CGGMP21** Threshold Signature Scheme (TSS) protocol.

> **Note**: This library is currently in active development (Alpha). Do not use in production environments without a thorough security audit.

## Overview

This library implements the [CGGMP21](https://eprint.iacr.org/2021/060) protocol (Canetti-Gennaro-Goldfeder-Makriyannis-Peled), which allows a group of parties to generate a key and sign messages without ever reconstructing the private key in a single location.

### Key Features

*   **Protocol Compliance**: Implements CGGMP21 protocols:
    - 4-round Key Generation
    - 5-round Signing
    - 4-round Key Refresh
    - 4-round Key Resharing (committee/threshold changes)
    - Presigning (offline preprocessing)
*   **Identification Protocol**: ZKP proof of key ownership for accountability.
*   **Batch Signing**: Sign multiple messages efficiently.
*   **Network Agnostic**: Designed as a pure state machine. You bring your own transport layer (HTTP, gRPC, Libp2p, NATS, etc.).
*   **Type Safety**: Leverages Go's strong typing to prevent common implementation errors.
*   **Curve Support**: Native support for `secp256k1`.

## Performance Benchmarks

Measured on Apple M1, 3-of-3 threshold configuration:

| Protocol | Time | Memory | Allocations |
|----------|------|--------|-------------|
| **KeyGen** | ~235ms | 8.5 MB | 14,609 |
| **Sign** | ~354ms | 1.2 MB | 2,456 |
| **PreSign** (offline) | ~318ms | 1.2 MB | 2,091 |
| **OnlineSign** | **~0.4ms** | 12 KB | 206 |
| **Refresh** | ~420ms | 10 MB | 27,378 |
| **Identify** | **~0.6ms** | 4.6 KB | 79 |

> 💡 **Tip**: Using Presigning reduces signing latency by ~1000x (from ~354ms to ~0.4ms).

Run benchmarks locally:
```bash
go test ./test/benchmark/... -bench=. -benchmem
```

## Installation

```bash
go get github.com/smallyu/go-cggmp-tss
```

## Quick Start

The core of the library is the `StateMachine` pattern. Here is a high-level view of how to integrate it:

```go
import (
    "github.com/smallyu/go-cggmp-tss/pkg/tss"
    "github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
)

// 1. Initialize the State Machine
state, outMsgs, err := keygen.NewStateMachine(params)

// 2. Run the Event Loop
for {
    // Receive message from your network layer
    msg := network.Receive()
    
    // Update the state machine
    nextState, outMsgs, err := state.Update(msg)
    if err != nil {
        log.Fatal(err)
    }
    
    // Send output messages to other parties
    network.Broadcast(outMsgs)
    
    // Check for completion
    if nextState == nil {
        result := state.Result()
        // Handle result (KeyShare or Signature)
        break
    }
    
    state = nextState
}
```

For a complete step-by-step guide, please read the **[Usage Documentation](docs/USAGE.md)**.

## Documentation

*   [Usage Guide](docs/USAGE.md): Detailed instructions on implementing KeyGen and Signing.
*   [Roadmap](docs/ROADMAP.md): Development status and future plans.

## Architecture

The library is structured to separate cryptographic primitives from protocol logic:

*   `pkg/tss`: Core interfaces (`PartyID`, `Message`, `StateMachine`).
*   `internal/crypto`: Cryptographic primitives (Paillier, ZK Proofs, Commitments).
*   `internal/protocol`: Protocol implementations (`keygen`, `sign`, `refresh`, `reshare`, `identify`).

## License

MIT

