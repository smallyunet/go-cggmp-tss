# go-cggmp-tss

[![Go Reference](https://pkg.go.dev/badge/github.com/smallyu/go-cggmp-tss.svg)](https://pkg.go.dev/github.com/smallyu/go-cggmp-tss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A pure Go implementation of the **CGGMP21** Threshold Signature Scheme (TSS) protocol.

> **Note**: This library is currently in active development (Alpha). Do not use in production environments without a thorough security audit.

## Overview

This library implements the [CGGMP21](https://eprint.iacr.org/2021/060) protocol (Canetti-Gennaro-Goldfeder-Makriyannis-Peled), which allows a group of parties to generate a key and sign messages without ever reconstructing the private key in a single location.

### Key Features

*   **Protocol Compliance**: Implements the 4-round Key Generation, 5-round Signing, and **4-round Key Refresh** protocols from CGGMP21.
*   **Network Agnostic**: Designed as a pure state machine. You bring your own transport layer (HTTP, gRPC, Libp2p, NATS, etc.).
*   **Type Safety**: Leverages Go's strong typing to prevent common implementation errors.
*   **Curve Support**: Native support for `secp256k1`.

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
*   `internal/protocol`: Protocol implementations (`keygen`, `sign`).

## License

MIT
