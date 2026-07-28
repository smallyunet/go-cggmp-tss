# go-cggmp-tss

[![Go Reference](https://pkg.go.dev/badge/github.com/smallyu/go-cggmp-tss.svg)](https://pkg.go.dev/github.com/smallyu/go-cggmp-tss)
[![CI](https://github.com/smallyu/go-cggmp-tss/actions/workflows/ci.yml/badge.svg)](https://github.com/smallyu/go-cggmp-tss/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A pure Go research implementation of a **CGGMP21-inspired** Threshold
Signature Scheme (TSS) state machine.

> **Security status**: v0.1.0 is an unaudited alpha and is not production
> ready. The honest-party flows are tested, but the implementation does not yet
> include every malicious-security proof required for CGGMP21 compliance.

## Overview

This library explores the protocol structure described by
[CGGMP21](https://eprint.iacr.org/2021/060), allowing parties to generate a key
and sign without reconstructing the private key in one place.

### Key Features

*   **Protocol flows**:
    - 4-round Key Generation
    - 5-round Signing
    - 4-round Key Refresh
    - 4-round Key Resharing (committee/threshold changes)
    - Presigning (offline preprocessing)
*   **Identification Protocol**: ZKP proof of key ownership for accountability.
*   **Network Agnostic**: Designed as a pure state machine. You bring an
    authenticated transport layer (HTTP, gRPC, Libp2p, NATS, etc.).
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
    "github.com/smallyu/go-cggmp-tss/cggmp"
    "github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// 1. Initialize the State Machine
state, outMsgs, err := cggmp.NewKeygen(params)

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
    
    state = nextState

    // Check for completion
    if result := state.Result(); result != nil {
        // Handle result (KeyShare or Signature)
        break
    }
}
```

`SessionID` must contain at least 16 bytes and must be unique for every
protocol run. The transport must authenticate the complete message envelope,
including session ID, sender, recipients, round, type, and payload.

Persist key shares with `cggmp.MarshalKeyShare` and restore them with
`cggmp.ParseKeyShare`. The serialized data contains secret material and must be
encrypted at rest.

For a complete step-by-step guide, please read the **[Usage Documentation](docs/USAGE.md)**.

## Documentation

*   [Usage Guide](docs/USAGE.md): Detailed instructions on implementing KeyGen and Signing.
*   [Mobile Bindings](docs/MOBILE.md): Build iOS/Android bindings using gomobile.
*   [Roadmap](docs/ROADMAP.md): Development status and future plans.

## Architecture

The library is structured to separate cryptographic primitives from protocol logic:

*   `cggmp`: Supported public constructors and result types.
*   `pkg/tss`: Transport-facing interfaces (`PartyID`, `Message`, `StateMachine`).
*   `internal/crypto`: Cryptographic primitives (Paillier, ZK Proofs, Commitments).
*   `internal/protocol`: Protocol implementations (`keygen`, `sign`, `refresh`, `reshare`, `identify`).

## License

MIT
