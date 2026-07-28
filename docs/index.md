# go-cggmp-tss

[![Go Reference](https://pkg.go.dev/badge/github.com/smallyu/go-cggmp-tss.svg)](https://pkg.go.dev/github.com/smallyu/go-cggmp-tss)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A pure Go research implementation of a **CGGMP21-inspired** Threshold
Signature Scheme (TSS) state machine.

> **Security status**: v0.1.0 is an unaudited alpha and is not production
> ready. It does not yet include every malicious-security proof required for
> CGGMP21 compliance.

## Overview

This library explores the protocol structure described by
[CGGMP21](https://eprint.iacr.org/2021/060).

### Key Features

*   **Protocol flows**: Experimental KeyGen, Sign, Refresh, Reshare, and Presign state machines.
*   **Network Agnostic**: Designed as a pure state machine. You bring your own authenticated transport layer.
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
    "github.com/smallyu/go-cggmp-tss/cggmp"
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

For a complete step-by-step guide, please read the **[Usage Documentation](USAGE.md)**.

## Documentation

*   [Usage Guide](USAGE.md): Detailed instructions on implementing KeyGen and Signing.

## Architecture

The library is structured to separate cryptographic primitives from protocol logic:

*   `cggmp`: Supported public constructors and result types.
*   `pkg/tss`: Transport-facing protocol interfaces.

## License

MIT
