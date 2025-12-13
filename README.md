# go-cggmp-tss

A modern, network-agnostic Go implementation of the **CGGMP21** Threshold Signature Scheme (TSS) protocol.

## Features

*   **Protocol**: Implements [CGGMP21](https://eprint.iacr.org/2021/060) (Canetti-Gennaro-Goldfeder-Makriyannis-Peled).
*   **Network Agnostic**: Pure computation library. You handle the networking (HTTP, gRPC, Libp2p, etc.), we handle the state machine.
*   **Type Safe**: Built with Go's strong type system, minimizing `interface{}` usage.
*   **Curve Support**: Primary support for `secp256k1`.

## Architecture

This library uses a **State Machine** pattern.

```go
// Example usage flow
state := keygen.NewStateMachine(params)

for {
    // 1. Receive message from network
    msg := network.Receive()
    
    // 2. Update state machine
    nextState, outMsgs, err := state.Update(msg)
    if err != nil {
        panic(err)
    }
    
    // 3. Send output messages
    network.Broadcast(outMsgs)
    
    // 4. Check if finished
    if nextState == nil {
        result := state.Result()
        break
    }
    
    state = nextState
}
```

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the detailed development plan.
# go-cggmp-tss
