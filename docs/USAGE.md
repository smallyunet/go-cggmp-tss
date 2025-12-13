# Usage Guide

This guide explains how to use the `go-cggmp-tss` library to perform Distributed Key Generation (DKG) and Threshold Signing.

## Core Concepts

### Network Agnostic
This library is a **pure computation engine**. It does not handle networking, database storage, or transport security. You are responsible for:
1.  Creating a transport layer (HTTP, gRPC, Libp2p, etc.).
2.  Routing messages between parties.
3.  Persisting the state if necessary.

### State Machine
The protocol is implemented as a **Finite State Machine (FSM)**.
- **Input**: Incoming messages from other parties.
- **Output**: Outgoing messages to be broadcast or sent P2P.
- **State**: The current round of the protocol.

## Prerequisites

### 1. Implement `PartyID`
You need to implement the `tss.PartyID` interface to identify participants.

```go
type MyPartyID struct {
    IDStr   string
    MonikerStr string
    PubKey  []byte
}

func (p *MyPartyID) ID() string      { return p.IDStr }
func (p *MyPartyID) Moniker() string { return p.MonikerStr }
func (p *MyPartyID) Key() []byte     { return p.PubKey }
```

### 2. Setup Parameters
Configure the session parameters.

```go
import "github.com/smallyu/go-cggmp-tss/pkg/tss"

// Create party IDs
p1 := &MyPartyID{IDStr: "1", ...}
p2 := &MyPartyID{IDStr: "2", ...}
p3 := &MyPartyID{IDStr: "3", ...}

params := &tss.Parameters{
    PartyID:   p1,                 // Local party
    Parties:   []tss.PartyID{p1, p2, p3}, // All participants
    Threshold: 1,                  // t (requires t+1 to sign)
    Curve:     "secp256k1",        // Curve
    SessionID: []byte("unique-session-id"),
}
```

## Key Generation (DKG)

The KeyGen protocol generates a distributed private key. At the end, each party receives a `LocalPartySaveData` object containing their share.

### Step 1: Initialize State Machine

```go
import "github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"

state, outMsgs, err := keygen.NewStateMachine(params)
if err != nil {
    panic(err)
}

// Send initial messages
network.Broadcast(outMsgs)
```

### Step 2: Event Loop

Run the state machine until it finishes.

```go
for {
    // 1. Receive a message from the network
    msg := network.Receive()

    // 2. Update the state machine
    nextState, outMsgs, err := state.Update(msg)
    if err != nil {
        panic(err)
    }

    // 3. Send output messages
    for _, m := range outMsgs {
        if m.IsBroadcast() {
            network.Broadcast(m)
        } else {
            network.SendTo(m.To(), m)
        }
    }

    // 4. Check if finished
    if nextState == nil {
        // Protocol finished
        break
    }
    
    // 5. Advance state
    state = nextState
}
```

### Step 3: Save Result

```go
result := state.Result()
if result == nil {
    panic("KeyGen failed")
}

keyData := result.(*keygen.LocalPartySaveData)
// Save keyData to disk securely!
```

## Threshold Signing

Signing requires the `LocalPartySaveData` from KeyGen and the hash of the message to sign.

### Step 1: Initialize State Machine

```go
import "github.com/smallyu/go-cggmp-tss/internal/protocol/sign"

msgHash := sha256.Sum256([]byte("hello world"))

state, outMsgs, err := sign.NewStateMachine(params, keyData, msgHash[:])
if err != nil {
    panic(err)
}

// Send initial messages
network.Broadcast(outMsgs)
```

### Step 2: Event Loop

The loop is identical to KeyGen.

### Step 3: Get Signature

```go
result := state.Result()
if result == nil {
    panic("Sign failed")
}

signature := result.(*sign.Signature)
fmt.Printf("R: %x\nS: %x\n", signature.R, signature.S)
```
