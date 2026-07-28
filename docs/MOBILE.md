# Mobile Bindings (iOS / Android)

This project provides an experimental mobile-friendly wrapper in `github.com/smallyu/go-cggmp-tss/pkg/mobile`.

The wrapper is designed for `gomobile bind` and uses **JSON strings** as the input/output format to avoid cross-language type limitations.

## Prerequisites

Install gomobile:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
```

## Build

### Android (AAR)

```bash
gomobile bind -target=android -o cggmp.aar github.com/smallyu/go-cggmp-tss/pkg/mobile
```

### iOS (XCFramework)

```bash
gomobile bind -target=ios -o CGGMPTSS.xcframework github.com/smallyu/go-cggmp-tss/pkg/mobile
```

## API Overview

The wrapper exposes a `Session` object.

- `NewKeyGenSession(paramsJSON)`
- `NewRefreshSession(paramsJSON)`
- `NewSigningSession(paramsJSON)`
- `(*Session).TakeMessages()`
- `(*Session).Update(msgJSON)`
- `(*Session).Result()`
- `(*Session).Details()`
- `(*Session).Close()`

All message passing is your responsibility (HTTP/gRPC/WebSocket/Libp2p/etc.).
The transport must authenticate the complete JSON envelope. The wrapper only
turns state-machine messages into JSON and back.

## JSON Schemas

### Params (KeyGen)

```json
{
  "partyID": "1",
  "allParties": ["1", "2", "3"],
  "threshold": 1,
  "sessionID": "keygen-session-0001",
  "oneRoundKeyGen": false
}
```

### Params (Signing)

```json
{
  "partyID": "1",
  "allParties": ["1", "2", "3"],
  "threshold": 1,
  "sessionID": "signing-session-0001",
  "oneRoundKeyGen": false,
  "keyData": { "...": "..." },
  "msgToSign": "<hex-encoded-hash>"
}
```

### Params (Refresh)

```json
{
  "partyID": "1",
  "allParties": ["1", "2", "3"],
  "threshold": 1,
  "sessionID": "refresh-session-0001",
  "oneRoundKeyGen": false,
  "keyData": { "...": "..." }
}
```

### Wire Message

```json
{
  "from": "1",
  "to": ["2"],
  "isBroadcast": false,
  "data": "<hex>",
  "type": "...",
  "round": 1,
  "sessionID": "keygen-session-0001"
}
```

Session IDs must contain at least 16 bytes and must never be reused.

## Minimal Flow

1. Each party creates a session (`NewKeyGenSession`).
2. Each party calls `TakeMessages()` and sends the returned JSON messages to other parties.
3. When a party receives a message, call `Update(msgJSON)`.
4. Repeat until `Result()` returns a non-empty JSON string.
5. Persist the returned KeyGen result JSON and embed it into Refresh or Signing params as `keyData`.
6. After Refresh completes, persist the refreshed key JSON and use it for subsequent Signing sessions.
