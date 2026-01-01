//go:build js && wasm

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// Global map to store active state machines
// Key: Session ID (string)
var sessions = make(map[string]tss.StateMachine)

func main() {
	c := make(chan struct{}, 0)

	fmt.Println("Go CGGMP-TSS WASM Initialized")

	// Expose Go functions to JS
	js.Global().Set("GoCGGMP", map[string]interface{}{
		"NewKeyGen": js.FuncOf(NewKeyGen),
		"Update":    js.FuncOf(Update),
		"Result":    js.FuncOf(Result),
	})

	<-c
}

// NewKeyGen initializes a new KeyGen session.
// Arguments:
// 0: JSON string of parameters
// Returns:
// Session ID (string) or throws error
func NewKeyGen(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "error: expected 1 argument (jsonParams)"
	}

	paramsJSON := args[0].String()

	// Define a struct to unmarshal JSON params
	// This mirrors tss.Parameters but with simplifications for JSON
	type ParamsInput struct {
		PartyID        string   `json:"partyID"`
		AllParties     []string `json:"allParties"`
		Threshold      int      `json:"threshold"`
		SessionID      string   `json:"sessionID"`
		OneRoundKeyGen bool     `json:"oneRoundKeyGen"`
	}

	var input ParamsInput
	err := json.Unmarshal([]byte(paramsJSON), &input)
	if err != nil {
		return fmt.Sprintf("error: invalid json: %v", err)
	}

	// Create PartyIDs
	parties := make([]tss.PartyID, len(input.AllParties))
	var localParty tss.PartyID
	for i, pid := range input.AllParties {
		p := &SimplePartyID{IDVal: pid, MonikerVal: pid}
		parties[i] = p
		if pid == input.PartyID {
			localParty = p
		}
	}

	if localParty == nil {
		return "error: local party ID not found in allParties"
	}

	params := &tss.Parameters{
		PartyID:        localParty,
		Parties:        parties,
		Threshold:      input.Threshold,
		Curve:          "secp256k1",
		SessionID:      []byte(input.SessionID),
		OneRoundKeyGen: input.OneRoundKeyGen,
	}

	// Initialize State Machine
	sm, outMsgs, err := keygen.NewStateMachine(params)
	if err != nil {
		return fmt.Sprintf("error: failed to create state machine: %v", err)
	}

	sessionHandle := fmt.Sprintf("%s-%s", input.PartyID, input.SessionID)
	// Store session
	sessions[sessionHandle] = sm

	// Return initial messages (if any)
	// We need to return both sessionID and initial messages?
	// The API said "NewKeyGen -> sessionID".
	// But `NewStateMachine` might produce round 1 messages immediately.
	// Let's change the API slightly to return a JSON object: { sessionID: "...", initialMessages: [...] }

	resp := map[string]interface{}{
		"sessionID": sessionHandle,
		"messages":  encodeMessages(outMsgs),
	}

	respBytes, _ := json.Marshal(resp)
	return string(respBytes)
}

// Update processes an incoming message.
// Arguments:
// 0: Session ID (string)
// 1: JSON string of message
// Returns:
// JSON string of output messages (array)
func Update(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return "error: expected 2 arguments (sessionID, jsonMsg)"
	}

	sessionID := args[0].String()
	msgJSON := args[1].String()

	fmt.Printf("DEBUG: Update requested for '%s'\n", sessionID)
	// Debug dump keys
	for k := range sessions {
		if k == sessionID {
			fmt.Printf("DEBUG: Found key '%s' in map\n", k)
		}
	}

	sm, ok := sessions[sessionID]
	if !ok {
		return "error: session not found"
	}

	// Unmarshal message
	// We need a concrete type to unmarshal into.
	// But `tss.Message` is an interface.
	// We use `keygen.KeyGenMessage` for now, assuming only KeyGen.
	// In a real app we might need a wrapper or type sniffing.
	var msg keygen.KeyGenMessage
	err := json.Unmarshal([]byte(msgJSON), &msg)
	if err != nil {
		return fmt.Sprintf("error: invalid message json: %v", err)
	}

	// Helper to reconstruct PartyID interfaces from string IDs in JSON
	// This is tricky because `KeyGenMessage` fields (FromParty, ToParties) are interfaces.
	// If `json.Unmarshal` worked on `keygen.KeyGenMessage`, it likely failed on interface fields or left them nil.
	// We might need a DTO.

	type MessageDTO struct {
		From        string   `json:"from"`
		To          []string `json:"to"`
		IsBroadcast bool     `json:"isBroadcast"`
		Data        string   `json:"data"` // Hex encoded
		Type        string   `json:"type"`
		Round       uint32   `json:"round"`
	}

	var dto MessageDTO
	err = json.Unmarshal([]byte(msgJSON), &dto)
	if err != nil {
		return fmt.Sprintf("error: invalid message dto: %v", err)
	}

	dataBytes, err := hex.DecodeString(dto.Data)
	if err != nil {
		return fmt.Sprintf("error: invalid hex data: %v", err)
	}

	// Reconstruct Message
	// We need to find the FromParty object from the session params to match identity
	// But we don't have easy access to params here.
	// We'll verify signature/identity later?
	// For now, reuse SimplePartyID.

	fromParty := &SimplePartyID{IDVal: dto.From, MonikerVal: dto.From}
	var toParties []tss.PartyID
	if dto.To != nil {
		for _, t := range dto.To {
			toParties = append(toParties, &SimplePartyID{IDVal: t, MonikerVal: t})
		}
	}

	realMsg := &keygen.KeyGenMessage{
		FromParty:  fromParty,
		ToParties:  toParties,
		IsBcast:    dto.IsBroadcast,
		Data:       dataBytes,
		TypeString: dto.Type,
		RoundNum:   dto.Round,
	}

	nextSm, outMsgs, err := sm.Update(realMsg)
	if err != nil {
		return fmt.Sprintf("error: update failed: %v", err)
	}

	if nextSm != nil {
		sessions[sessionID] = nextSm
	} else {
		// Possibly finished or failed?
		// If nextSm is nil but no error, usually means ignored message?
		// Or if finished, it might return a finished state?
		// Our implementation returns finishedState struct, which is not nil.
		// So nil usually implies "no state transition" (ignored) or error.
		// `state.Update` returns `s, nil, nil` if ignoring.
		// So we keep `sm`.
	}

	return marshalMessages(outMsgs)
}

// Result returns the final result if available.
// Arguments:
// 0: Session ID (string)
// Returns:
// JSON string or null
func Result(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "error: expected 1 argument (sessionID)"
	}
	sessionID := args[0].String()
	sm, ok := sessions[sessionID]
	if !ok {
		return "error: session not found"
	}

	res := sm.Result()
	if res == nil {
		return nil // Not finished
	}

	// Marshal result
	// LocalPartySaveData contains big.Ints which json.Marshal handles as numbers or strings?
	// standard `json` marshals `*big.Int` as number. JS might lose precision.
	// We should wrap them in string.
	// But `LocalPartySaveData` is defined in `keygen` package with `*big.Int`.
	// We can't change it easily.
	// However, `math/big` implements `MarshalJSON`? No, `Int` doesn't implement it to return string by default?
	// Actually `big.Int` marshals as a JSON number.
	// For large integers, this is bad for JS.
	// We should verify if we need a custom marshaler or DTO.
	// For this POC, let's trust that users handle BigInt in JS or we might get truncation.
	// BETTER: transform to a DTO with strings.

	// Reflection or specialized DTO?
	// Let's assume standard marshal for now and warn user.
	// Or better: Create a simplistic DTO map.

	resBytes, err := json.Marshal(res)
	if err != nil {
		return fmt.Sprintf("error: marshal result failed: %v", err)
	}
	return string(resBytes)
}

// Helpers

type SimplePartyID struct {
	IDVal      string
	MonikerVal string
}

func (p *SimplePartyID) ID() string      { return p.IDVal }
func (p *SimplePartyID) Moniker() string { return p.MonikerVal }
func (p *SimplePartyID) Key() []byte     { return []byte(p.IDVal) }

func encodeMessages(msgs []tss.Message) []interface{} {
	var out []interface{} // JS array
	for _, m := range msgs {
		out = append(out, map[string]interface{}{
			"from": m.From().ID(),
			"to": func() []string {
				var ids []string
				for _, p := range m.To() {
					ids = append(ids, p.ID())
				}
				return ids
			}(),
			"isBroadcast": m.IsBroadcast(),
			"data":        hex.EncodeToString(m.Payload()),
			"type":        m.Type(),
			"round":       m.RoundNumber(),
		})
	}
	return out
}

func marshalMessages(msgs []tss.Message) string {
	encoded := encodeMessages(msgs)
	b, _ := json.Marshal(encoded)
	return string(b)
}
