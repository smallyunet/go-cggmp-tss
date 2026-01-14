//go:build js && wasm

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"syscall/js"

	"github.com/smallyu/go-cggmp-tss/internal/crypto/paillier"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/keygen"
	"github.com/smallyu/go-cggmp-tss/internal/protocol/sign"
	"github.com/smallyu/go-cggmp-tss/pkg/tss"
)

// SessionWrapper holds the state machine and its type
type SessionWrapper struct {
	SM   tss.StateMachine
	Type string // "keygen", "sign"
}

// Global map to store active state machines
var sessions = make(map[string]*SessionWrapper)

func main() {
	c := make(chan struct{})

	fmt.Println("Go CGGMP-TSS WASM Initialized (v0.0.8)")

	// Expose Go functions to JS
	js.Global().Set("GoCGGMP", map[string]interface{}{
		"NewKeyGen":  js.FuncOf(NewKeyGen),
		"NewSigning": js.FuncOf(NewSigning),
		"Update":     js.FuncOf(Update),
		"Result":     js.FuncOf(Result),
	})

	<-c
}

// --- DTOs for JSON Communication ---

type ParamsInput struct {
	PartyID        string   `json:"partyID"`
	AllParties     []string `json:"allParties"`
	Threshold      int      `json:"threshold"`
	SessionID      string   `json:"sessionID"`
	OneRoundKeyGen bool     `json:"oneRoundKeyGen"`
}

type SignParamsInput struct {
	ParamsInput
	KeyData   json.RawMessage `json:"keyData"`   // LocalPartySaveDataDTO
	MsgToSign string          `json:"msgToSign"` // Hex string
}

// LocalPartySaveDataDTO uses strings for big.Int to prevent JS precision loss
type LocalPartySaveDataDTO struct {
	LocalPartyID string `json:"LocalPartyID"`

	ECDSAPubX string `json:"ECDSAPubX"`
	ECDSAPubY string `json:"ECDSAPubY"`

	ShareID string `json:"ShareID"`

	// Paillier Public Key
	PaillierN string `json:"PaillierN"`

	// Using a simplified map for peers
	// PeerID -> N string
	PeerPaillierPks map[string]string `json:"PeerPaillierPks"`

	Ui  string `json:"Ui"`
	Xi  string `json:"Xi"`
	XiX string `json:"XiX"`
	XiY string `json:"XiY"`

	PublicKeyX string `json:"PublicKeyX"`
	PublicKeyY string `json:"PublicKeyY"`

	// Private Paillier info is complex to serialize fully flat,
	// but we need it for signing.
	// For this POC we will serialize the critical private parts: Lambda, Mu.
	// We might need to reconstruct the full struct in Go.
	PaillierLambda string `json:"PaillierLambda"`
	PaillierMu     string `json:"PaillierMu"`
}

type SignatureDTO struct {
	R     string `json:"R"`
	S     string `json:"S"`
	RecID int    `json:"RecID"`
}

// --- KeyGen ---

func NewKeyGen(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "error: expected 1 argument (jsonParams)"
	}

	paramsJSON := args[0].String()
	var input ParamsInput
	err := json.Unmarshal([]byte(paramsJSON), &input)
	if err != nil {
		return fmt.Sprintf("error: invalid json: %v", err)
	}

	params, err := cleanParams(input)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	// Initialize State Machine
	sm, outMsgs, err := keygen.NewStateMachine(params)
	if err != nil {
		return fmt.Sprintf("error: failed to create state machine: %v", err)
	}

	sessionHandle := fmt.Sprintf("%s-%s", input.PartyID, input.SessionID)
	sessions[sessionHandle] = &SessionWrapper{SM: sm, Type: "keygen"}

	return makeResponse(sessionHandle, outMsgs)
}

// --- Signing ---

func NewSigning(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "error: expected 1 argument (jsonParams)"
	}

	paramsJSON := args[0].String()
	var input SignParamsInput
	err := json.Unmarshal([]byte(paramsJSON), &input)
	if err != nil {
		return fmt.Sprintf("error: invalid json: %v", err)
	}

	params, err := cleanParams(input.ParamsInput)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	// Decode Msg
	msgBytes, err := hex.DecodeString(input.MsgToSign)
	if err != nil {
		return fmt.Sprintf("error: invalid msgToSign hex: %v", err)
	}

	// Decode KeyData
	keyData, err := unmarshalKeyData(input.KeyData)
	if err != nil {
		return fmt.Sprintf("error: invalid keyData: %v", err)
	}

	// Initialize State Machine
	sm, outMsgs, err := sign.NewStateMachine(params, keyData, msgBytes)
	if err != nil {
		return fmt.Sprintf("error: failed to create signing state machine: %v", err)
	}

	sessionHandle := fmt.Sprintf("%s-%s", input.PartyID, input.SessionID)
	sessions[sessionHandle] = &SessionWrapper{SM: sm, Type: "sign"}

	return makeResponse(sessionHandle, outMsgs)
}

// --- Generic Update ---

func Update(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return "error: expected 2 arguments (sessionID, jsonMsg)"
	}

	sessionID := args[0].String()
	msgJSON := args[1].String()

	wrapper, ok := sessions[sessionID]
	if !ok {
		return "error: session not found"
	}

	// Decode generic DTO first
	type MessageDTO struct {
		From        string   `json:"from"`
		To          []string `json:"to"`
		IsBroadcast bool     `json:"isBroadcast"`
		Data        string   `json:"data"` // Hex encoded
		Type        string   `json:"type"`
		Round       uint32   `json:"round"`
	}
	var dto MessageDTO
	if err := json.Unmarshal([]byte(msgJSON), &dto); err != nil {
		return fmt.Sprintf("error: invalid message dto: %v", err)
	}

	dataBytes, err := hex.DecodeString(dto.Data)
	if err != nil {
		return fmt.Sprintf("error: invalid hex data: %v", err)
	}

	fromParty := &SimplePartyID{IDVal: dto.From, MonikerVal: dto.From}
	var toParties []tss.PartyID
	if dto.To != nil {
		for _, t := range dto.To {
			toParties = append(toParties, &SimplePartyID{IDVal: t, MonikerVal: t})
		}
	}

	// Construct concrete message based on session type
	var realMsg tss.Message
	if wrapper.Type == "keygen" {
		realMsg = &keygen.KeyGenMessage{
			FromParty:  fromParty,
			ToParties:  toParties,
			IsBcast:    dto.IsBroadcast,
			Data:       dataBytes,
			TypeString: dto.Type,
			RoundNum:   dto.Round,
		}
	} else {
		// sign
		realMsg = &sign.SignMessage{
			FromParty:  fromParty,
			ToParties:  toParties,
			IsBcast:    dto.IsBroadcast,
			Data:       dataBytes,
			TypeString: dto.Type,
			RoundNum:   dto.Round,
		}
	}

	nextSm, outMsgs, err := wrapper.SM.Update(realMsg)
	if err != nil {
		return fmt.Sprintf("error: update failed: %v", err)
	}

	if nextSm != nil {
		sessions[sessionID].SM = nextSm
	}

	return marshalMessages(outMsgs)
}

// --- Result ---

func Result(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "error: expected 1 argument (sessionID)"
	}
	sessionID := args[0].String()
	wrapper, ok := sessions[sessionID]
	if !ok {
		return "error: session not found"
	}

	res := wrapper.SM.Result()
	if res == nil {
		return nil
	}

	// Convert to DTO based on type
	if ks, ok := res.(*keygen.LocalPartySaveData); ok {
		dto := marshalKeyData(ks)
		b, _ := json.Marshal(dto)
		return string(b)
	} else if sig, ok := res.(*sign.Signature); ok {
		dto := SignatureDTO{
			R:     sig.R.String(),
			S:     sig.S.String(),
			RecID: sig.RecID,
		}
		b, _ := json.Marshal(dto)
		return string(b)
	}

	// Fallback generic marshal
	b, err := json.Marshal(res)
	if err != nil {
		return fmt.Sprintf("error: marshal result failed: %v", err)
	}
	return string(b)
}

// --- Helpers ---

func cleanParams(input ParamsInput) (*tss.Parameters, error) {
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
		return nil, fmt.Errorf("local party ID not found in allParties")
	}

	return &tss.Parameters{
		PartyID:        localParty,
		Parties:        parties,
		Threshold:      input.Threshold,
		Curve:          "secp256k1",
		SessionID:      []byte(input.SessionID),
		OneRoundKeyGen: input.OneRoundKeyGen,
	}, nil
}

func makeResponse(sessionID string, msgs []tss.Message) string {
	resp := map[string]interface{}{
		"sessionID": sessionID,
		"messages":  encodeMessages(msgs),
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// SimplePartyID implementation
type SimplePartyID struct {
	IDVal      string
	MonikerVal string
}

func (p *SimplePartyID) ID() string      { return p.IDVal }
func (p *SimplePartyID) Moniker() string { return p.MonikerVal }
func (p *SimplePartyID) Key() []byte     { return []byte(p.IDVal) }

func encodeMessages(msgs []tss.Message) []interface{} {
	var out []interface{}
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

// --- Marshal/Unmarshal Helpers for KeyData ---

// We need to manually reconstruct paillier keys because they are complex structs
// and `LocalPartySaveData` uses pointers.

func marshalKeyData(data *keygen.LocalPartySaveData) LocalPartySaveDataDTO {
	dto := LocalPartySaveDataDTO{
		LocalPartyID: data.LocalPartyID.ID(),
		ECDSAPubX:    data.ECDSAPubX.String(),
		ECDSAPubY:    data.ECDSAPubY.String(),
		ShareID:      data.ShareID.String(),
		Ui:           data.Ui.String(),
		Xi:           data.Xi.String(),
		XiX:          data.XiX.String(),
		XiY:          data.XiY.String(),
		PublicKeyX:   data.PublicKeyX.String(),
		PublicKeyY:   data.PublicKeyY.String(),
	}
	if data.PaillierPk != nil {
		dto.PaillierN = data.PaillierPk.N.String()
	}
	if data.PaillierSk != nil {
		dto.PaillierLambda = data.PaillierSk.Lambda.String()
		dto.PaillierMu = data.PaillierSk.Mu.String()
	}
	dto.PeerPaillierPks = make(map[string]string)
	for pid, pk := range data.PeerPaillierPks {
		dto.PeerPaillierPks[pid] = pk.N.String()
	}
	return dto
}

func unmarshalKeyData(raw json.RawMessage) (*keygen.LocalPartySaveData, error) {
	var dto LocalPartySaveDataDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return nil, err
	}

	toBig := func(s string) *big.Int {
		if s == "" {
			return nil
		}
		n, _ := new(big.Int).SetString(s, 10)
		return n
	}

	data := &keygen.LocalPartySaveData{
		LocalPartyID: &SimplePartyID{IDVal: dto.LocalPartyID, MonikerVal: dto.LocalPartyID},
		ECDSAPubX:    toBig(dto.ECDSAPubX),
		ECDSAPubY:    toBig(dto.ECDSAPubY),
		ShareID:      toBig(dto.ShareID),
		Ui:           toBig(dto.Ui),
		Xi:           toBig(dto.Xi),
		XiX:          toBig(dto.XiX),
		XiY:          toBig(dto.XiY),
		PublicKeyX:   toBig(dto.PublicKeyX),
		PublicKeyY:   toBig(dto.PublicKeyY),
	}

	// Reconstruct Paillier Keys
	if dto.PaillierN != "" {
		n := toBig(dto.PaillierN)
		n2 := new(big.Int).Mul(n, n)

		pk := &paillier.PublicKey{
			N:  n,
			N2: n2,
		}
		data.PaillierPk = pk

		if dto.PaillierLambda != "" && dto.PaillierMu != "" {
			sk := &paillier.PrivateKey{
				PublicKey: *pk,
				Lambda:    toBig(dto.PaillierLambda),
				Mu:        toBig(dto.PaillierMu),
			}
			data.PaillierSk = sk
		}
	}

	data.PeerPaillierPks = make(map[string]*paillier.PublicKey)
	for pid, nStr := range dto.PeerPaillierPks {
		n := toBig(nStr)
		n2 := new(big.Int).Mul(n, n)
		data.PeerPaillierPks[pid] = &paillier.PublicKey{
			N:  n,
			N2: n2,
		}
	}

	return data, nil
}
