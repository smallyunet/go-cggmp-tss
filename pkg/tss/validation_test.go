package tss

import (
	"errors"
	"testing"
)

func validTestParameters() (*Parameters, *MockPartyID, *MockPartyID) {
	p1 := &MockPartyID{id: "p1"}
	p2 := &MockPartyID{id: "p2"}
	return &Parameters{
		PartyID:   p1,
		Parties:   []PartyID{p1, p2},
		Threshold: 1,
		Curve:     "secp256k1",
		SessionID: []byte("0123456789abcdef"),
	}, p1, p2
}

func TestValidateParametersRejectsUnsafeConfigurations(t *testing.T) {
	params, _, _ := validTestParameters()
	if err := ValidateParameters(params); err != nil {
		t.Fatalf("valid parameters rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Parameters)
	}{
		{"short session", func(p *Parameters) { p.SessionID = []byte("short") }},
		{"unsupported curve", func(p *Parameters) { p.Curve = "ed25519" }},
		{"invalid threshold", func(p *Parameters) { p.Threshold = 2 }},
		{"duplicate party", func(p *Parameters) { p.Parties[1] = p.Parties[0] }},
		{"unsorted parties", func(p *Parameters) { p.Parties[0], p.Parties[1] = p.Parties[1], p.Parties[0] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copyParams := *params
			copyParams.Parties = append([]PartyID(nil), params.Parties...)
			tt.mutate(&copyParams)
			if err := ValidateParameters(&copyParams); !errors.Is(err, ErrInvalidParameters) {
				t.Fatalf("expected ErrInvalidParameters, got %v", err)
			}
		})
	}
}

func TestPartyIndexSupportsOpaqueIDs(t *testing.T) {
	params, _, _ := validTestParameters()
	index, err := PartyIndex(params.Parties, "p2")
	if err != nil {
		t.Fatal(err)
	}
	if index.Int64() != 2 {
		t.Fatalf("expected index 2, got %s", index)
	}
}

func TestValidateMessageRejectsReplayAndSpoofing(t *testing.T) {
	params, p1, p2 := validTestParameters()
	valid := &MockMessage{
		msgType:     "SignRound1",
		from:        p2,
		isBroadcast: true,
		payload:     []byte{1},
		round:       1,
		sessionID:   params.SessionID,
	}
	if err := ValidateMessage(params, valid, 1, "SignRound1"); err != nil {
		t.Fatalf("valid message rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*MockMessage)
	}{
		{"wrong session", func(m *MockMessage) { m.sessionID = []byte("fedcba9876543210") }},
		{"unknown sender", func(m *MockMessage) { m.from = &MockPartyID{id: "attacker"} }},
		{"wrong type", func(m *MockMessage) { m.msgType = "SignRound4_Si" }},
		{"wrong round", func(m *MockMessage) { m.round = 2 }},
		{"broadcast recipients", func(m *MockMessage) { m.to = []PartyID{p1} }},
		{"empty payload", func(m *MockMessage) { m.payload = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copyMessage := *valid
			tt.mutate(&copyMessage)
			if err := ValidateMessage(params, &copyMessage, 1, "SignRound1"); !errors.Is(err, ErrInvalidMsg) {
				t.Fatalf("expected ErrInvalidMsg, got %v", err)
			}
		})
	}
}

func TestValidateMessageChecksDirectRouting(t *testing.T) {
	params, p1, p2 := validTestParameters()
	msg := &MockMessage{
		msgType:   "SignRound2_MtA",
		from:      p2,
		to:        []PartyID{p1},
		payload:   []byte{1},
		round:     2,
		sessionID: params.SessionID,
	}
	if err := ValidateMessage(params, msg, 2, "SignRound2_MtA"); err != nil {
		t.Fatalf("valid direct message rejected: %v", err)
	}
	msg.to = []PartyID{p2}
	if err := ValidateMessage(params, msg, 2, "SignRound2_MtA"); !errors.Is(err, ErrInvalidMsg) {
		t.Fatalf("expected wrong recipient to be rejected, got %v", err)
	}
}
